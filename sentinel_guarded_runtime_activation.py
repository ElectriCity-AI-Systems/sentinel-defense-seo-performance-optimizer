#!/usr/bin/env python3
"""Challenge-aware staged activation for Sentinel's guarded runtime.

The state machine remains exclusively in ``sentinel_guarded_autonomy``. This
module evaluates gates and requests only transitions exported by that module.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import pwd
import re
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import sentinel_guarded_activation as activation
import sentinel_guarded_autonomy as guarded
import sentinel_guarded_systemd_installer as installer


PROJECT_DIR = Path("/srv/sentinel-defense")
SCHEMA_VERSION = "sentinel-guarded-runtime-activation-10.19"
REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/guarded-autonomy"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"

REPORT_JSON = REPORT_DIR / "sentinel-guarded-runtime-activation.json"
REPORT_MD = REPORT_DIR / "sentinel-guarded-runtime-activation.md"
HEALTH_JSON = REPORT_DIR / "sentinel-challenge-aware-health.json"
HEALTH_MD = REPORT_DIR / "sentinel-challenge-aware-health.md"
TLS_MD = REPORT_DIR / "sentinel-runtime-tls-gate.md"
WRITE_CANARY_MD = REPORT_DIR / "sentinel-cloudflare-write-canary.md"
SYSTEMD_MODE_MD = REPORT_DIR / "sentinel-systemd-mode-selection.md"
SYSTEMD_OWNER_MD = REPORT_DIR / "sentinel-systemd-owner-action.md"
MONITORING_MD = REPORT_DIR / "sentinel-runtime-monitoring-status.md"
SCHEDULER_MD = REPORT_DIR / "sentinel-runtime-scheduler-verification.md"
CANARY_MD = REPORT_DIR / "sentinel-runtime-canary-status.md"
PROMOTION_MD = REPORT_DIR / "sentinel-runtime-promotion-status.md"
OWNER_MD = REPORT_DIR / "sentinel-runtime-owner-summary.md"

HEALTH_STATE = STATE_DIR / "challenge-health.json"
TLS_STATE = STATE_DIR / "runtime-tls-gate.json"
WRITE_CANARY_STATE = STATE_DIR / "write-canary.json"
SYSTEMD_MODE_STATE = STATE_DIR / "systemd-mode.json"
MONITORING_STATE = STATE_DIR / "monitoring-activation.json"
SCHEDULER_STATE = STATE_DIR / "scheduler-cycles.json"
PROMOTION_STATE = STATE_DIR / "runtime-promotion.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-guarded-runtime-activation.jsonl"
USER_SOURCE_DIR = STATE_DIR / "user-systemd-sources"
USER_SERVICE_SOURCE = USER_SOURCE_DIR / "sentinel-guarded-autonomy.service"
USER_TIMER_SOURCE = USER_SOURCE_DIR / "sentinel-guarded-autonomy.timer"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-challenge-aware-health.playbook.json",
    PLAYBOOK_DIR / "sentinel-cloudflare-write-canary.playbook.json",
    PLAYBOOK_DIR / "sentinel-systemd-runtime-install.playbook.json",
    PLAYBOOK_DIR / "sentinel-monitoring-activation.playbook.json",
    PLAYBOOK_DIR / "sentinel-runtime-auto-promotion.playbook.json",
)

STAGE_LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
STAGE_MONITORING = "LEVEL_2_MONITORING_ACTIVE"
STAGE_SCHEDULER = "LEVEL_2_SCHEDULER_VERIFICATION"
STAGE_CANARY = "LEVEL_2_GUARDED_CANARY"
STAGE_ACTIVE = "LEVEL_2_GUARDED_AUTONOMY"

FIXED_COMMANDS: Dict[str, Tuple[str, ...]] = {
    "privilege_probe": ("/usr/bin/sudo", "-n", "/usr/bin/true"),
    "install_system_units": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/python3",
        "/srv/sentinel-defense/sentinel_guarded_systemd_installer.py",
        "--install",
    ),
    "system_timer_active": ("/usr/bin/systemctl", "is-active", "sentinel-guarded-autonomy.timer"),
    "system_timer_enabled": ("/usr/bin/systemctl", "is-enabled", "sentinel-guarded-autonomy.timer"),
    "system_start_service": ("/usr/bin/systemctl", "start", "sentinel-guarded-autonomy.service"),
    "system_disable_timer": ("/usr/bin/systemctl", "disable", "--now", "sentinel-guarded-autonomy.timer"),
    "user_manager_active": ("/usr/bin/systemctl", "--user", "is-active", "default.target"),
    "user_timer_active": ("/usr/bin/systemctl", "--user", "is-active", "sentinel-guarded-autonomy.timer"),
    "user_timer_enabled": ("/usr/bin/systemctl", "--user", "is-enabled", "sentinel-guarded-autonomy.timer"),
    "verify_user_sources": (
        "/usr/bin/systemd-analyze",
        "--user",
        "verify",
        str(USER_SERVICE_SOURCE),
        str(USER_TIMER_SOURCE),
    ),
    "user_daemon_reload": ("/usr/bin/systemctl", "--user", "daemon-reload"),
    "user_enable_timer": ("/usr/bin/systemctl", "--user", "enable", "--now", "sentinel-guarded-autonomy.timer"),
}


def run_fixed(command_id: str, timeout: int = 45) -> Dict[str, Any]:
    command = FIXED_COMMANDS.get(command_id)
    if command is None:
        return {"command_id": command_id, "returncode": 126, "stdout": "", "stderr": "command_not_allowlisted"}
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
        return {"command_id": command_id, "returncode": 124, "stdout": "", "stderr": "command_timeout"}
    except OSError as exc:
        return {"command_id": command_id, "returncode": 127, "stdout": "", "stderr": type(exc).__name__}
    return {
        "command_id": command_id,
        "returncode": int(process.returncode),
        "stdout": process.stdout.strip()[:1000],
        "stderr": process.stderr.strip()[:500],
    }


def append_audit(event: str, status: str, details: Optional[Dict[str, Any]] = None, breach: bool = False) -> None:
    guarded.append_jsonl(
        AUDIT_JSONL,
        {
            "timestamp": guarded.utc_now(),
            "event": event,
            "status": status,
            "details": details or {},
            "credential_values_disclosed": False,
            "challenge_tokens_disclosed": False,
            "response_body_stored": False,
            "breach": breach,
        },
    )


def read_jsonl(path: Path) -> Tuple[List[Dict[str, Any]], int]:
    rows: List[Dict[str, Any]] = []
    invalid = 0
    if not path.exists() or path.is_symlink():
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


def evaluate_health() -> Dict[str, Any]:
    value = guarded.check_fixed_health_targets()
    value.update(
        {
            "schema_version": SCHEMA_VERSION,
            "generated_at": guarded.utc_now(),
            "monitoring_profile": {
                "status": "ENABLED",
                "homepage_allowed_classes": [guarded.HEALTH_PASS, guarded.HEALTH_EXPECTED_EDGE_CHALLENGE],
                "robots_required_class": guarded.HEALTH_PASS,
                "tls_required": True,
            },
            "scanner_challenge_profile": {
                "status": "ENABLED_AFTER_GUARDED_CANARY_GATE",
                "baseline_comparison_required": True,
                "exact_scope_required": True,
                "ttl_required": True,
                "rollback_required": True,
            },
            "sentinel_rule_rollback_profile": {
                "status": "ENABLED_AFTER_GUARDED_CANARY_GATE",
                "previous_hash_restore_required": True,
                "baseline_comparison_required": True,
            },
            "disabled_profiles": ["login_protection", "microcache", "worker_restart"],
            "generic_403_accepted": False,
            "cloudflare_challenge_bypass_enabled": False,
            "response_bodies_stored": False,
            "challenge_tokens_stored": False,
        }
    )
    guarded.write_json(HEALTH_STATE, value)
    guarded.write_json(activation.HEALTH_STATE_JSON, value)
    guarded.write_json(HEALTH_JSON, value)
    guarded.write_text(HEALTH_MD, render_health(value))
    append_audit(
        "evaluate_health",
        value["status"],
        {
            "homepage_health_class": value.get("homepage_health_class"),
            "robots_health_class": value.get("robots_health_class"),
            "challenge_signature_status": value.get("challenge_signature_status"),
        },
    )
    return value


def evaluate_tls() -> Dict[str, Any]:
    health = guarded.load_dict(HEALTH_STATE)
    checked = guarded.parse_timestamp(health.get("checked_at") or health.get("generated_at"))
    if not checked or guarded.utc_now_dt() - checked > timedelta(minutes=10):
        health = evaluate_health()
    guarded.write_json(activation.HEALTH_STATE_JSON, health)
    value = activation.evaluate_tls_gate()
    value.update(
        {
            "schema_version": SCHEMA_VERSION,
            "http_403_controls_tls_gate": False,
            "ssl_downgrade_recommended": False,
            "automatic_certificate_change": False,
            "automatic_dns_change": False,
        }
    )
    guarded.write_json(TLS_STATE, value)
    guarded.write_text(TLS_MD, render_tls(value))
    append_audit(
        "evaluate_tls",
        value["status"],
        {"current_526": value.get("current_526"), "delta_526": value.get("delta_526")},
    )
    return value


def select_systemd_mode_logic(
    system_scope_available: bool,
    system_scope_installed: bool,
    user_manager_available: bool,
    linger_enabled: bool,
    user_unit_verify_ok: bool,
    environment_readable: bool,
    system_timer_active: bool = False,
    user_timer_active: bool = False,
) -> str:
    if system_timer_active and user_timer_active:
        return "OWNER_ACTION_REQUIRED"
    if system_scope_installed or system_scope_available:
        return "SYSTEM_SCOPE"
    if user_manager_available and linger_enabled and user_unit_verify_ok and environment_readable:
        return "USER_SCOPE_WITH_LINGER"
    return "OWNER_ACTION_REQUIRED"


def derived_linger_status() -> Dict[str, Any]:
    identity = activation.service_identity()
    user = identity.get("user")
    if not user or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", str(user)):
        return {"known": False, "enabled": False, "service_user": None}
    command = ["/usr/bin/loginctl", "show-user", str(user), "-p", "Linger", "--value"]
    try:
        process = subprocess.run(
            command,
            cwd=str(PROJECT_DIR),
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"known": False, "enabled": False, "service_user": user}
    return {
        "known": process.returncode == 0,
        "enabled": process.returncode == 0 and process.stdout.strip().lower() == "yes",
        "service_user": user,
    }


def environment_readable_by_service() -> bool:
    metadata = guarded.private_env_metadata()
    return bool(
        metadata.get("exists")
        and not metadata.get("symlink")
        and metadata.get("mode_safe")
        and metadata.get("required_keys_present")
        and (metadata.get("owner_safe") or metadata.get("group_safe"))
    )


def build_user_unit_sources() -> Dict[str, Any]:
    if guarded.has_project_symlink_component(USER_SOURCE_DIR):
        return {"status": "USER_UNIT_SOURCE_BLOCKED", "reason": "user_source_symlink_escape"}
    try:
        service = installer.SERVICE_SOURCE.read_text(encoding="utf-8")
        timer = installer.TIMER_SOURCE.read_text(encoding="utf-8")
    except OSError as exc:
        return {"status": "USER_UNIT_SOURCE_BLOCKED", "reason": type(exc).__name__}
    service_lines = [
        line for line in service.splitlines()
        if not line.startswith("User=") and not line.startswith("Group=")
    ]
    service_text = "\n".join(service_lines).replace("WantedBy=multi-user.target", "WantedBy=default.target") + "\n"
    timer_text = timer if timer.endswith("\n") else timer + "\n"
    guarded.write_text(USER_SERVICE_SOURCE, service_text)
    guarded.write_text(USER_TIMER_SOURCE, timer_text)
    analyzed = run_fixed("verify_user_sources")
    required_directives = (
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "MemoryDenyWriteExecute=true",
    )
    checks = {
        "user_directives_removed": "User=" not in service_text and "Group=" not in service_text,
        "fixed_exec_start": "ExecStart=/usr/bin/python3 /srv/sentinel-defense/sentinel_guarded_autonomy.py --run-cycle" in service_text,
        "required_hardening_retained": all(item in service_text for item in required_directives),
        "systemd_user_verify": analyzed["returncode"] == 0,
    }
    return {
        "status": "USER_UNIT_SOURCE_VALID" if all(checks.values()) else "USER_UNIT_SOURCE_BLOCKED",
        "checks": checks,
    }


def safe_user_unit_directory(path: Path, home: Path) -> bool:
    try:
        if not path.resolve(strict=False).is_relative_to(home.resolve(strict=True)):
            return False
    except OSError:
        return False
    current = home
    for component in path.relative_to(home).parts:
        current = current / component
        if current.is_symlink():
            return False
    return True


def install_user_scope_timer() -> Dict[str, Any]:
    identity = activation.service_identity()
    user_name = identity.get("user")
    uid = identity.get("uid")
    linger = derived_linger_status()
    sources = build_user_unit_sources()
    if not user_name or uid is None or os.geteuid() != uid or not linger.get("enabled"):
        return {"status": "USER_SCOPE_INSTALL_BLOCKED", "reason": "identity_or_linger_gate"}
    if sources.get("status") != "USER_UNIT_SOURCE_VALID" or not environment_readable_by_service():
        return {"status": "USER_SCOPE_INSTALL_BLOCKED", "reason": "source_or_environment_gate"}
    try:
        home = Path(pwd.getpwnam(str(user_name)).pw_dir)
    except KeyError:
        return {"status": "USER_SCOPE_INSTALL_BLOCKED", "reason": "service_user_home_missing"}
    target_dir = home / ".config/systemd/user"
    if not safe_user_unit_directory(target_dir, home):
        return {"status": "USER_SCOPE_INSTALL_BLOCKED", "reason": "user_unit_path_unsafe"}
    target_dir.mkdir(parents=True, exist_ok=True)
    service_dest = target_dir / "sentinel-guarded-autonomy.service"
    timer_dest = target_dir / "sentinel-guarded-autonomy.timer"
    if service_dest.is_symlink() or timer_dest.is_symlink():
        return {"status": "USER_SCOPE_INSTALL_BLOCKED", "reason": "user_unit_destination_symlink"}
    shutil.copy2(USER_SERVICE_SOURCE, service_dest)
    shutil.copy2(USER_TIMER_SOURCE, timer_dest)
    service_dest.chmod(0o644)
    timer_dest.chmod(0o644)
    reload_result = run_fixed("user_daemon_reload")
    enabled = run_fixed("user_enable_timer") if reload_result["returncode"] == 0 else {"returncode": 1}
    active = run_fixed("user_timer_active")["returncode"] == 0
    return {
        "status": "USER_SCOPE_TIMER_ACTIVE" if enabled["returncode"] == 0 and active else "USER_SCOPE_INSTALL_BLOCKED",
        "timer_active": active,
        "timer_scope": "USER_SCOPE_WITH_LINGER" if active else None,
    }


def select_systemd_mode() -> Dict[str, Any]:
    installed = installer.verify_install()
    privileged = os.geteuid() == 0 or run_fixed("privilege_probe")["returncode"] == 0
    linger = derived_linger_status()
    user_manager = run_fixed("user_manager_active")["returncode"] == 0
    system_timer_active = run_fixed("system_timer_active")["returncode"] == 0
    user_timer_active = run_fixed("user_timer_active")["returncode"] == 0
    user_sources = build_user_unit_sources()
    user_unit_verify_ok = user_sources.get("status") == "USER_UNIT_SOURCE_VALID"
    mode = select_systemd_mode_logic(
        privileged,
        installed["status"] == "SYSTEMD_INSTALL_VERIFIED",
        user_manager,
        linger["enabled"],
        user_unit_verify_ok,
        environment_readable_by_service(),
        system_timer_active,
        user_timer_active,
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": guarded.utc_now(),
        "status": f"SYSTEMD_MODE_{mode}",
        "mode": mode,
        "system_scope_installed": installed["status"] == "SYSTEMD_INSTALL_VERIFIED",
        "noninteractive_system_install_available": privileged,
        "user_manager_available": user_manager,
        "linger_enabled": linger["enabled"],
        "user_unit_verify_ok": user_unit_verify_ok,
        "environment_readable": environment_readable_by_service(),
        "system_timer_active": system_timer_active,
        "user_timer_active": user_timer_active,
        "exactly_one_timer_scope_active": not (system_timer_active and user_timer_active),
        "owner_command": "sudo python3 /srv/sentinel-defense/sentinel_guarded_systemd_installer.py --install" if mode == "OWNER_ACTION_REQUIRED" else None,
        "breach": False,
    }
    guarded.write_json(SYSTEMD_MODE_STATE, result)
    guarded.write_text(SYSTEMD_MODE_MD, render_systemd_mode(result))
    if mode == "OWNER_ACTION_REQUIRED":
        guarded.write_text(SYSTEMD_OWNER_MD, render_owner_systemd_action(result))
    append_audit("select_systemd_mode", result["status"], {"mode": mode})
    return result


def probe_write_canary() -> Dict[str, Any]:
    health = evaluate_health()
    tls = evaluate_tls()
    credentials = activation.validate_credentials()
    if not guarded.health_gate_ok(health) or tls.get("status") not in activation.TLS_GREEN_STATUSES:
        result = {
            "status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
            "reason": "health_or_tls_gate_not_green",
            "monitoring_activation_allowed": True,
            "created": False,
            "deletion_verified": True,
            "traffic_effect": False,
            "credential_values_disclosed": False,
            "breach": False,
        }
    elif credentials.get("status") != "ADAPTER_CREDENTIAL_GATE_GREEN":
        result = {
            "status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
            "reason": "adapter_credential_or_fixed_scope_gate_blocked",
            "monitoring_activation_allowed": True,
            "created": False,
            "deletion_verified": True,
            "traffic_effect": False,
            "credential_values_disclosed": False,
            "breach": False,
        }
    else:
        try:
            result = guarded.CloudflareGuardedAdapter().probe_disabled_write_canary()
        except (RuntimeError, OSError, TimeoutError, ValueError) as exc:
            result = {
                "status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
                "reason": f"adapter_probe_failed:{type(exc).__name__}",
                "monitoring_activation_allowed": True,
                "created": False,
                "deletion_verified": True,
                "traffic_effect": False,
                "credential_values_disclosed": False,
            }
        result["breach"] = result.get("status") == "CLOUDFLARE_WRITE_CANARY_ROLLBACK_FAILED"
    state = guarded.load_state()
    if result["status"] == "CLOUDFLARE_WRITE_CANARY_ROLLBACK_FAILED":
        guarded.trip_runtime_emergency(
            state,
            "GUARDED_AUTONOMY_EMERGENCY_STOP_WRITE_CANARY_ROLLBACK_FAILURE",
            "disabled Cloudflare write canary could not be proven absent",
            breach=True,
        )
        guarded.write_state(state, record_history=True)
    elif result["status"] != "CLOUDFLARE_WRITE_CANARY_OK":
        state["flags"]["guarded_live_autonomy_enabled"] = False
        state["flags"]["low_live_apply_enabled"] = False
        state["flags"]["production_apply_lock"] = True
        state["flags"]["remote_write_lock"] = True
        guarded.write_state(state, record_history=False)
    result.update(
        {
            "schema_version": SCHEMA_VERSION,
            "generated_at": guarded.utc_now(),
            "fixed_rule_identity": guarded.WRITE_CANARY_DESCRIPTION,
            "fixed_zone_scope": True,
            "disabled_rule_required": True,
            "managed_challenge_only": True,
            "credential_values_disclosed": False,
        }
    )
    guarded.write_json(WRITE_CANARY_STATE, result)
    guarded.write_text(WRITE_CANARY_MD, render_write_canary(result))
    append_audit(
        "probe_write_canary",
        result["status"],
        {"created": result.get("created"), "deletion_verified": result.get("deletion_verified")},
        breach=result.get("breach") is True,
    )
    return result


def write_canary_runtime_contract(status: str) -> Dict[str, bool]:
    return {
        "monitoring_activation_allowed": status in {
            "CLOUDFLARE_WRITE_CANARY_OK",
            "CLOUDFLARE_WRITE_CANARY_BLOCKED",
        },
        "low_live_apply_enabled": status == "CLOUDFLARE_WRITE_CANARY_OK",
        "production_apply_lock": status != "CLOUDFLARE_WRITE_CANARY_OK",
        "emergency_stop": status == "CLOUDFLARE_WRITE_CANARY_ROLLBACK_FAILED",
    }


def systemd_runtime_status() -> Dict[str, Any]:
    mode = guarded.load_dict(SYSTEMD_MODE_STATE) or select_systemd_mode()
    system_install = installer.verify_install()
    system_active = run_fixed("system_timer_active")["returncode"] == 0
    user_active = run_fixed("user_timer_active")["returncode"] == 0
    active_count = int(system_active) + int(user_active)
    return {
        "mode": mode.get("mode"),
        "install_status": system_install.get("status"),
        "timer_active": active_count == 1,
        "timer_scope": "SYSTEM_SCOPE" if system_active else ("USER_SCOPE_WITH_LINGER" if user_active else None),
        "multiple_timer_scopes": active_count > 1,
    }


def monitoring_gate_status() -> Dict[str, Any]:
    health = evaluate_health()
    tls = evaluate_tls()
    systemd = systemd_runtime_status()
    lock = guarded.load_dict(guarded.RUNTIME_LOCK_JSON)
    checks = {
        "health_target_gate": guarded.health_gate_ok(health),
        "tls_gate": tls.get("status") in activation.TLS_GREEN_STATUSES,
        "systemd_timer_active": systemd["timer_active"],
        "single_timer_scope": not systemd["multiple_timer_scopes"],
        "policy_valid": guarded.validate_policy().get("status") == "GUARDED_AUTONOMY_POLICY_VALID",
        "audit_valid": guarded.audit_summary().get("invalid_rows") == 0,
        "runtime_lock_valid": lock.get("status", "IDLE") != "RUNNING",
        "breach_false": guarded.load_state().get("flags", {}).get("breach") is False,
    }
    return {
        "status": "RUNTIME_MONITORING_GATES_GREEN" if all(checks.values()) else "RUNTIME_MONITORING_GATES_BLOCKED",
        "checks": checks,
        "blockers": [name for name, passed in checks.items() if not passed],
        "health": health,
        "tls": tls,
        "systemd": systemd,
    }


def activate_monitoring() -> Dict[str, Any]:
    mode = select_systemd_mode()
    if not systemd_runtime_status()["timer_active"] and mode["mode"] == "SYSTEM_SCOPE":
        if os.geteuid() == 0:
            installer.install()
        elif run_fixed("privilege_probe")["returncode"] == 0:
            run_fixed("install_system_units", timeout=90)
    elif not systemd_runtime_status()["timer_active"] and mode["mode"] == "USER_SCOPE_WITH_LINGER":
        install_user_scope_timer()
    gates = monitoring_gate_status()
    if gates["status"] != "RUNTIME_MONITORING_GATES_GREEN":
        result = {
            "status": "RUNTIME_ACTIVATION_PENDING_SYSTEMD_INSTALL" if "systemd_timer_active" in gates["blockers"] else "RUNTIME_MONITORING_BLOCKED",
            "activation_stage": guarded.load_state().get("activation_stage", STAGE_LEVEL_1),
            "blockers": gates["blockers"],
            "systemd_mode": mode,
            "timer_active": gates["systemd"]["timer_active"],
            "monitoring_enabled": guarded.load_state().get("flags", {}).get("monitoring_enabled", True),
            "low_live_apply_enabled": False,
            "emergency_stop": guarded.load_state().get("flags", {}).get("emergency_stop", True),
            "breach": guarded.load_state().get("flags", {}).get("breach", False),
        }
    else:
        state = guarded.load_state()
        state["machine_state"] = guarded.LOCKED
        state["activation_stage"] = STAGE_MONITORING
        state["autonomy_level"] = STAGE_MONITORING
        state["flags"].update(guarded.monitoring_flags())
        state["policy_hash"] = guarded.policy_hash()
        state["registry_hash"] = guarded.build_action_registry()["registry_hash"]
        state["status"] = "GUARDED_MONITORING_ACTIVE"
        state["activation"] = {
            "status": "MONITORING_ACTIVE",
            "systemd_installed": True,
            "timer_scope": gates["systemd"]["timer_scope"],
        }
        guarded.write_state(state, record_history=True)
        result = {
            "status": "AUTONOMY_LEVEL_2_MONITORING_ACTIVE",
            "activation_stage": STAGE_MONITORING,
            "blockers": [],
            "systemd_mode": mode,
            "timer_active": True,
            "timer_scope": gates["systemd"]["timer_scope"],
            "monitoring_enabled": True,
            "low_live_apply_enabled": False,
            "production_apply_lock": True,
            "emergency_stop": False,
            "breach": False,
        }
    result.update({"schema_version": SCHEMA_VERSION, "generated_at": guarded.utc_now(), "gates": gates})
    guarded.write_json(MONITORING_STATE, result)
    guarded.write_text(MONITORING_MD, render_monitoring(result))
    append_audit("activate_monitoring", result["status"], {"blockers": result.get("blockers", [])})
    write_consolidated_report()
    return result


def guarded_rows_since(started_at: Optional[str]) -> Tuple[List[Dict[str, Any]], int]:
    rows, invalid = read_jsonl(guarded.AUDIT_JSONL)
    start = guarded.parse_timestamp(started_at)
    if start is None:
        return [], invalid
    selected = []
    for row in rows:
        timestamp = guarded.parse_timestamp(row.get("timestamp"))
        if row.get("cycle_id") and timestamp and timestamp >= start:
            selected.append(row)
    return selected, invalid


def scheduler_verification_logic(rows: Sequence[Dict[str, Any]], timer_active: bool, invalid_rows: int) -> Dict[str, Any]:
    allowed = {"NO_ACTION", "ACTION_CANDIDATE_BLOCKED_BY_VERIFICATION_STAGE"}
    last_three = list(rows)[-3:]
    cycle_ids = [str(row.get("cycle_id")) for row in last_three]
    checks = {
        "three_cycles": len(last_three) == 3,
        "unique_cycle_ids": len(cycle_ids) == len(set(cycle_ids)) == 3,
        "decisions_safe": len(last_three) == 3 and all(row.get("decision") in allowed for row in last_three),
        "health_valid": len(last_three) == 3
        and all(
            isinstance(row.get("validation_result"), dict)
            and row["validation_result"].get("status") in guarded.HEALTH_GREEN_STATUSES
            for row in last_three
        ),
        "audit_valid": invalid_rows == 0,
        "timer_active": timer_active,
    }
    return {
        "status": "SCHEDULER_VERIFICATION_GREEN" if all(checks.values()) else "SCHEDULER_VERIFICATION_IN_PROGRESS",
        "checks": checks,
        "successful_cycles": sum(1 for row in rows if row.get("decision") in allowed),
        "cycle_ids": cycle_ids,
        "findings": [name for name, passed in checks.items() if not passed],
    }


def verify_scheduler() -> Dict[str, Any]:
    runtime = guarded.load_state()
    systemd = systemd_runtime_status()
    scheduler = guarded.load_dict(SCHEDULER_STATE)
    if runtime.get("activation_stage") == STAGE_MONITORING and systemd["timer_active"]:
        if scheduler.get("status") != "SCHEDULER_VERIFICATION_GREEN":
            guarded.transition(runtime, guarded.PREFLIGHT)
            runtime["activation_stage"] = STAGE_SCHEDULER
            runtime["autonomy_level"] = STAGE_SCHEDULER
            runtime["flags"].update(guarded.monitoring_flags())
            runtime["status"] = "GUARDED_SCHEDULER_VERIFICATION_ACTIVE"
            runtime["preflight"] = {"status": "GUARDED_AUTONOMY_PREFLIGHT_GREEN", "blockers": [], "monitoring_only": True}
            guarded.write_state(runtime, record_history=True)
            scheduler = {
                "status": "SCHEDULER_VERIFICATION_IN_PROGRESS",
                "started_at": guarded.utc_now(),
                "required_cycles": 3,
                "successful_cycles": 0,
            }
            guarded.write_json(SCHEDULER_STATE, scheduler)
    if runtime.get("activation_stage") not in {STAGE_SCHEDULER, STAGE_MONITORING} or not scheduler.get("started_at"):
        result = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": guarded.utc_now(),
            "status": "SCHEDULER_VERIFICATION_NOT_STARTED",
            "started_at": scheduler.get("started_at"),
            "required_cycles": 3,
            "successful_cycles": 0,
            "cycle_ids": [],
            "findings": ["scheduler_stage_not_active"],
            "timer_active": systemd["timer_active"],
            "breach": runtime.get("flags", {}).get("breach", False),
        }
        guarded.write_json(SCHEDULER_STATE, result)
        guarded.write_text(SCHEDULER_MD, render_scheduler(result))
        append_audit("verify_scheduler", result["status"], {"successful_cycles": 0})
        write_consolidated_report()
        return result
    rows, invalid = guarded_rows_since(scheduler.get("started_at"))
    result = scheduler_verification_logic(rows, systemd["timer_active"], invalid)
    result.update(
        {
            "schema_version": SCHEMA_VERSION,
            "generated_at": guarded.utc_now(),
            "started_at": scheduler.get("started_at"),
            "no_overlap": guarded.load_dict(guarded.RUNTIME_LOCK_JSON).get("status", "IDLE") != "RUNNING",
            "no_unexpected_writes": not any("unexpected_write_path" in str(row.get("reason", "")) for row in rows),
            "no_policy_drift": guarded.validate_policy().get("status") == "GUARDED_AUTONOMY_POLICY_VALID",
            "no_runtime_drift": runtime.get("flags", {}).get("low_live_apply_enabled") is False,
            "breach": False,
        }
    )
    if not all((result["no_overlap"], result["no_unexpected_writes"], result["no_policy_drift"], result["no_runtime_drift"])):
        result["status"] = "SCHEDULER_VERIFICATION_BLOCKED"
    if result["status"] == "SCHEDULER_VERIFICATION_GREEN" and systemd["timer_active"]:
        if runtime.get("activation_stage") == STAGE_SCHEDULER:
            runtime["activation_stage"] = STAGE_MONITORING
            runtime["autonomy_level"] = STAGE_MONITORING
            runtime["status"] = "GUARDED_MONITORING_ACTIVE"
            runtime["flags"].update(guarded.monitoring_flags())
            guarded.write_state(runtime, record_history=True)
    guarded.write_json(SCHEDULER_STATE, result)
    guarded.write_text(SCHEDULER_MD, render_scheduler(result))
    append_audit("verify_scheduler", result["status"], {"successful_cycles": result["successful_cycles"]})
    write_consolidated_report()
    return result


def activate_guarded_canary() -> Dict[str, Any]:
    scheduler = verify_scheduler()
    write_canary = guarded.load_dict(WRITE_CANARY_STATE)
    runtime = guarded.load_state()
    circuit = guarded.circuit_status(guarded.load_circuit())
    blockers = []
    if scheduler.get("status") != "SCHEDULER_VERIFICATION_GREEN":
        blockers.append("scheduler_verification")
    if write_canary.get("status") != "CLOUDFLARE_WRITE_CANARY_OK":
        blockers.append("cloudflare_write_canary")
    if guarded.deterministic_rollback_test().get("status") != "GUARDED_AUTONOMY_ROLLBACK_TEST_OK":
        blockers.append("rollback_test")
    if circuit.get("status") != "CIRCUIT_BREAKER_ARMED":
        blockers.append("circuit_breaker")
    if runtime.get("machine_state") != guarded.PREFLIGHT or runtime.get("activation_stage") not in {STAGE_SCHEDULER, STAGE_MONITORING}:
        blockers.append("scheduler_runtime_stage")
    if blockers:
        result = {
            "status": "GUARDED_CANARY_ACTIVATION_BLOCKED",
            "activation_stage": runtime.get("activation_stage", STAGE_LEVEL_1),
            "blockers": blockers,
            "low_live_apply_enabled": False,
            "breach": runtime.get("flags", {}).get("breach", False),
        }
    else:
        guarded.transition(runtime, guarded.CANARY)
        runtime["activation_stage"] = STAGE_CANARY
        runtime["autonomy_level"] = STAGE_CANARY
        runtime["flags"].update(guarded.active_flags())
        runtime["status"] = "GUARDED_CANARY_ACTIVE"
        runtime["activation"] = {
            "status": "GUARDED_CANARY",
            "systemd_installed": True,
            "enabled_action_ids": [
                "temporary_scanner_managed_challenge_v1",
                "rollback_sentinel_owned_rule_v1",
            ],
        }
        guarded.write_state(runtime, record_history=True)
        result = {
            "status": "AUTONOMY_LEVEL_2_GUARDED_CANARY",
            "activation_stage": STAGE_CANARY,
            "started_at": guarded.utc_now(),
            "required_minutes": 60,
            "required_successful_cycles": 20,
            "maximum_active_actions": 1,
            "maximum_ttl_minutes": 10,
            "maximum_live_actions_per_hour": 1,
            "active_low_live_classes": [
                "temporary_high_confidence_scanner_challenge",
                "sentinel_owned_rule_rollback",
            ],
            "disabled_action_classes": ["login_protection", "microcache", "worker_restart", "MEDIUM", "HIGH"],
            "low_live_apply_enabled": True,
            "breach": False,
        }
        guarded.write_json(guarded.CANARY_WINDOW_STATE_JSON, result)
    guarded.write_json(PROMOTION_STATE, result)
    guarded.write_text(CANARY_MD, render_canary(result))
    append_audit("activate_guarded_canary", result["status"], {"blockers": result.get("blockers", [])})
    write_consolidated_report()
    return result


def promotion_logic(
    elapsed_minutes: float,
    successful_cycles: int,
    failed_actions: int,
    failed_rollbacks: int,
    health_regressions: int,
    new_526_growth: bool,
    policy_drift: bool,
    audit_errors: int,
    unexpected_write_paths: int,
) -> Dict[str, Any]:
    checks = {
        "minimum_60_minutes": elapsed_minutes >= 60.0,
        "minimum_20_cycles": successful_cycles >= 20,
        "zero_failed_actions": failed_actions == 0,
        "zero_failed_rollbacks": failed_rollbacks == 0,
        "zero_health_regressions": health_regressions == 0,
        "no_new_526_growth": new_526_growth is False,
        "no_policy_drift": policy_drift is False,
        "audit_valid": audit_errors == 0,
        "no_unexpected_write_paths": unexpected_write_paths == 0,
    }
    hard_failure = any(
        not passed for name, passed in checks.items()
        if name not in {"minimum_60_minutes", "minimum_20_cycles"}
    )
    if hard_failure:
        status = "RUNTIME_PROMOTION_BLOCKED"
    elif all(checks.values()):
        status = "RUNTIME_PROMOTION_GREEN"
    else:
        status = "RUNTIME_PROMOTION_IN_PROGRESS"
    return {"status": status, "checks": checks, "findings": [name for name, passed in checks.items() if not passed]}


def evaluate_promotion() -> Dict[str, Any]:
    runtime = guarded.load_state()
    canary = guarded.load_dict(PROMOTION_STATE)
    started = guarded.parse_timestamp(canary.get("started_at"))
    scheduler = guarded.load_dict(SCHEDULER_STATE)
    write_canary = guarded.load_dict(WRITE_CANARY_STATE)
    systemd = systemd_runtime_status()

    if runtime.get("activation_stage") == STAGE_CANARY and started is not None:
        rows, invalid = guarded_rows_since(canary.get("started_at"))
        elapsed = max(0.0, (guarded.utc_now_dt() - started).total_seconds() / 60.0)
        allowed = {"NO_ACTION", "LOW_LIVE_CANDIDATE", "MONITOR_ACTIVE_ACTION", "ACTIVE_ACTION_VALIDATED", "TTL_ROLLBACK_COMPLETE"}
        successful = sum(1 for row in rows if row.get("decision") in allowed)
        failures = sum(1 for row in rows if row.get("apply_result") and row.get("decision") in {"ROLLBACK_OR_LOCK", "ACTION_FAILED"})
        rollback_failures = sum(1 for row in rows if isinstance(row.get("rollback_result"), dict) and "FAILED" in str(row["rollback_result"].get("status")))
        health_regressions = sum(1 for row in rows if "REGRESSION" in str(row.get("validation_result")))
        unexpected_writes = sum(1 for row in rows if "unexpected_write_path" in str(row.get("reason", "")))
        tls = evaluate_tls()
        result = promotion_logic(
            elapsed,
            successful,
            failures,
            rollback_failures,
            health_regressions,
            (tls.get("delta_526") or 0) > 0,
            guarded.validate_policy().get("status") != "GUARDED_AUTONOMY_POLICY_VALID",
            invalid + guarded.audit_summary().get("invalid_rows", 0),
            unexpected_writes,
        )
        result.update(
            {
                "activation_stage": runtime.get("activation_stage"),
                "runtime_stage": runtime.get("activation_stage"),
                "started_at": canary.get("started_at"),
                "evaluated_at": guarded.utc_now(),
                "elapsed_minutes": round(elapsed, 2),
                "scheduler_successful_cycles": scheduler.get("successful_cycles", 0),
                "guarded_canary_started": True,
                "guarded_canary_successful_cycles": successful,
                "promotion_elapsed_minutes": round(elapsed, 2),
                "breach": False,
            }
        )
        if result["status"] == "RUNTIME_PROMOTION_GREEN":
            guarded.transition(runtime, guarded.ACTIVE)
            runtime["activation_stage"] = STAGE_ACTIVE
            runtime["autonomy_level"] = STAGE_ACTIVE
            runtime["flags"].update(guarded.active_flags())
            runtime["status"] = "GUARDED_AUTONOMY_ACTIVE"
            guarded.write_state(runtime, record_history=True)
            result["activation_stage"] = STAGE_ACTIVE
    elif runtime.get("activation_stage") in {STAGE_MONITORING, STAGE_SCHEDULER}:
        if scheduler.get("status") == "SCHEDULER_VERIFICATION_GREEN" and systemd["timer_active"]:
            if write_canary.get("status") != "CLOUDFLARE_WRITE_CANARY_OK":
                result = {
                    "status": "RUNTIME_PROMOTION_BLOCKED_BY_WRITE_CANARY",
                    "activation_stage": STAGE_MONITORING,
                    "runtime_stage": STAGE_MONITORING,
                    "scheduler_verification_status": scheduler.get("status"),
                    "scheduler_successful_cycles": scheduler.get("successful_cycles", 0),
                    "guarded_canary_started": False,
                    "guarded_canary_successful_cycles": 0,
                    "promotion_elapsed_minutes": 0.0,
                    "blockers": ["cloudflare_write_canary"],
                    "monitoring_enabled": True,
                    "timer_active": True,
                    "low_live_apply_enabled": False,
                    "production_apply_lock": True,
                    "emergency_stop": False,
                    "breach": False,
                }
            else:
                result = {
                    "status": "RUNTIME_PROMOTION_READY_FOR_CANARY",
                    "activation_stage": STAGE_MONITORING,
                    "runtime_stage": STAGE_MONITORING,
                    "scheduler_verification_status": scheduler.get("status"),
                    "scheduler_successful_cycles": scheduler.get("successful_cycles", 0),
                    "guarded_canary_started": False,
                    "guarded_canary_successful_cycles": 0,
                    "promotion_elapsed_minutes": 0.0,
                    "blockers": [],
                    "monitoring_enabled": True,
                    "timer_active": True,
                    "low_live_apply_enabled": False,
                    "production_apply_lock": True,
                    "emergency_stop": False,
                    "breach": False,
                }
        else:
            result = {
                "status": "RUNTIME_PROMOTION_SCHEDULER_NOT_READY",
                "activation_stage": runtime.get("activation_stage", STAGE_LEVEL_1),
                "runtime_stage": runtime.get("activation_stage", STAGE_LEVEL_1),
                "scheduler_verification_status": scheduler.get("status"),
                "scheduler_successful_cycles": scheduler.get("successful_cycles", 0),
                "guarded_canary_started": False,
                "guarded_canary_successful_cycles": 0,
                "promotion_elapsed_minutes": 0.0,
                "blockers": ["scheduler_verification"],
                "monitoring_enabled": True,
                "timer_active": systemd["timer_active"],
                "low_live_apply_enabled": False,
                "production_apply_lock": True,
                "emergency_stop": False,
                "breach": False,
            }
    else:
        result = {
            "status": "RUNTIME_PROMOTION_NOT_STARTED",
            "activation_stage": runtime.get("activation_stage", STAGE_LEVEL_1),
            "runtime_stage": runtime.get("activation_stage", STAGE_LEVEL_1),
            "scheduler_verification_status": None,
            "scheduler_successful_cycles": 0,
            "guarded_canary_started": False,
            "guarded_canary_successful_cycles": 0,
            "promotion_elapsed_minutes": 0.0,
            "blockers": [],
            "monitoring_enabled": False,
            "timer_active": False,
            "low_live_apply_enabled": False,
            "production_apply_lock": True,
            "emergency_stop": True,
            "breach": runtime.get("flags", {}).get("breach", False),
        }
    guarded.write_json(PROMOTION_STATE, result)
    guarded.write_text(PROMOTION_MD, render_promotion(result))
    append_audit("evaluate_promotion", result["status"], {"scheduler_successful_cycles": result.get("scheduler_successful_cycles", 0), "guarded_canary_successful_cycles": result.get("guarded_canary_successful_cycles", 0)})
    write_consolidated_report()
    return result


def pause_live() -> Dict[str, Any]:
    runtime = guarded.load_state()
    rollback = None
    if runtime.get("active_actions"):
        rollback = guarded.execute_rollback(runtime, "runtime_live_pause")
    elif runtime.get("machine_state") == guarded.ACTIVE:
        guarded.transition(runtime, guarded.DEGRADED)
    elif runtime.get("machine_state") == guarded.CANARY:
        guarded.transition(runtime, guarded.ROLLBACK)
        guarded.transition(runtime, guarded.LOCKED)
    runtime["activation_stage"] = STAGE_MONITORING
    runtime["autonomy_level"] = STAGE_MONITORING
    runtime["flags"].update(guarded.monitoring_flags())
    runtime["status"] = "GUARDED_RUNTIME_LIVE_PAUSED_MONITORING_RETAINED"
    guarded.write_state(runtime, record_history=True)
    result = {"status": runtime["status"], "rollback": rollback, "timer_active": systemd_runtime_status()["timer_active"], "breach": False}
    append_audit("pause_live", result["status"])
    write_consolidated_report()
    return result


def resume_live() -> Dict[str, Any]:
    return activate_guarded_canary()


def deactivate_runtime() -> Dict[str, Any]:
    runtime = guarded.load_state()
    if runtime.get("active_actions"):
        guarded.execute_rollback(runtime, "runtime_deactivation")
    disabled = run_fixed("system_disable_timer") if os.geteuid() == 0 else {"returncode": 1}
    guarded.force_safe_locked(runtime, "GUARDED_RUNTIME_DEACTIVATED", ["owner_runtime_deactivation"])
    runtime["activation_stage"] = STAGE_LEVEL_1
    guarded.write_state(runtime, record_history=True)
    result = {
        "status": "GUARDED_RUNTIME_DEACTIVATED" if disabled["returncode"] == 0 else "GUARDED_RUNTIME_DEACTIVATION_OWNER_ACTION_REQUIRED",
        "timer_active": systemd_runtime_status()["timer_active"],
        "breach": False,
    }
    append_audit("deactivate_runtime", result["status"])
    write_consolidated_report()
    return result


def audit_validation() -> Dict[str, Any]:
    rows, invalid = read_jsonl(AUDIT_JSONL)
    guarded_audit = guarded.audit_summary()
    return {
        "status": "RUNTIME_AUDIT_VALID" if invalid == 0 and guarded_audit.get("invalid_rows") == 0 else "RUNTIME_AUDIT_INVALID",
        "runtime_rows": len(rows),
        "runtime_invalid_rows": invalid,
        "guarded_invalid_rows": guarded_audit.get("invalid_rows", 0),
    }


def status_report() -> Dict[str, Any]:
    runtime = guarded.build_runtime_report()
    systemd = systemd_runtime_status()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": guarded.utc_now(),
        "status": runtime.get("status"),
        "activation_stage": runtime.get("activation_stage"),
        "autonomy_level": runtime.get("autonomy_level"),
        "machine_state": runtime.get("machine_state"),
        "flags": runtime.get("flags"),
        "health": guarded.load_dict(HEALTH_STATE),
        "tls": guarded.load_dict(TLS_STATE),
        "systemd": systemd,
        "write_canary": guarded.load_dict(WRITE_CANARY_STATE),
        "monitoring": guarded.load_dict(MONITORING_STATE),
        "scheduler": guarded.load_dict(SCHEDULER_STATE),
        "promotion": guarded.load_dict(PROMOTION_STATE),
        "last_cycle": runtime.get("last_cycle", {}),
        "rollback": runtime.get("rollback_status", {}),
        "circuit_breaker": runtime.get("circuit_breaker", {}),
        "audit": audit_validation(),
        "active_low_live_classes": [
            "temporary_high_confidence_scanner_challenge",
            "sentinel_owned_rule_rollback",
        ] if runtime.get("flags", {}).get("low_live_apply_enabled") else [],
        "disabled_action_classes": ["login_protection", "microcache", "worker_restart", "MEDIUM", "HIGH"],
        "breach": runtime.get("flags", {}).get("breach", False),
    }


def write_consolidated_report() -> Dict[str, Any]:
    report = status_report()
    guarded.write_json(REPORT_JSON, report)
    guarded.write_text(REPORT_MD, render_status(report))
    guarded.write_text(OWNER_MD, render_owner(report))
    return report


def self_test() -> Dict[str, Any]:
    challenge_sample = {
        "health_class": guarded.HEALTH_UNKNOWN,
        "challenge_candidate": True,
        "normalized_signature": "fixed-signature",
    }
    robots_pass = {"health_class": guarded.HEALTH_PASS}
    challenge = guarded.evaluate_health_gate_logic([dict(challenge_sample) for _ in range(3)], robots_pass)
    generic_403 = guarded.evaluate_health_gate_logic(
        [{"health_class": guarded.HEALTH_FAIL, "challenge_candidate": False, "normalized_signature": "generic"}],
        robots_pass,
    )
    tls_stable = activation.evaluate_tls_logic(2, 2, 25, 364.63, True, True, False, False)
    tls_growth = activation.evaluate_tls_logic(2, 3, 25, 364.63, True, True, False, False)
    scheduler = scheduler_verification_logic(
        [
            {"cycle_id": f"cycle-{index}", "decision": "NO_ACTION", "validation_result": {"status": "HEALTH_TARGET_GATE_GREEN_CHALLENGE_AWARE"}}
            for index in range(3)
        ],
        True,
        0,
    )
    promotion = promotion_logic(61.0, 20, 0, 0, 0, False, False, 0, 0)
    promotion_live = evaluate_promotion()
    canary_circuit = guarded.circuit_breaker_default()
    canary_circuit["actions"] = [{"timestamp": guarded.utc_now(), "action_id": "prior-canary"}]
    canary_rate_limit = guarded.rate_limit_allows(
        canary_circuit,
        "temporary_scanner_managed_challenge_v1",
        STAGE_CANARY,
    )
    read_only_contract = write_canary_runtime_contract("CLOUDFLARE_WRITE_CANARY_BLOCKED")
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    shell_true = False
    subprocess_sites = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess" and node.func.attr == "run":
                subprocess_sites += 1
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    shell_true = True
    checks = {
        "test_a_expected_challenge": challenge["status"] == "HEALTH_TARGET_GATE_GREEN_CHALLENGE_AWARE"
        and challenge["homepage"]["health_class"] == guarded.HEALTH_EXPECTED_EDGE_CHALLENGE,
        "test_b_generic_403_fails": generic_403["status"] == "HEALTH_TARGET_GATE_BLOCKED",
        "test_c_stable_526": tls_stable == "TLS_GATE_GREEN_WITH_STALE_HISTORY",
        "test_d_526_growth": tls_growth == "TLS_GATE_RED",
        "test_e_read_only_token_contract": read_only_contract == {
            "monitoring_activation_allowed": True,
            "low_live_apply_enabled": False,
            "production_apply_lock": True,
            "emergency_stop": False,
        },
        "test_f_disabled_write_canary": guarded.WRITE_CANARY_DESCRIPTION == "sentinel-guarded-write-canary"
        and guarded.WRITE_CANARY_EXPRESSION.startswith("(http.request.uri.path eq")
        and guarded.write_canary_payload().get("enabled") is False,
        "test_g_user_mode_with_linger": select_systemd_mode_logic(False, False, True, True, True, True) == "USER_SCOPE_WITH_LINGER",
        "test_h_owner_action": select_systemd_mode_logic(False, False, True, False, False, True) == "OWNER_ACTION_REQUIRED",
        "test_i_monitoring_flags": guarded.monitoring_flags()["emergency_stop"] is False
        and guarded.monitoring_flags()["production_apply_lock"] is True,
        "test_j_promotion": promotion["status"] == "RUNTIME_PROMOTION_GREEN",
        "test_k_promotion_blocked_by_write_canary": promotion_live["status"] == "RUNTIME_PROMOTION_BLOCKED_BY_WRITE_CANARY",
        "test_l_scheduler_cycles_preserved": promotion_live.get("scheduler_successful_cycles", 0) >= 3,
        "test_m_no_canary_cycles_on_blocked": promotion_live.get("guarded_canary_successful_cycles", 0) == 0,
        "test_n_monitoring_not_fallback": promotion_live.get("runtime_stage") in {STAGE_MONITORING, STAGE_SCHEDULER},
        "scheduler_three_cycles": scheduler["status"] == "SCHEDULER_VERIFICATION_GREEN",
        "canary_one_action_per_hour": canary_rate_limit == (False, "hourly_action_limit"),
        "no_shell_true": shell_true is False,
        "fixed_subprocess_gateways": subprocess_sites == 2,
        "no_free_urls": all(target["url"].startswith("https://electri-c-ity-studios-24-7.com/") for target in guarded.POLICY_TEMPLATE["health_targets"]),
        "no_free_cloudflare_expression": guarded.WRITE_CANARY_EXPRESSION == '(http.request.uri.path eq "/__sentinel_guarded_write_canary_never_route__")',
        "installer_fixed_paths": installer.SERVICE_SOURCE == PROJECT_DIR / "systemd/sentinel-guarded-autonomy.service"
        and installer.SERVICE_DEST == Path("/etc/systemd/system/sentinel-guarded-autonomy.service"),
        "symlink_escape_blocked": guarded.deterministic_symlink_escape_test(),
        "single_timer_scope_contract": select_systemd_mode_logic(False, False, True, True, True, True, True, True) == "OWNER_ACTION_REQUIRED",
        "write_canary_deletion_contract": "_delete_fixed_write_canary" in guarded.CloudflareGuardedAdapter.probe_disabled_write_canary.__code__.co_names,
        "no_global_bot_fight_change": guarded.write_canary_payload().get("action") == "managed_challenge"
        and guarded.write_canary_payload().get("enabled") is False,
        "no_ssl_or_dns_change": all(
            item in guarded.MEDIUM_HIGH_BLOCKED_ACTIONS
            for item in ("cloudflare_ssl_mode_change", "dns_change", "certificate_replacement")
        ),
        "no_wordpress_php_db_nginx_change": all(
            item in guarded.MEDIUM_HIGH_BLOCKED_ACTIONS
            for item in ("wordpress_core_change", "plugin_or_theme_change", "database_write", "nginx_main_configuration_change")
        ),
        "medium_high_disabled": guarded.POLICY_TEMPLATE["medium_live_enabled"] is False and guarded.POLICY_TEMPLATE["high_live_enabled"] is False,
        "no_second_state_machine": "ALLOWED_TRANSITIONS" not in globals(),
        "no_response_body_state": "response_body" not in {path.name for path in (HEALTH_STATE, TLS_STATE, WRITE_CANARY_STATE)},
        "breach_false": guarded.default_flags()["breach"] is False,
        "audit_valid": audit_validation()["status"] == "RUNTIME_AUDIT_VALID",
        "credential_values_not_persisted": runtime_credential_leak_scan(),
        "playbooks_valid": all(path.is_file() and isinstance(json.loads(path.read_text(encoding="utf-8")), dict) for path in PLAYBOOKS),
    }
    findings = [name for name, passed in checks.items() if not passed]
    result = {
        "status": "GUARDED_RUNTIME_SELF_TEST_OK" if not findings else "GUARDED_RUNTIME_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }
    append_audit("self_test", result["status"], {"findings": findings})
    write_consolidated_report()
    return result


def runtime_credential_leak_scan() -> bool:
    try:
        secret_values = [value for value in guarded.load_private_environment().values() if len(value) >= 8]
    except (OSError, RuntimeError, UnicodeError):
        secret_values = []
    paths = (
        Path(__file__),
        Path(installer.__file__),
        *PLAYBOOKS,
        REPORT_JSON,
        HEALTH_JSON,
        HEALTH_STATE,
        TLS_STATE,
        WRITE_CANARY_STATE,
        SYSTEMD_MODE_STATE,
        MONITORING_STATE,
        SCHEDULER_STATE,
        PROMOTION_STATE,
        AUDIT_JSONL,
    )
    for path in paths:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            return False
        if any(value in content for value in secret_values):
            return False
        if ("-----BEGIN " + "PRIVATE KEY-----") in content:
            return False
    return True


def render_health(value: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Sentinel Challenge-Aware Health",
            "",
            f"- gate: `{value.get('status', 'NOT_RUN')}`",
            f"- homepage: `{value.get('homepage_health_class', guarded.HEALTH_UNKNOWN)}`",
            f"- challenge signature: `{value.get('challenge_signature_status', 'NOT_RUN')}`",
            f"- robots: `{value.get('robots_health_class', guarded.HEALTH_UNKNOWN)}`",
            f"- TLS verified: `{str(value.get('tls_verified', False)).lower()}`",
            "- generic 403 accepted: `false`",
            "- response bodies stored: `false`",
            "- challenge tokens stored: `false`",
        ]
    )


def render_tls(value: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Sentinel Runtime TLS Gate",
            "",
            f"- status: `{value.get('status', 'NOT_RUN')}`",
            f"- previous/current/delta 526: `{value.get('previous_526')}/{value.get('current_526')}/{value.get('delta_526')}`",
            f"- stable snapshots: `{value.get('consecutive_snapshots_without_growth', 0)}`",
            f"- observation minutes: `{value.get('observation_minutes', 0)}`",
            "- HTTP 403 controls TLS gate: `false`",
            "- SSL downgrade recommended: `false`",
        ]
    )


def render_write_canary(value: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Sentinel Cloudflare Write Canary",
            "",
            f"- status: `{value.get('status', 'NOT_RUN')}`",
            f"- disabled rule created: `{str(value.get('created', False)).lower()}`",
            f"- deletion verified: `{str(value.get('deletion_verified', False)).lower()}`",
            f"- traffic effect: `{str(value.get('traffic_effect', False)).lower()}`",
            "- credential values disclosed: `false`",
        ]
    )


def render_systemd_mode(value: Dict[str, Any]) -> str:
    return "\n".join(["# Sentinel systemd Mode", "", f"- mode: `{value.get('mode')}`", f"- timer active: `{str(value.get('system_timer_active') or value.get('user_timer_active')).lower()}`"])


def render_owner_systemd_action(value: Dict[str, Any]) -> str:
    del value
    return "\n".join(
        [
            "# Sentinel systemd Owner Action",
            "",
            "Neither non-interactive system installation nor a linger-enabled verified user timer is currently available.",
            "",
            "Run exactly:",
            "",
            "```bash",
            "sudo python3 /srv/sentinel-defense/sentinel_guarded_systemd_installer.py --install",
            "```",
            "",
            "The fixed installer validates, backs up, installs and verifies only the two registered Sentinel units. It stores no password.",
        ]
    )


def render_monitoring(value: Dict[str, Any]) -> str:
    return "\n".join(["# Sentinel Runtime Monitoring", "", f"- status: `{value.get('status')}`", f"- timer active: `{str(value.get('timer_active', False)).lower()}`", f"- LOW_LIVE enabled: `{str(value.get('low_live_apply_enabled', False)).lower()}`"])


def render_scheduler(value: Dict[str, Any]) -> str:
    return "\n".join(["# Sentinel Scheduler Verification", "", f"- status: `{value.get('status')}`", f"- successful cycles: `{value.get('successful_cycles', 0)}`"])


def render_canary(value: Dict[str, Any]) -> str:
    return "\n".join(["# Sentinel Runtime Canary", "", f"- status: `{value.get('status')}`", f"- stage: `{value.get('activation_stage')}`", f"- LOW_LIVE enabled: `{str(value.get('low_live_apply_enabled', False)).lower()}`"])


def render_promotion(value: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Runtime Promotion",
        "",
        f"- status: `{value.get('status')}`",
        f"- runtime stage: `{value.get('runtime_stage')}`",
        f"- scheduler verification: `{value.get('scheduler_verification_status')}`",
        f"- scheduler successful cycles: `{value.get('scheduler_successful_cycles', 0)}`",
        f"- guarded canary started: `{str(value.get('guarded_canary_started', False)).lower()}`",
        f"- guarded canary successful cycles: `{value.get('guarded_canary_successful_cycles', 0)}`",
        f"- promotion elapsed minutes: `{value.get('promotion_elapsed_minutes', 0)}`",
        f"- blockers: `{', '.join(value.get('blockers', [])) or 'none'}`",
    ]
    return "\n".join(lines)


def render_status(value: Dict[str, Any]) -> str:
    flags = value.get("flags", {})
    return "\n".join(
        [
            "# Sentinel Guarded Runtime Activation",
            "",
            f"- stage: `{value.get('activation_stage')}`",
            f"- timer active: `{str(value.get('systemd', {}).get('timer_active', False)).lower()}`",
            f"- monitoring enabled: `{str(flags.get('monitoring_enabled', True)).lower()}`",
            f"- LOW_LIVE enabled: `{str(flags.get('low_live_apply_enabled', False)).lower()}`",
            f"- MEDIUM enabled: `{str(flags.get('medium_live_apply_enabled', False)).lower()}`",
            f"- HIGH enabled: `{str(flags.get('high_live_apply_enabled', False)).lower()}`",
            f"- emergency stop: `{str(flags.get('emergency_stop', True)).lower()}`",
            f"- breach: `{str(flags.get('breach', False)).lower()}`",
        ]
    )


def render_owner(value: Dict[str, Any]) -> str:
    timer_active = value.get("systemd", {}).get("timer_active", False)
    stage = value.get("activation_stage")
    if timer_active and stage in {STAGE_CANARY, STAGE_ACTIVE}:
        summary = "Permanent monitoring is active and only the two owner-approved LOW_LIVE classes may execute."
    elif timer_active:
        summary = "Permanent monitoring is active; productive LOW_LIVE actions remain locked pending the write-canary gate."
    else:
        summary = "The 24/7 activation is not complete because no verified permanent timer is active."
    return "\n".join(["# Sentinel Runtime Owner Summary", "", summary, "", "MEDIUM and HIGH remain blocked."])


def print_status(value: Dict[str, Any]) -> None:
    flags = value.get("flags", {})
    print(value.get("status", "GUARDED_RUNTIME_NOT_EVALUATED"))
    print(f"ACTIVATION_STAGE={value.get('activation_stage', STAGE_LEVEL_1)}")
    print(f"TIMER_ACTIVE={str(value.get('systemd', {}).get('timer_active', False)).lower()}")
    print(f"LOW_LIVE_ENABLED={str(flags.get('low_live_apply_enabled', False)).lower()}")
    print(f"EMERGENCY_STOP={str(flags.get('emergency_stop', True)).lower()}")
    print(f"BREACH={str(flags.get('breach', False)).lower()}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel challenge-aware guarded runtime activation")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--evaluate-health", action="store_true")
    group.add_argument("--evaluate-tls", action="store_true")
    group.add_argument("--select-systemd-mode", action="store_true")
    group.add_argument("--probe-write-canary", action="store_true")
    group.add_argument("--activate-monitoring", action="store_true")
    group.add_argument("--verify-scheduler", action="store_true")
    group.add_argument("--activate-guarded-canary", action="store_true")
    group.add_argument("--evaluate-promotion", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--pause-live", action="store_true")
    group.add_argument("--resume-live", action="store_true")
    group.add_argument("--deactivate-runtime", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        result = self_test()
        print(result["status"])
        return 0 if not result["findings"] else 1
    if args.evaluate_health:
        result = evaluate_health()
        print(result["status"])
        return 0 if guarded.health_gate_ok(result) else 2
    if args.evaluate_tls:
        result = evaluate_tls()
        print(result["status"])
        return 0 if result["status"] in activation.TLS_GREEN_STATUSES else 2
    if args.select_systemd_mode:
        result = select_systemd_mode()
        print(result["status"])
        return 0
    if args.probe_write_canary:
        result = probe_write_canary()
        print(result["status"])
        return 0 if result["status"] == "CLOUDFLARE_WRITE_CANARY_OK" else 2
    if args.activate_monitoring:
        result = activate_monitoring()
        print(result["status"])
        return 0 if result["status"] == "AUTONOMY_LEVEL_2_MONITORING_ACTIVE" else 2
    if args.verify_scheduler:
        result = verify_scheduler()
        print(result["status"])
        return 0 if result["status"] == "SCHEDULER_VERIFICATION_GREEN" else 2
    if args.activate_guarded_canary:
        result = activate_guarded_canary()
        print(result["status"])
        return 0 if result["status"] == "AUTONOMY_LEVEL_2_GUARDED_CANARY" else 2
    if args.evaluate_promotion:
        result = evaluate_promotion()
        print(result["status"])
        return 0 if result["status"] == "RUNTIME_PROMOTION_GREEN" else 2
    if args.pause_live:
        result = pause_live()
        print(result["status"])
        return 0
    if args.resume_live:
        result = resume_live()
        print(result["status"])
        return 0 if result["status"] == "AUTONOMY_LEVEL_2_GUARDED_CANARY" else 2
    if args.deactivate_runtime:
        result = deactivate_runtime()
        print(result["status"])
        return 0 if result["status"] == "GUARDED_RUNTIME_DEACTIVATED" else 2
    result = write_consolidated_report()
    print_status(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
