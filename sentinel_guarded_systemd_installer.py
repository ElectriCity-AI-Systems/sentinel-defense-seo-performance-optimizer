#!/usr/bin/env python3
"""Fixed-scope installer for Sentinel guarded-autonomy systemd units."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sentinel_guarded_activation as activation
import sentinel_guarded_autonomy as guarded


PROJECT_DIR = Path("/srv/sentinel-defense")
SERVICE_SOURCE = PROJECT_DIR / "systemd/sentinel-guarded-autonomy.service"
TIMER_SOURCE = PROJECT_DIR / "systemd/sentinel-guarded-autonomy.timer"
SERVICE_DEST = Path("/etc/systemd/system/sentinel-guarded-autonomy.service")
TIMER_DEST = Path("/etc/systemd/system/sentinel-guarded-autonomy.timer")
BACKUP_DIR = PROJECT_DIR / "state/guarded-autonomy/systemd-backup"
SERVICE_BACKUP = BACKUP_DIR / "sentinel-guarded-autonomy.previous.service"
TIMER_BACKUP = BACKUP_DIR / "sentinel-guarded-autonomy.previous.timer"
MANIFEST = BACKUP_DIR / "installation-manifest.json"
INSTALL_STATE = PROJECT_DIR / "state/guarded-autonomy/systemd-install.json"

FIXED_COMMANDS: Dict[str, Tuple[str, ...]] = {
    "verify_sources": (
        "/usr/bin/systemd-analyze",
        "verify",
        str(SERVICE_SOURCE),
        str(TIMER_SOURCE),
    ),
    "daemon_reload": ("/usr/bin/systemctl", "daemon-reload"),
    "enable_timer": (
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "sentinel-guarded-autonomy.timer",
    ),
    "disable_timer": (
        "/usr/bin/systemctl",
        "disable",
        "--now",
        "sentinel-guarded-autonomy.timer",
    ),
    "timer_active": (
        "/usr/bin/systemctl",
        "is-active",
        "sentinel-guarded-autonomy.timer",
    ),
    "timer_enabled": (
        "/usr/bin/systemctl",
        "is-enabled",
        "sentinel-guarded-autonomy.timer",
    ),
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
        "NoNewPrivileges",
        "-p",
        "LoadState",
    ),
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
        "stdout": process.stdout.strip()[:2000],
        "stderr": process.stderr.strip()[:1000],
    }


def file_hash(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def safe_fixed_file(path: Path, expected_parent: Path) -> bool:
    return bool(
        path.parent == expected_parent
        and path.is_file()
        and not path.is_symlink()
    )


def write_state(value: Dict[str, Any]) -> None:
    guarded.write_json(INSTALL_STATE, {**value, "updated_at": guarded.utc_now()})


def verify_source() -> Dict[str, Any]:
    static = guarded.systemd_source_validation()
    analyzed = run_fixed("verify_sources")
    service_text = SERVICE_SOURCE.read_text(encoding="utf-8") if SERVICE_SOURCE.exists() else ""
    checks = {
        "fixed_service_source": safe_fixed_file(SERVICE_SOURCE, PROJECT_DIR / "systemd"),
        "fixed_timer_source": safe_fixed_file(TIMER_SOURCE, PROJECT_DIR / "systemd"),
        "static_hardening_valid": static.get("status") == "SYSTEMD_SOURCE_VALID",
        "systemd_analyze_valid": analyzed["returncode"] == 0,
        "fixed_exec_start": static.get("checks", {}).get("fixed_exec_start") is True,
        "no_shell_wrapper": "ExecStart=/bin/sh" not in service_text and "ExecStart=/bin/bash" not in service_text,
    }
    result = {
        "status": "SYSTEMD_SOURCE_GATE_GREEN" if all(checks.values()) else "SYSTEMD_SOURCE_GATE_BLOCKED",
        "checks": checks,
        "source_hashes": {
            "service": file_hash(SERVICE_SOURCE),
            "timer": file_hash(TIMER_SOURCE),
        },
        "fixed_sources": [str(SERVICE_SOURCE), str(TIMER_SOURCE)],
        "fixed_targets": [str(SERVICE_DEST), str(TIMER_DEST)],
        "breach": False,
    }
    write_state(result)
    return result


def verify_install() -> Dict[str, Any]:
    show = run_fixed("show_service")
    identity = activation.service_identity()
    checks = {
        "service_regular_file": safe_fixed_file(SERVICE_DEST, Path("/etc/systemd/system")),
        "timer_regular_file": safe_fixed_file(TIMER_DEST, Path("/etc/systemd/system")),
        "service_hash_matches": file_hash(SERVICE_DEST) is not None and file_hash(SERVICE_DEST) == file_hash(SERVICE_SOURCE),
        "timer_hash_matches": file_hash(TIMER_DEST) is not None and file_hash(TIMER_DEST) == file_hash(TIMER_SOURCE),
        "service_loaded": show["returncode"] == 0 and "LoadState=loaded" in show["stdout"],
        "fixed_service_user": bool(identity.get("user") and f"User={identity['user']}" in show["stdout"]),
        "fixed_service_group": bool(identity.get("group") and f"Group={identity['group']}" in show["stdout"]),
        "no_new_privileges": "NoNewPrivileges=yes" in show["stdout"],
        "fixed_exec_start": "/usr/bin/python3 /srv/sentinel-defense/sentinel_guarded_autonomy.py --run-cycle" in show["stdout"],
    }
    timer_active = run_fixed("timer_active")["returncode"] == 0
    timer_enabled = run_fixed("timer_enabled")["returncode"] == 0
    result = {
        "status": "SYSTEMD_INSTALL_VERIFIED" if all(checks.values()) else "SYSTEMD_INSTALL_NOT_VERIFIED",
        "checks": checks,
        "timer_active": timer_active,
        "timer_enabled": timer_enabled,
        "timer_scope": "SYSTEM_SCOPE" if all(checks.values()) else None,
        "breach": False,
    }
    write_state(result)
    return result


def runtime_activation_gates() -> Dict[str, Any]:
    health = guarded.load_dict(PROJECT_DIR / "state/guarded-autonomy/challenge-health.json")
    if not health:
        health = guarded.load_dict(activation.HEALTH_STATE_JSON)
    tls = guarded.load_dict(PROJECT_DIR / "state/guarded-autonomy/runtime-tls-gate.json")
    if not tls:
        tls = guarded.load_dict(activation.TLS_STATE_JSON)
    checked_at = guarded.parse_timestamp(health.get("checked_at") or health.get("generated_at"))
    lock = guarded.load_dict(guarded.RUNTIME_LOCK_JSON)
    checks = {
        "health_gate": guarded.health_gate_ok(health),
        "health_fresh": bool(checked_at and guarded.utc_now_dt() - checked_at <= timedelta(minutes=10)),
        "tls_gate": tls.get("status") in activation.TLS_GREEN_STATUSES,
        "policy_valid": guarded.validate_policy().get("status") == "GUARDED_AUTONOMY_POLICY_VALID",
        "audit_valid": guarded.audit_summary().get("invalid_rows") == 0,
        "runtime_lock_idle": lock.get("status", "IDLE") != "RUNNING",
        "breach_false": guarded.load_state().get("flags", {}).get("breach") is False,
    }
    return {
        "status": "MONITORING_RUNTIME_GATES_GREEN" if all(checks.values()) else "MONITORING_RUNTIME_GATES_BLOCKED",
        "checks": checks,
        "blockers": [name for name, passed in checks.items() if not passed],
    }


def set_monitoring_runtime(installed: bool) -> Dict[str, Any]:
    state = guarded.load_state()
    state["machine_state"] = guarded.LOCKED
    state["activation_stage"] = "LEVEL_2_MONITORING_ACTIVE"
    state["autonomy_level"] = "LEVEL_2_MONITORING_ACTIVE"
    state["flags"].update(guarded.monitoring_flags())
    state["policy_hash"] = guarded.policy_hash()
    state["registry_hash"] = guarded.build_action_registry()["registry_hash"]
    state["status"] = "GUARDED_MONITORING_ACTIVE"
    state["activation"] = {
        "status": "MONITORING_ACTIVE",
        "systemd_installed": installed,
        "timer_scope": "SYSTEM_SCOPE",
    }
    guarded.write_state(state, record_history=True)
    return state


def backup_existing_units() -> Dict[str, Any]:
    if guarded.has_project_symlink_component(BACKUP_DIR):
        raise RuntimeError("systemd backup path contains a symlink")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if MANIFEST.exists() and not MANIFEST.is_symlink():
        existing = guarded.load_dict(MANIFEST)
        if existing:
            return existing
    manifest: Dict[str, Any] = {
        "created_at": guarded.utc_now(),
        "service_existed": SERVICE_DEST.is_file() and not SERVICE_DEST.is_symlink(),
        "timer_existed": TIMER_DEST.is_file() and not TIMER_DEST.is_symlink(),
        "service_backup": str(SERVICE_BACKUP),
        "timer_backup": str(TIMER_BACKUP),
    }
    if manifest["service_existed"]:
        shutil.copy2(SERVICE_DEST, SERVICE_BACKUP)
    if manifest["timer_existed"]:
        shutil.copy2(TIMER_DEST, TIMER_BACKUP)
    guarded.write_json(MANIFEST, manifest)
    return manifest


def restore_from_manifest() -> Dict[str, Any]:
    if os.geteuid() != 0:
        return {"status": "SYSTEMD_ROLLBACK_REQUIRES_ROOT", "breach": False}
    run_fixed("disable_timer")
    manifest = guarded.load_dict(MANIFEST)
    restored: List[str] = []
    try:
        if manifest.get("service_existed") and SERVICE_BACKUP.is_file() and not SERVICE_BACKUP.is_symlink():
            shutil.copy2(SERVICE_BACKUP, SERVICE_DEST)
            os.chown(SERVICE_DEST, 0, 0)
            SERVICE_DEST.chmod(0o644)
            restored.append("service")
        elif SERVICE_DEST.exists() and not SERVICE_DEST.is_symlink():
            SERVICE_DEST.unlink()
        if manifest.get("timer_existed") and TIMER_BACKUP.is_file() and not TIMER_BACKUP.is_symlink():
            shutil.copy2(TIMER_BACKUP, TIMER_DEST)
            os.chown(TIMER_DEST, 0, 0)
            TIMER_DEST.chmod(0o644)
            restored.append("timer")
        elif TIMER_DEST.exists() and not TIMER_DEST.is_symlink():
            TIMER_DEST.unlink()
        reload_result = run_fixed("daemon_reload")
        state = guarded.load_state()
        guarded.force_safe_locked(state, "GUARDED_RUNTIME_INSTALLATION_ROLLED_BACK", ["systemd_installation_rolled_back"])
        state["activation_stage"] = "LEVEL_1_DRAFT_ONLY"
        guarded.write_state(state, record_history=True)
        result = {
            "status": "SYSTEMD_INSTALLATION_ROLLED_BACK" if reload_result["returncode"] == 0 else "SYSTEMD_ROLLBACK_FAILED",
            "restored": restored,
            "timer_active": False,
            "breach": False,
        }
    except OSError as exc:
        result = {"status": "SYSTEMD_ROLLBACK_FAILED", "reason": type(exc).__name__, "breach": False}
    write_state(result)
    return result


def install() -> Dict[str, Any]:
    source = verify_source()
    if source["status"] != "SYSTEMD_SOURCE_GATE_GREEN":
        return {"status": "SYSTEMD_INSTALL_BLOCKED", "reason": "source_validation_failed", "breach": False}
    if os.geteuid() != 0:
        result = {
            "status": "SYSTEMD_INSTALL_OWNER_ACTION_REQUIRED",
            "owner_command": "sudo python3 /srv/sentinel-defense/sentinel_guarded_systemd_installer.py --install",
            "credential_requested": False,
            "breach": False,
        }
        write_state(result)
        return result
    if SERVICE_DEST.is_symlink() or TIMER_DEST.is_symlink():
        result = {
            "status": "SYSTEMD_INSTALL_BLOCKED",
            "reason": "fixed_destination_is_symlink",
            "breach": False,
        }
        write_state(result)
        return result
    previous_runtime = guarded.load_state()
    backup_existing_units()
    try:
        shutil.copy2(SERVICE_SOURCE, SERVICE_DEST)
        shutil.copy2(TIMER_SOURCE, TIMER_DEST)
        for path in (SERVICE_DEST, TIMER_DEST):
            os.chown(path, 0, 0)
            path.chmod(0o644)
        if run_fixed("daemon_reload")["returncode"] != 0:
            raise RuntimeError("daemon_reload_failed")
        verified = verify_install()
        if verified["status"] != "SYSTEMD_INSTALL_VERIFIED":
            raise RuntimeError("installed_unit_verification_failed")
        gates = runtime_activation_gates()
        if gates["status"] != "MONITORING_RUNTIME_GATES_GREEN":
            result = {
                **verified,
                "status": "SYSTEMD_INSTALL_VERIFIED_RUNTIME_GATES_PENDING",
                "runtime_gates": gates,
                "timer_active": False,
                "breach": False,
            }
            write_state(result)
            return result
        set_monitoring_runtime(installed=True)
        enabled = run_fixed("enable_timer")
        if enabled["returncode"] != 0:
            raise RuntimeError("timer_enable_failed")
        final = verify_install()
        if not final.get("timer_active") or not final.get("timer_enabled"):
            raise RuntimeError("timer_activation_not_verified")
        result = {
            **final,
            "status": "SYSTEMD_TIMER_ACTIVE",
            "runtime_gates": gates,
            "activation_stage": "LEVEL_2_MONITORING_ACTIVE",
            "breach": False,
        }
        write_state(result)
        return result
    except (OSError, RuntimeError) as exc:
        guarded.write_state(previous_runtime, record_history=True)
        rollback = restore_from_manifest()
        result = {
            "status": "SYSTEMD_INSTALL_ROLLED_BACK",
            "reason": str(exc),
            "rollback": rollback,
            "breach": False,
        }
        write_state(result)
        return result


def status() -> Dict[str, Any]:
    result = verify_install()
    result["source"] = verify_source()["status"]
    result["running_as_root"] = os.geteuid() == 0
    result["owner_command"] = "sudo python3 /srv/sentinel-defense/sentinel_guarded_systemd_installer.py --install"
    write_state(result)
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Fixed Sentinel guarded-autonomy systemd installer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify-source", action="store_true")
    group.add_argument("--install", action="store_true")
    group.add_argument("--verify-install", action="store_true")
    group.add_argument("--rollback", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)
    if args.verify_source:
        result = verify_source()
        print(result["status"])
        return 0 if result["status"] == "SYSTEMD_SOURCE_GATE_GREEN" else 2
    if args.install:
        result = install()
        print(result["status"])
        return 0 if result["status"] in {"SYSTEMD_TIMER_ACTIVE", "SYSTEMD_INSTALL_VERIFIED_RUNTIME_GATES_PENDING"} else 2
    if args.verify_install:
        result = verify_install()
        print(result["status"])
        return 0 if result["status"] == "SYSTEMD_INSTALL_VERIFIED" else 2
    if args.rollback:
        result = restore_from_manifest()
        print(result["status"])
        return 0 if result["status"] == "SYSTEMD_INSTALLATION_ROLLED_BACK" else 2
    result = status()
    print(result["status"])
    return 0 if result["status"] == "SYSTEMD_INSTALL_VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
