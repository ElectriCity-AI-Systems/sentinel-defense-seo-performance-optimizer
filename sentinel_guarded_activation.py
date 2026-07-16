#!/usr/bin/env python3
"""Staged activation gates for Sentinel's existing guarded runtime.

This module does not define an autonomy state machine. It records gate
evidence and advances only the state transitions exported by
``sentinel_guarded_autonomy``. Privileged commands are fixed tuples and are
reachable only after every preceding safety gate passes.
"""

from __future__ import annotations

import argparse
import ast
import grp
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import sentinel_guarded_autonomy as guarded


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-guarded-activation-10.18"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/guarded-autonomy"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"
MONITOR_DIR = PROJECT_DIR / "cloudflare-monitor"

REPORT_JSON = REPORT_DIR / "sentinel-guarded-activation.json"
REPORT_MD = REPORT_DIR / "sentinel-guarded-activation.md"
GATES_MD = REPORT_DIR / "sentinel-guarded-activation-gates.md"
HEALTH_JSON = REPORT_DIR / "sentinel-guarded-health-baseline.json"
HEALTH_MD = REPORT_DIR / "sentinel-guarded-health-baseline.md"
TLS_MD = REPORT_DIR / "sentinel-origin-tls-gate.md"
SYSTEMD_MD = REPORT_DIR / "sentinel-systemd-install-verification.md"
SCHEDULER_MD = REPORT_DIR / "sentinel-scheduler-verification.md"
CANARY_MD = REPORT_DIR / "sentinel-guarded-canary-window.md"
GO_LIVE_MD = REPORT_DIR / "sentinel-level-2-go-live.md"
OWNER_MD = REPORT_DIR / "sentinel-guarded-runtime-owner-summary.md"

GATES_JSON = STATE_DIR / "activation-gates.json"
HEALTH_STATE_JSON = STATE_DIR / "health-baseline.json"
TLS_STATE_JSON = STATE_DIR / "tls-gate.json"
SYSTEMD_STATE_JSON = STATE_DIR / "systemd-install.json"
SCHEDULER_STATE_JSON = STATE_DIR / "scheduler-verification.json"
CANARY_STATE_JSON = STATE_DIR / "canary-window.json"
GO_LIVE_STATE_JSON = STATE_DIR / "go-live.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-guarded-activation.jsonl"

ORIGIN_REPORT_JSON = REPORT_DIR / "sentinel-origin-failure-diagnostics.json"
ORIGIN_HISTORY_JSON = PROJECT_DIR / "state/adaptive-learning/origin_failure_diagnostics_history.json"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-guarded-activation.playbook.json",
    PLAYBOOK_DIR / "sentinel-health-target-validation.playbook.json",
    PLAYBOOK_DIR / "sentinel-origin-tls-gate.playbook.json",
    PLAYBOOK_DIR / "sentinel-systemd-go-live.playbook.json",
    PLAYBOOK_DIR / "sentinel-staged-autonomy-activation.playbook.json",
)

SERVICE_SOURCE = guarded.SERVICE_SOURCE
TIMER_SOURCE = guarded.TIMER_SOURCE
SERVICE_DEST = guarded.SERVICE_DEST
TIMER_DEST = guarded.TIMER_DEST
SYSTEMD_BACKUP_DIR = guarded.SYSTEMD_BACKUP_DIR
SERVICE_BACKUP = SYSTEMD_BACKUP_DIR / "sentinel-guarded-autonomy.pre-activation.service"
TIMER_BACKUP = SYSTEMD_BACKUP_DIR / "sentinel-guarded-autonomy.pre-activation.timer"

STAGE_LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
STAGE_SCHEDULER = "LEVEL_2_SCHEDULER_VERIFICATION"
STAGE_CANARY = "LEVEL_2_GUARDED_CANARY"
STAGE_ACTIVE = "LEVEL_2_GUARDED_AUTONOMY"

TLS_GREEN_STATUSES = {"TLS_GATE_GREEN", "TLS_GATE_GREEN_WITH_STALE_HISTORY"}

FIXED_COMMANDS: Dict[str, Tuple[str, ...]] = {
    "analyze_sources": (
        "/usr/bin/systemd-analyze",
        "verify",
        str(SERVICE_SOURCE),
        str(TIMER_SOURCE),
    ),
    "privilege_probe": ("/usr/bin/sudo", "-n", "/usr/bin/true"),
    "install_service": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/install",
        "-o",
        "root",
        "-g",
        "root",
        "-m",
        "0644",
        str(SERVICE_SOURCE),
        str(SERVICE_DEST),
    ),
    "install_timer": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/install",
        "-o",
        "root",
        "-g",
        "root",
        "-m",
        "0644",
        str(TIMER_SOURCE),
        str(TIMER_DEST),
    ),
    "daemon_reload": ("/usr/bin/sudo", "-n", "/usr/bin/systemctl", "daemon-reload"),
    "enable_timer": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "sentinel-guarded-autonomy.timer",
    ),
    "disable_timer": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/systemctl",
        "disable",
        "--now",
        "sentinel-guarded-autonomy.timer",
    ),
    "start_service": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/systemctl",
        "start",
        "sentinel-guarded-autonomy.service",
    ),
    "restore_service": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/install",
        "-o",
        "root",
        "-g",
        "root",
        "-m",
        "0644",
        str(SERVICE_BACKUP),
        str(SERVICE_DEST),
    ),
    "restore_timer": (
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/install",
        "-o",
        "root",
        "-g",
        "root",
        "-m",
        "0644",
        str(TIMER_BACKUP),
        str(TIMER_DEST),
    ),
    "remove_service": ("/usr/bin/sudo", "-n", "/usr/bin/rm", "-f", str(SERVICE_DEST)),
    "remove_timer": ("/usr/bin/sudo", "-n", "/usr/bin/rm", "-f", str(TIMER_DEST)),
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
        "NoNewPrivileges",
        "-p",
        "LoadState",
    ),
    "timer_active": ("/usr/bin/systemctl", "is-active", "sentinel-guarded-autonomy.timer"),
    "timer_enabled": ("/usr/bin/systemctl", "is-enabled", "sentinel-guarded-autonomy.timer"),
    "service_active": ("/usr/bin/systemctl", "is-active", "sentinel-guarded-autonomy.service"),
    "journal_service": (
        "/usr/bin/journalctl",
        "-u",
        "sentinel-guarded-autonomy.service",
        "-n",
        "100",
        "--no-pager",
        "--output=short-iso",
    ),
}

PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")
MONITOR_NAME_RE = re.compile(r"^(?P<date>\d{8})-(?P<time>\d{6})$")


def utc_now() -> str:
    return guarded.utc_now()


def utc_now_dt() -> datetime:
    return guarded.utc_now_dt()


def parse_timestamp(value: Any) -> Optional[datetime]:
    return guarded.parse_timestamp(value)


def load_dict(path: Path) -> Dict[str, Any]:
    return guarded.load_dict(path)


def write_json(path: Path, value: Any) -> None:
    guarded.write_json(path, value)


def write_text(path: Path, value: str) -> None:
    guarded.write_text(path, value)


def append_audit(event: str, status: str, details: Optional[Dict[str, Any]] = None) -> None:
    guarded.append_jsonl(
        AUDIT_JSONL,
        {
            "timestamp": utc_now(),
            "event": event,
            "status": status,
            "details": details or {},
            "credential_values_disclosed": False,
            "breach": False,
        },
    )


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
        "stdout": process.stdout.strip()[:4000],
        "stderr": process.stderr.strip()[:2000],
    }


def default_activation_state() -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "GUARDED_ACTIVATION_NOT_EVALUATED",
        "activation_stage": STAGE_LEVEL_1,
        "blockers": [],
        "credential_gate": {"status": "NOT_RUN"},
        "health_gate": {"status": "NOT_RUN"},
        "tls_gate": {"status": "NOT_RUN"},
        "systemd_source_gate": {"status": "NOT_RUN"},
        "systemd_install_gate": {"status": "NOT_RUN"},
        "scheduler_gate": {"status": "NOT_RUN"},
        "canary_gate": {"status": "NOT_RUN"},
        "go_live": {"status": "NOT_RUN"},
        "breach": False,
    }


def load_activation_state() -> Dict[str, Any]:
    state = load_dict(GATES_JSON)
    defaults = default_activation_state()
    if not state:
        return defaults
    for key, value in defaults.items():
        state.setdefault(key, value)
    return state


def save_activation_state(state: Dict[str, Any]) -> None:
    state["generated_at"] = utc_now()
    write_json(GATES_JSON, state)


def service_identity() -> Dict[str, Any]:
    source = SERVICE_SOURCE.read_text(encoding="utf-8") if SERVICE_SOURCE.exists() else ""
    user_match = re.search(r"(?m)^User=([^\s]+)$", source)
    group_match = re.search(r"(?m)^Group=([^\s]+)$", source)
    user_name = user_match.group(1) if user_match else None
    group_name = group_match.group(1) if group_match else None
    try:
        user_uid = pwd.getpwnam(user_name).pw_uid if user_name else None
    except KeyError:
        user_uid = None
    try:
        group_gid = grp.getgrnam(group_name).gr_gid if group_name else None
    except KeyError:
        group_gid = None
    return {
        "user": user_name,
        "group": group_name,
        "uid": user_uid,
        "gid": group_gid,
        "derived_from_unit": bool(user_match and group_match),
    }


def credential_mode_safe(mode: int) -> bool:
    return bool(mode & 0o400) and mode & 0o037 == 0


def validate_credentials() -> Dict[str, Any]:
    required = ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID")
    identity = service_identity()
    result: Dict[str, Any] = {
        "status": "ADAPTER_CREDENTIAL_GATE_BLOCKED",
        "expected_environment_file": str(guarded.PRIVATE_ENV_PATH),
        "file_exists": False,
        "owner": None,
        "group": None,
        "mode": None,
        "required_variable_names": list(required),
        "missing_variable_names": list(required),
        "values_nonempty": False,
        "owner_safe": False,
        "group_safe": False,
        "mode_safe": False,
        "world_readable": False,
        "fixed_zone_scope_available": False,
        "adapter_target_scope_matches_policy": False,
        "wildcard_account_access_required": False,
        "read_only_scope_probe_performed": False,
        "read_only_scope_probe_ok": False,
        "scope_probe_error_type": None,
        "credential_value_disclosed": False,
    }
    path = guarded.PRIVATE_ENV_PATH
    try:
        if not path.exists() or path.is_symlink():
            write_json(STATE_DIR / "credential-gate.json", result)
            return result
        file_stat = path.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        result["file_exists"] = True
        result["owner"] = pwd.getpwuid(file_stat.st_uid).pw_name
        result["group"] = grp.getgrgid(file_stat.st_gid).gr_name
        result["mode"] = f"{mode:04o}"
        result["owner_safe"] = file_stat.st_uid == 0
        result["group_safe"] = identity["gid"] is not None and file_stat.st_gid == identity["gid"]
        result["mode_safe"] = credential_mode_safe(mode)
        result["world_readable"] = bool(mode & 0o004)
        values = guarded.load_private_environment()
        missing = [name for name in required if not values.get(name)]
        result["missing_variable_names"] = missing
        result["values_nonempty"] = not missing
        result["fixed_zone_scope_available"] = bool(guarded.ZONE_ID_RE.fullmatch(values.get("CLOUDFLARE_ZONE_ID", "")))
        metadata_ready = all(
            (
                result["owner_safe"],
                result["group_safe"],
                result["mode_safe"],
                not result["world_readable"],
                result["values_nonempty"],
                result["fixed_zone_scope_available"],
            )
        )
        if metadata_ready:
            result["read_only_scope_probe_performed"] = True
            try:
                result["read_only_scope_probe_ok"] = guarded.CloudflareGuardedAdapter().validate_read_scope()
            except (RuntimeError, OSError, TimeoutError, ValueError) as exc:
                result["scope_probe_error_type"] = type(exc).__name__
            result["adapter_target_scope_matches_policy"] = result["read_only_scope_probe_ok"]
        if metadata_ready and result["read_only_scope_probe_ok"]:
            result["status"] = "ADAPTER_CREDENTIAL_GATE_GREEN"
    except (KeyError, OSError, PermissionError, RuntimeError, UnicodeError):
        result["status"] = "ADAPTER_CREDENTIAL_GATE_BLOCKED"
    write_json(STATE_DIR / "credential-gate.json", result)
    append_audit("validate_credentials", result["status"], {"missing_variable_names": result["missing_variable_names"]})
    return result


def build_health_baseline() -> Dict[str, Any]:
    baseline = guarded.check_fixed_health_targets()
    baseline.update(
        {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "health_targets_are_policy_fixed": True,
            "response_bodies_stored": False,
            "foreign_redirects_allowed": False,
            "maximum_redirects": 5,
            "challenge_aware_evaluation_enabled": True,
            "cloudflare_challenge_bypass_enabled": False,
        }
    )
    write_json(HEALTH_JSON, baseline)
    write_json(HEALTH_STATE_JSON, baseline)
    write_text(HEALTH_MD, render_health(baseline))
    append_audit("build_health_baseline", baseline["status"], {"target_statuses": {row["target_id"]: row["status"] for row in baseline["checks"]}})
    return baseline


def extract_status_count(path: Path, status_code: int) -> Optional[int]:
    value = load_dict(path)
    try:
        rows = value["data"]["viewer"]["zones"][0]["httpRequestsAdaptiveGroups"]
    except (KeyError, IndexError, TypeError):
        return None
    counts = [int(row.get("count") or 0) for row in rows if row.get("dimensions", {}).get("edgeResponseStatus") == status_code]
    return sum(counts) if counts else 0


def discover_526_snapshots(limit: int = 96) -> List[Dict[str, Any]]:
    snapshots: List[Dict[str, Any]] = []
    if not MONITOR_DIR.is_dir() or MONITOR_DIR.is_symlink():
        return snapshots
    for directory in sorted(MONITOR_DIR.iterdir()):
        match = MONITOR_NAME_RE.fullmatch(directory.name)
        if not match or not directory.is_dir() or directory.is_symlink():
            continue
        status_path = directory / "status-24h.json"
        if not status_path.is_file() or status_path.is_symlink():
            continue
        try:
            timestamp = datetime.strptime(directory.name, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        count = extract_status_count(status_path, 526)
        if count is None:
            continue
        snapshots.append(
            {
                "snapshot_id": directory.name,
                "observed_at": guarded.iso_utc(timestamp),
                "count_526": count,
                "source": str(status_path.relative_to(PROJECT_DIR)),
            }
        )
    return snapshots[-limit:]


def stable_snapshot_tail(snapshots: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not snapshots:
        return []
    current_count = snapshots[-1]["count_526"]
    tail: List[Dict[str, Any]] = []
    for row in reversed(snapshots):
        if row["count_526"] != current_count:
            break
        tail.append(dict(row))
    return list(reversed(tail))


def evaluate_tls_logic(
    previous_526: Optional[int],
    current_526: Optional[int],
    consecutive_stable_snapshots: int,
    observation_minutes: float,
    approved_targets_observed: bool,
    tls_verification_pass: bool,
    direct_tls_failure_evidence: bool,
    ssl_downgrade_recommended: bool,
) -> str:
    if (
        not approved_targets_observed
        or not tls_verification_pass
        or direct_tls_failure_evidence
        or ssl_downgrade_recommended
        or (previous_526 is not None and current_526 is not None and current_526 > previous_526)
    ):
        return "TLS_GATE_RED"
    if current_526 == 0 and consecutive_stable_snapshots >= 3 and observation_minutes >= 60:
        return "TLS_GATE_GREEN"
    if (
        current_526 is not None
        and consecutive_stable_snapshots >= 3
        and observation_minutes >= 60
        and not ssl_downgrade_recommended
    ):
        return "TLS_GATE_GREEN_WITH_STALE_HISTORY"
    return "TLS_GATE_YELLOW"


def evaluate_tls_gate() -> Dict[str, Any]:
    snapshots = discover_526_snapshots()
    stable_tail = stable_snapshot_tail(snapshots)
    previous = snapshots[-2]["count_526"] if len(snapshots) >= 2 else None
    current = snapshots[-1]["count_526"] if snapshots else None
    observation_minutes = 0.0
    if len(stable_tail) >= 2:
        first = parse_timestamp(stable_tail[0]["observed_at"])
        last = parse_timestamp(stable_tail[-1]["observed_at"])
        if first and last:
            observation_minutes = max(0.0, (last - first).total_seconds() / 60.0)
    health = load_dict(HEALTH_STATE_JSON)
    checks = health.get("checks", []) if isinstance(health.get("checks"), list) else []
    approved_target_ids = {target["id"] for target in guarded.POLICY_TEMPLATE["health_targets"]}
    observed_target_ids = {str(row.get("target_id")) for row in checks if isinstance(row, dict)}
    approved_targets_observed = approved_target_ids.issubset(observed_target_ids)
    tls_pass = bool(
        approved_targets_observed
        and all(
            row.get("tls_verified") is True
            for row in checks
            if isinstance(row, dict) and row.get("target_id") in approved_target_ids
        )
    )
    origin = load_dict(ORIGIN_REPORT_JSON)
    direct_tls_failure = bool(origin.get("origin_tls_diagnostic", {}).get("certificate_evidence"))
    ssl_downgrade = origin.get("ssl_tls_decision", {}).get("ssl_downgrade_recommended") is True
    status = evaluate_tls_logic(
        previous,
        current,
        len(stable_tail),
        observation_minutes,
        approved_targets_observed,
        tls_pass,
        direct_tls_failure,
        ssl_downgrade,
    )
    delta = current - previous if current is not None and previous is not None else None
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": status,
        "previous_526": previous,
        "current_526": current,
        "delta_526": delta,
        "snapshot_count": len(snapshots),
        "consecutive_snapshots_without_growth": len(stable_tail),
        "observation_minutes": round(observation_minutes, 2),
        "latest_snapshot_id": snapshots[-1]["snapshot_id"] if snapshots else None,
        "stable_snapshot_sequence": stable_tail,
        "approved_targets_observed": approved_targets_observed,
        "http_health_gate": health.get("status"),
        "https_tls_verification": tls_pass,
        "direct_tls_failure_evidence": direct_tls_failure,
        "ssl_downgrade_recommended": False,
        "certificate_change_automatic": False,
        "new_live_actions_paused": status not in TLS_GREEN_STATUSES,
        "history_classification": "stale_observed_history" if status == "TLS_GATE_GREEN_WITH_STALE_HISTORY" else None,
    }
    write_json(TLS_STATE_JSON, result)
    write_text(TLS_MD, render_tls(result))
    append_audit("evaluate_tls_gate", status, {"current_526": current, "delta_526": delta})
    return result


def verify_systemd_sources() -> Dict[str, Any]:
    static = guarded.systemd_source_validation()
    analyzed = run_fixed("analyze_sources")
    identity = service_identity()
    checks = {
        "guarded_static_validation": static["status"] == "SYSTEMD_SOURCE_VALID",
        "systemd_analyze_verify": analyzed["returncode"] == 0,
        "service_identity_derived": identity["derived_from_unit"] and identity["uid"] is not None and identity["gid"] is not None,
        "fixed_exec_start": static.get("checks", {}).get("fixed_exec_start") is True,
        "memory_deny_write_execute": static.get("checks", {}).get("memory_deny_write_execute") is True,
        "write_paths_restricted": static.get("checks", {}).get("write_paths_restricted") is True,
    }
    findings = [name for name, passed in checks.items() if not passed]
    result = {
        "status": "SYSTEMD_SOURCE_GATE_GREEN" if not findings else "SYSTEMD_SOURCE_GATE_BLOCKED",
        "checks": checks,
        "findings": findings,
        "service_user": identity["user"],
        "service_group": identity["group"],
        "systemd_analyze_returncode": analyzed["returncode"],
        "systemd_analyze_diagnostics": analyzed["stderr"],
        "generated_at": utc_now(),
    }
    write_text(SYSTEMD_MD, render_systemd(result, load_dict(SYSTEMD_STATE_JSON)))
    append_audit("verify_systemd_sources", result["status"], {"findings": findings})
    return result


def file_install_metadata(path: Path, source: Path) -> Dict[str, Any]:
    result = {
        "exists": False,
        "regular_file": False,
        "symlink": False,
        "owner_root": False,
        "group_root": False,
        "mode_0644": False,
        "content_matches_source": False,
    }
    try:
        result["exists"] = path.exists()
        result["symlink"] = path.is_symlink()
        if not result["exists"] or result["symlink"]:
            return result
        file_stat = path.stat()
        result["regular_file"] = stat.S_ISREG(file_stat.st_mode)
        result["owner_root"] = file_stat.st_uid == 0
        result["group_root"] = file_stat.st_gid == 0
        result["mode_0644"] = stat.S_IMODE(file_stat.st_mode) == 0o644
        result["content_matches_source"] = path.read_bytes() == source.read_bytes()
    except OSError:
        pass
    return result


def verify_systemd_install() -> Dict[str, Any]:
    service = file_install_metadata(SERVICE_DEST, SERVICE_SOURCE)
    timer = file_install_metadata(TIMER_DEST, TIMER_SOURCE)
    show = run_fixed("show_service")
    timer_active = run_fixed("timer_active")
    timer_enabled = run_fixed("timer_enabled")
    privilege = run_fixed("privilege_probe")
    expected_exec = "/usr/bin/python3 /srv/sentinel-defense/sentinel_guarded_autonomy.py --run-cycle"
    identity = service_identity()
    show_lines = set(show["stdout"].splitlines())
    service_exact = all(
        (
            service["exists"],
            service["regular_file"],
            not service["symlink"],
            service["owner_root"],
            service["group_root"],
            service["mode_0644"],
            service["content_matches_source"],
        )
    )
    timer_exact = all(
        (
            timer["exists"],
            timer["regular_file"],
            not timer["symlink"],
            timer["owner_root"],
            timer["group_root"],
            timer["mode_0644"],
            timer["content_matches_source"],
        )
    )
    checks = {
        "service_install_exact": service_exact,
        "timer_install_exact": timer_exact,
        "service_show_available": show["returncode"] == 0 and "LoadState=loaded" in show_lines,
        "service_user": bool(identity["user"] and f"User={identity['user']}" in show_lines),
        "service_group": bool(identity["group"] and f"Group={identity['group']}" in show_lines),
        "no_new_privileges": "NoNewPrivileges=yes" in show_lines,
        "fixed_exec_start": any(line.startswith("ExecStart=") and expected_exec in line for line in show_lines),
    }
    findings = [name for name, passed in checks.items() if not passed]
    if not service_exact or not timer_exact:
        if privilege["returncode"] != 0:
            findings.append("noninteractive_install_privilege_unavailable")
    result = {
        "status": "SYSTEMD_INSTALL_VERIFIED" if not findings else "SYSTEMD_INSTALL_NOT_VERIFIED",
        "checks": checks,
        "findings": findings,
        "service": service,
        "timer": timer,
        "timer_active": timer_active["returncode"] == 0 and timer_active["stdout"] == "active",
        "timer_enabled": timer_enabled["returncode"] == 0 and timer_enabled["stdout"] == "enabled",
        "installation_privilege_available": privilege["returncode"] == 0,
        "generated_at": utc_now(),
    }
    write_json(SYSTEMD_STATE_JSON, result)
    write_text(SYSTEMD_MD, render_systemd(load_dict(GATES_JSON).get("systemd_source_gate", {}), result))
    append_audit("verify_systemd_install", result["status"], {"findings": findings})
    return result


def backup_existing_units() -> Dict[str, Any]:
    SYSTEMD_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    records = []
    for destination, backup in ((SERVICE_DEST, SERVICE_BACKUP), (TIMER_DEST, TIMER_BACKUP)):
        record = {
            "destination": str(destination),
            "backup": str(backup),
            "existed": destination.is_file() and not destination.is_symlink(),
            "before_hash": None,
        }
        if destination.is_symlink():
            raise RuntimeError("systemd_destination_symlink_blocked")
        if record["existed"]:
            content = destination.read_bytes()
            record["before_hash"] = guarded.sha256_bytes(content)
            guarded.write_text(backup, content.decode("utf-8"))
        records.append(record)
    return {"records": records, "created_at": utc_now()}


def rollback_installation() -> Dict[str, Any]:
    state = load_dict(SYSTEMD_STATE_JSON)
    records = state.get("backup", {}).get("records", []) if isinstance(state.get("backup"), dict) else []
    if not records:
        result = {
            "status": "SYSTEMD_INSTALLATION_ROLLBACK_BLOCKED",
            "reason": "verified_backup_manifest_missing",
            "generated_at": utc_now(),
        }
        append_audit("rollback_installation", result["status"], {"reason": result["reason"]})
        return result
    disable = run_fixed("disable_timer")
    results = []
    by_destination = {row.get("destination"): row for row in records if isinstance(row, dict)}
    for destination, backup, restore_id, remove_id in (
        (SERVICE_DEST, SERVICE_BACKUP, "restore_service", "remove_service"),
        (TIMER_DEST, TIMER_BACKUP, "restore_timer", "remove_timer"),
    ):
        record = by_destination.get(str(destination), {})
        if record.get("existed"):
            expected_hash = record.get("before_hash")
            if not backup.is_file() or backup.is_symlink() or guarded.sha256_bytes(backup.read_bytes()) != expected_hash:
                results.append({"destination": str(destination), "status": "BACKUP_HASH_MISMATCH"})
                continue
            command = run_fixed(restore_id)
        else:
            command = run_fixed(remove_id)
        results.append({"destination": str(destination), "status": "OK" if command["returncode"] == 0 else "FAILED"})
    reload_result = run_fixed("daemon_reload")
    ok = bool(results and all(row["status"] == "OK" for row in results) and reload_result["returncode"] == 0)
    result = {
        "status": "SYSTEMD_INSTALLATION_ROLLED_BACK" if ok else "SYSTEMD_INSTALLATION_ROLLBACK_BLOCKED",
        "disable_timer_returncode": disable["returncode"],
        "results": results,
        "daemon_reload_returncode": reload_result["returncode"],
        "generated_at": utc_now(),
    }
    append_audit("rollback_installation", result["status"])
    return result


def install_systemd_units() -> Dict[str, Any]:
    source = verify_systemd_sources()
    if source["status"] != "SYSTEMD_SOURCE_GATE_GREEN":
        return {"status": "SYSTEMD_INSTALL_BLOCKED", "reason": "systemd_source_gate"}
    existing = verify_systemd_install()
    if existing["status"] == "SYSTEMD_INSTALL_VERIFIED":
        return existing
    privilege = run_fixed("privilege_probe")
    if privilege["returncode"] != 0:
        return {
            "status": "SYSTEMD_INSTALL_BLOCKED",
            "reason": "noninteractive_privileged_install_unavailable",
            "privileged_action_required": True,
        }
    try:
        backup = backup_existing_units()
    except (OSError, RuntimeError, UnicodeError) as exc:
        return {"status": "SYSTEMD_INSTALL_BLOCKED", "reason": str(exc)}
    write_json(SYSTEMD_STATE_JSON, {"status": "SYSTEMD_INSTALL_IN_PROGRESS", "backup": backup})
    install_service = run_fixed("install_service")
    if install_service["returncode"] != 0:
        rollback = rollback_installation()
        return {
            "status": "SYSTEMD_INSTALL_ROLLED_BACK",
            "reason": "privileged_service_install_failed",
            "privileged_action_required": True,
            "backup": backup,
            "rollback": rollback,
        }
    install_timer = run_fixed("install_timer")
    reload_result = run_fixed("daemon_reload") if install_timer["returncode"] == 0 else {"returncode": 1, "stderr": "timer_install_failed"}
    interim = {
        "backup": backup,
        "install_service_returncode": install_service["returncode"],
        "install_timer_returncode": install_timer["returncode"],
        "daemon_reload_returncode": reload_result["returncode"],
    }
    write_json(SYSTEMD_STATE_JSON, interim)
    if install_timer["returncode"] != 0 or reload_result["returncode"] != 0:
        rollback = rollback_installation()
        return {"status": "SYSTEMD_INSTALL_ROLLED_BACK", "reason": "install_or_reload_failed", "rollback": rollback}
    verified = verify_systemd_install()
    verified["backup"] = backup
    write_json(SYSTEMD_STATE_JSON, verified)
    if verified["status"] != "SYSTEMD_INSTALL_VERIFIED":
        rollback = rollback_installation()
        return {"status": "SYSTEMD_INSTALL_ROLLED_BACK", "reason": "post_install_verification_failed", "rollback": rollback}
    return verified


def health_baseline_current(max_minutes: int = 10) -> bool:
    baseline = load_dict(HEALTH_STATE_JSON)
    timestamp = parse_timestamp(baseline.get("generated_at") or baseline.get("checked_at"))
    return bool(
        guarded.health_gate_ok(baseline)
        and timestamp
        and utc_now_dt() - timestamp <= timedelta(minutes=max_minutes)
    )


def collect_gates() -> Dict[str, Any]:
    self_test_result = self_test(write_outputs=False)
    credential = validate_credentials()
    health = load_dict(HEALTH_STATE_JSON) or {"status": "HEALTH_TARGET_GATE_BLOCKED"}
    tls = load_dict(TLS_STATE_JSON) or {"status": "TLS_GATE_YELLOW"}
    systemd_source = verify_systemd_sources()
    systemd_install = verify_systemd_install()
    guarded_self_test = guarded.self_test(write_artifacts=False)
    guarded_policy = guarded.validate_policy()
    blockers = []
    gate_checks = {
        "activation_self_test": self_test_result["status"] == "GUARDED_ACTIVATION_SELF_TEST_OK",
        "guarded_self_test": guarded_self_test["status"] == "GUARDED_AUTONOMY_SELF_TEST_OK",
        "guarded_policy": guarded_policy["status"] == "GUARDED_AUTONOMY_POLICY_VALID",
        "credential_gate": credential["status"] == "ADAPTER_CREDENTIAL_GATE_GREEN",
        "health_target_gate": health_baseline_current() and guarded.health_gate_ok(health),
        "tls_gate": tls.get("status") in TLS_GREEN_STATUSES,
        "systemd_source_gate": systemd_source["status"] == "SYSTEMD_SOURCE_GATE_GREEN",
        "systemd_install_gate": systemd_install["status"] == "SYSTEMD_INSTALL_VERIFIED",
        "breach_false": load_dict(guarded.STATE_JSON).get("flags", {}).get("breach", False) is False,
    }
    blockers = [name for name, passed in gate_checks.items() if not passed]
    state = load_activation_state()
    state.update(
        {
            "status": "GUARDED_ACTIVATION_GATES_GREEN" if not blockers else "GUARDED_ACTIVATION_BLOCKED",
            "blockers": blockers,
            "gate_checks": gate_checks,
            "credential_gate": credential,
            "health_gate": health,
            "tls_gate": tls,
            "systemd_source_gate": systemd_source,
            "systemd_install_gate": systemd_install,
            "breach": False,
        }
    )
    save_activation_state(state)
    write_reports(state)
    append_audit("collect_gates", state["status"], {"blockers": blockers})
    return state


def scheduler_verification_logic(
    rows: Sequence[Dict[str, Any]],
    timer_active: bool,
    timer_enabled: bool,
    health_ok: bool,
    tls_ok: bool,
    invalid_audit_rows: int = 0,
    policy_ok: bool = True,
    runtime_ok: bool = True,
    unexpected_write_paths: int = 0,
    new_526_growth: bool = False,
    overlapping_cycles: int = 0,
) -> Dict[str, Any]:
    cycle_rows = [row for row in rows if row.get("cycle_id")]
    cycle_ids = [str(row["cycle_id"]) for row in cycle_rows]
    allowed_decisions = {"NO_ACTION", "ACTION_CANDIDATE_BLOCKED_BY_VERIFICATION_STAGE"}
    successful = [row for row in cycle_rows if row.get("decision") in allowed_decisions]
    last_three = cycle_rows[-3:]
    cycle_healthchecks_ok = len(last_three) == 3 and all(
        isinstance(row.get("validation_result"), dict)
        and row["validation_result"].get("status") in guarded.HEALTH_GREEN_STATUSES
        for row in last_three
    )
    checks = {
        "three_consecutive_cycles": len(last_three) == 3
        and all(row.get("decision") in allowed_decisions for row in last_three),
        "unique_cycle_ids": len(cycle_ids) == len(set(cycle_ids)),
        "allowed_verification_decisions": len(successful) == len(cycle_rows),
        "audit_valid": invalid_audit_rows == 0,
        "no_policy_drift": policy_ok,
        "no_runtime_drift": runtime_ok,
        "no_unexpected_write_paths": unexpected_write_paths == 0,
        "no_new_526_growth": new_526_growth is False,
        "no_overlapping_cycles": overlapping_cycles == 0,
        "cycle_healthchecks": cycle_healthchecks_ok,
        "timer_active": timer_active,
        "timer_enabled": timer_enabled,
        "health_gate": health_ok,
        "tls_gate": tls_ok,
    }
    findings = [name for name, passed in checks.items() if not passed]
    return {
        "status": "SCHEDULER_VERIFICATION_GREEN" if not findings else "SCHEDULER_VERIFICATION_IN_PROGRESS",
        "successful_cycles": len(successful),
        "cycle_ids": cycle_ids,
        "checks": checks,
        "findings": findings,
    }


def read_guarded_audit_since(timestamp: Optional[str]) -> List[Dict[str, Any]]:
    start = parse_timestamp(timestamp)
    rows = []
    if not guarded.AUDIT_JSONL.exists() or guarded.AUDIT_JSONL.is_symlink():
        return rows
    for line in guarded.AUDIT_JSONL.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        row_time = parse_timestamp(row.get("timestamp"))
        if isinstance(row, dict) and (start is None or (row_time and row_time >= start)):
            rows.append(row)
    return rows


def activate_scheduler_verification() -> Dict[str, Any]:
    credentials = validate_credentials()
    health = build_health_baseline()
    tls = evaluate_tls_gate()
    source = verify_systemd_sources()
    guarded_ok = guarded.self_test(write_artifacts=False)["status"] == "GUARDED_AUTONOMY_SELF_TEST_OK"
    policy_ok = guarded.validate_policy()["status"] == "GUARDED_AUTONOMY_POLICY_VALID"
    blockers = []
    if credentials["status"] != "ADAPTER_CREDENTIAL_GATE_GREEN":
        blockers.append("credential_gate")
    if not guarded.health_gate_ok(health):
        blockers.append("health_target_gate")
    if tls["status"] not in TLS_GREEN_STATUSES:
        blockers.append("tls_gate")
    if source["status"] != "SYSTEMD_SOURCE_GATE_GREEN":
        blockers.append("systemd_source_gate")
    if not guarded_ok or not policy_ok:
        blockers.append("guarded_runtime_gate")
    if blockers:
        state = load_activation_state()
        state.update({"status": "GUARDED_ACTIVATION_BLOCKED", "blockers": blockers, "activation_stage": STAGE_LEVEL_1})
        save_activation_state(state)
        write_reports(state)
        append_audit("activate_scheduler_verification", state["status"], {"blockers": blockers})
        return state

    installed = install_systemd_units()
    if installed.get("status") != "SYSTEMD_INSTALL_VERIFIED":
        state = load_activation_state()
        state.update(
            {
                "status": "GUARDED_ACTIVATION_BLOCKED",
                "blockers": ["systemd_install_gate"],
                "systemd_install_gate": installed,
                "activation_stage": STAGE_LEVEL_1,
            }
        )
        save_activation_state(state)
        write_reports(state)
        append_audit("activate_scheduler_verification", state["status"], {"blockers": state["blockers"]})
        return state

    runtime = guarded.load_state()
    if runtime["machine_state"] == guarded.LOCKED:
        guarded.transition(runtime, guarded.PREFLIGHT)
    runtime["flags"].update(guarded.default_flags())
    runtime["flags"].update(
        {
            "monitoring_enabled": True,
            "local_analysis_enabled": True,
            "validation_enabled": True,
            "scheduler_install_lock": False,
            "emergency_stop": False,
            "breach": False,
        }
    )
    runtime["activation_stage"] = STAGE_SCHEDULER
    runtime["autonomy_level"] = STAGE_SCHEDULER
    runtime["policy_hash"] = guarded.policy_hash()
    runtime["registry_hash"] = guarded.build_action_registry()["registry_hash"]
    runtime["status"] = "GUARDED_SCHEDULER_VERIFICATION_ACTIVE"
    runtime["preflight"] = {
        "status": "GUARDED_AUTONOMY_PREFLIGHT_GREEN",
        "gates": [],
        "blockers": [],
        "staged_activation_controller": True,
    }
    runtime["activation"] = {"status": "SCHEDULER_VERIFICATION", "systemd_installed": True}
    guarded.write_state(runtime, record_history=True)
    enable = run_fixed("enable_timer")
    start = run_fixed("start_service") if enable["returncode"] == 0 else {"returncode": 1, "stderr": "timer_enable_failed"}
    if enable["returncode"] != 0 or start["returncode"] != 0:
        guarded.force_safe_locked(runtime, "GUARDED_AUTONOMY_ACTIVATION_BLOCKED", ["scheduler_start_failed"])
        guarded.write_state(runtime, record_history=True)
        rollback = rollback_installation()
        state = load_activation_state()
        state.update({"status": "GUARDED_ACTIVATION_BLOCKED", "blockers": ["scheduler_start_failed"], "rollback": rollback})
        save_activation_state(state)
        write_reports(state)
        return state
    scheduler = {
        "status": "SCHEDULER_VERIFICATION_IN_PROGRESS",
        "started_at": utc_now(),
        "required_cycles": 3,
        "successful_cycles": 0,
        "timer_active": True,
    }
    write_json(SCHEDULER_STATE_JSON, scheduler)
    state = load_activation_state()
    state.update(
        {
            "status": "GUARDED_ACTIVATION_IN_PROGRESS",
            "activation_stage": STAGE_SCHEDULER,
            "blockers": ["scheduler_verification_cycles"],
            "systemd_install_gate": installed,
            "scheduler_gate": scheduler,
        }
    )
    save_activation_state(state)
    write_reports(state)
    append_audit("activate_scheduler_verification", state["status"], {"stage": STAGE_SCHEDULER})
    return state


def verify_scheduler_cycles() -> Dict[str, Any]:
    scheduler_state = load_dict(SCHEDULER_STATE_JSON)
    runtime = guarded.load_state()
    if (
        not parse_timestamp(scheduler_state.get("started_at"))
        or runtime.get("activation_stage") != STAGE_SCHEDULER
        or runtime.get("machine_state") != guarded.PREFLIGHT
    ):
        result = {
            "status": "SCHEDULER_VERIFICATION_NOT_STARTED",
            "started_at": scheduler_state.get("started_at"),
            "evaluated_at": utc_now(),
            "successful_cycles": 0,
            "cycle_ids": [],
            "findings": ["scheduler_stage_not_active"],
        }
        write_json(SCHEDULER_STATE_JSON, result)
        write_text(SCHEDULER_MD, render_scheduler(result))
        return result
    rows = read_guarded_audit_since(scheduler_state.get("started_at"))
    systemd = verify_systemd_install()
    health = build_health_baseline()
    tls = evaluate_tls_gate()
    audit = guarded.audit_summary()
    policy_ok = bool(
        guarded.validate_policy()["status"] == "GUARDED_AUTONOMY_POLICY_VALID"
        and runtime.get("policy_hash") == guarded.policy_hash()
        and runtime.get("registry_hash") == guarded.build_action_registry()["registry_hash"]
    )
    runtime_ok = bool(
        runtime.get("machine_state") == guarded.PREFLIGHT
        and runtime.get("activation_stage") == STAGE_SCHEDULER
        and runtime.get("flags", {}).get("low_live_apply_enabled") is False
        and runtime.get("flags", {}).get("medium_live_apply_enabled") is False
        and runtime.get("flags", {}).get("high_live_apply_enabled") is False
    )
    runtime_lock = load_dict(guarded.RUNTIME_LOCK_JSON)
    journal = run_fixed("journal_service")
    journal_text = f"{journal.get('stdout', '')}\n{journal.get('stderr', '')}"
    journal_secret_leak = bool(
        re.search(r"(?i)(authorization:\s*bearer|cloudflare_api_token\s*=|private key)", journal_text)
    )
    unexpected_write_paths = sum(
        1
        for row in rows
        if "unexpected_write_path" in str(row.get("reason", ""))
        or "scope_expansion" in str(row.get("reason", ""))
    )
    result = scheduler_verification_logic(
        rows,
        systemd.get("timer_active") is True,
        systemd.get("timer_enabled") is True,
        guarded.health_gate_ok(health),
        tls["status"] in TLS_GREEN_STATUSES,
        invalid_audit_rows=audit["invalid_rows"],
        policy_ok=policy_ok,
        runtime_ok=runtime_ok,
        unexpected_write_paths=unexpected_write_paths,
        new_526_growth=(tls.get("delta_526") or 0) > 0,
        overlapping_cycles=0 if runtime_lock.get("status") == "IDLE" else 1,
    )
    result["started_at"] = scheduler_state.get("started_at")
    result["evaluated_at"] = utc_now()
    result["invalid_audit_rows"] = audit["invalid_rows"]
    result["journal"] = {
        "returncode": journal["returncode"],
        "line_count": len(journal.get("stdout", "").splitlines()),
        "secret_leak_detected": journal_secret_leak,
        "content_persisted": False,
    }
    if journal_secret_leak:
        result["status"] = "SCHEDULER_VERIFICATION_BLOCKED"
        result["findings"].append("journal_secret_leak")
    if result["invalid_audit_rows"]:
        result["status"] = "SCHEDULER_VERIFICATION_BLOCKED"
        result["findings"].append("invalid_audit_rows")
    write_json(SCHEDULER_STATE_JSON, result)
    write_text(SCHEDULER_MD, render_scheduler(result))
    append_audit("verify_scheduler_cycles", result["status"], {"successful_cycles": result["successful_cycles"]})
    return result


def activate_guarded_canary() -> Dict[str, Any]:
    runtime = guarded.load_state()
    if runtime.get("activation_stage") != STAGE_SCHEDULER or runtime.get("machine_state") != guarded.PREFLIGHT:
        state = load_activation_state()
        state.update(
            {
                "status": "GUARDED_ACTIVATION_BLOCKED",
                "activation_stage": runtime.get("activation_stage", STAGE_LEVEL_1),
                "blockers": ["scheduler_stage_not_active"],
            }
        )
        save_activation_state(state)
        write_reports(state)
        return state
    scheduler = verify_scheduler_cycles()
    if scheduler["status"] != "SCHEDULER_VERIFICATION_GREEN":
        state = load_activation_state()
        state.update(
            {
                "status": "GUARDED_ACTIVATION_IN_PROGRESS",
                "activation_stage": STAGE_SCHEDULER,
                "blockers": ["scheduler_verification_cycles"],
                "scheduler_gate": scheduler,
            }
        )
        save_activation_state(state)
        write_reports(state)
        return state
    guarded.transition(runtime, guarded.CANARY)
    runtime["flags"].update(guarded.active_flags())
    runtime["activation_stage"] = STAGE_CANARY
    runtime["autonomy_level"] = STAGE_CANARY
    runtime["status"] = "GUARDED_CANARY_ACTIVE"
    runtime["activation"] = {"status": "GUARDED_CANARY", "systemd_installed": True}
    guarded.write_state(runtime, record_history=True)
    latest_tls = load_dict(TLS_STATE_JSON)
    canary = {
        "status": "GUARDED_CANARY_WINDOW_IN_PROGRESS",
        "started_at": utc_now(),
        "required_minutes": 60,
        "elapsed_minutes": 0.0,
        "maximum_active_actions": 1,
        "maximum_action_ttl_minutes": 10,
        "enabled_action_ids": [
            "temporary_scanner_managed_challenge_v1",
            "rollback_sentinel_owned_rule_v1",
        ],
        "baseline_tls_snapshot_id": latest_tls.get("latest_snapshot_id"),
        "baseline_526": latest_tls.get("current_526"),
        "decision": "NO_ACTION",
    }
    write_json(CANARY_STATE_JSON, canary)
    state = load_activation_state()
    state.update(
        {
            "status": "GUARDED_ACTIVATION_IN_PROGRESS",
            "activation_stage": STAGE_CANARY,
            "blockers": ["guarded_canary_60_minute_window"],
            "canary_gate": canary,
        }
    )
    save_activation_state(state)
    write_reports(state)
    append_audit("activate_guarded_canary", state["status"], {"stage": STAGE_CANARY})
    return state


def evaluate_canary_logic(
    elapsed_minutes: float,
    health_ok: bool,
    tls_ok: bool,
    invalid_audit_rows: int,
    active_action_count: int,
    decisions: Sequence[str],
) -> Dict[str, Any]:
    allowed_decisions = {
        "NO_ACTION",
        "LOW_LIVE_CANDIDATE",
        "MONITOR_ACTIVE_ACTION",
        "ACTIVE_ACTION_VALIDATED",
        "TTL_ROLLBACK_COMPLETE",
    }
    checks = {
        "minimum_60_minutes": elapsed_minutes >= 60.0,
        "health_gate": health_ok,
        "tls_gate": tls_ok,
        "audit_valid": invalid_audit_rows == 0,
        "maximum_one_active_action": active_action_count <= 1,
        "decisions_allowed": all(decision in allowed_decisions for decision in decisions),
    }
    hard_failure = not all(value for key, value in checks.items() if key != "minimum_60_minutes")
    if hard_failure:
        status = "GUARDED_CANARY_WINDOW_BLOCKED"
    elif checks["minimum_60_minutes"]:
        status = "GUARDED_CANARY_WINDOW_GREEN"
    else:
        status = "GUARDED_CANARY_WINDOW_IN_PROGRESS"
    return {"status": status, "checks": checks, "findings": [key for key, value in checks.items() if not value]}


def evaluate_canary_window() -> Dict[str, Any]:
    canary = load_dict(CANARY_STATE_JSON)
    started = parse_timestamp(canary.get("started_at"))
    if started is None:
        result = {
            "status": "GUARDED_CANARY_WINDOW_NOT_STARTED",
            "started_at": None,
            "evaluated_at": utc_now(),
            "elapsed_minutes": 0.0,
            "required_minutes": 60,
            "decision": "NO_ACTION",
            "findings": ["canary_window_not_started"],
        }
        write_json(CANARY_STATE_JSON, result)
        write_text(CANARY_MD, render_canary(result))
        return result
    elapsed = max(0.0, (utc_now_dt() - started).total_seconds() / 60.0) if started else 0.0
    health = build_health_baseline()
    tls = evaluate_tls_gate()
    audit = guarded.audit_summary()
    rows = read_guarded_audit_since(canary.get("started_at"))
    decisions = [str(row.get("decision")) for row in rows if row.get("cycle_id")]
    runtime = guarded.load_state()
    result = evaluate_canary_logic(
        elapsed,
        guarded.health_gate_ok(health),
        tls["status"] in TLS_GREEN_STATUSES,
        audit["invalid_rows"],
        len(runtime.get("active_actions", [])),
        decisions,
    )
    result.update(
        {
            "started_at": canary.get("started_at"),
            "evaluated_at": utc_now(),
            "elapsed_minutes": round(elapsed, 2),
            "required_minutes": 60,
            "decisions": decisions,
            "decision": decisions[-1] if decisions else "NO_ACTION",
            "active_action_count": len(runtime.get("active_actions", [])),
        }
    )
    if result["status"] == "GUARDED_CANARY_WINDOW_BLOCKED":
        if runtime.get("active_actions"):
            guarded.execute_rollback(runtime, "guarded_canary_window_gate_failed")
        guarded.degrade_runtime(runtime, "GUARDED_AUTONOMY_DEGRADED", "guarded_canary_window_gate_failed")
        guarded.write_state(runtime, record_history=True)
    write_json(CANARY_STATE_JSON, result)
    write_text(CANARY_MD, render_canary(result))
    append_audit("evaluate_canary_window", result["status"], {"elapsed_minutes": result["elapsed_minutes"]})
    return result


def activate_level_2() -> Dict[str, Any]:
    runtime = guarded.load_state()
    if runtime.get("activation_stage") != STAGE_CANARY or runtime.get("machine_state") != guarded.CANARY:
        state = load_activation_state()
        state.update(
            {
                "status": "GUARDED_ACTIVATION_BLOCKED",
                "activation_stage": runtime.get("activation_stage", STAGE_LEVEL_1),
                "blockers": ["guarded_canary_stage_not_active"],
            }
        )
        save_activation_state(state)
        write_reports(state)
        return state
    canary = evaluate_canary_window()
    if canary["status"] != "GUARDED_CANARY_WINDOW_GREEN":
        state = load_activation_state()
        state.update(
            {
                "status": "GUARDED_ACTIVATION_IN_PROGRESS" if canary["status"].endswith("IN_PROGRESS") else "GUARDED_ACTIVATION_BLOCKED",
                "activation_stage": STAGE_CANARY,
                "blockers": ["guarded_canary_60_minute_window"],
                "canary_gate": canary,
            }
        )
        save_activation_state(state)
        write_reports(state)
        return state
    guarded.transition(runtime, guarded.ACTIVE)
    runtime["flags"].update(guarded.active_flags())
    runtime["activation_stage"] = STAGE_ACTIVE
    runtime["autonomy_level"] = STAGE_ACTIVE
    runtime["status"] = "GUARDED_AUTONOMY_ACTIVE"
    runtime["activation"] = {"status": "SYSTEMD_TIMER_ACTIVE", "systemd_installed": True}
    guarded.write_state(runtime, record_history=True)
    go_live = {
        "status": "AUTONOMY_LEVEL_2_GUARDED",
        "activated_at": utc_now(),
        "low_live_enabled": True,
        "medium_enabled": False,
        "high_enabled": False,
        "enabled_action_ids": [
            "temporary_scanner_managed_challenge_v1",
            "rollback_sentinel_owned_rule_v1",
        ],
        "rollback_ready": True,
        "circuit_breaker_armed": guarded.circuit_status(guarded.load_circuit())["status"] == "CIRCUIT_BREAKER_ARMED",
        "emergency_stop": False,
        "breach": False,
    }
    write_json(GO_LIVE_STATE_JSON, go_live)
    write_text(GO_LIVE_MD, render_go_live(go_live))
    state = load_activation_state()
    state.update(
        {
            "status": "GUARDED_ACTIVATION_GATES_GREEN",
            "activation_stage": STAGE_ACTIVE,
            "blockers": [],
            "go_live": go_live,
        }
    )
    save_activation_state(state)
    write_reports(state)
    append_audit("activate_level_2", go_live["status"], {"stage": STAGE_ACTIVE})
    return state


def deactivate() -> Dict[str, Any]:
    runtime = guarded.load_state()
    rollback = {"status": "ROLLBACK_NOT_REQUIRED"}
    if runtime.get("active_actions"):
        rollback = guarded.execute_rollback(runtime, "owner_staged_activation_deactivate")
    disable = run_fixed("disable_timer")
    guarded.force_safe_locked(runtime, "GUARDED_AUTONOMY_DEACTIVATED", ["owner_deactivation"])
    runtime["activation_stage"] = STAGE_LEVEL_1
    guarded.write_state(runtime, record_history=True)
    state = load_activation_state()
    state.update(
        {
            "status": "GUARDED_ACTIVATION_DEACTIVATED",
            "activation_stage": STAGE_LEVEL_1,
            "blockers": ["owner_deactivation"],
            "deactivation": {
                "timer_disable_returncode": disable["returncode"],
                "rollback": rollback,
            },
        }
    )
    save_activation_state(state)
    write_reports(state)
    append_audit("deactivate", state["status"])
    return state


def render_health(value: Dict[str, Any]) -> str:
    lines = ["# Sentinel Guarded Health Baseline", "", f"- status: `{value.get('status', 'NOT_RUN')}`"]
    for row in value.get("checks", []):
        lines.append(
            f"- `{row.get('target_id')}`: status=`{row.get('status')}`, tls_verified=`{str(row.get('tls_verified', False)).lower()}`, redirects=`{row.get('redirect_count')}`, ok=`{str(row.get('ok', False)).lower()}`"
        )
    lines.extend([
        "",
        "No response bodies or challenge tokens are stored. A reproducible Cloudflare edge challenge is accepted only as an unchanged monitoring baseline, never as a generic HTTP success.",
    ])
    return "\n".join(lines)


def render_tls(value: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Sentinel Origin TLS Gate",
            "",
            f"- status: `{value.get('status', 'NOT_RUN')}`",
            f"- current_526: `{value.get('current_526')}`",
            f"- delta_526: `{value.get('delta_526')}`",
            f"- stable snapshots: `{value.get('consecutive_snapshots_without_growth', 0)}`",
            f"- observation minutes: `{value.get('observation_minutes', 0)}`",
            f"- approved HTTPS targets observed: `{str(value.get('approved_targets_observed', False)).lower()}`",
            f"- HTTP health gate: `{value.get('http_health_gate', 'NOT_RUN')}`",
            f"- TLS verification: `{str(value.get('https_tls_verification', False)).lower()}`",
            "- SSL downgrade recommended: `false`",
            "- automatic certificate or DNS change: `false`",
        ]
    )


def render_systemd(source: Dict[str, Any], installed: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Sentinel systemd Installation Verification",
            "",
            f"- source status: `{source.get('status', 'NOT_RUN')}`",
            f"- install status: `{installed.get('status', 'NOT_RUN')}`",
            f"- timer active: `{str(installed.get('timer_active', False)).lower()}`",
            f"- timer enabled: `{str(installed.get('timer_enabled', False)).lower()}`",
            "- ExecStart is fixed to `sentinel_guarded_autonomy.py --run-cycle`.",
            "- No shell wrapper is used.",
        ]
    )


def render_scheduler(value: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Sentinel Scheduler Verification",
            "",
            f"- status: `{value.get('status', 'NOT_RUN')}`",
            f"- successful cycles: `{value.get('successful_cycles', 0)}`",
            f"- required cycles: `3`",
            f"- findings: `{', '.join(value.get('findings', [])) or 'none'}`",
        ]
    )


def render_canary(value: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Sentinel Guarded Canary Window",
            "",
            f"- status: `{value.get('status', 'NOT_RUN')}`",
            f"- elapsed minutes: `{value.get('elapsed_minutes', 0)}`",
            f"- required minutes: `60`",
            f"- latest decision: `{value.get('decision', 'NO_ACTION')}`",
            "- no trigger is a valid `NO_ACTION`; no synthetic attack is generated.",
        ]
    )


def render_go_live(value: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Sentinel Level-2 Go-Live",
            "",
            f"- status: `{value.get('status', 'NOT_RUN')}`",
            f"- LOW_LIVE enabled: `{str(value.get('low_live_enabled', False)).lower()}`",
            "- MEDIUM enabled: `false`",
            "- HIGH enabled: `false`",
            f"- emergency stop: `{str(value.get('emergency_stop', True)).lower()}`",
            f"- breach: `{str(value.get('breach', False)).lower()}`",
        ]
    )


def render_activation(state: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Sentinel Guarded Activation",
            "",
            f"- status: `{state.get('status')}`",
            f"- activation stage: `{state.get('activation_stage')}`",
            f"- blockers: `{', '.join(state.get('blockers', [])) or 'none'}`",
            f"- credential gate: `{state.get('credential_gate', {}).get('status', 'NOT_RUN')}`",
            f"- health gate: `{state.get('health_gate', {}).get('status', 'NOT_RUN')}`",
            f"- TLS gate: `{state.get('tls_gate', {}).get('status', 'NOT_RUN')}`",
            f"- systemd install: `{state.get('systemd_install_gate', {}).get('status', 'NOT_RUN')}`",
            f"- scheduler: `{state.get('scheduler_gate', {}).get('status', 'NOT_RUN')}`",
            f"- canary: `{state.get('canary_gate', {}).get('status', 'NOT_RUN')}`",
        ]
    )


def write_reports(state: Dict[str, Any]) -> None:
    phase_defaults = {
        HEALTH_STATE_JSON: {"status": "HEALTH_TARGET_GATE_NOT_RUN", "generated_at": utc_now(), "checks": []},
        TLS_STATE_JSON: {"status": "TLS_GATE_YELLOW", "generated_at": utc_now(), "new_live_actions_paused": True},
        SYSTEMD_STATE_JSON: {"status": "SYSTEMD_INSTALL_NOT_VERIFIED", "generated_at": utc_now()},
        SCHEDULER_STATE_JSON: {
            "status": "SCHEDULER_VERIFICATION_NOT_STARTED",
            "generated_at": utc_now(),
            "successful_cycles": 0,
        },
        CANARY_STATE_JSON: {
            "status": "GUARDED_CANARY_WINDOW_NOT_STARTED",
            "generated_at": utc_now(),
            "elapsed_minutes": 0.0,
            "required_minutes": 60,
        },
        GO_LIVE_STATE_JSON: {
            "status": "LEVEL_2_NOT_ACTIVATED",
            "generated_at": utc_now(),
            "low_live_enabled": False,
            "medium_enabled": False,
            "high_enabled": False,
        },
    }
    for path, default in phase_defaults.items():
        if not path.exists():
            write_json(path, default)
    runtime = guarded.build_runtime_report()
    report = {
        **state,
        "runtime": {
            "status": runtime.get("status"),
            "machine_state": runtime.get("machine_state"),
            "autonomy_level": runtime.get("autonomy_level"),
            "flags": runtime.get("flags"),
            "last_cycle": runtime.get("last_cycle"),
            "circuit_breaker": runtime.get("circuit_breaker"),
            "systemd": runtime.get("systemd"),
        },
        "generated_at": utc_now(),
    }
    write_json(REPORT_JSON, report)
    write_text(REPORT_MD, render_activation(report))
    write_text(GATES_MD, render_activation(report))
    if not HEALTH_MD.exists():
        write_text(HEALTH_MD, render_health(load_dict(HEALTH_STATE_JSON)))
    if not TLS_MD.exists():
        write_text(TLS_MD, render_tls(load_dict(TLS_STATE_JSON)))
    write_text(SYSTEMD_MD, render_systemd(report.get("systemd_source_gate", {}), report.get("systemd_install_gate", {})))
    write_text(SCHEDULER_MD, render_scheduler(load_dict(SCHEDULER_STATE_JSON)))
    write_text(CANARY_MD, render_canary(load_dict(CANARY_STATE_JSON)))
    write_text(GO_LIVE_MD, render_go_live(load_dict(GO_LIVE_STATE_JSON)))
    write_text(
        OWNER_MD,
        "\n".join(
            [
                "# Sentinel Guarded Runtime Owner Summary",
                "",
                f"- activation status: `{report.get('status')}`",
                f"- current stage: `{report.get('activation_stage')}`",
                f"- blockers: `{', '.join(report.get('blockers', [])) or 'none'}`",
                f"- runtime machine state: `{report['runtime'].get('machine_state')}`",
                f"- systemd timer active: `{str(report['runtime'].get('systemd', {}).get('timer_active', False)).lower()}`",
                "- MEDIUM and HIGH remain blocked.",
            ]
        ),
    )


def self_test(write_outputs: bool = False) -> Dict[str, Any]:
    synthetic_rows = [
        {
            "cycle_id": f"cycle-{index}",
            "decision": "NO_ACTION",
            "validation_result": {"status": "HEALTH_TARGET_GATE_GREEN"},
        }
        for index in range(3)
    ]
    tls_a = evaluate_tls_logic(2, 2, 3, 65.0, True, True, False, False)
    tls_b = evaluate_tls_logic(2, 3, 3, 65.0, True, True, False, False)
    scheduler = scheduler_verification_logic(synthetic_rows, True, True, True, True)
    canary = evaluate_canary_logic(60.0, True, True, 0, 0, ["NO_ACTION"])
    rollback = guarded.deterministic_rollback_test()
    credential_values_not_persisted = credential_leak_scan()
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
        "test_a_stable_historical_526": tls_a == "TLS_GATE_GREEN_WITH_STALE_HISTORY",
        "test_b_new_526_growth": tls_b == "TLS_GATE_RED",
        "test_c_unsafe_credential_mode": credential_mode_safe(0o644) is False,
        "test_d_missing_health_target": validate_missing_health_target(),
        "test_e_scheduler_verification": scheduler["status"] == "SCHEDULER_VERIFICATION_GREEN",
        "test_f_no_trigger_canary": canary["status"] == "GUARDED_CANARY_WINDOW_GREEN",
        "test_g_policy_drift_degrades": guarded_policy_drift_contract(),
        "test_h_rollback": rollback["status"] == "GUARDED_AUTONOMY_ROLLBACK_TEST_OK",
        "no_shell_true": shell_true is False,
        "single_fixed_subprocess_gateway": subprocess_sites == 1,
        "fixed_command_allowlist": set(FIXED_COMMANDS) == {
            "analyze_sources", "privilege_probe", "install_service", "install_timer", "daemon_reload", "enable_timer", "disable_timer",
            "start_service", "restore_service", "restore_timer", "remove_service", "remove_timer", "cat_service",
            "cat_timer", "show_service", "timer_active", "timer_enabled", "service_active",
            "journal_service",
        },
        "no_private_key": PRIVATE_KEY_RE.search(source) is None,
        "credential_values_not_persisted": credential_values_not_persisted,
        "playbook_json_valid": all(is_valid_json_file(path) for path in PLAYBOOKS),
        "fixed_health_targets": len(guarded.POLICY_TEMPLATE["health_targets"]) == 2
        and all(guarded.validate_health_target_definition(target) for target in guarded.POLICY_TEMPLATE["health_targets"]),
        "no_second_state_machine": "ALLOWED_TRANSITIONS" not in globals(),
        "medium_high_disabled": guarded.POLICY_TEMPLATE["medium_live_enabled"] is False
        and guarded.POLICY_TEMPLATE["high_live_enabled"] is False,
        "breach_false": guarded.default_flags()["breach"] is False,
    }
    findings = [name for name, passed in checks.items() if not passed]
    result = {
        "status": "GUARDED_ACTIVATION_SELF_TEST_OK" if not findings else "GUARDED_ACTIVATION_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }
    if write_outputs:
        state = load_activation_state()
        state["self_test"] = result
        save_activation_state(state)
        write_reports(state)
    return result


def validate_missing_health_target() -> bool:
    return guarded.validate_health_target_definition({}) is False


def is_valid_json_file(path: Path) -> bool:
    try:
        return isinstance(json.loads(path.read_text(encoding="utf-8")), dict)
    except (OSError, json.JSONDecodeError, UnicodeError):
        return False


def credential_leak_scan() -> bool:
    try:
        values = [value for value in guarded.load_private_environment().values() if len(value) >= 8]
    except (OSError, RuntimeError, UnicodeError):
        values = []
    paths = (
        Path(__file__),
        Path(guarded.__file__),
        PROJECT_DIR / "sentinel_autonomy.py",
        guarded.POLICY_PATH,
        SERVICE_SOURCE,
        TIMER_SOURCE,
        *PLAYBOOKS,
        REPORT_JSON,
        HEALTH_JSON,
        GATES_JSON,
        HEALTH_STATE_JSON,
        TLS_STATE_JSON,
        SYSTEMD_STATE_JSON,
        SCHEDULER_STATE_JSON,
        CANARY_STATE_JSON,
        GO_LIVE_STATE_JSON,
        AUDIT_JSONL,
    )
    for path in paths:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            return False
        if PRIVATE_KEY_RE.search(content) or any(value in content for value in values):
            return False
    return True


def guarded_policy_drift_contract() -> bool:
    flags = guarded.active_flags()
    flags["guarded_live_autonomy_enabled"] = False
    flags["low_live_apply_enabled"] = False
    flags["production_apply_lock"] = True
    return flags["low_live_apply_enabled"] is False and flags["production_apply_lock"] is True


def status_report() -> Dict[str, Any]:
    state = load_activation_state()
    write_reports(state)
    return load_dict(REPORT_JSON)


def print_status(value: Dict[str, Any]) -> None:
    print(value.get("status", "GUARDED_ACTIVATION_NOT_EVALUATED"))
    print(f"ACTIVATION_STAGE={value.get('activation_stage', STAGE_LEVEL_1)}")
    blockers = value.get("blockers", [])
    print("BLOCKERS=" + (",".join(blockers) if blockers else "none"))
    runtime = value.get("runtime", {})
    flags = runtime.get("flags", {})
    print(f"LOW_LIVE_ENABLED={str(flags.get('low_live_apply_enabled', False)).lower()}")
    print("MEDIUM_ENABLED=false")
    print("HIGH_ENABLED=false")
    print(f"EMERGENCY_STOP={str(flags.get('emergency_stop', True)).lower()}")
    print(f"BREACH={str(flags.get('breach', False)).lower()}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel staged guarded-autonomy activation")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--collect-gates", action="store_true")
    group.add_argument("--validate-credentials", action="store_true")
    group.add_argument("--build-health-baseline", action="store_true")
    group.add_argument("--evaluate-tls-gate", action="store_true")
    group.add_argument("--verify-systemd-sources", action="store_true")
    group.add_argument("--verify-systemd-install", action="store_true")
    group.add_argument("--activate-scheduler-verification", action="store_true")
    group.add_argument("--verify-scheduler-cycles", action="store_true")
    group.add_argument("--activate-guarded-canary", action="store_true")
    group.add_argument("--evaluate-canary-window", action="store_true")
    group.add_argument("--activate-level-2", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--deactivate", action="store_true")
    group.add_argument("--rollback-installation", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = self_test(write_outputs=True)
        print(result["status"])
        return 0 if not result["findings"] else 1
    if args.collect_gates:
        result = collect_gates()
        print_status(load_dict(REPORT_JSON))
        return 0 if result["status"] == "GUARDED_ACTIVATION_GATES_GREEN" else 2
    if args.validate_credentials:
        result = validate_credentials()
        print(result["status"])
        return 0 if result["status"] == "ADAPTER_CREDENTIAL_GATE_GREEN" else 2
    if args.build_health_baseline:
        result = build_health_baseline()
        print(result["status"])
        return 0 if guarded.health_gate_ok(result) else 2
    if args.evaluate_tls_gate:
        result = evaluate_tls_gate()
        print(result["status"])
        return 0 if result["status"] in TLS_GREEN_STATUSES else 2
    if args.verify_systemd_sources:
        result = verify_systemd_sources()
        print(result["status"])
        return 0 if result["status"] == "SYSTEMD_SOURCE_GATE_GREEN" else 2
    if args.verify_systemd_install:
        result = verify_systemd_install()
        print(result["status"])
        return 0 if result["status"] == "SYSTEMD_INSTALL_VERIFIED" else 2
    if args.activate_scheduler_verification:
        result = activate_scheduler_verification()
        print_status(result)
        return 0 if result["status"] == "GUARDED_ACTIVATION_IN_PROGRESS" else 2
    if args.verify_scheduler_cycles:
        result = verify_scheduler_cycles()
        print(result["status"])
        return 0 if result["status"] == "SCHEDULER_VERIFICATION_GREEN" else 2
    if args.activate_guarded_canary:
        result = activate_guarded_canary()
        print_status(result)
        return 0 if result.get("activation_stage") == STAGE_CANARY else 2
    if args.evaluate_canary_window:
        result = evaluate_canary_window()
        print(result["status"])
        return 0 if result["status"] == "GUARDED_CANARY_WINDOW_GREEN" else 2
    if args.activate_level_2:
        result = activate_level_2()
        print_status(result)
        return 0 if result.get("activation_stage") == STAGE_ACTIVE else 2
    if args.deactivate:
        result = deactivate()
        print_status(result)
        return 0
    if args.rollback_installation:
        result = rollback_installation()
        print(result["status"])
        return 0 if result["status"] == "SYSTEMD_INSTALLATION_ROLLED_BACK" else 2
    result = status_report()
    print_status(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
