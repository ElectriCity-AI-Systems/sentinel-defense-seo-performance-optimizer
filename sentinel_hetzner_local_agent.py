#!/usr/bin/env python3
"""Passive Hetzner local defense agent for Sentinel.

The agent reads local system state, writes defensive reports, and updates the
Sentinel master-compatible local inbox. It does not use sudo, does not contact
external hosts, and does not collect secrets.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

DEFAULT_OUT_MD = PROJECT_DIR / "reports/latest/hetzner-local-defense-report.md"
DEFAULT_OUT_JSON = PROJECT_DIR / "reports/latest/hetzner-local-defense-report.json"
DEFAULT_HISTORY = PROJECT_DIR / "reports/history/hetzner-local-defense-history.jsonl"
DEFAULT_COMPAT_INBOX = PROJECT_DIR / "inbox/local"

COMPAT_MD_NAME = "local-defense-report.md"
COMPAT_JSON_NAME = "local-defense-report.json"

STATUS_OK = "OK"
STATUS_INFO = "INFO"
STATUS_WARNING = "WARNING"
STATUS_CRITICAL = "CRITICAL"
STATUS_ORDER = {STATUS_OK: 0, STATUS_WARNING: 1, STATUS_CRITICAL: 2}

AUTH_LOG = Path("/var/log/auth.log")
DEPLOY_SSH_DIR = Path("/home/deploy/.ssh")
DEPLOY_AUTHORIZED_KEYS = Path("/home/deploy/.ssh/authorized_keys")
SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SENTINEL_ENV = Path("/etc/sentinel-defense.env")
UFW_CONFIG = Path("/etc/ufw/ufw.conf")

HELPER_CANDIDATES = (
    Path(os.environ.get("SENTINEL_HETZNER_STATUS_HELPER", "")),
    Path("/usr/local/sbin/sentinel-hetzner-readonly-helper"),
    PROJECT_DIR / "sentinel_hetzner_status_helper.py",
)

TIMER_UNITS = (
    "cloudflare-daily-monitor.timer",
    "sentinel-defense.timer",
    "sentinel-master.timer",
    "sentinel-daily-mail.timer",
)
OPTIONAL_SERVICE_UNITS = (
    "cloudflare-daily-monitor.service",
    "sentinel-defense.service",
)

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|credential)"
    r"\s*[:=]\s*[^\s,;]+"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def redact_text(value: Any, max_len: int = 320) -> str:
    text = str(value)
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = BEARER_RE.sub("Bearer <redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    text = CONTROL_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def markdown_text(value: Any) -> str:
    text = redact_text(value)
    return text.replace("|", "\\|")


def run_command(args: Sequence[str], timeout: int = 8) -> Dict[str, Any]:
    if not args:
        return {"returncode": 127, "stdout": "", "stderr": "empty command", "ok": False}
    if args[0] == "sudo" or "sudo" in Path(args[0]).name:
        return {"returncode": 126, "stdout": "", "stderr": "sudo is not allowed", "ok": False}

    env = {
        "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        completed = subprocess.run(
            list(args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        return {"returncode": 127, "stdout": "", "stderr": "command not found", "ok": False}
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "command timed out", "ok": False}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
        "ok": completed.returncode == 0,
    }


def run_helper_command(args: Sequence[str], timeout: int = 8) -> Dict[str, Any]:
    if not args:
        return {"returncode": 127, "stdout": "", "stderr": "empty command", "ok": False}

    if args[0] == "sudo":
        allowed = len(args) >= 4 and args[1] == "-n"
        command_tail = args[2:]
    else:
        allowed = True
        command_tail = args

    helper_name_seen = any("sentinel" in Path(part).name and "helper" in Path(part).name for part in command_tail)
    if not allowed or not helper_name_seen:
        return {"returncode": 126, "stdout": "", "stderr": "helper command is not allowlisted", "ok": False}

    env = {
        "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        completed = subprocess.run(
            list(args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        return {"returncode": 127, "stdout": "", "stderr": "command not found", "ok": False}
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "command timed out", "ok": False}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
        "ok": completed.returncode == 0,
    }


def helper_command_candidates(subcommand: str) -> List[List[str]]:
    commands: List[List[str]] = []
    seen: set[Tuple[str, ...]] = set()
    for path in HELPER_CANDIDATES:
        if not str(path) or str(path) == "." or not path.exists() or not path.is_file():
            continue
        if path.suffix == ".py":
            direct = [sys.executable, str(path), subcommand]
        else:
            direct = [str(path), subcommand]
        for command in (direct, ["sudo", "-n", *direct] if shutil.which("sudo") else []):
            if not command:
                continue
            key = tuple(command)
            if key not in seen:
                commands.append(command)
                seen.add(key)
    return commands


def command_label(args: Sequence[str]) -> str:
    return " ".join(redact_text(part, 120) for part in args)


def query_helper(subcommand: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    metadata: Dict[str, Any] = {"subcommand": subcommand, "attempted": False, "used": False, "attempts": []}
    for command in helper_command_candidates(subcommand):
        metadata["attempted"] = True
        result = run_helper_command(command, timeout=8)
        attempt = {
            "command": command_label(command),
            "sudo": bool(command and command[0] == "sudo"),
            "returncode": result["returncode"],
            "ok": result["ok"],
        }
        if not result["ok"] and result.get("stderr"):
            attempt["stderr"] = redact_text(result.get("stderr"), 180)
        metadata["attempts"].append(attempt)

        parsed: Optional[Dict[str, Any]] = None
        if result.get("stdout"):
            try:
                payload = json.loads(result["stdout"])
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                parsed = payload
        if parsed and parsed.get("ok"):
            metadata["used"] = True
            return parsed, metadata
    return None, metadata


def systemctl_active(unit: str) -> Optional[str]:
    if not shutil.which("systemctl"):
        return None
    result = run_command(["systemctl", "is-active", unit], timeout=6)
    value = (result["stdout"].strip() or result["stderr"].strip() or "unknown").splitlines()[0]
    return redact_text(value, 80)


def read_ufw_config_enabled() -> Optional[bool]:
    try:
        for line in UFW_CONFIG.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("ENABLED="):
                return line.split("=", 1)[1].strip().casefold() in {"yes", "true", "1"}
    except OSError:
        return None
    return None


def add_finding(
    findings: List[Dict[str, str]],
    status: str,
    category: str,
    title: str,
    detail: str,
    recommendation: str,
) -> None:
    findings.append(
        {
            "status": status,
            "category": redact_text(category, 80),
            "title": redact_text(title, 160),
            "detail": redact_text(detail),
            "recommendation": redact_text(recommendation),
        }
    )


def add_observation(
    observations: List[Dict[str, str]],
    category: str,
    title: str,
    detail: str,
    recommendation: str,
    status: str = STATUS_INFO,
) -> None:
    observations.append(
        {
            "status": status,
            "category": redact_text(category, 80),
            "title": redact_text(title, 160),
            "detail": redact_text(detail),
            "recommendation": redact_text(recommendation),
        }
    )


def mode_string(path: Path) -> Optional[str]:
    try:
        return f"{stat.S_IMODE(path.stat().st_mode):04o}"
    except OSError:
        return None


def path_stat(path: Path) -> Dict[str, Any]:
    details: Dict[str, Any] = {"path": str(path), "exists": path.exists()}
    try:
        st = path.stat()
    except OSError as exc:
        details["error"] = redact_text(exc)
        return details

    mode = stat.S_IMODE(st.st_mode)
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    details.update(
        {
            "mode": f"{mode:04o}",
            "uid": st.st_uid,
            "gid": st.st_gid,
            "owner": owner,
            "group": group,
            "is_dir": path.is_dir(),
            "is_file": path.is_file(),
            "readable": os.access(path, os.R_OK),
            "world_readable": bool(mode & stat.S_IROTH),
            "world_writable": bool(mode & stat.S_IWOTH),
            "group_readable": bool(mode & stat.S_IRGRP),
            "group_writable": bool(mode & stat.S_IWGRP),
        }
    )
    return details


def read_meminfo() -> Dict[str, int]:
    values: Dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in line:
                continue
            key, rest = line.split(":", 1)
            parts = rest.strip().split()
            if parts and parts[0].isdigit():
                values[key] = int(parts[0]) * 1024
    except OSError:
        return {}
    return values


def bytes_to_gib(value: float) -> float:
    return round(value / (1024**3), 2)


def collect_system_load(findings: List[Dict[str, str]]) -> Dict[str, Any]:
    cpu_count = os.cpu_count() or 1
    try:
        load_average = os.getloadavg()
    except OSError:
        load_average = (0.0, 0.0, 0.0)
    load_per_cpu = load_average[0] / cpu_count

    meminfo = read_meminfo()
    mem_total = meminfo.get("MemTotal", 0)
    mem_available = meminfo.get("MemAvailable", 0)
    mem_used = max(mem_total - mem_available, 0) if mem_total else 0
    ram_used_percent = (mem_used / mem_total * 100.0) if mem_total else 0.0

    disk = shutil.disk_usage("/")
    disk_used_percent = disk.used / disk.total * 100.0 if disk.total else 0.0

    if load_per_cpu > 3.0:
        add_finding(
            findings,
            STATUS_CRITICAL,
            "system_load",
            "Load per CPU is critical",
            f"1m load per CPU is {load_per_cpu:.2f}.",
            "Inspect local service load manually; no automated action was applied.",
        )
    elif load_per_cpu > 1.5:
        add_finding(
            findings,
            STATUS_WARNING,
            "system_load",
            "Load per CPU is elevated",
            f"1m load per CPU is {load_per_cpu:.2f}.",
            "Review top local processes and recent service logs.",
        )

    if ram_used_percent > 97.0:
        add_finding(
            findings,
            STATUS_CRITICAL,
            "system_load",
            "RAM usage is critical",
            f"RAM usage is {ram_used_percent:.2f}%.",
            "Review memory-heavy local processes before taking manual action.",
        )
    elif ram_used_percent > 90.0:
        add_finding(
            findings,
            STATUS_WARNING,
            "system_load",
            "RAM usage is elevated",
            f"RAM usage is {ram_used_percent:.2f}%.",
            "Review memory trend and top RAM processes.",
        )

    if disk_used_percent > 97.0:
        add_finding(
            findings,
            STATUS_CRITICAL,
            "system_load",
            "Root disk usage is critical",
            f"Disk / usage is {disk_used_percent:.2f}%.",
            "Free space manually; do not delete data automatically.",
        )
    elif disk_used_percent > 90.0:
        add_finding(
            findings,
            STATUS_WARNING,
            "system_load",
            "Root disk usage is elevated",
            f"Disk / usage is {disk_used_percent:.2f}%.",
            "Review logs, backups, and large files manually.",
        )

    return {
        "cpu_count": cpu_count,
        "load_average": [round(value, 2) for value in load_average],
        "load_per_cpu_1m": round(load_per_cpu, 3),
        "ram_total_gib": bytes_to_gib(mem_total),
        "ram_used_gib": bytes_to_gib(mem_used),
        "ram_used_percent": round(ram_used_percent, 2),
        "disk_root_total_gib": bytes_to_gib(disk.total),
        "disk_root_used_gib": bytes_to_gib(disk.used),
        "disk_root_used_percent": round(disk_used_percent, 2),
    }


def read_last_lines(path: Path, max_lines: int = 5000, max_bytes: int = 4 * 1024 * 1024) -> List[str]:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            data = handle.read()
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()[-max_lines:]


def count_ssh_events(lines: Iterable[str]) -> Tuple[int, int]:
    failed = 0
    successful = 0
    failed_markers = (
        "failed password",
        "failed publickey",
        "invalid user",
        "authentication failure",
        "maximum authentication attempts exceeded",
    )
    success_markers = (
        "accepted password",
        "accepted publickey",
        "accepted keyboard-interactive",
    )
    for line in lines:
        lowered = line.lower()
        if "sshd" not in lowered and "ssh" not in lowered:
            continue
        if any(marker in lowered for marker in failed_markers):
            failed += 1
        if any(marker in lowered for marker in success_markers):
            successful += 1
    return failed, successful


def collect_auth(findings: List[Dict[str, str]]) -> Dict[str, Any]:
    sources: List[Dict[str, Any]] = []
    lines: List[str] = []

    if AUTH_LOG.exists() and os.access(AUTH_LOG, os.R_OK):
        lines = read_last_lines(AUTH_LOG)
        sources.append(
            {
                "type": "file",
                "path": str(AUTH_LOG),
                "line_count": len(lines),
                "window": "latest 5000 readable auth log lines",
            }
        )
    elif shutil.which("journalctl"):
        result = run_command(
            ["journalctl", "-u", "ssh", "-u", "sshd", "-n", "5000", "--no-pager", "--output", "short-iso"],
            timeout=10,
        )
        if result["ok"] and result["stdout"].strip():
            lines = result["stdout"].splitlines()
            sources.append(
                {
                    "type": "journalctl",
                    "command": "journalctl -u ssh -u sshd -n 5000 --no-pager",
                    "line_count": len(lines),
                    "window": "latest 5000 readable journal lines",
                }
            )
        else:
            sources.append(
                {
                    "type": "journalctl",
                    "command": "journalctl -u ssh -u sshd -n 5000 --no-pager",
                    "line_count": 0,
                    "readable": False,
                    "note": "journalctl did not return readable SSH auth lines without elevated privileges",
                }
            )
    else:
        sources.append({"type": "none", "line_count": 0, "readable": False})

    failed, successful = count_ssh_events(lines)
    if failed > 100:
        add_finding(
            findings,
            STATUS_CRITICAL,
            "ssh_auth",
            "Many failed SSH logins",
            f"Failed SSH login count is {failed} in the reviewed local window.",
            "Review SSH exposure and fail2ban/firewall posture manually; no IPs or users are reported here.",
        )
    elif failed > 25:
        add_finding(
            findings,
            STATUS_WARNING,
            "ssh_auth",
            "Elevated failed SSH logins",
            f"Failed SSH login count is {failed} in the reviewed local window.",
            "Continue monitoring and verify SSH hardening manually.",
        )

    if not lines:
        add_finding(
            findings,
            STATUS_WARNING,
            "ssh_auth",
            "SSH auth logs are not readable",
            "No readable /var/log/auth.log or journalctl SSH auth lines were available without sudo.",
            "If needed, grant read-only log access through a reviewed local helper; the agent did not use sudo.",
        )

    return {
        "failed_ssh_logins": failed,
        "successful_ssh_logins": successful,
        "privacy": "Counts only; remote IPs and usernames are not reported.",
        "sources": sources,
    }


def collect_firewall(findings: List[Dict[str, str]], observations: List[Dict[str, str]]) -> Dict[str, Any]:
    details: Dict[str, Any] = {
        "tool": "ufw",
        "available": bool(shutil.which("ufw")),
        "readable_without_sudo": False,
        "readable_with_helper": False,
        "rules_reported": False,
        "note": "Only ufw status summary is reported; firewall rules and IPs are not included.",
    }
    if not details["available"]:
        add_finding(
            findings,
            STATUS_WARNING,
            "firewall",
            "ufw is not available",
            "ufw command was not found in PATH.",
            "Verify local or provider firewall posture manually if ufw is intentionally not installed.",
        )
        return details

    result = run_command(["ufw", "status"], timeout=6)
    details["returncode"] = result["returncode"]
    if not result["ok"]:
        helper_payload, helper_meta = query_helper("ufw-status")
        details["helper"] = helper_meta
        if helper_payload:
            status_value = str(helper_payload.get("status") or "unknown").casefold()
            details["readable_with_helper"] = True
            details["status"] = redact_text(status_value, 80)
            details["helper_summary"] = {
                key: helper_payload.get(key)
                for key in ("component", "command", "status", "enabled", "firewall_active")
                if key in helper_payload
            }
            if status_value == "inactive" or helper_payload.get("firewall_active") is False:
                add_finding(
                    findings,
                    STATUS_WARNING,
                    "firewall",
                    "ufw is inactive",
                    "Read-only helper reports ufw inactive.",
                    "Confirm whether another firewall layer is intentionally used.",
                )
            elif status_value not in {"active", "enabled"} and helper_payload.get("firewall_active") is not True:
                add_finding(
                    findings,
                    STATUS_WARNING,
                    "firewall",
                    "ufw status is unknown",
                    f"Read-only helper returned status '{status_value or 'unknown'}'.",
                    "Review ufw status manually.",
                )
            return details

        systemd_status = systemctl_active("ufw") or systemctl_active("ufw.service")
        config_enabled = read_ufw_config_enabled()
        details["systemd_status"] = systemd_status or "unknown"
        details["config_enabled"] = config_enabled
        if systemd_status == "active" and config_enabled is not False:
            details["status"] = "active_via_systemctl"
            add_observation(
                observations,
                "firewall",
                "ufw active state confirmed without rule disclosure",
                "ufw status output is not readable by the agent, but systemd reports ufw active.",
                "Install the documented read-only helper if exact ufw status wording is required in reports.",
            )
            return details
        if config_enabled is True:
            details["status"] = "enabled_via_config"
            add_observation(
                observations,
                "firewall",
                "ufw enabled state confirmed from local config metadata",
                "/etc/ufw/ufw.conf reports ENABLED=yes; firewall rules were not read or reported.",
                "Use the documented read-only helper for a root-confirmed ufw status summary.",
            )
            return details

        add_finding(
            findings,
            STATUS_WARNING,
            "firewall",
            "ufw status could not be read",
            "ufw status read permission is not available and no helper/systemd/config evidence confirmed it active.",
            "Check firewall status manually or install the documented read-only helper.",
        )
        details["status"] = "unreadable"
        return details

    status_line = ""
    for line in result["stdout"].splitlines():
        if line.lower().startswith("status:"):
            status_line = line.split(":", 1)[1].strip().lower()
            break
    details["readable_without_sudo"] = True
    details["status"] = redact_text(status_line or "unknown", 80)

    if status_line == "inactive":
        add_finding(
            findings,
            STATUS_WARNING,
            "firewall",
            "ufw is inactive",
            "ufw status reports inactive.",
            "Confirm whether another firewall layer is intentionally used.",
        )
    elif status_line not in {"active", "inactive"}:
        add_finding(
            findings,
            STATUS_WARNING,
            "firewall",
            "ufw status is unknown",
            f"ufw returned status '{status_line or 'unknown'}'.",
            "Review ufw status manually.",
        )
    return details


def fail2ban_jails_from_output(output: str) -> List[str]:
    for line in output.splitlines():
        if "Jail list:" in line:
            _, value = line.split("Jail list:", 1)
            return [redact_text(item, 80) for item in re.split(r"[, ]+", value.strip()) if item.strip()]
    return []


def collect_fail2ban(findings: List[Dict[str, str]], observations: List[Dict[str, str]]) -> Dict[str, Any]:
    details: Dict[str, Any] = {
        "tool": "fail2ban-client",
        "installed": bool(shutil.which("fail2ban-client")),
        "readable_without_sudo": False,
        "readable_with_helper": False,
        "jails": [],
    }
    if not details["installed"]:
        details["note"] = "fail2ban-client is not installed or not in PATH."
        return details

    result = run_command(["fail2ban-client", "status"], timeout=8)
    details["returncode"] = result["returncode"]
    if not result["ok"]:
        helper_payload, helper_meta = query_helper("fail2ban-status")
        details["helper"] = helper_meta
        if helper_payload:
            details["readable_with_helper"] = True
            details["status"] = redact_text(helper_payload.get("status", "unknown"), 80)
            jails = helper_payload.get("jails") if isinstance(helper_payload.get("jails"), list) else []
            details["jails"] = [redact_text(item, 80) for item in jails]
            details["helper_summary"] = {
                key: helper_payload.get(key)
                for key in ("component", "command", "status", "active", "jails")
                if key in helper_payload
            }
            if helper_payload.get("active") is False or details["status"] in {"inactive", "failed", "unknown"}:
                add_finding(
                    findings,
                    STATUS_WARNING,
                    "fail2ban",
                    "fail2ban is not active",
                    f"Read-only helper reports fail2ban status '{details['status']}'.",
                    "Review fail2ban locally if it is expected to protect SSH or web services.",
                )
            elif details["jails"] and "sshd" not in {item.casefold() for item in details["jails"]}:
                add_finding(
                    findings,
                    STATUS_WARNING,
                    "fail2ban",
                    "fail2ban sshd jail is not reported",
                    "fail2ban is active, but the readable jail list does not include sshd.",
                    "Confirm whether SSH is protected by another jail name or mechanism.",
                )
            return details

        systemd_status = systemctl_active("fail2ban") or systemctl_active("fail2ban.service")
        details["systemd_status"] = systemd_status or "unknown"
        if systemd_status == "active":
            details["status"] = "running_via_systemctl"
            add_observation(
                observations,
                "fail2ban",
                "fail2ban active state confirmed without jail disclosure",
                "fail2ban-client status is not readable by the agent, but systemd reports fail2ban active.",
                "Install the documented read-only helper to report aggregate jail status without exposing raw logs or IP lists.",
            )
            return details

        details["status"] = "unreadable_or_not_running"
        add_finding(
            findings,
            STATUS_WARNING,
            "fail2ban",
            "fail2ban status could not be read",
            "fail2ban-client status was not readable and no helper/systemd evidence confirmed it active.",
            "Review fail2ban locally if it is expected to protect SSH or web services.",
        )
        return details

    details["readable_without_sudo"] = True
    details["status"] = "running"
    details["jails"] = fail2ban_jails_from_output(result["stdout"])
    if details["jails"] and "sshd" not in {item.casefold() for item in details["jails"]}:
        add_finding(
            findings,
            STATUS_WARNING,
            "fail2ban",
            "fail2ban sshd jail is not reported",
            "fail2ban is readable and running, but the jail list does not include sshd.",
            "Confirm whether SSH is protected by another jail name or mechanism.",
        )
    return details


def parse_ps_line(line: str) -> Optional[Dict[str, Any]]:
    parts = line.split(None, 4)
    if len(parts) != 5:
        return None
    pid, ppid, name, cpu, ram = parts
    try:
        return {
            "pid": int(pid),
            "ppid": int(ppid),
            "name": redact_text(name, 80),
            "cpu_percent": float(cpu),
            "ram_percent": float(ram),
        }
    except ValueError:
        return None


def collect_processes(findings: List[Dict[str, str]]) -> Dict[str, Any]:
    result = run_command(["ps", "-eo", "pid=,ppid=,comm=,pcpu=,pmem="], timeout=8)
    if not result["ok"]:
        add_finding(
            findings,
            STATUS_WARNING,
            "processes",
            "Process list could not be read",
            "ps did not return process data.",
            "Review process table manually if local load is elevated.",
        )
        return {"top_cpu": [], "top_ram": [], "privacy": "Command lines are not collected."}

    processes = [item for item in (parse_ps_line(line) for line in result["stdout"].splitlines()) if item]
    top_cpu = sorted(processes, key=lambda item: item["cpu_percent"], reverse=True)[:8]
    top_ram = sorted(processes, key=lambda item: item["ram_percent"], reverse=True)[:8]
    return {
        "top_cpu": top_cpu,
        "top_ram": top_ram,
        "privacy": "Process command lines and arguments are not collected.",
    }


def split_address_port(value: str) -> Tuple[str, str]:
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        address, port = value.rsplit("]:", 1)
        return address[1:], port
    if ":" in value:
        address, port = value.rsplit(":", 1)
        return address, port
    return value, ""


def extract_process_label(process_text: str) -> str:
    names = []
    for name in re.findall(r'"([^"]{1,80})"', process_text):
        safe_name = redact_text(name, 80)
        if safe_name and safe_name not in names:
            names.append(safe_name)
    if names:
        return ", ".join(names[:3])

    services = []
    for service in re.findall(r"/([^/\s]+\.service)\b", process_text):
        safe_service = redact_text(service, 80)
        if safe_service and safe_service not in services:
            services.append(safe_service)
    if services:
        return ", ".join(services[:3])
    return "-"


def parse_ss_output(output: str) -> List[Dict[str, str]]:
    sockets: List[Dict[str, str]] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        protocol = parts[0]
        state = parts[1]
        local_raw = parts[4]
        address, port = split_address_port(local_raw)
        process_label = extract_process_label(" ".join(parts[6:])) if len(parts) > 6 else "-"
        sockets.append(
            {
                "protocol": redact_text(protocol, 20),
                "state": redact_text(state, 30),
                "local_address": redact_text(address, 120),
                "port": redact_text(port, 20),
                "process": process_label,
            }
        )
    return sockets


def collect_listening_ports(findings: List[Dict[str, str]]) -> Dict[str, Any]:
    details: Dict[str, Any] = {
        "tool": "ss",
        "available": bool(shutil.which("ss")),
        "note": "Passive local socket inventory only; no external hosts were contacted or scanned.",
        "sockets": [],
    }
    if not details["available"]:
        add_finding(
            findings,
            STATUS_WARNING,
            "local_listening_ports",
            "ss is not available",
            "The ss command was not found in PATH.",
            "Install or expose a local socket inventory tool if listening-port reports are required.",
        )
        return details

    command = ["ss", "-H", "-tulpen"]
    result = run_command(command, timeout=8)
    if not result["ok"]:
        command = ["ss", "-H", "-tulpn"]
        result = run_command(command, timeout=8)
    details["command"] = " ".join(command)
    details["returncode"] = result["returncode"]

    if not result["ok"]:
        add_finding(
            findings,
            STATUS_WARNING,
            "local_listening_ports",
            "Listening ports could not be read",
            "ss did not return a readable local listening socket inventory.",
            "Review local listening sockets manually if needed.",
        )
        return details

    sockets = parse_ss_output(result["stdout"])
    wildcard_addresses = {"0.0.0.0", "*", "::", "[::]"}
    details["sockets"] = sockets[:80]
    details["socket_count"] = len(sockets)
    details["wildcard_binding_count"] = sum(1 for item in sockets if item["local_address"] in wildcard_addresses)
    return details


def evaluate_file_watchpoint(
    findings: List[Dict[str, str]],
    details: Dict[str, Any],
    label: str,
    missing_status: str,
    missing_recommendation: str,
) -> None:
    if not details.get("exists"):
        add_finding(
            findings,
            missing_status,
            "integrity_watchpoints",
            f"{label} is missing",
            f"{details.get('path')} does not exist.",
            missing_recommendation,
        )
        return
    if details.get("world_writable") or details.get("group_writable"):
        add_finding(
            findings,
            STATUS_CRITICAL,
            "integrity_watchpoints",
            f"{label} is writable by group or world",
            f"{details.get('path')} mode is {details.get('mode')}.",
            "Tighten permissions manually after confirming ownership and access requirements.",
        )


def collect_integrity(findings: List[Dict[str, str]], observations: List[Dict[str, str]]) -> Dict[str, Any]:
    watchpoints = {
        "deploy_ssh_directory": path_stat(DEPLOY_SSH_DIR),
        "deploy_authorized_keys": path_stat(DEPLOY_AUTHORIZED_KEYS),
        "sshd_config": path_stat(SSHD_CONFIG),
        "sentinel_project_dir": path_stat(PROJECT_DIR),
        "sentinel_env_file": path_stat(SENTINEL_ENV),
    }

    ssh_dir = watchpoints["deploy_ssh_directory"]
    if not ssh_dir.get("exists"):
        add_finding(
            findings,
            STATUS_WARNING,
            "integrity_watchpoints",
            "/home/deploy/.ssh is missing",
            "/home/deploy/.ssh does not exist.",
            "Confirm whether deploy-user SSH access is expected on this server.",
        )
    elif not ssh_dir.get("is_dir"):
        add_finding(
            findings,
            STATUS_CRITICAL,
            "integrity_watchpoints",
            "/home/deploy/.ssh is not a directory",
            "/home/deploy/.ssh exists but is not a directory.",
            "Inspect the path manually.",
        )
    elif ssh_dir.get("world_writable") or ssh_dir.get("group_writable"):
        add_finding(
            findings,
            STATUS_CRITICAL,
            "integrity_watchpoints",
            "/home/deploy/.ssh permissions are unsafe",
            f"/home/deploy/.ssh mode is {ssh_dir.get('mode')}.",
            "Set SSH directory permissions manually after review.",
        )

    authorized_keys = watchpoints["deploy_authorized_keys"]
    if not authorized_keys.get("exists"):
        add_observation(
            observations,
            "integrity_watchpoints",
            "/home/deploy/.ssh/authorized_keys is absent",
            (
                "/home/deploy/.ssh/authorized_keys does not exist. This is treated as informational "
                "because deploy-user key login may be intentionally disabled or managed elsewhere."
            ),
            "No keys were created and no key contents were read; confirm manually if deploy-user key login is expected.",
        )
    else:
        evaluate_file_watchpoint(
            findings,
            authorized_keys,
            "/home/deploy/.ssh/authorized_keys",
            STATUS_WARNING,
            "Confirm whether key-based deploy-user login is expected.",
        )

    evaluate_file_watchpoint(
        findings,
        watchpoints["sshd_config"],
        "/etc/ssh/sshd_config",
        STATUS_CRITICAL,
        "Restore or inspect sshd_config manually.",
    )
    if watchpoints["sshd_config"].get("exists") and not watchpoints["sshd_config"].get("readable"):
        add_finding(
            findings,
            STATUS_WARNING,
            "integrity_watchpoints",
            "/etc/ssh/sshd_config is not readable",
            "/etc/ssh/sshd_config exists but is not readable by this agent.",
            "Review read permissions manually if the agent should verify SSH config metadata.",
        )

    project = watchpoints["sentinel_project_dir"]
    if project.get("world_writable"):
        add_finding(
            findings,
            STATUS_CRITICAL,
            "integrity_watchpoints",
            "/srv/sentinel-defense is world-writable",
            f"/srv/sentinel-defense mode is {project.get('mode')}.",
            "Remove world-write permission manually.",
        )

    env_file = watchpoints["sentinel_env_file"]
    if not env_file.get("exists"):
        add_finding(
            findings,
            STATUS_WARNING,
            "integrity_watchpoints",
            "/etc/sentinel-defense.env is missing",
            "/etc/sentinel-defense.env does not exist.",
            "Create the env file manually if daily SMTP reporting should be active.",
        )
    else:
        if env_file.get("world_readable"):
            add_finding(
                findings,
                STATUS_CRITICAL,
                "integrity_watchpoints",
                "/etc/sentinel-defense.env is world-readable",
                f"/etc/sentinel-defense.env mode is {env_file.get('mode')}.",
                "Remove world-read permission manually; the agent never reads this file content.",
            )
        if env_file.get("world_writable") or env_file.get("group_writable"):
            add_finding(
                findings,
                STATUS_CRITICAL,
                "integrity_watchpoints",
                "/etc/sentinel-defense.env is writable by group or world",
                f"/etc/sentinel-defense.env mode is {env_file.get('mode')}.",
                "Tighten env-file write permissions manually.",
            )
        elif (
            env_file.get("group_readable")
            and env_file.get("mode") == "0640"
            and env_file.get("owner") == "root"
            and env_file.get("group") == "deploy"
        ):
            add_observation(
                observations,
                "integrity_watchpoints",
                "/etc/sentinel-defense.env is readable by deploy group",
                (
                    "/etc/sentinel-defense.env mode is 0640 root:deploy, which supports a deploy-run "
                    "daily mailer without making the file world-readable."
                ),
                "Keep world-read and group/world-write disabled; the agent did not read env-file contents.",
            )
        elif env_file.get("group_readable"):
            add_finding(
                findings,
                STATUS_WARNING,
                "integrity_watchpoints",
                "/etc/sentinel-defense.env is group-readable by an unexpected group",
                f"/etc/sentinel-defense.env mode is {env_file.get('mode')} {env_file.get('owner')}:{env_file.get('group')}.",
                "Confirm the group needs read access, or tighten permissions manually.",
            )

    return {
        "watchpoints": watchpoints,
        "note": "/etc/sentinel-defense.env content is never read.",
    }


def systemctl_is_active(unit: str) -> str:
    if not shutil.which("systemctl"):
        return "unknown"
    result = run_command(["systemctl", "is-active", unit], timeout=6)
    value = (result["stdout"].strip() or result["stderr"].strip() or "unknown").splitlines()[0]
    if result["returncode"] == 4:
        return "unknown"
    return redact_text(value, 80)


def collect_sentinel_timers(findings: List[Dict[str, str]]) -> Dict[str, Any]:
    timers = {unit: systemctl_is_active(unit) for unit in TIMER_UNITS}
    optional_services = {unit: systemctl_is_active(unit) for unit in OPTIONAL_SERVICE_UNITS}
    non_active_timers = [unit for unit, status_value in timers.items() if status_value != "active"]

    if len(non_active_timers) > 1:
        add_finding(
            findings,
            STATUS_CRITICAL,
            "sentinel_timers",
            "Multiple Sentinel timers are inactive",
            "Non-active timers: " + ", ".join(f"{unit}={timers[unit]}" for unit in non_active_timers),
            "Review systemd timer installation/status manually; the agent made no changes.",
        )
    elif len(non_active_timers) == 1:
        unit = non_active_timers[0]
        add_finding(
            findings,
            STATUS_WARNING,
            "sentinel_timers",
            "One Sentinel timer is inactive",
            f"{unit} status is {timers[unit]}.",
            "Review the timer manually if daily automation is expected.",
        )

    return {
        "timers": timers,
        "optional_services": optional_services,
        "non_active_timer_count": len(non_active_timers),
    }


def build_simulated_actions(findings: List[Dict[str, str]], mode: str) -> List[Dict[str, str]]:
    if mode != "simulate":
        return []
    if not findings:
        return [
            {
                "action": "watch",
                "status": "simulated",
                "detail": "No findings would trigger manual follow-up.",
            }
        ]
    actions = []
    for finding in findings[:10]:
        actions.append(
            {
                "action": "manual_review",
                "status": "simulated",
                "detail": f"Would review {finding['category']}: {finding['title']}. No change applied.",
            }
        )
    return actions


def helper_sudo_stats(*sections: Dict[str, Any]) -> Tuple[bool, bool]:
    attempted = False
    succeeded = False
    for section in sections:
        helper = section.get("helper") if isinstance(section, dict) else None
        attempts = helper.get("attempts", []) if isinstance(helper, dict) else []
        for attempt in attempts:
            if not isinstance(attempt, dict) or not attempt.get("sudo"):
                continue
            attempted = True
            if attempt.get("ok"):
                succeeded = True
    return attempted, succeeded


def defensive_boundaries(sudo_attempted: bool = False, sudo_used: bool = False) -> Dict[str, bool]:
    return {
        "defensive_only": True,
        "external_hosts_contacted": False,
        "foreign_system_scans": False,
        "attacks": False,
        "credential_collection": False,
        "cloudflare_changes": False,
        "system_changes": False,
        "sudo_attempted": sudo_attempted,
        "sudo_used": sudo_used,
        "secrets_in_reports": False,
        "python_standard_library_only": True,
    }


def overall_from_findings(findings: List[Dict[str, str]]) -> Tuple[str, int, int]:
    warning_count = sum(1 for item in findings if item.get("status") == STATUS_WARNING)
    critical_count = sum(1 for item in findings if item.get("status") == STATUS_CRITICAL)
    if critical_count:
        return STATUS_CRITICAL, warning_count, critical_count
    if warning_count:
        return STATUS_WARNING, warning_count, critical_count
    return STATUS_OK, warning_count, critical_count


def build_report(mode: str, out_md: Path, out_json: Path, history_path: Path, compat_inbox_dir: Path) -> Dict[str, Any]:
    findings: List[Dict[str, str]] = []
    observations: List[Dict[str, str]] = []
    generated_at = utc_now()

    system_load = collect_system_load(findings)
    auth = collect_auth(findings)
    firewall = collect_firewall(findings, observations)
    fail2ban = collect_fail2ban(findings, observations)
    processes = collect_processes(findings)
    listening_ports = collect_listening_ports(findings)
    integrity = collect_integrity(findings, observations)
    sentinel_timers = collect_sentinel_timers(findings)
    sudo_attempted, sudo_used = helper_sudo_stats(firewall, fail2ban)

    overall_status, warning_count, critical_count = overall_from_findings(findings)
    simulated_actions = build_simulated_actions(findings, mode)

    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "generated_at_utc": generated_at,
        "mode": mode,
        "overall_status": overall_status,
        "warning_count": warning_count,
        "critical_count": critical_count,
        "findings": findings,
        "observations": observations,
        "metrics": {
            "system_load": system_load,
            "ssh_auth": auth,
            "firewall": firewall,
            "fail2ban": fail2ban,
            "processes": processes,
            "local_listening_ports": listening_ports,
            "integrity_watchpoints": integrity,
        },
        "sentinel_timers": sentinel_timers,
        "defensive_boundaries": defensive_boundaries(sudo_attempted=sudo_attempted, sudo_used=sudo_used),
        "simulated_actions": simulated_actions,
        "applied_actions": [],
        "outputs": {
            "markdown": str(out_md),
            "json": str(out_json),
            "history": str(history_path),
            "compat_markdown": str(compat_inbox_dir / COMPAT_MD_NAME),
            "compat_json": str(compat_inbox_dir / COMPAT_JSON_NAME),
        },
    }


def render_findings(findings: List[Dict[str, str]]) -> List[str]:
    lines = ["## Findings", ""]
    if not findings:
        lines.extend(["Keine Findings.", ""])
        return lines
    lines.extend(["| Status | Category | Finding | Detail | Recommendation |", "|---|---|---|---|---|"])
    for finding in findings:
        lines.append(
            "| {status} | {category} | {title} | {detail} | {recommendation} |".format(
                status=f"`{markdown_text(finding.get('status'))}`",
                category=markdown_text(finding.get("category")),
                title=markdown_text(finding.get("title")),
                detail=markdown_text(finding.get("detail")),
                recommendation=markdown_text(finding.get("recommendation")),
            )
        )
    lines.append("")
    return lines


def render_observations(observations: List[Dict[str, str]]) -> List[str]:
    lines = ["## Informational Observations", ""]
    if not observations:
        lines.extend(["Keine informational observations.", ""])
        return lines
    lines.extend(["| Status | Category | Observation | Detail | Recommendation |", "|---|---|---|---|---|"])
    for observation in observations:
        lines.append(
            "| {status} | {category} | {title} | {detail} | {recommendation} |".format(
                status=f"`{markdown_text(observation.get('status'))}`",
                category=markdown_text(observation.get("category")),
                title=markdown_text(observation.get("title")),
                detail=markdown_text(observation.get("detail")),
                recommendation=markdown_text(observation.get("recommendation")),
            )
        )
    lines.append("")
    return lines


def render_process_table(title: str, rows: List[Dict[str, Any]]) -> List[str]:
    lines = [f"### {title}", ""]
    if not rows:
        lines.extend(["Keine Prozessdaten verfuegbar.", ""])
        return lines
    lines.extend(["| PID | PPID | Name | CPU % | RAM % |", "|---:|---:|---|---:|---:|"])
    for row in rows:
        lines.append(
            f"| {row.get('pid')} | {row.get('ppid')} | {markdown_text(row.get('name'))} | "
            f"{row.get('cpu_percent'):.1f} | {row.get('ram_percent'):.1f} |"
        )
    lines.append("")
    return lines


def render_markdown(report: Dict[str, Any]) -> str:
    metrics = report["metrics"]
    system_load = metrics["system_load"]
    auth = metrics["ssh_auth"]
    firewall = metrics["firewall"]
    fail2ban = metrics["fail2ban"]
    processes = metrics["processes"]
    listening_ports = metrics["local_listening_ports"]
    integrity = metrics["integrity_watchpoints"]
    sentinel_timers = report["sentinel_timers"]

    lines = [
        "# Hetzner Local Defense Report",
        "",
        "## Summary",
        "",
        f"- Generated: `{markdown_text(report.get('generated_at'))}`",
        f"- Mode: `{markdown_text(report.get('mode'))}`",
        f"- Overall Status: `{markdown_text(report.get('overall_status'))}`",
        f"- Warnings: `{report.get('warning_count')}`",
        f"- Criticals: `{report.get('critical_count')}`",
        f"- Informational Observations: `{len(report.get('observations', []))}`",
        "- Scope: passive local defense observation only.",
        "- Actions applied: none.",
        "",
    ]

    lines.extend(render_findings(report.get("findings", [])))
    lines.extend(render_observations(report.get("observations", [])))

    if report.get("mode") == "simulate":
        lines.extend(["## Simulated Measures", ""])
        for action in report.get("simulated_actions", []):
            lines.append(f"- `{markdown_text(action.get('action'))}`: {markdown_text(action.get('detail'))}")
        lines.append("")

    lines.extend(
        [
            "## System Load",
            "",
            "| Metric | Value |",
            "|---|---:|",
            f"| CPU count | {system_load.get('cpu_count')} |",
            f"| Load average | {' / '.join(str(value) for value in system_load.get('load_average', []))} |",
            f"| 1m load per CPU | {system_load.get('load_per_cpu_1m')} |",
            f"| RAM used | {system_load.get('ram_used_percent')}% ({system_load.get('ram_used_gib')} GiB / {system_load.get('ram_total_gib')} GiB) |",
            f"| Disk / used | {system_load.get('disk_root_used_percent')}% ({system_load.get('disk_root_used_gib')} GiB / {system_load.get('disk_root_total_gib')} GiB) |",
            "",
            "## SSH/Auth",
            "",
            "| Metric | Value |",
            "|---|---:|",
            f"| Failed SSH logins | {auth.get('failed_ssh_logins')} |",
            f"| Successful SSH logins | {auth.get('successful_ssh_logins')} |",
            "",
            markdown_text(auth.get("privacy")),
            "",
            "| Source | Detail | Lines |",
            "|---|---|---:|",
        ]
    )
    for source in auth.get("sources", []):
        detail = source.get("path") or source.get("command") or source.get("type")
        lines.append(f"| {markdown_text(source.get('type'))} | {markdown_text(detail)} | {source.get('line_count', 0)} |")
    lines.append("")

    lines.extend(
        [
            "## Firewall",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| ufw available | `{markdown_text(firewall.get('available'))}` |",
            f"| readable without sudo | `{markdown_text(firewall.get('readable_without_sudo'))}` |",
            f"| status | `{markdown_text(firewall.get('status', 'unknown'))}` |",
            f"| rules reported | `{markdown_text(firewall.get('rules_reported'))}` |",
            "",
            markdown_text(firewall.get("note")),
            "",
            "## fail2ban",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| installed | `{markdown_text(fail2ban.get('installed'))}` |",
            f"| readable without sudo | `{markdown_text(fail2ban.get('readable_without_sudo'))}` |",
            f"| status | `{markdown_text(fail2ban.get('status', fail2ban.get('note', 'not_installed')))}` |",
            f"| jails | `{markdown_text(', '.join(fail2ban.get('jails', [])) or '-')}` |",
            "",
            "## Processes",
            "",
            markdown_text(processes.get("privacy")),
            "",
        ]
    )
    lines.extend(render_process_table("Top CPU Processes", processes.get("top_cpu", [])))
    lines.extend(render_process_table("Top RAM Processes", processes.get("top_ram", [])))

    lines.extend(
        [
            "## Local Listening Ports",
            "",
            f"- Socket count: `{listening_ports.get('socket_count', 0)}`",
            f"- Wildcard binding count: `{listening_ports.get('wildcard_binding_count', 0)}`",
            f"- Command: `{markdown_text(listening_ports.get('command', '-'))}`",
            "",
            "| Protocol | State | Local Address | Port | Process/Service |",
            "|---|---|---|---:|---|",
        ]
    )
    for socket in listening_ports.get("sockets", []):
        lines.append(
            f"| {markdown_text(socket.get('protocol'))} | {markdown_text(socket.get('state'))} | "
            f"{markdown_text(socket.get('local_address'))} | {markdown_text(socket.get('port'))} | "
            f"{markdown_text(socket.get('process'))} |"
        )
    if not listening_ports.get("sockets"):
        lines.append("| - | - | - | - | - |")
    lines.extend(["", markdown_text(listening_ports.get("note")), ""])

    lines.extend(
        [
            "## Integrity Watchpoints",
            "",
            "| Watchpoint | Exists | Mode | Owner | Group | Readable | Notes |",
            "|---|---:|---|---|---|---:|---|",
        ]
    )
    for key, details in integrity.get("watchpoints", {}).items():
        note = "content not read" if key == "sentinel_env_file" else "-"
        lines.append(
            f"| {markdown_text(details.get('path'))} | `{markdown_text(details.get('exists'))}` | "
            f"`{markdown_text(details.get('mode', '-'))}` | {markdown_text(details.get('owner', '-'))} | "
            f"{markdown_text(details.get('group', '-'))} | `{markdown_text(details.get('readable', '-'))}` | {note} |"
        )
    lines.extend(["", markdown_text(integrity.get("note")), ""])

    lines.extend(["## Sentinel Timers", "", "| Unit | Kind | Status |", "|---|---|---|"])
    for unit, status_value in sentinel_timers.get("timers", {}).items():
        lines.append(f"| {markdown_text(unit)} | timer | `{markdown_text(status_value)}` |")
    for unit, status_value in sentinel_timers.get("optional_services", {}).items():
        lines.append(f"| {markdown_text(unit)} | optional service | `{markdown_text(status_value)}` |")
    lines.append("")

    lines.extend(["## Defensive Boundaries", "", "| Boundary | Value |", "|---|---:|"])
    for key, value in report.get("defensive_boundaries", {}).items():
        lines.append(f"| {markdown_text(key)} | `{markdown_text(value)}` |")
    lines.append("")

    lines.extend(
        [
            "## Outputs",
            "",
            f"- Markdown: `{markdown_text(report['outputs'].get('markdown'))}`",
            f"- JSON: `{markdown_text(report['outputs'].get('json'))}`",
            f"- History: `{markdown_text(report['outputs'].get('history'))}`",
            f"- Master-compatible Markdown: `{markdown_text(report['outputs'].get('compat_markdown'))}`",
            f"- Master-compatible JSON: `{markdown_text(report['outputs'].get('compat_json'))}`",
            "",
        ]
    )
    return "\n".join(lines)


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=True, indent=2, sort_keys=True) + "\n")


def append_history(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "generated_at": report.get("generated_at"),
        "mode": report.get("mode"),
        "overall_status": report.get("overall_status"),
        "warning_count": report.get("warning_count"),
        "critical_count": report.get("critical_count"),
        "failed_ssh_logins": report["metrics"]["ssh_auth"].get("failed_ssh_logins"),
        "load_per_cpu_1m": report["metrics"]["system_load"].get("load_per_cpu_1m"),
        "ram_used_percent": report["metrics"]["system_load"].get("ram_used_percent"),
        "disk_root_used_percent": report["metrics"]["system_load"].get("disk_root_used_percent"),
        "non_active_timer_count": report["sentinel_timers"].get("non_active_timer_count"),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")


def atomic_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dst.with_name(f".{dst.name}.tmp")
    tmp_path.write_bytes(src.read_bytes())
    tmp_path.replace(dst)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Hetzner local Sentinel defense report.")
    parser.add_argument("--mode", choices=("observe", "simulate"), default="observe")
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--history-path", type=Path, default=DEFAULT_HISTORY)
    parser.add_argument("--compat-inbox-dir", type=Path, default=DEFAULT_COMPAT_INBOX)
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    report = build_report(args.mode, args.out_md, args.out_json, args.history_path, args.compat_inbox_dir)
    markdown = render_markdown(report)

    write_json_atomic(args.out_json, report)
    write_text_atomic(args.out_md, markdown)
    append_history(args.history_path, report)

    atomic_copy(args.out_json, args.compat_inbox_dir / COMPAT_JSON_NAME)
    atomic_copy(args.out_md, args.compat_inbox_dir / COMPAT_MD_NAME)

    print(
        "Hetzner local defense report written: "
        f"{args.out_md} ({report['overall_status']}, warnings={report['warning_count']}, "
        f"criticals={report['critical_count']})"
    )
    print(f"Master-compatible inbox updated: {args.compat_inbox_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
