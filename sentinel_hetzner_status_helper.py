#!/usr/bin/env python3
"""Read-only Hetzner status helper for Sentinel.

The helper prints small JSON summaries for allowlisted local status commands.
It performs no writes, does not read secrets, and never contacts external hosts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Sequence


TIMER_UNITS = (
    "cloudflare-daily-monitor.timer",
    "sentinel-defense.timer",
    "sentinel-master.timer",
    "sentinel-daily-mail.timer",
)


def run_command(args: Sequence[str], timeout: int = 8) -> Dict[str, Any]:
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


def safe_text(value: object, max_len: int = 160) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|credential)\s*[:=]\s*[^\s,;]+",
        lambda match: f"{match.group(1)}=<redacted>",
        text,
    )
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def parse_ufw_status(output: str) -> str:
    for line in output.splitlines():
        if line.casefold().startswith("status:"):
            return safe_text(line.split(":", 1)[1], 80).casefold()
    return "unknown"


def parse_fail2ban_jails(output: str) -> List[str]:
    for line in output.splitlines():
        if "Jail list:" in line:
            _, value = line.split("Jail list:", 1)
            return [safe_text(item, 80) for item in re.split(r"[, ]+", value.strip()) if item.strip()]
    return []


def parse_fail2ban_counter(output: str, label: str) -> int | None:
    pattern = re.compile(rf"^\s*\|?\s*{re.escape(label)}:\s*(\d+)\s*$", re.IGNORECASE)
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            return int(match.group(1))
    return None


def helper_result(ok: bool, **fields: Any) -> Dict[str, Any]:
    return {"ok": ok, **fields}


def ufw_status() -> Dict[str, Any]:
    if not shutil.which("ufw"):
        return helper_result(False, component="ufw", status="missing", error="ufw command not found")
    result = run_command(["ufw", "status", "verbose"], timeout=8)
    status = parse_ufw_status(result["stdout"]) if result["stdout"] else "unknown"
    return helper_result(
        result["ok"] and status != "unknown",
        component="ufw",
        command="ufw status verbose",
        status=status,
        firewall_active=status == "active",
        rules_reported=False,
        returncode=result["returncode"],
        error=safe_text(result["stderr"]) if not result["ok"] else "",
    )


def fail2ban_status() -> Dict[str, Any]:
    if not shutil.which("fail2ban-client"):
        return helper_result(False, component="fail2ban", status="missing", error="fail2ban-client command not found")
    result = run_command(["fail2ban-client", "status"], timeout=8)
    jails = parse_fail2ban_jails(result["stdout"]) if result["stdout"] else []
    return helper_result(
        result["ok"],
        component="fail2ban",
        command="fail2ban-client status",
        status="running" if result["ok"] else "unreadable_or_not_running",
        active=result["ok"],
        jails=jails,
        returncode=result["returncode"],
        error=safe_text(result["stderr"]) if not result["ok"] else "",
    )


def fail2ban_sshd() -> Dict[str, Any]:
    if not shutil.which("fail2ban-client"):
        return helper_result(False, component="fail2ban-sshd", status="missing", error="fail2ban-client command not found")
    result = run_command(["fail2ban-client", "status", "sshd"], timeout=8)
    return helper_result(
        result["ok"],
        component="fail2ban-sshd",
        command="fail2ban-client status sshd",
        status="running" if result["ok"] else "unreadable_or_not_running",
        active=result["ok"],
        currently_failed=parse_fail2ban_counter(result["stdout"], "Currently failed"),
        total_failed=parse_fail2ban_counter(result["stdout"], "Total failed"),
        currently_banned=parse_fail2ban_counter(result["stdout"], "Currently banned"),
        total_banned=parse_fail2ban_counter(result["stdout"], "Total banned"),
        banned_ips_reported=False,
        returncode=result["returncode"],
        error=safe_text(result["stderr"]) if not result["ok"] else "",
    )


def systemctl_is_active(unit: str) -> str:
    if not shutil.which("systemctl"):
        return "unknown"
    result = run_command(["systemctl", "is-active", unit], timeout=6)
    value = (result["stdout"].strip() or result["stderr"].strip() or "unknown").splitlines()[0]
    if result["returncode"] == 4:
        return "unknown"
    return safe_text(value, 80)


def sentinel_timers() -> Dict[str, Any]:
    statuses = {unit: systemctl_is_active(unit) for unit in TIMER_UNITS}
    return helper_result(
        True,
        component="sentinel-timers",
        command="systemctl is-active for allowlisted Sentinel timer units",
        timers=statuses,
    )


COMMANDS = {
    "ufw-status": ufw_status,
    "fail2ban-status": fail2ban_status,
    "fail2ban-sshd": fail2ban_sshd,
    "sentinel-timers": sentinel_timers,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only Sentinel Hetzner status helper.")
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = COMMANDS[args.command]()
    print(json.dumps(payload, ensure_ascii=True, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    sys.exit(main())
