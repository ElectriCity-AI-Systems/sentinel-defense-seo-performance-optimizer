#!/usr/bin/env python3
"""Read-only Cloudflare DNS origin discovery for the AI-Radio hostname."""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path("/srv/sentinel-defense")
OUT_MD = BASE_DIR / "reports/latest/ai-radio-cloudflare-origin-discovery.md"
OUT_JSON = BASE_DIR / "reports/latest/ai-radio-cloudflare-origin-discovery.json"
HOSTNAME = "ai-radio.electri-c-ity-studios-24-7.com"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_readonly(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, check=False, text=True, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"{exc.__class__.__name__}"
    return proc.returncode, proc.stdout.strip()


def env_presence() -> dict[str, bool]:
    keys = ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID", "CF_API_TOKEN", "CF_ZONE_ID"]
    return {key: bool(os.environ.get(key)) for key in keys}


def cf_api_credentials() -> tuple[str | None, str | None]:
    token = os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN")
    zone_id = os.environ.get("CLOUDFLARE_ZONE_ID") or os.environ.get("CF_ZONE_ID")
    return token, zone_id


def query_cloudflare_dns(token: str, zone_id: str) -> dict[str, Any]:
    params = urllib.parse.urlencode({"name": HOSTNAME, "per_page": "100"})
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?{params}"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "SentinelDefense-OriginDiscovery/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "lookup_status": "api_error",
            "error_type": exc.__class__.__name__,
            "records": [],
        }

    if not payload.get("success"):
        return {
            "lookup_status": "api_unsuccessful",
            "records": [],
            "errors": [
                {"code": item.get("code"), "message": item.get("message")}
                for item in payload.get("errors", [])
            ],
        }

    records = []
    for item in payload.get("result", []):
        if item.get("type") not in {"A", "AAAA", "CNAME"}:
            continue
        records.append(
            {
                "id_present": bool(item.get("id")),
                "name": item.get("name"),
                "record_type": item.get("type"),
                "content": item.get("content"),
                "proxied": item.get("proxied"),
                "ttl": item.get("ttl"),
                "comment": item.get("comment"),
                "tags": item.get("tags") or [],
                "modified_on": item.get("modified_on"),
            }
        )
    return {"lookup_status": "ok", "records": records}


def inspect_cloudflared() -> dict[str, Any]:
    config_path = Path("/etc/cloudflared/config.yml")
    config_summary: dict[str, Any] = {"path": str(config_path), "exists": config_path.exists()}
    if config_path.exists():
        try:
            lines = config_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            config_summary["read_error"] = exc.__class__.__name__
        else:
            sanitized = []
            for raw in lines:
                line = raw.strip()
                lower = line.lower()
                if any(secret_key in lower for secret_key in ("credentials-file:", "token:", "secret:", "password:")):
                    key = line.split(":", 1)[0] if ":" in line else "sensitive"
                    sanitized.append(f"{key}: [redacted]")
                elif any(marker in lower for marker in ("hostname:", "service:", "tunnel:", "url:")):
                    sanitized.append(line)
            config_summary["sanitized_relevant_lines"] = sanitized

    _, systemd_out = run_readonly(["bash", "-lc", "systemctl list-units --type=service --all --no-pager | grep -Ei 'cloudflared|tunnel' || true"])
    _, docker_out = run_readonly(["bash", "-lc", "docker ps --format '{{.Names}}\\t{{.Image}}\\t{{.Status}}' | grep -Ei 'cloudflared|tunnel' || true"])
    detected = bool(systemd_out or docker_out or config_path.exists())
    return {
        "detected": detected,
        "config": config_summary,
        "systemd_matches": systemd_out.splitlines() if systemd_out else [],
        "docker_matches": docker_out.splitlines() if docker_out else [],
    }


def classify_origin(record: dict[str, Any] | None, cloudflared: dict[str, Any]) -> str:
    if not record:
        return "unknown"
    record_type = record.get("record_type")
    content = str(record.get("content") or "")
    if record_type == "CNAME" and content.endswith(".cfargotunnel.com"):
        return "cloudflare_tunnel"
    if cloudflared.get("detected") and record.get("proxied"):
        return "possible_local_cloudflare_tunnel"
    if record_type in {"A", "AAAA"}:
        return "direct_ip_origin_proxied" if record.get("proxied") else "direct_ip_origin_dns_only"
    if record_type == "CNAME":
        return "external_cname_origin_proxied" if record.get("proxied") else "external_cname_origin_dns_only"
    return "unknown"


def summarize_target(records: list[dict[str, Any]], lookup_status: str) -> str:
    if lookup_status != "ok":
        return "unknown; Cloudflare API lookup did not complete"
    if not records:
        return "unknown; no A/AAAA/CNAME record returned for hostname"
    parts = []
    for record in records:
        parts.append(
            f"{record.get('record_type')} {record.get('content')} proxied={record.get('proxied')} ttl={record.get('ttl')}"
        )
    return "; ".join(parts)


def build_report() -> dict[str, Any]:
    presence = env_presence()
    token, zone_id = cf_api_credentials()
    cloudflare_api_available = bool(token and zone_id)
    cloudflared = inspect_cloudflared()

    if cloudflare_api_available:
        cf_lookup = query_cloudflare_dns(token or "", zone_id or "")
    else:
        cf_lookup = {
            "lookup_status": "skipped_api_credentials_missing",
            "records": [],
        }

    records = cf_lookup.get("records", [])
    primary = records[0] if records else None
    likely_origin_kind = classify_origin(primary, cloudflared)
    manual_plan = [
        "Open Cloudflare dashboard for the electri-c-ity-studios-24-7.com zone.",
        "Go to DNS -> Records.",
        f"Search for {HOSTNAME} or the ai-radio subdomain.",
        "Record Type, Target/Content, Proxy Status, TTL, Comment, and Tags.",
        "If target is a CNAME ending in .cfargotunnel.com, inspect the matching Cloudflare Tunnel and its public hostname route.",
        "If target is A/AAAA, identify which server owns that IP before placing the NowPlaying microcache.",
        "Do not change DNS, WAF, or Cloudflare settings during this discovery.",
    ]

    return {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "productive_change": False,
        "cloudflare_mutation": False,
        "hostname": HOSTNAME,
        "environment_presence": presence,
        "cloudflare_api_available": cloudflare_api_available,
        "dns_lookup_status": cf_lookup.get("lookup_status"),
        "dns_record_found": bool(records) if cloudflare_api_available else None,
        "records": records,
        "record_type": primary.get("record_type") if primary else None,
        "proxied": primary.get("proxied") if primary else None,
        "target_summary": summarize_target(records, cf_lookup.get("lookup_status", "unknown")),
        "likely_origin_kind": likely_origin_kind if cloudflare_api_available else "unknown_cloudflare_api_unavailable",
        "cloudflare_tunnel_detected": bool(
            cloudflared.get("detected")
            or any(str(record.get("content", "")).endswith(".cfargotunnel.com") for record in records)
        ),
        "local_cloudflared": cloudflared,
        "safe_to_plan_microcache_here": False,
        "recommended_next_step": (
            "Use the Cloudflare dashboard manual plan to identify the ai-radio DNS target, then plan the "
            "NowPlaying microcache at that actual origin/proxy. Do not deploy on this Hetzner server until "
            "the record target confirms this server or an intentional route is created."
            if not cloudflare_api_available
            else "Plan the NowPlaying microcache at the reported DNS target/origin after operator review."
        ),
        "manual_dashboard_plan": manual_plan,
    }


def md_bool(value: Any) -> str:
    if value is None:
        return "unknown"
    return "true" if bool(value) else "false"


def render_markdown(report: dict[str, Any]) -> str:
    records = report.get("records", [])
    lines = [
        "# AI-Radio Cloudflare Origin Discovery",
        "",
        "## Summary",
        "",
        f"- Hostname: `{report['hostname']}`",
        f"- Productive Change: `{md_bool(report['productive_change'])}`",
        f"- Cloudflare Mutation: `{md_bool(report['cloudflare_mutation'])}`",
        f"- Cloudflare API Available: `{md_bool(report['cloudflare_api_available'])}`",
        f"- DNS Lookup Status: `{report.get('dns_lookup_status')}`",
        f"- DNS Record Found: `{md_bool(report.get('dns_record_found'))}`",
        f"- Record Type: `{report.get('record_type')}`",
        f"- Proxied: `{md_bool(report.get('proxied'))}`",
        f"- Target Summary: `{report.get('target_summary')}`",
        f"- Likely Origin Kind: `{report.get('likely_origin_kind')}`",
        f"- Cloudflare Tunnel Detected: `{md_bool(report.get('cloudflare_tunnel_detected'))}`",
        f"- Safe To Plan Microcache Here: `{md_bool(report.get('safe_to_plan_microcache_here'))}`",
        "",
        "## Environment Presence",
        "",
        "| Variable | State |",
        "| --- | --- |",
    ]
    for key, present in report.get("environment_presence", {}).items():
        lines.append(f"| `{key}` | `{'present' if present else 'missing'}` |")

    lines.extend(["", "## DNS Records", "", "| Type | Content | Proxied | TTL | Comment | Tags |", "| --- | --- | --- | ---: | --- | --- |"])
    if records:
        for record in records:
            tags = ", ".join(record.get("tags") or [])
            comment = record.get("comment") or ""
            lines.append(
                f"| `{record.get('record_type')}` | `{record.get('content')}` | `{md_bool(record.get('proxied'))}` | {record.get('ttl')} | `{comment}` | `{tags}` |"
            )
    else:
        lines.append("| unknown | unknown | unknown | 0 | no API result in this environment |  |")

    cloudflared = report.get("local_cloudflared", {})
    lines.extend(
        [
            "",
            "## Local Cloudflared Check",
            "",
            f"- Detected: `{md_bool(cloudflared.get('detected'))}`",
            f"- Config Exists: `{md_bool(cloudflared.get('config', {}).get('exists'))}`",
            f"- systemd Matches: `{len(cloudflared.get('systemd_matches') or [])}`",
            f"- Docker Matches: `{len(cloudflared.get('docker_matches') or [])}`",
            "",
            "## Recommended Next Step",
            "",
            report.get("recommended_next_step", ""),
            "",
            "## Manual Cloudflare Dashboard Plan",
            "",
        ]
    )
    for step in report.get("manual_dashboard_plan", []):
        lines.append(f"- {step}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    report = build_report()
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    OUT_MD.write_text(render_markdown(report), encoding="utf-8")
    print(f"Wrote {OUT_MD}")
    print(f"Wrote {OUT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
