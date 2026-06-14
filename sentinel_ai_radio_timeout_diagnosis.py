#!/usr/bin/env python3
"""Diagnose AI-Radio/AzuraCast 504 timeout pressure without mutations.

This script is defensive and read-only:
- reads Sentinel/Cloudflare JSON snapshots
- runs local read-only service/port inventory commands
- writes Markdown/JSON diagnosis and prevention-plan reports
- never changes Cloudflare, services, files outside reports, or credentials
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

DEFAULT_ERRORS_5XX = PROJECT_DIR / "cloudflare-monitor/latest/errors-5xx-24h.json"
DEFAULT_TOP_PATHS = PROJECT_DIR / "cloudflare-monitor/latest/top-paths-24h.json"
DEFAULT_STATUS_24H = PROJECT_DIR / "cloudflare-monitor/latest/status-24h.json"
DEFAULT_MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
DEFAULT_DEFENSE_JSON = PROJECT_DIR / "reports/latest/sentinel-defense-report.json"
DEFAULT_OUT_MD = PROJECT_DIR / "reports/latest/ai-radio-api-timeout-diagnosis.md"
DEFAULT_OUT_JSON = PROJECT_DIR / "reports/latest/ai-radio-api-timeout-diagnosis.json"
DEFAULT_PLAN_MD = PROJECT_DIR / "reports/latest/ai-radio-api-timeout-prevention-plan.md"
DEFAULT_PLAN_JSON = PROJECT_DIR / "reports/latest/ai-radio-api-timeout-prevention-plan.json"
DEFAULT_MICROCACHE_STATUS_MD = PROJECT_DIR / "docs/ai-radio-nowplaying-microcache-status.md"
DEFAULT_MICROCACHE_STATUS_JSON = PROJECT_DIR / "reports/latest/ai-radio-nowplaying-microcache-status.json"

AI_RADIO_HOST = "ai-radio.electri-c-ity-studios-24-7.com"
NOWPLAYING_PATH = "/api/nowplaying/electri-city-ai-electro-radio"
STATIC_NOWPLAYING_PATH = "/api/nowplaying_static/electri-city-ai-electro-radio.json"
API_TIME_PATH = "/api/time"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_count(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except ValueError:
            return 0
    return 0


def safe_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    text = str(value).replace("\n", " ").replace("\r", " ")
    if len(text) > 240:
        return text[:237] + "..."
    return text


def read_json(path: Path) -> Tuple[Dict[str, Any], Optional[str], bool]:
    if not path.exists():
        return {}, "missing", False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, str(exc), True
    if not isinstance(data, dict):
        return {}, "json root is not an object", True
    return data, None, True


def read_microcache_status(json_path: Path, md_path: Path) -> Dict[str, Any]:
    data, error, exists = read_json(json_path)
    if exists and not error:
        data["present"] = True
        data["source"] = str(json_path)
        data["source_type"] = "json"
        return data
    if md_path.exists():
        return {
            "present": True,
            "source": str(md_path),
            "source_type": "markdown",
            "json_error": error,
            "microcache_deployed": True,
            "local_validation": "documented",
        }
    return {
        "present": False,
        "source": str(json_path),
        "source_type": "missing",
        "json_error": error,
        "microcache_deployed": False,
    }


def summarize_rolling_window(defense_data: Dict[str, Any]) -> Dict[str, Any]:
    context = defense_data.get("rolling_window_context")
    if not isinstance(context, dict):
        return {"present": False}

    history = context.get("history") if isinstance(context.get("history"), dict) else {}
    candidates: List[Dict[str, Any]] = []
    for key in ("elevated_metrics", "old_window_blockers"):
        values = history.get(key)
        if isinstance(values, list):
            candidates.extend(item for item in values if isinstance(item, dict))
    values = context.get("elevated_watchpoints")
    if isinstance(values, list):
        candidates.extend(item for item in values if isinstance(item, dict))

    total_5xx = {}
    for item in candidates:
        if item.get("delta_key") == "total_5xx" or item.get("key") == "total_5xx":
            total_5xx = item
            break

    latest_delta = (
        total_5xx.get("latest_delta")
        if "latest_delta" in total_5xx
        else total_5xx.get("delta_since_previous")
    )
    low_growth_limit = parse_count(total_5xx.get("low_growth_limit")) if total_5xx else 0
    latest_delta_count = parse_count(latest_delta)
    low_growth = bool(total_5xx) and latest_delta is not None and latest_delta_count <= low_growth_limit
    return {
        "present": True,
        "status": context.get("status"),
        "interpretation": context.get("interpretation"),
        "latest_5xx_delta": latest_delta,
        "low_growth_limit": low_growth_limit,
        "latest_5xx_delta_low": low_growth,
        "max_recent_5xx_delta": total_5xx.get("max_recent_delta"),
        "stable_minutes": total_5xx.get("stable_minutes"),
        "remaining_stable_minutes_for_old_window": total_5xx.get("remaining_stable_minutes_for_old_window"),
        "stable_since_utc": total_5xx.get("stable_since_utc"),
        "stable_since_reason": total_5xx.get("stable_since_reason"),
        "old_window_required_stable_minutes": history.get("old_window_required_stable_minutes"),
    }


def build_microcache_remediation(
    status: Dict[str, Any],
    rolling_window: Dict[str, Any],
) -> Dict[str, Any]:
    deployed = bool(status.get("microcache_deployed"))
    latest_delta_low = bool(rolling_window.get("latest_5xx_delta_low"))
    note = ""
    if deployed:
        note = "Microcache remediation deployed and locally validated."
        if latest_delta_low:
            note += " NowPlaying 504s may be historical-window remainder after microcache deployment."
    return {
        "present": bool(status.get("present")),
        "microcache_deployed": deployed,
        "deployed_on_host": status.get("deployed_on_host"),
        "origin_ip": status.get("origin_ip"),
        "endpoint": status.get("endpoint"),
        "local_validation": status.get("local_validation"),
        "cache_header": status.get("cache_header"),
        "nginx_cache_ttl_seconds": status.get("nginx_cache_ttl_seconds"),
        "stale_on_error": bool(status.get("stale_on_error")),
        "cloudflare_change": bool(status.get("cloudflare_change")),
        "waf_change": bool(status.get("waf_change")),
        "expected_effect": status.get("expected_effect"),
        "status_note": note,
        "rolling_window_remainder_hint": (
            "NowPlaying 504s may be historical-window remainder after microcache deployment."
            if deployed and latest_delta_low
            else ""
        ),
        "next_action": (
            "Observe 24h rolling-window decay; do not add a new WAF rule."
            if deployed
            else "Plan microcache plus stale fallback at the confirmed origin/proxy; do not add a WAF rule."
        ),
        "source": status.get("source"),
    }


def adaptive_groups(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    groups: List[Dict[str, Any]] = []
    if not isinstance(zones, list):
        return groups
    for zone in zones:
        if not isinstance(zone, dict):
            continue
        zone_groups = zone.get("httpRequestsAdaptiveGroups")
        if isinstance(zone_groups, list):
            groups.extend(item for item in zone_groups if isinstance(item, dict))
    return groups


def dims(group: Dict[str, Any]) -> Dict[str, Any]:
    value = group.get("dimensions")
    return value if isinstance(value, dict) else {}


def group_count(group: Dict[str, Any]) -> int:
    return parse_count(group.get("count"))


def count_items(mapping: Dict[str, int], key: str, limit: int = 8) -> List[Dict[str, Any]]:
    return [
        {key: name, "count": count}
        for name, count in sorted(mapping.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def run_cmd(args: List[str], timeout: int = 12) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command": args[:2], "ok": False, "returncode": None, "error": safe_text(exc)}
    return {
        "command": args[:2],
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": safe_text(result.stderr),
    }


def collect_local_readonly() -> Dict[str, Any]:
    docker = run_cmd(["docker", "ps", "--format", "{{json .}}"])
    containers: List[Dict[str, str]] = []
    if docker.get("ok"):
        for line in str(docker.get("stdout", "")).splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            containers.append(
                {
                    "name": safe_text(item.get("Names")),
                    "image": safe_text(item.get("Image")),
                    "status": safe_text(item.get("Status")),
                    "ports": safe_text(item.get("Ports"), max_len=400) if False else safe_text(item.get("Ports")),
                }
            )

    units = {}
    for unit in (
        "azuracast.service",
        "docker.service",
        "nginx.service",
        "mariadb.service",
        "mysql.service",
        "redis-server.service",
    ):
        show = run_cmd(
            [
                "systemctl",
                "show",
                unit,
                "--no-pager",
                "-p",
                "Id",
                "-p",
                "LoadState",
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                "-p",
                "MainPID",
                "-p",
                "FragmentPath",
            ]
        )
        parsed: Dict[str, str] = {}
        for line in str(show.get("stdout", "")).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                parsed[key] = safe_text(value)
        units[unit] = {"ok": bool(show.get("ok")), "properties": parsed, "error": show.get("stderr")}

    list_units = run_cmd(["systemctl", "list-units", "--type=service", "--all", "--no-pager"])
    relevant_units = []
    if list_units.get("stdout"):
        needles = ("azura", "radio", "icecast", "nginx", "docker", "mariadb", "mysql", "redis", "php")
        for line in str(list_units.get("stdout", "")).splitlines():
            lowered = line.lower()
            if any(needle in lowered for needle in needles):
                relevant_units.append(safe_text(" ".join(line.split())))

    ss_result = run_cmd(["ss", "-tulpen"])
    listening_ports: List[Dict[str, str]] = []
    for line in str(ss_result.get("stdout", "")).splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[4]
        process = " ".join(parts[6:]) if len(parts) > 6 else ""
        listening_ports.append(
            {
                "netid": safe_text(parts[0]),
                "state": safe_text(parts[1]),
                "local": safe_text(local),
                "process_hint": safe_text(process),
            }
        )

    return {
        "docker_ps_ok": bool(docker.get("ok")),
        "containers": containers,
        "systemd_units": units,
        "relevant_service_lines": relevant_units[:20],
        "listening_ports": listening_ports[:30],
        "local_readonly_only": True,
        "logs_collected": False,
    }


def summarize_cloudflare(
    errors_data: Dict[str, Any],
    top_paths_data: Dict[str, Any],
    status_data: Dict[str, Any],
    defense_data: Dict[str, Any],
) -> Dict[str, Any]:
    status_counts: Dict[str, int] = {}
    for group in adaptive_groups(status_data):
        status = str(dims(group).get("edgeResponseStatus", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + group_count(group)

    path_status: Dict[Tuple[str, str, str], int] = defaultdict(int)
    path_cache: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    path_countries: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    host_counts: Dict[str, int] = defaultdict(int)
    total_5xx_detail = 0
    for group in adaptive_groups(errors_data):
        d = dims(group)
        status = str(d.get("edgeResponseStatus", "unknown"))
        path = str(d.get("clientRequestPath", "-"))
        host = str(d.get("clientRequestHTTPHost", "-"))
        count = group_count(group)
        total_5xx_detail += count
        path_status[(host, path, status)] += count
        path_cache[path][str(d.get("cacheStatus", "-"))] += count
        path_countries[path][str(d.get("clientCountryName", "-"))] += count
        host_counts[host] += count

    path_totals: Dict[Tuple[str, str], int] = defaultdict(int)
    for (host, path, _status), count in path_status.items():
        path_totals[(host, path)] += count

    top_5xx_paths = []
    for (host, path), count in sorted(path_totals.items(), key=lambda item: (-item[1], item[0]))[:15]:
        statuses = {
            status: path_status[(host, path, status)]
            for (h, p, status) in path_status
            if h == host and p == path
        }
        top_5xx_paths.append(
            {
                "host": host,
                "path": path,
                "count": count,
                "statuses": count_items(statuses, "status", limit=6),
                "cache_status": count_items(path_cache[path], "cache_status", limit=4),
                "countries": count_items(path_countries[path], "country", limit=4),
            }
        )

    top_path_status: Dict[Tuple[str, str, str], int] = defaultdict(int)
    for group in adaptive_groups(top_paths_data):
        d = dims(group)
        host = str(d.get("clientRequestHTTPHost", "-"))
        path = str(d.get("clientRequestPath", "-"))
        status = str(d.get("edgeResponseStatus", "unknown"))
        top_path_status[(host, path, status)] += group_count(group)

    def top_status_count(path: str, status: int, host: str = AI_RADIO_HOST) -> int:
        return top_path_status.get((host, path, str(status)), 0)

    metrics = defense_data.get("metrics") if isinstance(defense_data.get("metrics"), list) else []
    metric_map = {
        str(item.get("key")): item
        for item in metrics
        if isinstance(item, dict)
    }
    origin = defense_data.get("origin_pressure_breakdown")
    if not isinstance(origin, dict):
        origin = {}
    top_classification = origin.get("top_5xx_status_inclusive_classification")
    likely_cloudflare_timeout = 0
    if isinstance(top_classification, list):
        for item in top_classification:
            if isinstance(item, dict) and item.get("classification") == "likely_cloudflare_timeout":
                likely_cloudflare_timeout = parse_count(item.get("count"))

    total_504 = status_counts.get("504", 0)
    nowplaying_504 = sum(
        item["count"]
        for item in top_5xx_paths
        if item["host"] == AI_RADIO_HOST and item["path"] == NOWPLAYING_PATH
    )
    if not nowplaying_504:
        nowplaying_504 = path_totals.get((AI_RADIO_HOST, NOWPLAYING_PATH), 0)
    api_time_504 = path_totals.get((AI_RADIO_HOST, API_TIME_PATH), 0)
    public_504 = path_totals.get((AI_RADIO_HOST, "/public/electri-city-ai-electro-radio"), 0)

    return {
        "status_counts": count_items(status_counts, "status", limit=12),
        "total_504": total_504,
        "total_5xx_detail": total_5xx_detail,
        "likely_cloudflare_timeout": likely_cloudflare_timeout,
        "total_5xx_metric": parse_count(metric_map.get("total_5xx", {}).get("value")),
        "website_status": defense_data.get("overall_status"),
        "website_correlation_status": defense_data.get("correlation_status"),
        "top_5xx_paths": top_5xx_paths,
        "host_5xx_counts": count_items(host_counts, "host", limit=8),
        "nowplaying_504": nowplaying_504,
        "nowplaying_200": top_status_count(NOWPLAYING_PATH, 200),
        "nowplaying_static_200": top_status_count(STATIC_NOWPLAYING_PATH, 200),
        "api_time_504": api_time_504,
        "api_time_200": top_status_count(API_TIME_PATH, 200),
        "public_station_504": public_504,
        "nowplaying_504_share_percent": round((nowplaying_504 / total_504 * 100), 2) if total_504 else 0.0,
        "ai_radio_5xx_share_percent": round((host_counts.get(AI_RADIO_HOST, 0) / total_5xx_detail * 100), 2)
        if total_5xx_detail
        else 0.0,
        "cache_behavior": {
            "nowplaying": count_items(path_cache[NOWPLAYING_PATH], "cache_status", limit=4),
            "api_time": count_items(path_cache[API_TIME_PATH], "cache_status", limit=4),
        },
    }


def classify_findings(summary: Dict[str, Any], local: Dict[str, Any]) -> List[Dict[str, Any]]:
    total_504 = parse_count(summary.get("total_504"))
    nowplaying_504 = parse_count(summary.get("nowplaying_504"))
    api_time_504 = parse_count(summary.get("api_time_504"))
    likely_timeout = parse_count(summary.get("likely_cloudflare_timeout"))
    containers = local.get("containers") if isinstance(local.get("containers"), list) else []
    azuracast_unit = (
        local.get("systemd_units", {})
        .get("azuracast.service", {})
        .get("properties", {})
    )
    azuracast_local = azuracast_unit.get("LoadState") == "loaded" or any(
        "azura" in str(item.get("name", "")).lower() or "azura" in str(item.get("image", "")).lower()
        for item in containers
        if isinstance(item, dict)
    )

    findings = []
    findings.append(
        {
            "signal_id": "cloudflare_to_origin_timeout",
            "status": "CRITICAL" if likely_timeout > 1000 or total_504 > 1000 else "WARNING",
            "count": likely_timeout or total_504,
            "explanation": "Cloudflare status and Sentinel origin-pressure data classify the 504 surge as Cloudflare-to-origin timeout shaped.",
            "recommendation": "Do not derive a WAF rule. Reduce origin latency/load for the AI-Radio API path and add fallback/cache.",
        }
    )
    findings.append(
        {
            "signal_id": "azuracast_origin_timeout",
            "status": "CRITICAL" if nowplaying_504 > 500 else "WARNING" if nowplaying_504 else "OK",
            "count": nowplaying_504,
            "explanation": (
                "The nowplaying endpoint on ai-radio dominates timeout detail. "
                + ("No local AzuraCast service/container is visible on Hetzner, so the origin is likely external or proxied elsewhere." if not azuracast_local else "A local AzuraCast signal is visible.")
            ),
            "recommendation": "Inspect the AzuraCast origin path and add a short cache/fallback for nowplaying before changing security controls.",
        }
    )
    findings.append(
        {
            "signal_id": "frontend_polling_too_frequent",
            "status": "WARNING" if (parse_count(summary.get("nowplaying_200")) + nowplaying_504) > 1000 else "WATCH",
            "count": parse_count(summary.get("nowplaying_200")) + nowplaying_504,
            "explanation": "Top-path data shows high request volume against nowplaying plus a separate static nowplaying endpoint.",
            "recommendation": "Increase browser polling interval and prefer the static nowplaying JSON where possible.",
        }
    )
    cache_values = summary.get("cache_behavior", {}).get("nowplaying", [])
    cache_labels = {item.get("cache_status") for item in cache_values if isinstance(item, dict)}
    findings.append(
        {
            "signal_id": "api_no_cache",
            "status": "CRITICAL" if "miss" in cache_labels and nowplaying_504 > 500 else "WARNING",
            "count": nowplaying_504,
            "explanation": "Timeout rows for nowplaying are cache miss shaped. Dynamic 200 rows also indicate origin-facing behavior.",
            "recommendation": "Introduce a 10-30 second cache or stale-while-error fallback for nowplaying/time endpoints outside Cloudflare WAF.",
        }
    )
    findings.append(
        {
            "signal_id": "endpoint_unavailable",
            "status": "WARNING" if api_time_504 > 50 else "WATCH",
            "count": api_time_504,
            "explanation": "/api/time and station/admin endpoints also time out, indicating broader API/origin unavailability during the window.",
            "recommendation": "Serve /api/time statically/cached and keep admin/station endpoints out of public polling paths.",
        }
    )
    findings.append(
        {
            "signal_id": "unknown",
            "status": "WATCH",
            "count": 0,
            "explanation": "No local AzuraCast logs were read and no remote hosts were probed, so process-level root cause remains unconfirmed.",
            "recommendation": "Next safe step is a read-only healthcheck against the local/proxy target selected by the operator.",
        }
    )
    return findings


def prevention_options(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    nowplaying_504 = parse_count(summary.get("nowplaying_504"))
    api_time_504 = parse_count(summary.get("api_time_504"))
    return [
        {
            "option_id": "A",
            "title": "NowPlaying API clientseitig seltener pollen",
            "priority": "HIGH",
            "risk": "LOW",
            "expected_effect": "Reduziert Origin-Requests sofort, besonders wenn viele Browser/Widgets gleichzeitig pollen.",
            "evidence": f"nowplaying 504={nowplaying_504}, nowplaying 200={parse_count(summary.get('nowplaying_200'))}.",
            "operator_action": "Frontend/Widget-Polling auf 15-30 Sekunden anheben und jitter/backoff bei Fehlern nutzen.",
        },
        {
            "option_id": "B",
            "title": "Kurzer Server-/Edge-Cache fuer NowPlaying",
            "priority": "HIGH",
            "risk": "MEDIUM",
            "expected_effect": "10-30 Sekunden Cache decken hohe Polling-Frequenz ab und verhindern Origin-Kaskaden.",
            "evidence": "Timeouts sind cache-miss geformt; statischer nowplaying-Endpunkt liefert bereits viele 200.",
            "operator_action": "Nginx/App-Microcache oder statische JSON-Aktualisierung planen. Keine Cloudflare-WAF-Regel.",
        },
        {
            "option_id": "C",
            "title": "Fallback-JSON ausliefern, wenn AzuraCast nicht antwortet",
            "priority": "HIGH",
            "risk": "LOW",
            "expected_effect": "Verhindert 504 fuer Nutzer, wenn AzuraCast kurz haengt; liefert stale/last-known state.",
            "evidence": "Cloudflare 504 deutet auf fehlende rechtzeitige Origin-Antwort.",
            "operator_action": "Last-known nowplaying JSON periodisch schreiben und bei Upstream-Timeout ausliefern.",
        },
        {
            "option_id": "D",
            "title": "Healthcheck fuer Radio-Service in Sentinel integrieren",
            "priority": "MEDIUM",
            "risk": "LOW",
            "expected_effect": "Fruehere Diagnose von Radio-Origin-Ausfaellen ohne WAF-Aktionen.",
            "evidence": "Lokaler Hetzner-Check sieht keinen AzuraCast-Service; ein expliziter Healthcheck fehlt.",
            "operator_action": "Read-only Healthcheck gegen operator-bestaetigten lokalen/proxy Zielpfad integrieren.",
        },
        {
            "option_id": "E",
            "title": "/api/time statisch oder gecacht beantworten",
            "priority": "MEDIUM" if api_time_504 < 500 else "HIGH",
            "risk": "LOW",
            "expected_effect": "Entlastet einen einfachen, stark cachebaren API-Pfad.",
            "evidence": f"/api/time 504={api_time_504}.",
            "operator_action": "Zeitantwort clientseitig berechnen oder lokal/statisch mit kurzer TTL ausgeben.",
        },
        {
            "option_id": "F",
            "title": "Keine Cloudflare-WAF-Regel daraus ableiten",
            "priority": "MANDATORY",
            "risk": "LOW",
            "expected_effect": "Verhindert Fehlbehandlung eines Origin-Timeouts als Angriffssignal.",
            "evidence": "SentinelDefense not_covered/actual=false; 504 ist Origin-Verfuegbarkeit, nicht WAF-Traffic.",
            "operator_action": "Cloudflare-Regeln unveraendert lassen.",
        },
    ]


def suggested_prevention(options: List[Dict[str, Any]]) -> str:
    return "B+C: NowPlaying 10-30s Microcache plus stale fallback JSON; A parallel polling interval/backoff reduzieren."


def build_reports(args: argparse.Namespace) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    errors, errors_error, errors_exists = read_json(args.errors_5xx)
    top_paths, top_paths_error, top_paths_exists = read_json(args.top_paths)
    status, status_error, status_exists = read_json(args.status_24h)
    master, master_error, master_exists = read_json(args.master_json)
    defense, defense_error, defense_exists = read_json(args.defense_json)
    microcache_status = read_microcache_status(args.microcache_status_json, args.microcache_status_md)

    summary = summarize_cloudflare(errors, top_paths, status, defense)
    local = collect_local_readonly()
    rolling_window = summarize_rolling_window(defense)
    microcache_remediation = build_microcache_remediation(microcache_status, rolling_window)
    findings = classify_findings(summary, local)
    options = prevention_options(summary)
    top_endpoint = max(
        summary.get("top_5xx_paths", []),
        key=lambda item: parse_count(item.get("count")),
        default={},
    )

    nowplaying_is_driver = (
        top_endpoint.get("host") == AI_RADIO_HOST
        and top_endpoint.get("path") == NOWPLAYING_PATH
        and parse_count(top_endpoint.get("count")) > 0
    )

    prevention_text = suggested_prevention(options)
    if microcache_remediation.get("microcache_deployed"):
        prevention_text = (
            "NowPlaying Microcache is deployed and HIT-confirmed on origin; remaining 504s are evaluated "
            "through the 24h rolling window. Next action: observe 24h, not a new WAF rule."
        )

    diagnosis = {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "status": "CRITICAL" if summary.get("total_504", 0) > 1000 else "WARNING",
        "safe_to_auto_apply": False,
        "requires_operator_review": True,
        "cloudflare_mutation": False,
        "productive_change": False,
        "nowplaying_is_primary_driver": nowplaying_is_driver,
        "top_timeout_endpoint": top_endpoint,
        "suggested_prevention": prevention_text,
        "microcache_remediation": microcache_remediation,
        "rolling_window_status": rolling_window,
        "next_action": microcache_remediation.get("next_action"),
        "classification": findings,
        "cloudflare_summary": summary,
        "local_readonly": local,
        "input_sources": {
            "errors_5xx": {"path": str(args.errors_5xx), "exists": errors_exists, "error": errors_error},
            "top_paths": {"path": str(args.top_paths), "exists": top_paths_exists, "error": top_paths_error},
            "status_24h": {"path": str(args.status_24h), "exists": status_exists, "error": status_error},
            "master_json": {"path": str(args.master_json), "exists": master_exists, "error": master_error},
            "defense_json": {"path": str(args.defense_json), "exists": defense_exists, "error": defense_error},
            "microcache_status_json": {
                "path": str(args.microcache_status_json),
                "exists": args.microcache_status_json.exists(),
                "error": microcache_status.get("json_error"),
            },
            "microcache_status_md": {
                "path": str(args.microcache_status_md),
                "exists": args.microcache_status_md.exists(),
                "error": None,
            },
        },
        "master_context": {
            "overall_master_status": master.get("overall_master_status"),
            "action_status": master.get("action_status"),
            "website_status": master.get("website_status"),
            "website_correlation_status": master.get("website_correlation_status"),
        },
        "boundaries": {
            "cloudflare_changes": False,
            "waf_rules": False,
            "apply_safe": False,
            "secrets_read": False,
            "env_files_opened": False,
            "external_scans": False,
            "service_restarts": False,
        },
        "outputs": {
            "markdown": str(args.out_md),
            "json": str(args.out_json),
            "prevention_plan_markdown": str(args.plan_md),
            "prevention_plan_json": str(args.plan_json),
        },
    }

    plan = {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "status": "READY_FOR_OPERATOR_REVIEW",
        "safe_to_auto_apply": False,
        "requires_operator_review": True,
        "cloudflare_mutation": False,
        "productive_change": False,
        "top_timeout_endpoint": top_endpoint,
        "nowplaying_is_primary_driver": nowplaying_is_driver,
        "suggested_prevention": prevention_text,
        "microcache_remediation": microcache_remediation,
        "rolling_window_status": rolling_window,
        "prevention_options": options,
        "recommended_next_step": {
            "step_id": "observe-microcache-rolling-window" if microcache_remediation.get("microcache_deployed") else "prevention-microcache-fallback-design",
            "description": (
                "NowPlaying Microcache ist deployed und HIT-confirmed; 24h-Rolling-Window weiter beobachten, keine neue WAF-Regel."
                if microcache_remediation.get("microcache_deployed")
                else "Operator bestaetigt den AI-Radio-Origin/Proxy-Pfad; danach kleiner, reversibler Plan fuer 10-30s NowPlaying-Cache plus stale fallback JSON."
            ),
            "requires_approval": True,
            "cloudflare_change": False,
            "productive_change": False,
        },
        "rollback_ready": "No change performed; rollback not required for this preflight.",
        "boundaries": diagnosis["boundaries"],
        "outputs": {
            "markdown": str(args.plan_md),
            "json": str(args.plan_json),
        },
    }
    return diagnosis, plan


def md_count_items(items: Any, key: str, limit: int = 6) -> str:
    if not isinstance(items, list) or not items:
        return "-"
    parts = []
    for item in items[:limit]:
        if isinstance(item, dict):
            parts.append(f"{safe_text(item.get(key))}: {safe_text(item.get('count'), '0')}")
    return ", ".join(parts) if parts else "-"


def render_diagnosis(report: Dict[str, Any]) -> str:
    summary = report["cloudflare_summary"]
    top = report.get("top_timeout_endpoint") if isinstance(report.get("top_timeout_endpoint"), dict) else {}
    remediation = report.get("microcache_remediation") if isinstance(report.get("microcache_remediation"), dict) else {}
    rolling = report.get("rolling_window_status") if isinstance(report.get("rolling_window_status"), dict) else {}
    lines = [
        "# AI-Radio API Timeout Diagnosis",
        "",
        f"**Generated:** `{safe_text(report.get('generated_at_utc'))}` UTC",
        "",
        "## Summary",
        "",
        f"- Status: `{safe_text(report.get('status'))}`",
        f"- Website Status: `{safe_text(report.get('master_context', {}).get('website_status'))}`",
        f"- 504 total: `{safe_text(summary.get('total_504'))}`",
        f"- likely_cloudflare_timeout: `{safe_text(summary.get('likely_cloudflare_timeout'))}`",
        f"- Top timeout endpoint: `{safe_text(top.get('host'))}{safe_text(top.get('path'))}` (`{safe_text(top.get('count'))}`)",
        f"- /api/nowplaying primary driver: `{str(bool(report.get('nowplaying_is_primary_driver'))).lower()}`",
        f"- /api/nowplaying 504 share: `{safe_text(summary.get('nowplaying_504_share_percent'))}%`",
        f"- ai-radio host 5xx share: `{safe_text(summary.get('ai_radio_5xx_share_percent'))}%`",
        f"- Microcache deployed: `{str(bool(remediation.get('microcache_deployed'))).lower()}`",
        f"- Local validation: `{safe_text(remediation.get('local_validation'))}`",
        f"- Latest 5xx delta: `{safe_text(rolling.get('latest_5xx_delta'))}`",
        f"- Stable minutes: `{safe_text(rolling.get('stable_minutes'))}`",
        f"- Suggested prevention: {safe_text(report.get('suggested_prevention'))}",
        f"- Next action: {safe_text(report.get('next_action'))}",
        f"- Safe to auto apply: `{str(bool(report.get('safe_to_auto_apply'))).lower()}`",
        f"- Requires operator review: `{str(bool(report.get('requires_operator_review'))).lower()}`",
        "",
        "## Microcache Remediation",
        "",
        f"- Status note: {safe_text(remediation.get('status_note'))}",
        f"- Deployed host: `{safe_text(remediation.get('deployed_on_host'))}`",
        f"- Origin IP: `{safe_text(remediation.get('origin_ip'))}`",
        f"- Endpoint: `{safe_text(remediation.get('endpoint'))}`",
        f"- Cache header: `{safe_text(remediation.get('cache_header'))}`",
        f"- Nginx cache TTL seconds: `{safe_text(remediation.get('nginx_cache_ttl_seconds'))}`",
        f"- Stale on error: `{str(bool(remediation.get('stale_on_error'))).lower()}`",
        f"- Cloudflare change: `{str(bool(remediation.get('cloudflare_change'))).lower()}`",
        f"- WAF change: `{str(bool(remediation.get('waf_change'))).lower()}`",
        f"- Expected effect: {safe_text(remediation.get('expected_effect'))}",
        f"- Rolling-window note: {safe_text(remediation.get('rolling_window_remainder_hint'))}",
        "",
        "## Rolling-Window Context",
        "",
        f"- Present: `{str(bool(rolling.get('present'))).lower()}`",
        f"- Status: `{safe_text(rolling.get('status'))}`",
        f"- Interpretation: {safe_text(rolling.get('interpretation'))}",
        f"- Latest 5xx delta: `{safe_text(rolling.get('latest_5xx_delta'))}`",
        f"- Low growth limit: `{safe_text(rolling.get('low_growth_limit'))}`",
        f"- Latest 5xx delta low: `{str(bool(rolling.get('latest_5xx_delta_low'))).lower()}`",
        f"- Stable minutes: `{safe_text(rolling.get('stable_minutes'))}`",
        f"- Remaining stable minutes for old window: `{safe_text(rolling.get('remaining_stable_minutes_for_old_window'))}`",
        "",
        "## Top 5xx Paths",
        "",
        "| Count | Host | Path | Status | Cache | Countries |",
        "|---:|---|---|---|---|---|",
    ]
    for item in summary.get("top_5xx_paths", [])[:10]:
        lines.append(
            f"| {safe_text(item.get('count'))} | `{safe_text(item.get('host'))}` | "
            f"`{safe_text(item.get('path'))}` | {md_count_items(item.get('statuses'), 'status')} | "
            f"{md_count_items(item.get('cache_status'), 'cache_status')} | "
            f"{md_count_items(item.get('countries'), 'country')} |"
        )

    lines.extend(
        [
            "",
            "## Classification",
            "",
            "| Signal | Status | Count | Explanation | Recommendation |",
            "|---|---|---:|---|---|",
        ]
    )
    for finding in report.get("classification", []):
        lines.append(
            f"| `{safe_text(finding.get('signal_id'))}` | `{safe_text(finding.get('status'))}` | "
            f"{safe_text(finding.get('count'))} | {safe_text(finding.get('explanation')).replace('|', '\\|')} | "
            f"{safe_text(finding.get('recommendation')).replace('|', '\\|')} |"
        )

    local = report.get("local_readonly") if isinstance(report.get("local_readonly"), dict) else {}
    lines.extend(
        [
            "",
            "## Local Read-Only Signals",
            "",
            f"- Docker ps readable: `{str(bool(local.get('docker_ps_ok'))).lower()}`",
            f"- Logs collected: `{str(bool(local.get('logs_collected'))).lower()}`",
            "",
            "### Containers",
            "",
            "| Name | Image | Status | Ports |",
            "|---|---|---|---|",
        ]
    )
    for container in local.get("containers", [])[:12]:
        lines.append(
            f"| `{safe_text(container.get('name'))}` | `{safe_text(container.get('image'))}` | "
            f"`{safe_text(container.get('status'))}` | {safe_text(container.get('ports')).replace('|', '\\|')} |"
        )

    lines.extend(["", "### Key Services", "", "| Unit | Load | Active | Sub | MainPID |", "|---|---|---|---|---:|"])
    units = local.get("systemd_units") if isinstance(local.get("systemd_units"), dict) else {}
    for unit, detail in units.items():
        props = detail.get("properties") if isinstance(detail, dict) else {}
        if not isinstance(props, dict):
            props = {}
        lines.append(
            f"| `{safe_text(unit)}` | `{safe_text(props.get('LoadState'))}` | "
            f"`{safe_text(props.get('ActiveState'))}` | `{safe_text(props.get('SubState'))}` | "
            f"{safe_text(props.get('MainPID'))} |"
        )

    lines.extend(["", "### Local Listening Ports", "", "| Net | State | Local | Process Hint |", "|---|---|---|---|"])
    for port in local.get("listening_ports", [])[:20]:
        if not isinstance(port, dict):
            continue
        lines.append(
            f"| `{safe_text(port.get('netid'))}` | `{safe_text(port.get('state'))}` | "
            f"`{safe_text(port.get('local'))}` | {safe_text(port.get('process_hint')).replace('|', '\\|')} |"
        )

    lines.extend(
        [
            "",
            "## Boundaries",
            "",
            "- Keine Cloudflare-Aenderung.",
            "- Kein apply-safe.",
            "- Keine WAF-Regel.",
            "- Keine Secrets oder .env-Dateien gelesen.",
            "- Keine fremden Hosts gescannt.",
            "- Keine produktive Aenderung.",
            "",
            "## Outputs",
            "",
            f"- Markdown: `{safe_text(report.get('outputs', {}).get('markdown'))}`",
            f"- JSON: `{safe_text(report.get('outputs', {}).get('json'))}`",
            f"- Prevention Plan Markdown: `{safe_text(report.get('outputs', {}).get('prevention_plan_markdown'))}`",
            f"- Prevention Plan JSON: `{safe_text(report.get('outputs', {}).get('prevention_plan_json'))}`",
            "",
        ]
    )
    return "\n".join(lines)


def render_plan(plan: Dict[str, Any]) -> str:
    top = plan.get("top_timeout_endpoint") if isinstance(plan.get("top_timeout_endpoint"), dict) else {}
    remediation = plan.get("microcache_remediation") if isinstance(plan.get("microcache_remediation"), dict) else {}
    rolling = plan.get("rolling_window_status") if isinstance(plan.get("rolling_window_status"), dict) else {}
    lines = [
        "# AI-Radio API Timeout Prevention Plan",
        "",
        f"**Generated:** `{safe_text(plan.get('generated_at_utc'))}` UTC",
        "",
        "## Summary",
        "",
        f"- Status: `{safe_text(plan.get('status'))}`",
        f"- Top timeout endpoint: `{safe_text(top.get('host'))}{safe_text(top.get('path'))}` (`{safe_text(top.get('count'))}`)",
        f"- /api/nowplaying primary driver: `{str(bool(plan.get('nowplaying_is_primary_driver'))).lower()}`",
        f"- Microcache deployed: `{str(bool(remediation.get('microcache_deployed'))).lower()}`",
        f"- Local validation: `{safe_text(remediation.get('local_validation'))}`",
        f"- Latest 5xx delta: `{safe_text(rolling.get('latest_5xx_delta'))}`",
        f"- Suggested prevention: {safe_text(plan.get('suggested_prevention'))}",
        f"- Safe to auto apply: `{str(bool(plan.get('safe_to_auto_apply'))).lower()}`",
        f"- Requires operator review: `{str(bool(plan.get('requires_operator_review'))).lower()}`",
        "",
        "## Prevention Options",
        "",
        "| Option | Priority | Risk | Expected Effect | Operator Action |",
        "|---|---|---|---|---|",
    ]
    for item in plan.get("prevention_options", []):
        lines.append(
            f"| {safe_text(item.get('option_id'))}: {safe_text(item.get('title'))} | "
            f"`{safe_text(item.get('priority'))}` | `{safe_text(item.get('risk'))}` | "
            f"{safe_text(item.get('expected_effect')).replace('|', '\\|')} | "
            f"{safe_text(item.get('operator_action')).replace('|', '\\|')} |"
        )

    step = plan.get("recommended_next_step") if isinstance(plan.get("recommended_next_step"), dict) else {}
    lines.extend(
        [
            "",
            "## Recommended Next Safe Step",
            "",
            f"- Step: `{safe_text(step.get('step_id'))}`",
            f"- Description: {safe_text(step.get('description'))}",
            f"- Requires approval: `{str(bool(step.get('requires_approval'))).lower()}`",
            f"- Cloudflare change: `{str(bool(step.get('cloudflare_change'))).lower()}`",
            f"- Productive change now: `{str(bool(step.get('productive_change'))).lower()}`",
            "",
            "## Non-Goals",
            "",
            "- Keine Cloudflare-WAF-Regel.",
            "- Keine Bot-Fight-/Challenge-Aenderung.",
            "- Keine Service-Neustarts.",
            "- Keine Secrets oder .env-Zugriffe.",
            "",
            "## Rollback",
            "",
            f"- {safe_text(plan.get('rollback_ready'))}",
            "",
        ]
    )
    return "\n".join(lines)


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Diagnose AI-Radio API 504 timeouts without mutations.")
    parser.add_argument("--errors-5xx", type=Path, default=DEFAULT_ERRORS_5XX)
    parser.add_argument("--top-paths", type=Path, default=DEFAULT_TOP_PATHS)
    parser.add_argument("--status-24h", type=Path, default=DEFAULT_STATUS_24H)
    parser.add_argument("--master-json", type=Path, default=DEFAULT_MASTER_JSON)
    parser.add_argument("--defense-json", type=Path, default=DEFAULT_DEFENSE_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--plan-md", type=Path, default=DEFAULT_PLAN_MD)
    parser.add_argument("--plan-json", type=Path, default=DEFAULT_PLAN_JSON)
    parser.add_argument("--microcache-status-md", type=Path, default=DEFAULT_MICROCACHE_STATUS_MD)
    parser.add_argument("--microcache-status-json", type=Path, default=DEFAULT_MICROCACHE_STATUS_JSON)
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    diagnosis, plan = build_reports(args)
    write_json_atomic(args.out_json, diagnosis)
    write_text_atomic(args.out_md, render_diagnosis(diagnosis))
    write_json_atomic(args.plan_json, plan)
    write_text_atomic(args.plan_md, render_plan(plan))
    top = diagnosis.get("top_timeout_endpoint") if isinstance(diagnosis.get("top_timeout_endpoint"), dict) else {}
    print(
        "AI-Radio timeout diagnosis written: "
        f"{args.out_md} (top={top.get('path')}, count={top.get('count')})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
