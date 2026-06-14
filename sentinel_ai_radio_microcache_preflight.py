#!/usr/bin/env python3
"""Read-only preflight for AI-Radio NowPlaying microcache prevention."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path("/srv/sentinel-defense")
REPORT_MD = BASE_DIR / "reports/latest/ai-radio-nowplaying-microcache-preflight.md"
REPORT_JSON = BASE_DIR / "reports/latest/ai-radio-nowplaying-microcache-preflight.json"
DIAGNOSIS_JSON = BASE_DIR / "reports/latest/ai-radio-api-timeout-diagnosis.json"
PREVENTION_JSON = BASE_DIR / "reports/latest/ai-radio-api-timeout-prevention-plan.json"
DRAFT_DIR = BASE_DIR / "drafts/ai-radio-nowplaying-cache"

AI_RADIO_HOST = "ai-radio.electri-c-ity-studios-24-7.com"
NOWPLAYING_PATH = "/api/nowplaying/electri-city-ai-electro-radio"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def nginx_candidate_files() -> list[Path]:
    roots = [
        Path("/etc/nginx/nginx.conf"),
        Path("/etc/nginx/sites-available"),
        Path("/etc/nginx/sites-enabled"),
        Path("/etc/nginx/snippets"),
    ]
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(p for p in root.rglob("*") if p.is_file())
    return sorted(set(files))


def inspect_nginx() -> dict:
    evidence = []
    ai_radio_mentions = []
    proxy_passes = []
    files_seen = []
    for path in nginx_candidate_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files_seen.append(str(path))
        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            line = " ".join(raw_line.strip().split())
            if not line or line.startswith("#"):
                continue
            interesting = (
                "server_name" in line
                or "proxy_pass" in line
                or AI_RADIO_HOST in line
                or "nowplaying" in line.lower()
                or "azura" in line.lower()
            )
            if not interesting:
                continue
            item = {"file": str(path), "line": line_no, "directive": line}
            evidence.append(item)
            if AI_RADIO_HOST in line or "nowplaying" in line.lower() or "azura" in line.lower():
                ai_radio_mentions.append(item)
            if "proxy_pass" in line:
                proxy_passes.append(item)

    ai_radio_server_block_found = any(
        "server_name" in item["directive"] and AI_RADIO_HOST in item["directive"]
        for item in evidence
    )
    visible_soc_proxy_only = bool(proxy_passes) and not ai_radio_server_block_found
    return {
        "files_examined": files_seen,
        "relevant_directives": evidence,
        "ai_radio_mentions": ai_radio_mentions,
        "proxy_passes": proxy_passes,
        "ai_radio_server_block_found": ai_radio_server_block_found,
        "local_nginx_reverse_proxy_confirmed": ai_radio_server_block_found,
        "visible_soc_proxy_only": visible_soc_proxy_only,
        "nowplaying_proxyable": "operator_review_required"
        if not ai_radio_server_block_found
        else "candidate_after_nginx_test",
        "finding": (
            "No visible local Nginx server block for ai-radio host was found."
            if not ai_radio_server_block_found
            else "A visible local Nginx server block for ai-radio host was found."
        ),
    }


def draft_file_status() -> list[dict]:
    expected = [
        "nowplaying_cache_fetcher.py",
        "sentinel-ai-radio-nowplaying-cache.service",
        "sentinel-ai-radio-nowplaying-cache.timer",
        "nginx-ai-radio-nowplaying-cache-snippet.conf",
        "README.md",
    ]
    return [
        {
            "path": str(DRAFT_DIR / name),
            "exists": (DRAFT_DIR / name).exists(),
            "purpose": {
                "nowplaying_cache_fetcher.py": "Fetches origin NowPlaying JSON and atomically writes last-known-good fallback JSON.",
                "sentinel-ai-radio-nowplaying-cache.service": "Draft systemd oneshot service for the fetcher.",
                "sentinel-ai-radio-nowplaying-cache.timer": "Draft systemd timer for short interval refresh.",
                "nginx-ai-radio-nowplaying-cache-snippet.conf": "Draft Nginx exact-path microcache and stale fallback pattern.",
                "README.md": "Operator deploy, validation, and rollback notes.",
            }[name],
        }
        for name in expected
    ]


def build_architectures() -> list[dict]:
    return [
        {
            "variant": "A",
            "title": "Nginx proxy_cache with 10-30s TTL",
            "security_risk": "medium",
            "maintainability": "medium",
            "rollback": "restore Nginx vhost backup and reload after nginx -t",
            "frontend_impact": "transparent if exact NowPlaying path is preserved",
            "cloudflare_504_impact": "high if this host is actually local Nginx and origin timeouts are cacheable",
            "systemd_timer_needed": False,
            "readiness": "blocked_until_ai_radio_vhost_and_upstream_are_confirmed",
        },
        {
            "variant": "B",
            "title": "Python/CLI fetcher writes latest-nowplaying.json every 15s",
            "security_risk": "low",
            "maintainability": "high",
            "rollback": "disable timer and remove generated JSON after review",
            "frontend_impact": "requires frontend or Nginx endpoint switch to fallback JSON",
            "cloudflare_504_impact": "medium to high if traffic can be routed to cached JSON on failures",
            "systemd_timer_needed": True,
            "readiness": "draft_ready_operator_source_url_required",
        },
        {
            "variant": "C",
            "title": "Hybrid: Nginx tries origin, falls back to stale JSON",
            "security_risk": "medium",
            "maintainability": "medium",
            "rollback": "restore Nginx backup, disable timer, keep backup JSON for inspection",
            "frontend_impact": "transparent for clients when exact path is retained",
            "cloudflare_504_impact": "highest, because stale JSON avoids 504 during short AzuraCast stalls",
            "systemd_timer_needed": True,
            "readiness": "recommended_after_operator_confirms_origin_and_vhost",
        },
    ]


def build_report() -> dict:
    diagnosis = load_json(DIAGNOSIS_JSON)
    prevention = load_json(PREVENTION_JSON)
    nginx = inspect_nginx()
    top_endpoint = diagnosis.get("top_timeout_endpoint", {})
    cloudflare_summary = diagnosis.get("cloudflare_summary", {})

    gates = [
        {
            "gate": "cloudflare_mutation_absent",
            "passed": True,
            "evidence": "This preflight does not call Cloudflare APIs and writes only reports/drafts.",
        },
        {
            "gate": "no_productive_config_write",
            "passed": True,
            "evidence": "No writes to /etc/nginx or /etc/systemd/system are performed.",
        },
        {
            "gate": "ai_radio_local_nginx_confirmed",
            "passed": nginx["local_nginx_reverse_proxy_confirmed"],
            "evidence": nginx["finding"],
        },
        {
            "gate": "operator_origin_required",
            "passed": False,
            "evidence": "The concrete AzuraCast/local upstream is not visible from read-only local checks.",
        },
        {
            "gate": "exact_path_scope",
            "passed": True,
            "evidence": f"Draft Nginx scope is exact path {NOWPLAYING_PATH}, not a broad /api rule.",
        },
    ]

    return {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "status": "READY_FOR_OPERATOR_REVIEW",
        "productive_change": False,
        "cloudflare_mutation": False,
        "safe_to_auto_apply": False,
        "requires_operator_review": True,
        "top_timeout_endpoint": top_endpoint,
        "nowplaying_is_primary_driver": diagnosis.get("nowplaying_is_primary_driver", False),
        "nowplaying_504_count": cloudflare_summary.get("nowplaying_504"),
        "nowplaying_504_share_percent": cloudflare_summary.get("nowplaying_504_share_percent"),
        "ai_radio_5xx_share_percent": cloudflare_summary.get("ai_radio_5xx_share_percent"),
        "recommended_prevention": diagnosis.get(
            "suggested_prevention",
            "B+C: NowPlaying microcache plus stale fallback JSON.",
        ),
        "prevention_context": prevention.get("recommended_next_step", {}),
        "read_only_nginx_assessment": nginx,
        "cache_path_options": [
            {
                "path": "/var/cache/sentinel-ai-radio/",
                "assessment": "good runtime cache path, but likely needs root-owned setup during approved deploy",
                "selected_for_draft": False,
            },
            {
                "path": "/srv/sentinel-defense/cache/ai-radio/",
                "assessment": "project-local, easy backup/rollback, suitable for first approved apply-safe",
                "selected_for_draft": True,
            },
        ],
        "static_fallback_json_endpoint_possible": "yes_after_nginx_vhost_confirmed",
        "python_fetcher_preferred_first": True,
        "architectures": build_architectures(),
        "preflight_safety_gates": gates,
        "draft_files": draft_file_status(),
        "deploy_plan_later": [
            "Confirm the real AI-Radio origin/upstream and whether this Hetzner Nginx serves ai-radio host.",
            "Back up the relevant Nginx vhost before any approved edit.",
            "Create the project-local cache directory with deploy-readable permissions.",
            "Run the Python fetcher manually against the confirmed source URL and verify JSON output.",
            "Install the systemd service/timer only after review; do not use secrets.",
            "Add an exact-path Nginx microcache/fallback snippet, run nginx -t, then reload Nginx only after approval.",
            "Validate the public endpoint, response headers, and Sentinel 5xx metrics.",
            "Observe for 24h before considering the issue closed.",
        ],
        "rollback_plan_later": [
            "Restore the Nginx vhost backup and run nginx -t before reload.",
            "Disable and stop the draft cache timer/service if installed later.",
            "Leave generated JSON files for forensic review or remove after backup.",
            "No Cloudflare rollback is needed because this plan does not change Cloudflare.",
        ],
        "operating_sequence": [
            "problem_erkennen",
            "ursache_isolieren",
            "microcache_planen",
            "spaeter_apply_safe_mit_backup",
            "validieren",
            "24h_beobachten",
        ],
    }


def md_bool(value: object) -> str:
    return "true" if value else "false"


def render_markdown(data: dict) -> str:
    top = data.get("top_timeout_endpoint", {})
    nginx = data.get("read_only_nginx_assessment", {})
    lines = [
        "# AI-Radio NowPlaying Microcache Preflight",
        "",
        "## Summary",
        "",
        f"- Status: {data['status']}",
        f"- Productive Change: {md_bool(data['productive_change'])}",
        f"- Cloudflare Mutation: {md_bool(data['cloudflare_mutation'])}",
        f"- Safe To Auto Apply: {md_bool(data['safe_to_auto_apply'])}",
        f"- Requires Operator Review: {md_bool(data['requires_operator_review'])}",
        f"- Top Timeout Endpoint: {top.get('host', 'UNKNOWN')}{top.get('path', '')}",
        f"- NowPlaying 504 Count: {data.get('nowplaying_504_count', 'UNKNOWN')}",
        f"- NowPlaying 504 Share: {data.get('nowplaying_504_share_percent', 'UNKNOWN')}%",
        f"- AI-Radio Host 5xx Share: {data.get('ai_radio_5xx_share_percent', 'UNKNOWN')}%",
        f"- Recommended Prevention: {data['recommended_prevention']}",
        "",
        "## Read-Only Nginx Assessment",
        "",
        f"- Local Nginx Reverse Proxy Confirmed: {md_bool(nginx.get('local_nginx_reverse_proxy_confirmed'))}",
        f"- AI-Radio Server Block Found: {md_bool(nginx.get('ai_radio_server_block_found'))}",
        f"- NowPlaying Proxyable: {nginx.get('nowplaying_proxyable', 'UNKNOWN')}",
        f"- Finding: {nginx.get('finding', 'UNKNOWN')}",
        "",
        "| File | Line | Directive |",
        "| --- | ---: | --- |",
    ]
    directives = nginx.get("relevant_directives", [])[:20]
    if directives:
        for item in directives:
            directive = str(item.get("directive", "")).replace("|", "\\|")
            lines.append(f"| `{item.get('file')}` | {item.get('line')} | `{directive}` |")
    else:
        lines.append("| none | 0 | no relevant directives found |")

    lines.extend(
        [
            "",
            "## Architecture Options",
            "",
            "| Variante | Titel | Risiko | Wartbarkeit | Cloudflare-504-Auswirkung | Timer | Readiness |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in data["architectures"]:
        lines.append(
            "| {variant} | {title} | {security_risk} | {maintainability} | {cloudflare_504_impact} | {timer} | {readiness} |".format(
                variant=item["variant"],
                title=item["title"],
                security_risk=item["security_risk"],
                maintainability=item["maintainability"],
                cloudflare_504_impact=item["cloudflare_504_impact"],
                timer=md_bool(item["systemd_timer_needed"]),
                readiness=item["readiness"],
            )
        )

    lines.extend(
        [
            "",
            "## Safety Gates",
            "",
            "| Gate | Passed | Evidence |",
            "| --- | --- | --- |",
        ]
    )
    for gate in data["preflight_safety_gates"]:
        evidence = gate["evidence"].replace("|", "\\|")
        lines.append(f"| {gate['gate']} | {md_bool(gate['passed'])} | {evidence} |")

    lines.extend(
        [
            "",
            "## Draft Files",
            "",
            "| Path | Exists | Purpose |",
            "| --- | --- | --- |",
        ]
    )
    for item in data["draft_files"]:
        lines.append(f"| `{item['path']}` | {md_bool(item['exists'])} | {item['purpose']} |")

    lines.extend(
        [
            "",
            "## Later Apply-Safe Outline",
            "",
        ]
    )
    for step in data["deploy_plan_later"]:
        lines.append(f"- {step}")

    lines.extend(
        [
            "",
            "## Rollback Outline",
            "",
        ]
    )
    for step in data["rollback_plan_later"]:
        lines.append(f"- {step}")

    lines.extend(
        [
            "",
            "## Operating Sequence",
            "",
            "Problem erkennen -> Ursache isolieren -> Microcache planen -> spaeter apply-safe mit Backup -> validieren -> 24h beobachten.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    data = build_report()
    write_json(REPORT_JSON, data)
    REPORT_MD.write_text(render_markdown(data), encoding="utf-8")
    print(f"Wrote {REPORT_MD}")
    print(f"Wrote {REPORT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
