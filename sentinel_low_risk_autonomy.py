#!/usr/bin/env python3
import argparse
import datetime as dt
import html as html_lib
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

SITE_URL = "https://electri-c-ity-studios-24-7.com/"
KNOWN_SOC_ISSUE = "KNOWN_ISSUE_HIGH_RISK_FSE_SOC_SOURCE"

STATUS_OK = "LOW_RISK_AUTONOMY_OK"
STATUS_WARN = "LOW_RISK_AUTONOMY_WARNINGS"
STATUS_CRIT = "LOW_RISK_AUTONOMY_CRITICAL_KNOWN_ISSUES"
STATUS_FAIL = "LOW_RISK_AUTONOMY_FAILED"
STATUS_BLOCK = "LOW_RISK_AUTONOMY_BLOCKED_BY_SAFETY"

ALLOWED_WRITE_ROOTS = [
    "reports/latest",
    "snapshots",
    "audit",
    "state/low-risk-autonomy",
    "playbooks",
]

SCHEMA_TYPES = [
    "Organization",
    "WebSite",
    "RadioStation",
    "MusicGroup",
    "WebPage",
    "CollectionPage",
]

SOC_MARKERS = [
    "soc-schema-graph",
    "data-soc-schema",
    "#soc-entity",
]

COMMANDS = {
    "self-test",
    "run-once",
    "status",
    "draft-actions",
    "write-playbook",
}


def utc_ts():
    return dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")


def iso_now():
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_dirs():
    for root in ALLOWED_WRITE_ROOTS:
        Path(root).mkdir(parents=True, exist_ok=True)


def clamp(value):
    return max(0, min(100, int(round(value))))


def safe_write_text(path, text):
    p = Path(path)
    allowed = False
    for root in ALLOWED_WRITE_ROOTS:
        try:
            p.resolve().relative_to(Path(root).resolve())
            allowed = True
            break
        except Exception:
            continue
    if not allowed:
        raise RuntimeError(f"blocked write outside allowed roots: {path}")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def safe_append_text(path, text):
    p = Path(path)
    allowed = False
    for root in ALLOWED_WRITE_ROOTS:
        try:
            p.resolve().relative_to(Path(root).resolve())
            allowed = True
            break
        except Exception:
            continue
    if not allowed:
        raise RuntimeError(f"blocked append outside allowed roots: {path}")
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(text)


def redact(text):
    if text is None:
        return text
    text = str(text)
    patterns = [
        r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[^'\"\s]+",
        r"sk-[A-Za-z0-9_\-]{20,}",
        r"AIza[0-9A-Za-z_\-]{20,}",
    ]
    for pat in patterns:
        text = re.sub(pat, r"\1=REDACTED", text)
    return text


def fetch(url, timeout=25):
    start = time.perf_counter()
    result = {
        "url": url,
        "http_status": None,
        "headers": {},
        "body": "",
        "elapsed_ms": None,
        "size_bytes": 0,
        "error": None,
    }
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SentinelLowRiskAutonomy/1.0",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            result["http_status"] = r.status
            result["headers"] = dict(r.headers.items())
            result["body"] = body.decode("utf-8", errors="replace")
            result["size_bytes"] = len(body)
    except Exception as e:
        result["error"] = redact(str(e))
    finally:
        result["elapsed_ms"] = int((time.perf_counter() - start) * 1000)
    return result


def first_match(pattern, text, flags=re.I | re.S):
    m = re.search(pattern, text or "", flags)
    return html_lib.unescape(m.group(1).strip()) if m else ""


def all_matches(pattern, text, flags=re.I | re.S):
    return [html_lib.unescape(x.strip()) for x in re.findall(pattern, text or "", flags)]


def tag_attr(tag, attr):
    return first_match(r'\b' + re.escape(attr) + r'\s*=\s*["\']([^"\']*)["\']', tag)


def find_meta(html, key, value):
    tags = re.findall(r"<meta\b[^>]*>", html or "", re.I | re.S)
    for tag in tags:
        attr_val = tag_attr(tag, key)
        if attr_val.lower() == value.lower():
            return tag_attr(tag, "content")
    return ""


def find_link(html, rel_value):
    tags = re.findall(r"<link\b[^>]*>", html or "", re.I | re.S)
    for tag in tags:
        rel = tag_attr(tag, "rel")
        if rel.lower() == rel_value.lower():
            return tag_attr(tag, "href")
    return ""


def extract_jsonld_blocks(html):
    pattern = r'<script\b[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>'
    return re.findall(pattern, html or "", re.I | re.S)


def collect_types_from_json(obj, out):
    if isinstance(obj, dict):
        t = obj.get("@type")
        if isinstance(t, str):
            out.append(t)
        elif isinstance(t, list):
            out.extend([x for x in t if isinstance(x, str)])
        for v in obj.values():
            collect_types_from_json(v, out)
    elif isinstance(obj, list):
        for x in obj:
            collect_types_from_json(x, out)


def schema_type_counts(blocks):
    types = []
    for block in blocks:
        try:
            data = json.loads(block)
            collect_types_from_json(data, types)
        except Exception:
            for t in SCHEMA_TYPES:
                if re.search(r'"@type"\s*:\s*"' + re.escape(t) + r'"', block):
                    types.append(t)
    return {t: types.count(t) for t in SCHEMA_TYPES}


def analyze_home(fetch_result):
    html = fetch_result.get("body", "")
    headers = fetch_result.get("headers", {})
    jsonld = extract_jsonld_blocks(html)
    schema_counts = schema_type_counts(jsonld)

    scripts = re.findall(r"<script\b[^>]*>", html, re.I)
    stylesheets = re.findall(r'<link\b[^>]*rel=["\'][^"\']*stylesheet[^"\']*["\'][^>]*>', html, re.I)
    images = re.findall(r"<img\b[^>]*>", html, re.I)
    inline_scripts = re.findall(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.I | re.S)

    external_hosts = set()
    for attr in re.findall(r'\b(?:src|href)=["\'](https?://[^"\']+)["\']', html, re.I):
        try:
            external_hosts.add(urlparse(attr).netloc.lower())
        except Exception:
            pass

    title = first_match(r"<title[^>]*>(.*?)</title>", html)
    h1s = all_matches(r"<h1\b[^>]*>(.*?)</h1>", html)
    h1_texts = [re.sub("<[^>]+>", "", h).strip() for h in h1s]

    soc_present = {m: (m.lower() in html.lower()) for m in SOC_MARKERS}

    return {
        "http_status": fetch_result.get("http_status"),
        "ttfb_ms": fetch_result.get("elapsed_ms"),
        "response_size_bytes": fetch_result.get("size_bytes"),
        "html_size_bytes": len(html.encode("utf-8", errors="replace")),
        "title": title,
        "title_length": len(title),
        "meta_description": find_meta(html, "name", "description"),
        "meta_description_length": len(find_meta(html, "name", "description")),
        "canonical": find_link(html, "canonical"),
        "robots_meta": find_meta(html, "name", "robots"),
        "h1_count": len(h1_texts),
        "h1_texts": h1_texts[:5],
        "open_graph": {
            "title": find_meta(html, "property", "og:title"),
            "description": find_meta(html, "property", "og:description"),
            "image": find_meta(html, "property", "og:image"),
        },
        "twitter": {
            "card": find_meta(html, "name", "twitter:card"),
            "title": find_meta(html, "name", "twitter:title"),
            "description": find_meta(html, "name", "twitter:description"),
            "image": find_meta(html, "name", "twitter:image"),
        },
        "jsonld_script_count": len(jsonld),
        "schema_type_counts": schema_counts,
        "duplicate_schema_types": {k: v for k, v in schema_counts.items() if v > 1},
        "soc_watch": soc_present,
        "headers_subset": {
            k: v for k, v in headers.items()
            if k.lower() in {
                "cache-control",
                "cf-cache-status",
                "content-encoding",
                "content-length",
                "server",
                "x-cache",
                "x-litespeed-cache",
            }
        },
        "script_tag_count": len(scripts),
        "stylesheet_count": len(stylesheets),
        "image_count": len(images),
        "lazy_image_count": len([i for i in images if "loading=" in i.lower() and "lazy" in i.lower()]),
        "webp_hint_count": len(re.findall(r"\.webp\b|image/webp", html, re.I)),
        "large_inline_script_count": len([s for s in inline_scripts if len(s) > 5000]),
        "external_resource_host_count": len(external_hosts),
        "external_resource_hosts_sample": sorted(external_hosts)[:20],
    }


def endpoint_status(path):
    r = fetch(SITE_URL.rstrip("/") + path)
    return {
        "url": r["url"],
        "http_status": r["http_status"],
        "elapsed_ms": r["elapsed_ms"],
        "size_bytes": r["size_bytes"],
        "error": r["error"],
    }


def build_warnings(analysis, endpoints):
    warnings = []
    known = []

    if analysis["http_status"] != 200:
        warnings.append(f"homepage_http_status_{analysis['http_status']}")
    if not analysis["title"]:
        warnings.append("missing_title")
    elif analysis["title_length"] > 65:
        warnings.append("title_may_be_too_long")
    if not analysis["meta_description"]:
        warnings.append("missing_meta_description")
    elif not (70 <= analysis["meta_description_length"] <= 170):
        warnings.append("meta_description_length_review")
    if not analysis["canonical"]:
        warnings.append("missing_canonical")
    if analysis["h1_count"] != 1:
        warnings.append(f"h1_count_review_{analysis['h1_count']}")
    if not analysis["open_graph"]["title"] or not analysis["open_graph"]["description"]:
        warnings.append("open_graph_incomplete")
    if not analysis["twitter"]["card"]:
        warnings.append("twitter_card_missing")
    if analysis["duplicate_schema_types"]:
        warnings.append("duplicate_schema_types_present")
    if any(analysis["soc_watch"].values()):
        known.append(KNOWN_SOC_ISSUE)
        warnings.append("soc_schema_known_high_risk_source_visible")
    for name, data in endpoints.items():
        if data["http_status"] not in (200, 301, 302):
            warnings.append(f"{name}_not_ok_{data['http_status']}")
    if analysis["html_size_bytes"] > 250000:
        warnings.append("html_size_large")
    if analysis["script_tag_count"] > 60:
        warnings.append("many_script_tags")
    if analysis["image_count"] > 0 and analysis["lazy_image_count"] < max(1, analysis["image_count"] // 3):
        warnings.append("lazy_loading_review")
    if not analysis["headers_subset"].get("Cache-Control"):
        warnings.append("cache_control_missing")

    return warnings, known


def score_all(analysis, warnings, known):
    seo = 100
    perf = 100
    schema = 100
    safety = 100

    for w in warnings:
        if w.startswith(("missing_title", "title_", "missing_meta", "meta_", "missing_canonical", "h1_", "open_graph", "twitter", "robots", "sitemap")):
            seo -= 8
        if w in ("html_size_large", "many_script_tags", "lazy_loading_review", "cache_control_missing"):
            perf -= 8
        if "schema" in w:
            schema -= 15

    if analysis["duplicate_schema_types"]:
        schema -= 10 * len(analysis["duplicate_schema_types"])
    if KNOWN_SOC_ISSUE in known:
        schema -= 25

    if analysis["ttfb_ms"] and analysis["ttfb_ms"] > 2500:
        perf -= 15
    elif analysis["ttfb_ms"] and analysis["ttfb_ms"] > 1200:
        perf -= 8

    # This runner has no apply mode and only local writes.
    safety = 100

    seo = clamp(seo)
    perf = clamp(perf)
    schema = clamp(schema)
    safety = clamp(safety)
    overall = clamp((seo + perf + schema + safety) / 4)

    return {
        "seo_score": seo,
        "performance_basic_score": perf,
        "schema_health_score": schema,
        "autonomy_safety_score": safety,
        "overall_safe_monitor_score": overall,
    }


def build_draft_actions(result):
    actions = []
    for w in result.get("warnings", []):
        if w == "soc_schema_known_high_risk_source_visible":
            actions.append({
                "id": "known-issue:fse-soc-source",
                "risk": "HIGH_RISK_MANUAL_REVIEW_REQUIRED",
                "title": "FSE/Content SOC source manually review",
                "description": "SOC markers are still visible. Monitor only; do not edit DB/FSE automatically.",
            })
        elif w in ("missing_meta_description", "meta_description_length_review"):
            actions.append({
                "id": "seo:meta-description-review",
                "risk": "MEDIUM_REQUIRES_OWNER_APPROVAL",
                "title": "Review meta description",
                "description": "Prepare an editorial meta description update for owner review.",
            })
        elif w.startswith("h1_count"):
            actions.append({
                "id": "seo:h1-review",
                "risk": "MEDIUM_REQUIRES_OWNER_APPROVAL",
                "title": "Review H1 structure",
                "description": "Inspect homepage H1 count manually in WordPress editor.",
            })
        elif w == "duplicate_schema_types_present":
            actions.append({
                "id": "schema:duplicate-review",
                "risk": "HIGH_RISK_MANUAL_REVIEW_REQUIRED",
                "title": "Review duplicate schema source",
                "description": "Schema duplicates require owner review because FSE/content/DB edits are high risk.",
            })
        elif w in ("html_size_large", "many_script_tags", "lazy_loading_review", "cache_control_missing"):
            actions.append({
                "id": "perf:" + w,
                "risk": "MEDIUM_REQUIRES_OWNER_APPROVAL",
                "title": "Performance optimization draft",
                "description": f"Review performance warning: {w}. No automatic change.",
            })

    actions.append({
        "id": "monitor:next-run",
        "risk": "LOW_RISK_AUTO_ALLOWED",
        "title": "Run read-only monitor again",
        "description": "Repeat public SEO/performance checks and append local history.",
    })

    return {
        "timestamp_utc": result.get("timestamp_utc", iso_now()),
        "status": "DRAFT_ACTIONS_READY",
        "actions_count": len(actions),
        "actions": actions,
        "breach": False,
    }


def write_reports(result):
    ensure_dirs()
    ts = result["timestamp"]

    json_text = json.dumps(result, indent=2, ensure_ascii=False)
    safe_write_text("reports/latest/low-risk-autonomy.json", json_text + "\n")
    safe_write_text(f"snapshots/low-risk-autonomy-{ts}.json", json_text + "\n")
    safe_write_text("state/low-risk-autonomy/latest.json", json_text + "\n")
    safe_append_text("state/low-risk-autonomy/history.jsonl", json.dumps(result, ensure_ascii=False) + "\n")
    safe_append_text("audit/low-risk-autonomy.jsonl", json.dumps(result, ensure_ascii=False) + "\n")

    lines = [
        "# Sentinel LOW-RISK Autonomy",
        "",
        f"- timestamp_utc: `{result['timestamp_utc']}`",
        f"- status: `{result['status']}`",
        f"- breach: `{result['breach']}`",
        f"- seo_score: `{result['scores']['seo_score']}`",
        f"- performance_basic_score: `{result['scores']['performance_basic_score']}`",
        f"- schema_health_score: `{result['scores']['schema_health_score']}`",
        f"- autonomy_safety_score: `{result['scores']['autonomy_safety_score']}`",
        f"- overall_safe_monitor_score: `{result['scores']['overall_safe_monitor_score']}`",
        "",
        "## Known Issues",
    ]
    for issue in result["known_issues"]:
        lines.append(f"- `{issue}`")

    lines.extend(["", "## Warnings"])
    for w in result["warnings"]:
        lines.append(f"- `{w}`")

    lines.extend([
        "",
        "## SEO Summary",
        f"- HTTP status: `{result['analysis']['http_status']}`",
        f"- Title length: `{result['analysis']['title_length']}`",
        f"- Meta description length: `{result['analysis']['meta_description_length']}`",
        f"- H1 count: `{result['analysis']['h1_count']}`",
        f"- JSON-LD count: `{result['analysis']['jsonld_script_count']}`",
        f"- Duplicate schema types: `{json.dumps(result['analysis']['duplicate_schema_types'], ensure_ascii=False)}`",
        "",
        "## Performance Summary",
        f"- TTFB ms: `{result['analysis']['ttfb_ms']}`",
        f"- HTML size bytes: `{result['analysis']['html_size_bytes']}`",
        f"- Script tags: `{result['analysis']['script_tag_count']}`",
        f"- Stylesheets: `{result['analysis']['stylesheet_count']}`",
        f"- Images: `{result['analysis']['image_count']}`",
        f"- Lazy images: `{result['analysis']['lazy_image_count']}`",
        f"- WebP hints: `{result['analysis']['webp_hint_count']}`",
        "",
        "## Safety",
        "- Read-only public HTTP checks only.",
        "- No apply mode.",
        "- No SFTP write.",
        "- No database write.",
        "- No cache purge.",
        "- No Cloudflare/Nginx/.htaccess/theme/plugin change.",
    ])
    safe_write_text("reports/latest/low-risk-autonomy.md", "\n".join(lines) + "\n")

    drafts = build_draft_actions(result)
    safe_write_text("reports/latest/low-risk-autonomy-draft-actions.json", json.dumps(drafts, indent=2, ensure_ascii=False) + "\n")
    md = ["# LOW-RISK Autonomy Draft Actions", "", f"- actions_count: `{drafts['actions_count']}`", ""]
    for a in drafts["actions"]:
        md.append(f"- `{a['risk']}` **{a['title']}** — {a['description']}")
    safe_write_text("reports/latest/low-risk-autonomy-draft-actions.md", "\n".join(md) + "\n")

    learning = {
        "timestamp_utc": result["timestamp_utc"],
        "phase": "7.1-low-risk-autonomy-runner",
        "mode": "read_only_monitoring_and_draft_actions",
        "known_issues": result["known_issues"],
        "allowed_low_risk": [
            "public_http_checks",
            "seo_tag_checks",
            "schema_counting",
            "performance_header_checks",
            "report_generation",
            "history_update",
            "draft_action_generation",
        ],
        "blocked_high_risk": [
            "db_update_delete",
            "fse_template_edit",
            "post_page_edit",
            "theme_plugin_code_edit",
            "htaccess_change",
            "cloudflare_rule_change",
            "nginx_change",
            "redirect_change",
        ],
        "breach": False,
    }
    safe_write_text("reports/latest/bot-learning-low-risk-autonomy.json", json.dumps(learning, indent=2, ensure_ascii=False) + "\n")
    safe_write_text(
        "reports/latest/bot-learning-low-risk-autonomy.md",
        "# Bot Learning LOW-RISK Autonomy\n\n"
        "- LOW-RISK automation is read-only monitoring plus draft actions.\n"
        "- No live changes are made.\n"
        f"- Known issue monitored: `{KNOWN_SOC_ISSUE}`.\n"
        "- FSE/DB/template changes remain HIGH risk and require owner review.\n",
    )
    safe_write_text(
        "reports/latest/sentinel-safe-autonomy-policy-update.md",
        "# Sentinel Safe Autonomy Policy Update\n\n"
        "- LOW-RISK read-only monitoring may run repeatedly after owner timer review.\n"
        "- Emergency Stop remains active for write/apply actions.\n"
        "- No DB, FSE, theme, plugin, .htaccess, Cloudflare or Nginx changes are autonomous.\n"
        "- Medium and high risk actions remain owner-review only.\n",
    )


def run_once():
    ensure_dirs()
    ts = utc_ts()
    home = fetch(SITE_URL)
    analysis = analyze_home(home)

    endpoints = {
        "robots_txt": endpoint_status("/robots.txt"),
        "sitemap_index_xml": endpoint_status("/sitemap_index.xml"),
        "sitemap_xml": endpoint_status("/sitemap.xml"),
    }

    warnings, known = build_warnings(analysis, endpoints)
    scores = score_all(analysis, warnings, known)

    if home["error"]:
        status = STATUS_FAIL
    elif known:
        status = STATUS_CRIT
    elif warnings:
        status = STATUS_WARN
    else:
        status = STATUS_OK

    result = {
        "phase": "7.1-low-risk-autonomy-runner",
        "timestamp": ts,
        "timestamp_utc": iso_now(),
        "target_url": SITE_URL,
        "status": status,
        "breach": False,
        "error": home["error"],
        "analysis": analysis,
        "endpoints": endpoints,
        "warnings": warnings,
        "known_issues": known,
        "scores": scores,
        "live_apply": False,
        "apply_function_exists": False,
        "safety": {
            "read_only_public_http": True,
            "sftp_write": False,
            "db_write": False,
            "cache_purge": False,
            "cloudflare_change": False,
            "nginx_change": False,
            "htaccess_change": False,
        },
    }
    write_reports(result)
    print(json.dumps({
        "status": result["status"],
        "seo_score": scores["seo_score"],
        "performance_basic_score": scores["performance_basic_score"],
        "schema_health_score": scores["schema_health_score"],
        "autonomy_safety_score": scores["autonomy_safety_score"],
        "overall_safe_monitor_score": scores["overall_safe_monitor_score"],
        "warnings_count": len(warnings),
        "known_issues": known,
        "breach": False,
    }, indent=2, ensure_ascii=False))


def status():
    p = Path("state/low-risk-autonomy/latest.json")
    if not p.exists():
        print("No LOW-RISK autonomy run found yet.")
        return
    data = json.loads(p.read_text(encoding="utf-8"))
    print(f"last_run={data.get('timestamp_utc')}")
    print(f"status={data.get('status')}")
    for k, v in data.get("scores", {}).items():
        print(f"{k}={v}")
    print(f"warnings={len(data.get('warnings', []))}")
    if data.get("warnings"):
        print("top_warnings=" + ", ".join(data["warnings"][:8]))
    print("known_issues=" + ", ".join(data.get("known_issues", [])))
    print(f"breach={data.get('breach')}")


def draft_actions():
    p = Path("state/low-risk-autonomy/latest.json")
    if not p.exists():
        raise SystemExit("latest state missing; run --run-once first")
    result = json.loads(p.read_text(encoding="utf-8"))
    drafts = build_draft_actions(result)
    safe_write_text("reports/latest/low-risk-autonomy-draft-actions.json", json.dumps(drafts, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"status": drafts["status"], "actions_count": drafts["actions_count"], "breach": False}, indent=2))


def write_playbook():
    ensure_dirs()
    playbook = {
        "name": "low-risk-seo-performance-monitor",
        "purpose": "Read-only SEO and performance monitoring with local reporting and draft actions.",
        "allowed_actions": [
            "public_http_checks",
            "seo_tag_checks",
            "schema_counting",
            "performance_header_checks",
            "local_reports",
            "local_history",
            "draft_actions",
        ],
        "forbidden_actions": [
            "live_apply",
            "db_write",
            "sftp_write",
            "cache_purge",
            "fse_template_edit",
            "post_page_edit",
            "theme_plugin_code_edit",
            "htaccess_change",
            "cloudflare_change",
            "nginx_change",
        ],
        "command": "python3 sentinel_low_risk_autonomy.py --run-once",
        "status_values": [STATUS_OK, STATUS_WARN, STATUS_CRIT, STATUS_FAIL, STATUS_BLOCK],
        "owner_review_boundary": "Medium and high risk actions are never executed by this runner.",
        "rollback": "No remote changes are performed; rollback is not required for monitoring output.",
        "breach": False,
    }
    safe_write_text("playbooks/low-risk-seo-performance-monitor.playbook.json", json.dumps(playbook, indent=2, ensure_ascii=False) + "\n")
    safe_write_text(
        "reports/latest/low-risk-seo-performance-monitor-playbook.md",
        "# LOW-RISK SEO Performance Monitor Playbook\n\n"
        "- Command: `python3 sentinel_low_risk_autonomy.py --run-once`\n"
        "- Scope: read-only public monitoring.\n"
        "- Writes only local reports/state/audit/snapshots/playbook files.\n"
        "- No live apply, no cache purge, no SFTP/DB write.\n",
    )
    print(json.dumps({"playbook_written": True, "breach": False}, indent=2))


def self_test():
    assert "apply" not in COMMANDS
    assert clamp(-10) == 0 and clamp(120) == 100
    sample = """
    <html><head>
    <title>Test Title</title>
    <meta name="description" content="A useful description for testing.">
    <link rel="canonical" href="https://example.com/">
    <meta property="og:title" content="OG">
    <meta name="twitter:card" content="summary_large_image">
    <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization"}</script>
    </head><body><h1>Hello</h1><img src="x.webp" loading="lazy"><script>console.log(1)</script>soc-schema-graph</body></html>
    """
    fake = {"body": sample, "headers": {"Cache-Control": "public"}, "http_status": 200, "elapsed_ms": 10, "size_bytes": len(sample)}
    a = analyze_home(fake)
    assert a["title"] == "Test Title"
    assert a["h1_count"] == 1
    assert a["schema_type_counts"]["Organization"] == 1
    assert a["soc_watch"]["soc-schema-graph"] is True
    assert a["webp_hint_count"] >= 1
    s = score_all(a, [], [])
    assert all(0 <= v <= 100 for v in s.values())
    test_path = "reports/latest/self-test-low-risk-autonomy.json"
    safe_write_text(test_path, json.dumps({"ok": True}) + "\n")
    json.loads(Path(test_path).read_text(encoding="utf-8"))
    print("SELF_TEST_OK")


def main():
    parser = argparse.ArgumentParser(description="Sentinel LOW-RISK read-only SEO/performance autonomy runner")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--self-test", action="store_true")
    g.add_argument("--run-once", action="store_true")
    g.add_argument("--status", action="store_true")
    g.add_argument("--draft-actions", action="store_true")
    g.add_argument("--write-playbook", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
    elif args.run_once:
        run_once()
    elif args.status:
        status()
    elif args.draft_actions:
        draft_actions()
    elif args.write_playbook:
        write_playbook()
    else:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
