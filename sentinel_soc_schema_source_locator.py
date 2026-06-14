#!/usr/bin/env python3
import argparse
import datetime
import json
import re
import urllib.request
from pathlib import Path

SITE_URL = "https://electri-c-ity-studios-24-7.com/"

OUT_JSON = Path("reports/latest/soc-schema-source-locator.json")
OUT_MD = Path("reports/latest/soc-schema-source-locator.md")
OWNER_MD = Path("drafts/owner/soc-schema-source-locator-owner-review.md")
SNAPSHOT_DIR = Path("snapshots")
AUDIT = Path("audit/soc-schema-source-locator.jsonl")

STATUS_FOUND = "SOC_SCHEMA_SOURCE_LOCATOR_FOUND_PUBLIC_MARKER"
STATUS_NOT_FOUND = "SOC_SCHEMA_SOURCE_LOCATOR_NOT_FOUND"
STATUS_PARTIAL = "SOC_SCHEMA_SOURCE_LOCATOR_PARTIAL"
STATUS_FETCH_FAILED = "SOC_SCHEMA_SOURCE_LOCATOR_FETCH_FAILED"
STATUS_BREACH = "SOC_SCHEMA_SOURCE_LOCATOR_BREACH"

ALLOWED_WRITE_ROOTS = [
    "reports/latest",
    "drafts/owner",
    "snapshots",
    "audit",
]


def utc_ts():
    return datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def ensure_allowed_write(path: Path):
    target = path.resolve()
    cwd = Path.cwd().resolve()

    for root in ALLOWED_WRITE_ROOTS:
        allowed = (cwd / root).resolve()
        if is_relative_to(target, allowed):
            return

    raise RuntimeError(f"blocked write outside allowed roots: {path}")


def write_text(path: Path, text: str):
    ensure_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def append_audit(path: Path, item: dict):
    ensure_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def fetch_html(ts: str):
    url = f"{SITE_URL}?sentinel_soc_source_locator={ts}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SentinelSOCSchemaSourceLocator/1.0",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        return response.status, url, response.read().decode("utf-8", errors="replace")


def extract_jsonld_scripts(html: str):
    pattern = re.compile(
        r'(<script[^>]+type=["\']application/ld\+json["\'][^>]*>)(.*?)(</script>)',
        flags=re.I | re.S,
    )

    scripts = []

    for idx, match in enumerate(pattern.finditer(html), start=1):
        open_tag = match.group(1)
        content = match.group(2).strip()
        start = match.start()
        end = match.end()

        nearby_before = html[max(0, start - 1200):start]
        nearby_after = html[end:min(len(html), end + 600)]

        scripts.append({
            "index": idx,
            "open_tag": open_tag,
            "content_preview": content[:500],
            "nearby_before": nearby_before,
            "nearby_after": nearby_after,
            "is_soc_schema": (
                "soc-schema-graph" in open_tag.lower()
                or "data-soc-schema" in open_tag.lower()
                or "soc-schema-graph" in content.lower()
                or "data-soc-schema" in content.lower()
            ),
        })

    return scripts


def extract_public_clues(html: str, soc_context: str):
    plugin_paths = sorted(set(re.findall(r"/wp-content/plugins/([^/'\"?\s]+)/", html)))
    theme_paths = sorted(set(re.findall(r"/wp-content/themes/([^/'\"?\s]+)/", html)))

    meta_generators = []
    for m in re.finditer(r'<meta[^>]+name=["\']generator["\'][^>]*>', html, flags=re.I):
        meta_generators.append(m.group(0)[:300])

    soc_terms = sorted(set(re.findall(r"[\w.-]*soc[\w.-]*", soc_context, flags=re.I)))

    nearby_plugin_paths = sorted(set(re.findall(r"/wp-content/plugins/([^/'\"?\s]+)/", soc_context)))
    nearby_theme_paths = sorted(set(re.findall(r"/wp-content/themes/([^/'\"?\s]+)/", soc_context)))

    html_comments_nearby = []
    for m in re.finditer(r"<!--(.*?)-->", soc_context, flags=re.S):
        comment = " ".join(m.group(1).split())
        if comment:
            html_comments_nearby.append(comment[:300])

    return {
        "all_public_plugin_paths": plugin_paths,
        "all_public_theme_paths": theme_paths,
        "nearby_plugin_paths": nearby_plugin_paths,
        "nearby_theme_paths": nearby_theme_paths,
        "meta_generators": meta_generators,
        "soc_terms_nearby": soc_terms,
        "html_comments_nearby": html_comments_nearby,
    }


def infer_confidence(clues: dict):
    if clues["nearby_plugin_paths"]:
        return "medium", "SOC block appears near a public plugin asset path."
    if clues["soc_terms_nearby"]:
        return "low_to_medium", "SOC-specific marker exists, but public HTML does not reveal exact WordPress source."
    return "low", "Only the script id/data marker is visible publicly."


def build_markdown(result: dict):
    lines = [
        "# SOC Schema Source Locator",
        "",
        f"- status: {result['status']}",
        f"- breach: {result['breach']}",
        f"- http_status: {result['http_status']}",
        f"- jsonld_script_count: {result['jsonld_script_count']}",
        f"- soc_schema_block_found: {result['soc_schema_block_found']}",
        f"- soc_schema_block_index: {result['soc_schema_block_index']}",
        f"- confidence: {result['confidence']}",
        f"- confidence_reason: {result['confidence_reason']}",
        f"- error: `{result['error']}`",
        "",
        "## Public Clues",
        "",
        f"- nearby_plugin_paths: {json.dumps(result['clues'].get('nearby_plugin_paths', []), ensure_ascii=False)}",
        f"- nearby_theme_paths: {json.dumps(result['clues'].get('nearby_theme_paths', []), ensure_ascii=False)}",
        f"- soc_terms_nearby: {json.dumps(result['clues'].get('soc_terms_nearby', []), ensure_ascii=False)}",
        f"- html_comments_nearby: {json.dumps(result['clues'].get('html_comments_nearby', []), ensure_ascii=False)}",
        f"- meta_generators: {json.dumps(result['clues'].get('meta_generators', []), ensure_ascii=False)}",
        "",
        "## Interpretation",
        "",
        "- This module only identifies public HTML clues.",
        "- It does not log in to WordPress.",
        "- It does not use SFTP.",
        "- It does not modify the website.",
        "- If the exact source is not visible publicly, the next safe step is a manual WordPress admin review for a plugin/snippet that outputs `id=\"soc-schema-graph\"` or `data-soc-schema=\"1\"`.",
        "",
        "## Recommended Owner Action",
        "",
        "Do not remove anything automatically. First identify whether `soc_schema_graph` is produced by a plugin, theme snippet, custom HTML block, or older SEO automation.",
        "",
        "## Safety",
        "",
        "- No SFTP used.",
        "- No password requested.",
        "- No live apply.",
        "- No upload.",
        "- No installation.",
        "- No restore executed.",
        "- No WordPress, Cloudflare, Nginx, .htaccess, database, theme, systemd or crontab change.",
    ]

    return "\n".join(lines) + "\n"


def run():
    ts = utc_ts()

    result = {
        "phase": "6.6-soc-schema-source-locator",
        "timestamp_utc": ts,
        "url": None,
        "http_status": None,
        "status": None,
        "breach": False,
        "error": None,
        "jsonld_script_count": 0,
        "soc_schema_block_found": False,
        "soc_schema_block_index": None,
        "soc_open_tag": None,
        "soc_content_preview": None,
        "confidence": None,
        "confidence_reason": None,
        "clues": {},
        "recommended_next_step": None,
    }

    try:
        status_code, url, html = fetch_html(ts)
        result["http_status"] = status_code
        result["url"] = url

        scripts = extract_jsonld_scripts(html)
        result["jsonld_script_count"] = len(scripts)

        soc = next((s for s in scripts if s["is_soc_schema"]), None)

        if soc:
            context = soc["nearby_before"] + "\n" + soc["open_tag"] + "\n" + soc["content_preview"] + "\n" + soc["nearby_after"]
            clues = extract_public_clues(html, context)
            confidence, reason = infer_confidence(clues)

            result.update({
                "status": STATUS_FOUND,
                "soc_schema_block_found": True,
                "soc_schema_block_index": soc["index"],
                "soc_open_tag": soc["open_tag"][:500],
                "soc_content_preview": soc["content_preview"],
                "confidence": confidence,
                "confidence_reason": reason,
                "clues": clues,
                "recommended_next_step": "Manual WordPress admin review: search plugin/snippet/custom HTML source for soc-schema-graph or data-soc-schema.",
            })
        else:
            result.update({
                "status": STATUS_NOT_FOUND,
                "confidence": "none",
                "confidence_reason": "No soc-schema-graph/data-soc-schema marker found in public HTML.",
                "clues": extract_public_clues(html, ""),
                "recommended_next_step": "Re-run post-disable verification and compare HTML cache state.",
            })

        if status_code != 200:
            result["status"] = STATUS_BREACH
            result["breach"] = True
            result["error"] = f"unexpected HTTP status: {status_code}"

    except Exception as exc:
        result["status"] = STATUS_FETCH_FAILED
        result["breach"] = True
        result["error"] = str(exc)
        result["recommended_next_step"] = "Retry public read-only fetch later."

    snapshot_json = SNAPSHOT_DIR / f"soc-schema-source-locator-{ts}.json"
    snapshot_md = SNAPSHOT_DIR / f"soc-schema-source-locator-{ts}.md"

    json_text = json.dumps(result, indent=2, ensure_ascii=False)
    md_text = build_markdown(result)

    write_text(OUT_JSON, json_text + "\n")
    write_text(OUT_MD, md_text)
    write_text(OWNER_MD, md_text)
    write_text(snapshot_json, json_text + "\n")
    write_text(snapshot_md, md_text)
    append_audit(AUDIT, result)

    print(json_text)
    return 2 if result["breach"] else 0


def self_test():
    html = '''
    <html><head>
    <link rel="stylesheet" href="/wp-content/plugins/example-plugin/style.css">
    <script id="soc-schema-graph" data-soc-schema="1" type="application/ld+json">{"@type":"WebPage"}</script>
    </head></html>
    '''

    scripts = extract_jsonld_scripts(html)
    assert len(scripts) == 1
    assert scripts[0]["is_soc_schema"] is True

    context = scripts[0]["nearby_before"] + scripts[0]["open_tag"] + scripts[0]["nearby_after"]
    clues = extract_public_clues(html, context)

    assert "example-plugin" in clues["all_public_plugin_paths"]
    confidence, reason = infer_confidence(clues)
    assert confidence in {"medium", "low_to_medium", "low"}

    print(json.dumps({"self_test": "passed"}, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    return run()


if __name__ == "__main__":
    raise SystemExit(main())
