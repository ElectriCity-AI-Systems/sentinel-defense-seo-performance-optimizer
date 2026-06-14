#!/usr/bin/env python3
import argparse
import ast
import datetime
import json
import re
import urllib.request
from pathlib import Path

SITE_URL = "https://electri-c-ity-studios-24-7.com/"
ALLOWED_WRITE_ROOTS = [
    "reports/latest",
    "snapshots",
    "audit",
    "drafts/owner",
]

STATUS_OK = "POST_DISABLE_SCHEMA_VERIFIED_OK"
STATUS_SENTINEL = "POST_DISABLE_SCHEMA_SENTINEL_STILL_PRESENT"
STATUS_PARTIAL = "POST_DISABLE_SCHEMA_PARTIAL"
STATUS_PARSE_WARNING = "POST_DISABLE_SCHEMA_PARSE_WARNING"
STATUS_FETCH_FAILED = "POST_DISABLE_SCHEMA_FETCH_FAILED"
STATUS_BREACH = "POST_DISABLE_SCHEMA_BREACH"


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

    raise RuntimeError(f"blocked write outside allowed output roots: {path}")


def safe_write_text(path: Path, text: str):
    ensure_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def append_audit(path: Path, line: str):
    ensure_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def collect_types(obj):
    found = []

    if isinstance(obj, dict):
        t = obj.get("@type")
        if isinstance(t, str):
            found.append(t)
        elif isinstance(t, list):
            found.extend([x for x in t if isinstance(x, str)])

        for value in obj.values():
            if isinstance(value, (dict, list)):
                found.extend(collect_types(value))

    elif isinstance(obj, list):
        for item in obj:
            found.extend(collect_types(item))

    return found


def source_hint(context: str) -> str:
    c = context.lower()

    if "rank-math-schema" in c:
        return "rank_math"

    if "soc-schema-graph" in c or "data-soc-schema" in c:
        return "soc_schema_graph"

    if "structured data for global search engines" in c:
        return "custom_structured_data"

    if "sentinel-seo-jsonld" in c or "sentinel_schema" in c or "sentinel schema" in c:
        return "sentinel"

    return "unknown"


def fetch_live_html(ts: str):
    url = f"{SITE_URL}?sentinel_post_disable_schema_verify={ts}"

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SentinelPostDisableSchemaVerifier/1.0",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        html = response.read().decode("utf-8", errors="replace")
        return response.status, url, html


def extract_jsonld_blocks(html: str):
    pattern = re.compile(
        r'(<script[^>]+type=["\']application/ld\+json["\'][^>]*>)(.*?)(</script>)',
        flags=re.I | re.S,
    )

    blocks = []
    type_counts = {}

    for index, match in enumerate(pattern.finditer(html), start=1):
        open_tag = match.group(1)
        content = match.group(2).strip()
        start = match.start()

        prefix_context = html[max(0, start - 700):start]

        # Detect source from the current script first.
        # Only use preceding context as fallback for nearby HTML comments,
        # so one previous schema block cannot contaminate the next block.
        current_context = open_tag + "\n" + content
        hint = source_hint(current_context)

        if hint == "unknown":
            hint = source_hint(prefix_context + "\n" + current_context)

        parsed_ok = False
        parse_error = None
        types = []

        try:
            data = json.loads(content)
            parsed_ok = True
            types = collect_types(data)
        except Exception as exc:
            parse_error = str(exc)

        for item_type in types:
            type_counts[item_type] = type_counts.get(item_type, 0) + 1

        blocks.append({
            "block": index,
            "source_hint": hint,
            "parsed_ok": parsed_ok,
            "parse_error": parse_error,
            "types": sorted(set(types)),
            "type_count_total": len(types),
        })

    return blocks, type_counts


def determine_status(result):
    if result["error"]:
        result["breach"] = True
        return STATUS_FETCH_FAILED

    if result["http_status"] != 200:
        result["breach"] = True
        return STATUS_BREACH

    if result["sentinel_block_detected"]:
        result["breach"] = True
        return STATUS_SENTINEL

    if result["jsonld_script_count"] < 1:
        result["breach"] = False
        return STATUS_PARTIAL

    if result["parse_warning_count"] > 0:
        result["breach"] = False
        return STATUS_PARSE_WARNING

    result["breach"] = False
    return STATUS_OK


def build_markdown(result):
    lines = [
        "# Post-Disable Schema Verification",
        "",
        f"- status: {result['status']}",
        f"- http_status: {result['http_status']}",
        f"- jsonld_script_count: {result['jsonld_script_count']}",
        f"- sentinel_block_detected: {result['sentinel_block_detected']}",
        f"- parse_warning_count: {result['parse_warning_count']}",
        f"- RadioStation count: {result['radio_station_type_count']}",
        f"- MusicGroup count: {result['music_group_type_count']}",
        f"- Organization count: {result['organization_type_count']}",
        f"- WebSite count: {result['website_type_count']}",
        f"- WebPage count: {result['webpage_type_count']}",
        f"- CollectionPage count: {result['collectionpage_type_count']}",
        f"- Place count: {result['place_type_count']}",
        f"- breach: {result['breach']}",
        f"- error: `{result['error']}`",
        "",
        "## Blocks",
    ]

    for block in result["blocks"]:
        lines.append(
            f"- Block {block['block']}: "
            f"source={block['source_hint']}, "
            f"parsed_ok={block['parsed_ok']}, "
            f"types={', '.join(block['types']) if block['types'] else '-'}"
        )

    lines.extend([
        "",
        "## Safety",
        "",
        "- No SFTP was used.",
        "- No password was requested.",
        "- No live apply.",
        "- No upload.",
        "- No installation.",
        "- No restore executed.",
        "- No WordPress, Cloudflare, Nginx, .htaccess, database, theme, systemd or crontab change.",
    ])

    return "\n".join(lines) + "\n"


def run_verifier():
    ts = utc_ts()

    result = {
        "phase": "6.4-post-disable-schema-verification",
        "timestamp_utc": ts,
        "url": None,
        "http_status": None,
        "jsonld_script_count": 0,
        "blocks": [],
        "type_counts": {},
        "sentinel_block_detected": False,
        "parse_warning_count": 0,
        "radio_station_type_count": 0,
        "music_group_type_count": 0,
        "organization_type_count": 0,
        "website_type_count": 0,
        "webpage_type_count": 0,
        "collectionpage_type_count": 0,
        "place_type_count": 0,
        "status": None,
        "breach": False,
        "error": None,
    }

    try:
        http_status, url, html = fetch_live_html(ts)
        result["http_status"] = http_status
        result["url"] = url

        blocks, type_counts = extract_jsonld_blocks(html)
        result["blocks"] = blocks
        result["type_counts"] = type_counts
        result["jsonld_script_count"] = len(blocks)
        result["sentinel_block_detected"] = any(
            block["source_hint"] == "sentinel" for block in blocks
        )
        result["parse_warning_count"] = sum(
            1 for block in blocks if not block["parsed_ok"]
        )

        result["radio_station_type_count"] = type_counts.get("RadioStation", 0)
        result["music_group_type_count"] = type_counts.get("MusicGroup", 0)
        result["organization_type_count"] = type_counts.get("Organization", 0)
        result["website_type_count"] = type_counts.get("WebSite", 0)
        result["webpage_type_count"] = type_counts.get("WebPage", 0)
        result["collectionpage_type_count"] = type_counts.get("CollectionPage", 0)
        result["place_type_count"] = type_counts.get("Place", 0)

    except Exception as exc:
        result["error"] = str(exc)

    result["status"] = determine_status(result)

    report_json = Path("reports/latest/post-disable-schema-verification.json")
    report_md = Path("reports/latest/post-disable-schema-verification.md")
    snapshot_json = Path(f"snapshots/post-disable-schema-verification-{ts}.json")
    snapshot_md = Path(f"snapshots/post-disable-schema-verification-{ts}.md")
    owner_md = Path("drafts/owner/post-disable-schema-verification-owner-summary.md")
    audit_jsonl = Path("audit/post-disable-schema-verification.jsonl")

    json_text = json.dumps(result, indent=2, ensure_ascii=False)
    md_text = build_markdown(result)

    safe_write_text(report_json, json_text + "\n")
    safe_write_text(report_md, md_text)
    safe_write_text(snapshot_json, json_text + "\n")
    safe_write_text(snapshot_md, md_text)
    safe_write_text(owner_md, md_text)
    append_audit(audit_jsonl, json.dumps(result, ensure_ascii=False))

    print(json_text)
    return 0 if not result["breach"] else 2


def self_test():
    # Direct source_hint checks. These are stable and do not depend on mock block ordering.
    assert source_hint('<script class="rank-math-schema" type="application/ld+json">') == "rank_math"
    assert source_hint('<script id="soc-schema-graph" data-soc-schema="1" type="application/ld+json">') == "soc_schema_graph"
    assert source_hint('<!-- Structured data for global search engines -->') == "custom_structured_data"
    assert source_hint('<script id="sentinel-seo-jsonld" type="application/ld+json">') == "sentinel"
    assert source_hint('<script type="application/ld+json">') == "unknown"

    # collect_types must handle nested graphs and lists.
    nested = {
        "@graph": [
            {"@type": "Organization"},
            {"@type": ["RadioStation", "MusicGroup"]},
            {
                "mainEntity": {
                    "@type": "WebSite",
                    "potentialAction": {"@type": "SearchAction"}
                }
            }
        ]
    }

    types = collect_types(nested)
    assert "Organization" in types
    assert "RadioStation" in types
    assert "MusicGroup" in types
    assert "WebSite" in types
    assert "SearchAction" in types

    # extract_jsonld_blocks should parse valid JSON-LD and tolerate invalid JSON.
    mock = """
    <script class="rank-math-schema" type="application/ld+json">{"@graph":[{"@type":"WebSite"},{"@type":"CollectionPage"}]}</script>
    <script id="soc-schema-graph" data-soc-schema="1" type="application/ld+json">{"@type":"WebPage"}</script>
    <script id="sentinel-seo-jsonld" type="application/ld+json">{"@type":["RadioStation","MusicGroup"]}</script>
    <script type="application/ld+json">{broken json</script>
    """

    blocks, counts = extract_jsonld_blocks(mock)

    assert len(blocks) == 4
    assert counts["WebSite"] == 1
    assert counts["CollectionPage"] == 1
    assert counts["WebPage"] == 1
    assert counts["RadioStation"] == 1
    assert counts["MusicGroup"] == 1
    assert any(b["source_hint"] == "rank_math" for b in blocks)
    assert any(b["source_hint"] == "soc_schema_graph" for b in blocks)
    assert any(b["source_hint"] == "sentinel" for b in blocks)
    assert any(not b["parsed_ok"] for b in blocks)

    # Safety: forbidden modules must not be imported.
    import ast
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    forbidden_imports = {"paramiko", "subprocess", "ftplib"}
    imported = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])

    forbidden_found = imported & forbidden_imports
    assert not forbidden_found, f"forbidden imports found: {forbidden_found}"

    print(json.dumps({
        "self_test": "passed",
        "forbidden_imports_found": sorted(forbidden_found),
        "blocks_tested": len(blocks),
        "types_tested": sorted(set(types)),
    }, indent=2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    return run_verifier()


if __name__ == "__main__":
    raise SystemExit(main())
