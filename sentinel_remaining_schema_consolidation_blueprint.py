#!/usr/bin/env python3
import argparse
import datetime
import json
from pathlib import Path

INPUT = Path("reports/latest/post-disable-schema-verification.json")

OUT_JSON = Path("reports/latest/remaining-schema-consolidation-blueprint.json")
OUT_MD = Path("reports/latest/remaining-schema-consolidation-blueprint.md")
OWNER_MD = Path("drafts/owner/remaining-schema-consolidation-owner-decision.md")
SNAPSHOT_DIR = Path("snapshots")
AUDIT = Path("audit/remaining-schema-consolidation-blueprint.jsonl")

STATUS_READY = "REMAINING_SCHEMA_CONSOLIDATION_BLUEPRINT_READY"
STATUS_PARTIAL = "REMAINING_SCHEMA_CONSOLIDATION_BLUEPRINT_PARTIAL"
STATUS_BLOCKED = "REMAINING_SCHEMA_CONSOLIDATION_BLUEPRINT_BLOCKED_BY_BREACH"
STATUS_BREACH = "REMAINING_SCHEMA_CONSOLIDATION_BLUEPRINT_BREACH"

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


def load_input():
    if not INPUT.exists():
        return None, f"missing input: {INPUT}"

    try:
        return json.loads(INPUT.read_text(encoding="utf-8")), None
    except Exception as exc:
        return None, str(exc)


def build_analysis(data: dict):
    blocks = data.get("blocks", [])
    type_counts = data.get("type_counts", {})

    sources = []
    for block in blocks:
        source = block.get("source_hint", "unknown")
        types = block.get("types", [])
        sources.append({
            "block": block.get("block"),
            "source": source,
            "types": types,
            "role": classify_source(source, types),
            "recommendation": recommend_source(source, types),
        })

    duplicate_types = {
        k: v for k, v in type_counts.items()
        if k in {"Organization", "WebSite", "WebPage", "RadioStation", "MusicGroup"} and v > 1
    }

    return sources, duplicate_types


def classify_source(source: str, types: list):
    if source == "rank_math":
        return "primary_global_seo_schema_candidate"
    if source == "soc_schema_graph":
        return "secondary_global_schema_candidate"
    if source == "custom_structured_data":
        if "RadioStation" in types or "MusicGroup" in types:
            return "music_radio_entity_schema_current_primary"
        return "custom_schema_candidate"
    if source == "sentinel":
        return "should_be_disabled"
    return "unknown_schema_source"


def recommend_source(source: str, types: list):
    if source == "rank_math":
        return "Keep for now. Rank Math appears to provide broad global schema including Organization/WebSite/CollectionPage."
    if source == "soc_schema_graph":
        return "Review later. This source duplicates Organization/WebSite/WebPage and may be removable if Rank Math fully covers global schema."
    if source == "custom_structured_data":
        return "Keep for now because it is currently the only remaining source for RadioStation and MusicGroup after Sentinel disable."
    if source == "sentinel":
        return "Should remain disabled after Phase 6.3 because it would duplicate RadioStation/MusicGroup."
    return "Do not change automatically. Identify source manually first."


def determine_status(data, duplicate_types):
    if not data:
        return STATUS_PARTIAL, False

    if data.get("breach") is True:
        return STATUS_BLOCKED, True

    if data.get("sentinel_block_detected") is True:
        return STATUS_BREACH, True

    return STATUS_READY, False


def build_markdown(result: dict):
    lines = [
        "# Remaining Schema Consolidation Blueprint",
        "",
        f"- status: {result['status']}",
        f"- breach: {result['breach']}",
        f"- source_count: {result['source_count']}",
        f"- jsonld_script_count: {result['jsonld_script_count']}",
        f"- sentinel_block_detected: {result['sentinel_block_detected']}",
        f"- duplicate_types: {json.dumps(result['duplicate_types'], ensure_ascii=False)}",
        "",
        "## Current Interpretation",
        "",
        "- Sentinel MU schema is disabled and should stay disabled.",
        "- RadioStation and MusicGroup are now present exactly once.",
        "- Organization and WebSite are still duplicated across remaining non-Sentinel sources.",
        "- The safest next action is not automatic removal, but source consolidation planning.",
        "",
        "## Source Assessment",
        "",
    ]

    for source in result["sources"]:
        lines.extend([
            f"### Block {source['block']} — {source['source']}",
            "",
            f"- role: {source['role']}",
            f"- types: {', '.join(source['types']) if source['types'] else '-'}",
            f"- recommendation: {source['recommendation']}",
            "",
        ])

    lines.extend([
        "## Recommended Owner Decision",
        "",
        "Recommended safe path:",
        "",
        "1. Keep Rank Math schema active for now.",
        "2. Keep Custom Structured Data for now because it currently provides RadioStation and MusicGroup.",
        "3. Investigate the SOC schema source next, because it duplicates Organization/WebSite/WebPage.",
        "4. Do not auto-remove SOC or Custom schema until the exact WordPress origin is known.",
        "5. Do not re-enable Sentinel schema unless Custom Structured Data is removed or rewritten.",
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
    ])

    return "\n".join(lines) + "\n"


def run():
    ts = utc_ts()
    data, error = load_input()

    result = {
        "phase": "6.5-remaining-schema-consolidation-blueprint",
        "timestamp_utc": ts,
        "input": str(INPUT),
        "status": None,
        "breach": False,
        "error": error,
        "jsonld_script_count": None,
        "sentinel_block_detected": None,
        "source_count": 0,
        "sources": [],
        "duplicate_types": {},
        "recommended_next_step": None,
    }

    if data:
        sources, duplicate_types = build_analysis(data)
        status, breach = determine_status(data, duplicate_types)

        result.update({
            "status": status,
            "breach": breach,
            "jsonld_script_count": data.get("jsonld_script_count"),
            "sentinel_block_detected": data.get("sentinel_block_detected"),
            "source_count": len(sources),
            "sources": sources,
            "duplicate_types": duplicate_types,
            "recommended_next_step": "Investigate SOC schema source first; do not modify automatically.",
        })
    else:
        result["status"] = STATUS_PARTIAL
        result["breach"] = False
        result["recommended_next_step"] = "Run post-disable schema verification first."

    snapshot_json = SNAPSHOT_DIR / f"remaining-schema-consolidation-blueprint-{ts}.json"
    snapshot_md = SNAPSHOT_DIR / f"remaining-schema-consolidation-blueprint-{ts}.md"

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
    sample = {
        "breach": False,
        "sentinel_block_detected": False,
        "jsonld_script_count": 3,
        "type_counts": {
            "Organization": 3,
            "WebSite": 3,
            "RadioStation": 1,
            "MusicGroup": 1,
        },
        "blocks": [
            {"block": 1, "source_hint": "rank_math", "types": ["Organization", "WebSite"]},
            {"block": 2, "source_hint": "soc_schema_graph", "types": ["Organization", "WebSite", "WebPage"]},
            {"block": 3, "source_hint": "custom_structured_data", "types": ["Organization", "WebSite", "RadioStation", "MusicGroup"]},
        ],
    }

    sources, duplicates = build_analysis(sample)
    status, breach = determine_status(sample, duplicates)

    assert status == STATUS_READY
    assert breach is False
    assert duplicates["Organization"] == 3
    assert duplicates["WebSite"] == 3
    assert len(sources) == 3
    assert sources[0]["source"] == "rank_math"
    assert sources[1]["source"] == "soc_schema_graph"
    assert sources[2]["source"] == "custom_structured_data"

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
