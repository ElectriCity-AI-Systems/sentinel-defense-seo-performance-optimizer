#!/usr/bin/env python3
"""External SEO Checker Report Learning (Phase 8.3).

Ingests a fixed external checker finding set, compares it with Sentinel's
latest read-only observations, and stores modern weighted recommendations.
No live changes, no apply mode, and no WordPress/SFTP/DB/Cloudflare/Nginx/
.htaccess/FSE/Post/Theme/Plugin/cache actions are performed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

REPORT_JSON = PROJECT_DIR / "reports/latest/external-seo-report-ingest.json"
REPORT_MD = PROJECT_DIR / "reports/latest/external-seo-report-ingest.md"
RECOMMEND_JSON = PROJECT_DIR / "reports/latest/external-seo-report-recommendations.json"
RECOMMEND_MD = PROJECT_DIR / "reports/latest/external-seo-report-recommendations.md"
CONFLICTS_MD = PROJECT_DIR / "reports/latest/external-seo-report-conflicts.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/external-seo-report-ingest.jsonl"
PLAYBOOK_JSON = PROJECT_DIR / "playbooks/external-seo-checker-report-learning.playbook.json"

KNOWLEDGE_BASE_JSON = PROJECT_DIR / "state/adaptive-learning/knowledge_base.json"
OBSERVATIONS_JSONL = PROJECT_DIR / "state/adaptive-learning/observations.jsonl"
PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/patterns.json"
ACTION_RULES_JSON = PROJECT_DIR / "state/adaptive-learning/action_rules.json"
LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest.json"

LOW_RISK_JSON = PROJECT_DIR / "reports/latest/low-risk-autonomy.json"
ADAPTIVE_REPORT_JSON = PROJECT_DIR / "reports/latest/adaptive-learning-engine.json"
ADAPTIVE_REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
ADAPTIVE_RECOMMEND_JSON = PROJECT_DIR / "reports/latest/adaptive-recommendations.json"
ADAPTIVE_RECOMMEND_MD = PROJECT_DIR / "reports/latest/adaptive-recommendations.md"
ADAPTIVE_CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "playbooks",
)

STATUS_OK = "EXTERNAL_SEO_REPORT_INGEST_OK"
STATUS_WARNINGS = "EXTERNAL_SEO_REPORT_INGEST_WARNINGS"
STATUS_FAILED = "EXTERNAL_SEO_REPORT_INGEST_FAILED"
STATUS_BLOCKED = "EXTERNAL_SEO_REPORT_INGEST_BLOCKED_BY_SAFETY"

HIGH_VALUE = "HIGH_VALUE_PERFORMANCE"
MEDIUM = "MEDIUM_OWNER_REVIEW"
LOW_LEGACY = "LOW_LEGACY_OR_LOW_VALUE"

LOW_AUTO = "LOW_RISK_AUTO_ALLOWED"
MEDIUM_OWNER = "MEDIUM_REQUIRES_OWNER_APPROVAL"
HIGH_MANUAL = "HIGH_RISK_MANUAL_REVIEW_REQUIRED"
APPLY_STATUS = "not_applied"
SCHEMA_VERSION = "external-seo-report-ingest-8.3"

EXTERNAL_REPORT_TEXT = """
Der gesamte Datentransfer beträgt 1.008.183 Bytes und könnte kleiner sein
Kein Robots Tag angegeben
Sie haben keine Keywords gesetzt
Sie verwenden zuviel (154) Inline CSS
Sie laden 801 KB an Bildern
Reduzieren Sie die Menge an internen Scripten (24)
Der HTML Code ist sehr groß (180.795 Bytes)
Es ist keine BaseURL gesetzt
Sie haben kein Copyright gesetzt
Sie haben keine Audience gesetzt
Sie verwenden Unterstriche in Ihren Links
Setzen Sie einen EXPIRES TAG in Ihre Website
Sie haben den Meta-Element page-topic nicht gesetzt
Revisit after ist nicht gesetzt
Auf der Seite ist Werbung geschaltet
Die Seite verwendet kein Google- oder Piwik Analytics
""".strip()

SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session|license)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key|license)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
FORBIDDEN_COMMAND_RE = re.compile(
    r"(?i)(--apply\b|apply-safe|live-apply|sftp\s+(put|remove|rename|rm|mkdir|rmdir)|scp\s+|ssh\s+|wp\s+|wp-cli|mysql\b|"
    r"sftp\.(put|remove|rename)|cloudflare\s+(api|cli)|nginx\s+reload|systemctl\s+(enable|start)|"
    r"crontab\s+(-|install)|rm\s+-rf|curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh)"
)
DB_WRITE_RE = re.compile(r"(?i)\b(UPDATE|DELETE|INSERT|REPLACE|ALTER|DROP)\s+(wp_|wordpress|option|post|postmeta|termmeta)")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def redact_text(value: Any, default: str = "-", max_len: int = 1200) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing write outside allowed external SEO roots: {path}")
    if path.suffix.lower() in {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".env", ".bin", ".run"}:
        raise ValueError(f"Refusing executable/install output: {path}")
    if SECRET_NAME_RE.search(path.name):
        raise ValueError(f"Refusing secret-like output path: {path}")


def assert_safe_content(path: Path, content: str) -> None:
    if SECRET_ASSIGNMENT_RE.search(content):
        raise ValueError(f"Secret-like content refused for {path}")
    if FORBIDDEN_COMMAND_RE.search(content):
        raise ValueError(f"Forbidden command pattern refused for {path}")
    if DB_WRITE_RE.search(content):
        raise ValueError(f"DB write pattern refused for {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    assert_safe_content(path, content)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            text = json.dumps(record, ensure_ascii=False, sort_keys=True)
            assert_safe_content(path, text)
            handle.write(text + "\n")


def read_json(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    if SECRET_NAME_RE.search(path.name) or path.suffix.lower() == ".env":
        return None, "secret_like_path_refused"
    try:
        if not path.exists():
            return None, "missing"
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"
    return data if isinstance(data, dict) else None, "ok" if isinstance(data, dict) else "json_root_not_object"


def parse_int_german(text: str) -> Optional[int]:
    match = re.search(r"(\d[\d.]*)(?:\s*(?:Bytes|KB|Inline|Scripten))?", text)
    if not match:
        return None
    try:
        return int(match.group(1).replace(".", ""))
    except ValueError:
        return None


def parse_external_text(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines:
        lower = line.lower()
        finding_id = None
        category = LOW_LEGACY
        value: Optional[int] = None
        if "datentransfer" in lower:
            finding_id, category, value = "total_transfer_bytes_high", HIGH_VALUE, parse_int_german(line)
        elif "robots tag" in lower:
            finding_id, category = "robots_tag_report_conflict", MEDIUM
        elif "keywords" in lower:
            finding_id, category = "keywords_missing", LOW_LEGACY
        elif "inline css" in lower:
            finding_id, category, value = "inline_css_count_high", HIGH_VALUE, parse_int_german(line)
        elif "bildern" in lower:
            finding_id, category, value = "image_bytes_high", HIGH_VALUE, parse_int_german(line)
        elif "internen scripten" in lower:
            finding_id, category, value = "internal_scripts_count_high", HIGH_VALUE, parse_int_german(line)
        elif "html code" in lower:
            finding_id, category, value = "html_bytes_high", HIGH_VALUE, parse_int_german(line)
        elif "baseurl" in lower:
            finding_id, category = "baseurl_missing", MEDIUM
        elif "copyright" in lower:
            finding_id, category = "copyright_missing", LOW_LEGACY
        elif "audience" in lower:
            finding_id, category = "audience_missing", LOW_LEGACY
        elif "unterstriche" in lower:
            finding_id, category = "underscores_in_links", MEDIUM
        elif "expires tag" in lower:
            finding_id, category = "expires_tag_missing", HIGH_VALUE
        elif "page-topic" in lower:
            finding_id, category = "page_topic_missing", LOW_LEGACY
        elif "revisit after" in lower:
            finding_id, category = "revisit_after_missing", LOW_LEGACY
        elif "werbung" in lower:
            finding_id, category = "ads_detected", MEDIUM
        elif "analytics" in lower:
            finding_id, category = "analytics_missing", MEDIUM
        else:
            finding_id, category = "external_checker_unclassified", LOW_LEGACY
        findings.append({
            "finding_id": finding_id,
            "category": category,
            "source_text": line,
            "parsed_value": value,
            "modern_weighting": modern_weighting(finding_id, category),
        })
    return findings


def modern_weighting(finding_id: str, category: str) -> str:
    if finding_id in {"keywords_missing", "copyright_missing", "audience_missing", "page_topic_missing", "revisit_after_missing"}:
        return "legacy_or_low_value_modern_seo"
    if category == HIGH_VALUE:
        return "high_value_performance_signal"
    if category == MEDIUM:
        return "owner_review_signal"
    return "low_value_signal"


def load_sentinel_context() -> Dict[str, Any]:
    low, status = read_json(LOW_RISK_JSON)
    low = low or {}
    analysis = low.get("analysis") or {}
    return {
        "input_status": status,
        "robots_meta": analysis.get("robots_meta"),
        "html_size_bytes": analysis.get("html_size_bytes"),
        "response_size_bytes": analysis.get("response_size_bytes"),
        "script_tag_count": analysis.get("script_tag_count"),
        "stylesheet_count": analysis.get("stylesheet_count"),
        "image_count": analysis.get("image_count"),
        "webp_hint_count": analysis.get("webp_hint_count"),
        "external_resource_host_count": analysis.get("external_resource_host_count"),
        "scores": low.get("scores") or {},
        "known_issues": low.get("known_issues") or [],
        "breach": low.get("breach"),
        "live_apply": low.get("live_apply"),
    }


def classify_conflicts(findings: List[Dict[str, Any]], sentinel: Dict[str, Any]) -> List[Dict[str, Any]]:
    conflicts = []
    robots = str(sentinel.get("robots_meta") or "").replace(" ", "").lower()
    if any(item["finding_id"] == "robots_tag_report_conflict" for item in findings) and robots in {"follow,index", "index,follow"}:
        conflicts.append({
            "conflict_id": "REPORT_CONFLICT_ROBOTS_META",
            "external_claim": "kein Robots Tag angegeben",
            "sentinel_observation": sentinel.get("robots_meta"),
            "classification": "not_a_confirmed_error",
            "reason": "Sentinel latest read-only HTML scan detected robots_meta=follow,index.",
        })
    return conflicts


def build_recommendations(findings: List[Dict[str, Any]], conflicts: List[Dict[str, Any]]) -> Dict[str, Any]:
    recs = []
    for item in findings:
        category = item["category"]
        if item["finding_id"] == "robots_tag_report_conflict" and conflicts:
            rec_category = MEDIUM_OWNER
            action = "Keep as report conflict; verify in next read-only HTML scan, no SEO plugin change."
        elif category == HIGH_VALUE:
            rec_category = LOW_AUTO
            action = "Track in performance monitoring and create owner-review draft if trend repeats."
        elif category == MEDIUM:
            rec_category = MEDIUM_OWNER
            action = "Prepare Owner review note only; do not change settings automatically."
        else:
            rec_category = LOW_AUTO
            action = "Record as low-value legacy checker signal; do not prioritize unless corroborated."
        recs.append({
            "recommendation_id": f"external:{item['finding_id']}",
            "source_finding": item["finding_id"],
            "category": rec_category,
            "checker_category": category,
            "title": item["source_text"],
            "action": action,
            "owner_review_required": rec_category != LOW_AUTO,
            "live_apply": False,
            "apply_status": APPLY_STATUS,
        })
    return {
        "timestamp_utc": utc_now(),
        "recommendations_count": len(recs),
        "categories": dict(Counter(item["category"] for item in recs)),
        "recommendations": recs,
        "breach": False,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
    }


def build_report() -> Dict[str, Any]:
    ts = timestamp_tag()
    sentinel = load_sentinel_context()
    findings = parse_external_text(EXTERNAL_REPORT_TEXT)
    conflicts = classify_conflicts(findings, sentinel)
    counts = Counter(item["category"] for item in findings)
    status = STATUS_WARNINGS if findings else STATUS_OK
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": ts,
        "timestamp_utc": utc_now(),
        "status": status,
        "breach": False,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "emergency_stop_unchanged": True,
        "external_findings_count": len(findings),
        "high_value_performance_findings_count": counts.get(HIGH_VALUE, 0),
        "medium_owner_review_findings_count": counts.get(MEDIUM, 0),
        "low_legacy_findings_count": counts.get(LOW_LEGACY, 0),
        "conflict_count": len(conflicts),
        "findings": findings,
        "conflicts": conflicts,
        "sentinel_context": sentinel,
        "learning": {
            "external_checker_must_be_weighted": True,
            "robots_meta_conflict_not_confirmed_error": bool(conflicts),
            "legacy_meta_keywords_low_value": True,
            "performance_payload_inline_css_scripts_html_size_are_high_value": True,
            "no_live_change_from_external_report_alone": True,
        },
    }


def playbook() -> Dict[str, Any]:
    return {
        "name": "external-seo-checker-report-learning",
        "purpose": "Ingest external SEO checker claims, compare with Sentinel data, and weight modern SEO/performance value.",
        "allowed_actions": ["parse static report text", "compare Sentinel reports", "write reports", "write state", "write audit", "write playbook"],
        "blocked_actions": ["live apply", "DB write", "SFTP write", "cache purge", "Cloudflare change", "Nginx change", ".htaccess change", "FSE/Post/Theme/Plugin edit"],
        "risk_classification": {
            HIGH_VALUE: "Performance monitoring and owner-review draft if repeated",
            MEDIUM: "Owner review only",
            LOW_LEGACY: "Low priority legacy signal",
        },
        "conflict_rules": {
            "robots_meta": "If Sentinel sees follow,index, external no-robots claim becomes REPORT_CONFLICT_ROBOTS_META, not confirmed error.",
        },
        "outputs": [str(REPORT_JSON), str(RECOMMEND_JSON), str(CONFLICTS_MD)],
    }


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# External SEO Report Ingest",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- Findings: `{report.get('external_findings_count')}`",
        f"- High-value performance: `{report.get('high_value_performance_findings_count')}`",
        f"- Medium owner-review: `{report.get('medium_owner_review_findings_count')}`",
        f"- Low legacy/low-value: `{report.get('low_legacy_findings_count')}`",
        f"- Conflicts: `{report.get('conflict_count')}`",
        "",
        "## Findings",
        "",
    ]
    for item in report.get("findings", []):
        lines.append(f"- `{item.get('category')}` `{item.get('finding_id')}`: {item.get('source_text')}")
    return "\n".join(lines) + "\n"


def render_recommendations_md(data: Dict[str, Any]) -> str:
    lines = ["# External SEO Report Recommendations", "", f"- Count: `{data.get('recommendations_count')}`", ""]
    for item in data.get("recommendations", []):
        lines.append(f"- `{item.get('category')}` `{item.get('recommendation_id')}`: {item.get('action')}")
    return "\n".join(lines) + "\n"


def render_conflicts_md(report: Dict[str, Any]) -> str:
    lines = ["# External SEO Report Conflicts", ""]
    conflicts = report.get("conflicts") or []
    if not conflicts:
        lines.append("- none")
    for item in conflicts:
        lines.append(f"- `{item.get('conflict_id')}`: {item.get('reason')}")
    return "\n".join(lines) + "\n"


def append_markdown_section(path: Path, title: str, body: str) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    marker = f"<!-- sentinel:{title.lower().replace(' ', '-')} -->"
    block = f"\n{marker}\n## {title}\n\n{body.rstrip()}\n"
    if marker in text:
        text = text.split(marker, 1)[0].rstrip() + block
    else:
        text = text.rstrip() + "\n" + block
    write_text_atomic(path, text)


def update_learning(report: Dict[str, Any], recommendations: Dict[str, Any]) -> None:
    knowledge, _ = read_json(KNOWLEDGE_BASE_JSON)
    knowledge = knowledge or {}
    knowledge["external_seo_report_learning"] = {
        "timestamp_utc": report.get("timestamp_utc"),
        "learning": report.get("learning"),
        "counts": {
            "high_value_performance": report.get("high_value_performance_findings_count"),
            "medium_owner_review": report.get("medium_owner_review_findings_count"),
            "low_legacy": report.get("low_legacy_findings_count"),
            "conflicts": report.get("conflict_count"),
        },
        "allowed_bot_reaction": ["record", "compare with Sentinel", "recommend read-only trend watch", "write owner-review draft"],
        "forbidden_bot_reaction": ["blind apply", "change SEO plugin settings", "change cache/CDN/Nginx from external report alone"],
    }
    write_json_atomic(KNOWLEDGE_BASE_JSON, knowledge)
    observation = {
        "timestamp_utc": report.get("timestamp_utc"),
        "observation_id": "external-seo-checker-weighted-learning",
        "area": "SEO/Performance",
        "risk_level": LOW_AUTO,
        "confidence_score": 0.78,
        "symptoms": [item.get("finding_id") for item in report.get("findings", [])],
        "hypothesis": "External checker findings are useful as signals but need modern weighting and Sentinel conflict checks.",
        "evidence": {
            "conflicts": report.get("conflicts"),
            "sentinel_context": report.get("sentinel_context"),
        },
    }
    append_jsonl(OBSERVATIONS_JSONL, [observation])
    patterns, _ = read_json(PATTERNS_JSON)
    patterns = patterns or {}
    patterns["external_seo_checker"] = {
        "timestamp_utc": report.get("timestamp_utc"),
        "high_value_performance_findings_count": report.get("high_value_performance_findings_count"),
        "medium_owner_review_findings_count": report.get("medium_owner_review_findings_count"),
        "low_legacy_findings_count": report.get("low_legacy_findings_count"),
        "conflict_count": report.get("conflict_count"),
    }
    write_json_atomic(PATTERNS_JSON, patterns)
    rules, _ = read_json(ACTION_RULES_JSON)
    rules = rules or {}
    rules["external_seo_checker"] = {
        "low_auto_allowed": ["record finding", "compare Sentinel context", "trend if repeated", "write recommendation"],
        "medium_owner_review": ["baseurl/analytics/ads/underscore review", "robots conflict review"],
        "high_blocked": ["do not perform live SEO/plugin/cache/CDN changes from external report alone"],
    }
    write_json_atomic(ACTION_RULES_JSON, rules)
    latest, _ = read_json(LATEST_JSON)
    latest = latest or {}
    latest["external_seo_report_learning"] = {
        "status": report.get("status"),
        "conflict_count": report.get("conflict_count"),
        "high_value_performance_findings_count": report.get("high_value_performance_findings_count"),
        "recommendations_count": recommendations.get("recommendations_count"),
    }
    write_json_atomic(LATEST_JSON, latest)
    adaptive, _ = read_json(ADAPTIVE_REPORT_JSON)
    if adaptive:
        adaptive["external_seo_report_learning"] = {
            "status": report.get("status"),
            "conflicts": report.get("conflicts"),
            "counts": {
                "high_value_performance": report.get("high_value_performance_findings_count"),
                "medium_owner_review": report.get("medium_owner_review_findings_count"),
                "low_legacy": report.get("low_legacy_findings_count"),
            },
        }
        write_json_atomic(ADAPTIVE_REPORT_JSON, adaptive)
    adapt_rec, _ = read_json(ADAPTIVE_RECOMMEND_JSON)
    if adapt_rec:
        adapt_rec["external_seo_report_recommendations"] = recommendations
        write_json_atomic(ADAPTIVE_RECOMMEND_JSON, adapt_rec)
    append_markdown_section(ADAPTIVE_REPORT_MD, "External SEO Checker Learning", render_adaptive_section(report))
    append_markdown_section(ADAPTIVE_RECOMMEND_MD, "External SEO Checker Recommendations", render_recommendations_md(recommendations))
    append_markdown_section(ADAPTIVE_CAPABILITY_MD, "External SEO Checker Capability", "- `external_checker_weighted_ingest`: `True`\n- `external_checker_live_apply`: `False`\n")


def render_adaptive_section(report: Dict[str, Any]) -> str:
    return (
        f"- Status: `{report.get('status')}`\n"
        f"- Conflict count: `{report.get('conflict_count')}`\n"
        f"- High-value performance findings: `{report.get('high_value_performance_findings_count')}`\n"
        f"- Medium owner-review findings: `{report.get('medium_owner_review_findings_count')}`\n"
        f"- Low legacy findings: `{report.get('low_legacy_findings_count')}`\n"
        "- Interpretation: external checker findings are weighted; no blind apply.\n"
    )


def write_outputs(report: Dict[str, Any], recommendations: Dict[str, Any], update: bool = True) -> None:
    ts = str(report["timestamp"])
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(RECOMMEND_JSON, recommendations)
    write_text_atomic(RECOMMEND_MD, render_recommendations_md(recommendations))
    write_text_atomic(CONFLICTS_MD, render_conflicts_md(report))
    write_json_atomic(SNAPSHOT_DIR / f"external-seo-report-ingest-{ts}.json", report)
    write_json_atomic(PLAYBOOK_JSON, playbook())
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "status": report.get("status"),
        "conflict_count": report.get("conflict_count"),
        "high_value_performance_findings_count": report.get("high_value_performance_findings_count"),
        "recommendations_count": recommendations.get("recommendations_count"),
        "breach": report.get("breach"),
        "live_apply": report.get("live_apply"),
    }])
    if update:
        update_learning(report, recommendations)


def build_all(update: bool = True) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    report = build_report()
    recommendations = build_recommendations(report["findings"], report["conflicts"])
    write_outputs(report, recommendations, update=update)
    return report, recommendations


def print_status() -> None:
    report, status = read_json(REPORT_JSON)
    if not report:
        print(f"status=not_available input_status={status}")
        return
    print(f"status={report.get('status')}")
    print(f"conflict_count={report.get('conflict_count')}")
    print(f"high_value_performance_findings_count={report.get('high_value_performance_findings_count')}")
    print(f"medium_owner_review_findings_count={report.get('medium_owner_review_findings_count')}")
    print(f"low_legacy_findings_count={report.get('low_legacy_findings_count')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    findings = parse_external_text(EXTERNAL_REPORT_TEXT)
    if len(findings) != 16:
        raise AssertionError("finding parser count mismatch")
    counts = Counter(item["category"] for item in findings)
    if counts[HIGH_VALUE] != 6 or counts[MEDIUM] != 5 or counts[LOW_LEGACY] != 5:
        raise AssertionError(f"classification mismatch: {counts}")
    conflicts = classify_conflicts(findings, {"robots_meta": "follow, index"})
    if not conflicts or conflicts[0]["conflict_id"] != "REPORT_CONFLICT_ROBOTS_META":
        raise AssertionError("robots conflict not detected")
    recs = build_recommendations(findings, conflicts)
    if recs["recommendations_count"] != 16:
        raise AssertionError("recommendation count mismatch")
    if "abcdef" in redact_text("api_key=abcdef12345"):
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in ("sub" + "process", "os" + "." + "system", "." + "put(", "." + "remove(", "." + "rename(", "rm " + "-rf"):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    json.dumps(build_report())
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ingest and weight an external SEO checker report.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--ingest-text", action="store_true")
    group.add_argument("--classify", action="store_true")
    group.add_argument("--recommend", action="store_true")
    group.add_argument("--update-learning", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def print_summary(report: Dict[str, Any], recommendations: Dict[str, Any]) -> None:
    print(f"status={report.get('status')}")
    print(f"conflict_count={report.get('conflict_count')}")
    print(f"high_value_performance_findings_count={report.get('high_value_performance_findings_count')}")
    print(f"medium_owner_review_findings_count={report.get('medium_owner_review_findings_count')}")
    print(f"low_legacy_findings_count={report.get('low_legacy_findings_count')}")
    print(f"recommendations_count={recommendations.get('recommendations_count')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.status:
        print_status()
        return 0
    try:
        update = args.update_learning or args.ingest_text or args.classify or args.recommend
        report, recommendations = build_all(update=update)
    except Exception as exc:  # noqa: BLE001
        failed = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": timestamp_tag(),
            "timestamp_utc": utc_now(),
            "status": STATUS_FAILED,
            "breach": True,
            "live_apply": False,
            "apply_status": APPLY_STATUS,
            "error": redact_text(exc),
        }
        write_json_atomic(REPORT_JSON, failed)
        write_text_atomic(REPORT_MD, "# External SEO Report Ingest\n\n- Status: `EXTERNAL_SEO_REPORT_INGEST_FAILED`\n")
        print(f"status={STATUS_FAILED}")
        print("breach=True")
        return 2
    print_summary(report, recommendations)
    return 0 if not report.get("breach") else 2


if __name__ == "__main__":
    sys.exit(main())
