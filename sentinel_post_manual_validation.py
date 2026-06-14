#!/usr/bin/env python3
"""Sentinel Post Manual Change Validation (Phase 2.6).

Validates local SEO/performance/safety signals after manual owner changes.
This module is read-only: no network, no login, no API, no apply function, and
no production writes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

# Optional local inputs only.
INPUT_MANUAL_CHECKLIST = PROJECT_DIR / "drafts/manual/manual-apply-checklist.json"
INPUT_OWNER_REVIEW_PACK = PROJECT_DIR / "drafts/review/owner-review-pack.json"
INPUT_HOMEPAGE_HTML = PROJECT_DIR / "seo-inputs/latest/homepage.html"
INPUT_HEADERS_HOMEPAGE = PROJECT_DIR / "seo-inputs/latest/headers-homepage.txt"
INPUT_ROBOTS = PROJECT_DIR / "seo-inputs/latest/robots.txt"
INPUT_SITEMAP = PROJECT_DIR / "seo-inputs/latest/sitemap.xml"
INPUT_SEO_REPORT = PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.json"
INPUT_PERFORMANCE_REPORT = PROJECT_DIR / "reports/latest/performance-safe-audit-report.json"
INPUT_MASTER_REPORT = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

# Outputs.
REPORT_MD = PROJECT_DIR / "reports/latest/post-manual-validation-report.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/post-manual-validation-report.json"
VALIDATION_DIR = PROJECT_DIR / "drafts/validation"
VALIDATION_MD = VALIDATION_DIR / "post-manual-validation-checklist.md"
VALIDATION_JSON = VALIDATION_DIR / "post-manual-validation-checklist.json"
AUDIT_JSONL = PROJECT_DIR / "audit/post-manual-validation.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/validation",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "post-manual-validation-2.6"
OWN_DOMAIN = "electri-c-ity-studios-24-7.com"

STATUS_OK = "OK"
STATUS_WARNING = "WARNING"
STATUS_NOT_AVAILABLE = "NOT_AVAILABLE"
STATUS_READY = "READY_FOR_OWNER_VALIDATION"
STATUS_VALIDATION_WARNING = "VALIDATION_WARNING"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"
APPLY_NOT_APPLIED = "not_applied"

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(value: Any, default: str = "-", max_len: int = 800) -> str:
    if value is None:
        return default
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def sanitize_value(value: Any, *, max_len: int = 2000) -> Any:
    if isinstance(value, dict):
        safe: Dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if SECRETISH_RE.search(key_text):
                safe[key_text] = "[redacted]"
            else:
                safe[key_text] = sanitize_value(child, max_len=max_len)
        return safe
    if isinstance(value, list):
        return [sanitize_value(item, max_len=max_len) for item in value]
    if isinstance(value, str) or value is None:
        return redact_text(value, default="", max_len=max_len)
    if isinstance(value, (int, float, bool)):
        return value
    return redact_text(value, default="", max_len=max_len)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed validation roots: {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def read_optional_json(path: Path) -> Tuple[Optional[Any], str]:
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return None, "refused_secret_like_path"
    if path.suffix.lower() != ".json":
        return None, "unsupported_suffix"
    try:
        if not path.exists():
            return None, "not_available"
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None, "read_error"
    try:
        return json.loads(raw), "ok"
    except (ValueError, json.JSONDecodeError):
        return None, "invalid_json"


def read_optional_text(path: Path, suffixes: Iterable[str], max_bytes: int = 3_000_000) -> Tuple[Optional[str], str]:
    suffix_set = {suffix.lower() for suffix in suffixes}
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return None, "refused_secret_like_path"
    if path.suffix.lower() not in suffix_set:
        return None, "unsupported_suffix"
    try:
        if not path.exists():
            return None, "not_available"
        if not path.is_file():
            return None, "not_a_file"
        if path.stat().st_size > max_bytes:
            return None, "too_large"
        return path.read_text(encoding="utf-8", errors="replace"), "ok"
    except OSError:
        return None, "read_error"


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY}:
        return risk
    return RISK_REVIEW_ONLY


def status_from_bool(value: Optional[bool]) -> str:
    if value is None:
        return STATUS_NOT_AVAILABLE
    return STATUS_OK if value else STATUS_WARNING


def count_warnings(items: Iterable[Dict[str, Any]]) -> int:
    return len([item for item in items if item.get("status") == STATUS_WARNING])


class HomepageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.meta_description = ""
        self.canonical = ""
        self.og_title = ""
        self.og_description = ""
        self.twitter_title = ""
        self.twitter_description = ""
        self._capture_title = False
        self._title_chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        attr = {str(k).lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._capture_title = True
            self._title_chunks = []
            return
        if tag == "meta":
            name = attr.get("name", "").lower()
            prop = attr.get("property", "").lower()
            content = redact_text(attr.get("content", ""), default="", max_len=1000)
            if name == "description":
                self.meta_description = content
            elif prop == "og:title":
                self.og_title = content
            elif prop == "og:description":
                self.og_description = content
            elif name == "twitter:title":
                self.twitter_title = content
            elif name == "twitter:description":
                self.twitter_description = content
            return
        if tag == "link" and attr.get("rel", "").lower() == "canonical":
            self.canonical = strip_url(attr.get("href", ""))

    def handle_data(self, data: str) -> None:
        if self._capture_title:
            self._title_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title" and self._capture_title:
            self.title = redact_text(" ".join(self._title_chunks), default="", max_len=1000)
            self._capture_title = False


def strip_url(value: Any) -> str:
    text = redact_text(value, default="", max_len=1000)
    if not text:
        return ""
    return text.split("?", 1)[0].split("#", 1)[0]


def parse_homepage(html: Optional[str]) -> Dict[str, Any]:
    if not html:
        return {}
    parser = HomepageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return {}
    return {
        "title": parser.title,
        "meta_description": parser.meta_description,
        "canonical": parser.canonical,
        "og_title": parser.og_title,
        "og_description": parser.og_description,
        "twitter_title": parser.twitter_title,
        "twitter_description": parser.twitter_description,
    }


def parse_robots_local(text: Optional[str]) -> Dict[str, Any]:
    if not text:
        return {"robots_public_crawl_allowed": None, "sitemap_present": None}
    current_agents: List[str] = []
    wildcard_disallow_root = False
    wildcard_allow_root = False
    sitemap_present = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "sitemap":
            sitemap_present = True
            continue
        if key == "user-agent":
            current_agents = [value.lower()]
            continue
        if "*" not in current_agents:
            continue
        if key == "disallow" and value == "/":
            wildcard_disallow_root = True
        elif key == "allow" and value in {"", "/"}:
            wildcard_allow_root = True
    return {
        "robots_public_crawl_allowed": not (wildcard_disallow_root and not wildcard_allow_root),
        "sitemap_present": sitemap_present,
    }


def parse_sitemap_local(text: Optional[str]) -> Dict[str, Any]:
    if not text:
        return {"sitemap_present": None, "url_count": 0}
    urls = re.findall(r"<loc>\s*([^<]+)\s*</loc>", text, flags=re.IGNORECASE)
    return {"sitemap_present": bool(urls), "url_count": len(urls)}


def checklist_items(data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("checklist_items"), list):
        return []
    return [item for item in data["checklist_items"] if isinstance(item, dict)]


def find_seo_finding(seo_report: Optional[Any], signal: str) -> Optional[Dict[str, Any]]:
    if not isinstance(seo_report, dict) or not isinstance(seo_report.get("findings"), list):
        return None
    for item in seo_report["findings"]:
        if isinstance(item, dict) and item.get("signal") == signal:
            return item
    return None


def build_seo_validation(
    homepage: Dict[str, Any],
    robots_local: Dict[str, Any],
    sitemap_local: Dict[str, Any],
    seo_report: Optional[Any],
) -> Dict[str, Any]:
    detected = seo_report.get("detected_homepage_seo", {}) if isinstance(seo_report, dict) else {}
    robots_report = seo_report.get("robots", {}) if isinstance(seo_report, dict) else {}
    sitemap_report = seo_report.get("sitemap", {}) if isinstance(seo_report, dict) else {}
    schema_finding = find_seo_finding(seo_report, "schema_json_ld")

    def text_value(key: str, fallback_key: Optional[str] = None) -> str:
        value = homepage.get(key)
        if value:
            return str(value)
        if fallback_key and detected.get(fallback_key):
            return str(detected.get(fallback_key))
        return ""

    canonical = text_value("canonical", "canonical")
    robots_allowed = robots_report.get("robots_public_crawl_allowed")
    if robots_allowed is None:
        robots_allowed = robots_local.get("robots_public_crawl_allowed")
    sitemap_present = sitemap_report.get("sitemap_present")
    if sitemap_present is None:
        sitemap_present = robots_local.get("sitemap_present")
    if sitemap_present is None:
        sitemap_present = sitemap_local.get("sitemap_present")

    schema_status = (
        str(schema_finding.get("status")) if isinstance(schema_finding, dict) else None
    )
    if schema_status is None and isinstance(detected, dict):
        json_ld_count = detected.get("json_ld_count")
        if isinstance(json_ld_count, int):
            schema_status = "ok" if json_ld_count > 0 else "missing"

    checks = [
        {"name": "title_present", "status": status_from_bool(bool(text_value("title", "title"))), "value": redact_text(text_value("title", "title"))},
        {"name": "meta_description_present", "status": status_from_bool(bool(text_value("meta_description")) or bool(detected.get("meta_description_present"))), "value": redact_text(text_value("meta_description"))},
        {"name": "canonical_own_domain", "status": status_from_bool(bool(canonical and OWN_DOMAIN in canonical)), "value": redact_text(canonical)},
        {"name": "og_title_present", "status": status_from_bool(bool(homepage.get("og_title")) or int(detected.get("open_graph_count") or 0) > 0), "value": redact_text(homepage.get("og_title"), default="from_report_count" if detected.get("open_graph_count") else "-")},
        {"name": "og_description_present", "status": status_from_bool(bool(homepage.get("og_description")) or int(detected.get("open_graph_count") or 0) > 0), "value": redact_text(homepage.get("og_description"), default="from_report_count" if detected.get("open_graph_count") else "-")},
        {"name": "twitter_title_present", "status": status_from_bool(bool(homepage.get("twitter_title")) or int(detected.get("twitter_card_count") or 0) > 0), "value": redact_text(homepage.get("twitter_title"), default="from_report_count" if detected.get("twitter_card_count") else "-")},
        {"name": "twitter_description_present", "status": status_from_bool(bool(homepage.get("twitter_description")) or int(detected.get("twitter_card_count") or 0) > 0), "value": redact_text(homepage.get("twitter_description"), default="from_report_count" if detected.get("twitter_card_count") else "-")},
        {"name": "robots_public_crawl_allowed", "status": status_from_bool(robots_allowed if isinstance(robots_allowed, bool) else None), "value": robots_allowed},
        {"name": "sitemap_present", "status": status_from_bool(sitemap_present if isinstance(sitemap_present, bool) else None), "value": sitemap_present},
        {"name": "schema_status", "status": STATUS_NOT_AVAILABLE if schema_status is None else (STATUS_OK if str(schema_status).lower() == "ok" else STATUS_WARNING), "value": redact_text(schema_status)},
    ]
    statuses = {item["status"] for item in checks}
    if STATUS_WARNING in statuses:
        status = STATUS_WARNING
    elif statuses == {STATUS_NOT_AVAILABLE}:
        status = STATUS_NOT_AVAILABLE
    elif STATUS_NOT_AVAILABLE in statuses:
        status = STATUS_WARNING
    else:
        status = STATUS_OK
    return {
        "status": status,
        "warning_count": count_warnings(checks),
        "checks": checks,
    }


def build_performance_validation(perf_report: Optional[Any]) -> Dict[str, Any]:
    if not isinstance(perf_report, dict):
        checks = [
            {"name": name, "status": STATUS_NOT_AVAILABLE, "value": "not_available"}
            for name in (
                "image_webp_status",
                "lazy_loading_status",
                "external_embed_risk",
                "render_blocking_risk",
                "cache_status",
                "ai_radio_nowplaying_cache_status",
                "origin_5xx_status",
                "source_map_status",
            )
        ]
        return {"status": STATUS_NOT_AVAILABLE, "warning_count": 0, "checks": checks}

    mapping = {
        "image_webp_status": "image_optimization_status",
        "lazy_loading_status": "lazy_loading_status",
        "external_embed_risk": "external_embed_risk",
        "render_blocking_risk": "render_blocking_risk",
        "cache_status": "cache_header_status",
        "ai_radio_nowplaying_cache_status": "ai_radio_nowplaying_cache_status",
        "origin_5xx_status": "origin_5xx_status",
        "source_map_status": "source_map_status",
    }
    checks: List[Dict[str, Any]] = []
    warning_values = {"WARNING", "HIGH", "HIGH_SCRIPT_COUNT_REVIEW", "MANY_EXTERNAL_EMBEDS"}
    for name, source_key in mapping.items():
        value = perf_report.get(source_key)
        if value is None:
            status = STATUS_NOT_AVAILABLE
        else:
            text = str(value).upper()
            status = STATUS_WARNING if text in warning_values or text.startswith("HIGH") else STATUS_OK
        checks.append({"name": name, "status": status, "value": redact_text(value)})
    statuses = {item["status"] for item in checks}
    if STATUS_WARNING in statuses:
        status = STATUS_WARNING
    elif statuses == {STATUS_NOT_AVAILABLE}:
        status = STATUS_NOT_AVAILABLE
    elif STATUS_NOT_AVAILABLE in statuses:
        status = STATUS_WARNING
    else:
        status = STATUS_OK
    return {"status": status, "warning_count": count_warnings(checks), "checks": checks}


def build_safety_validation(manual_checklist: Optional[Any]) -> Dict[str, Any]:
    items = checklist_items(manual_checklist)
    checklist_present = isinstance(manual_checklist, dict)
    productive_change = bool(manual_checklist.get("productive_change", False)) if checklist_present else False
    high_medium_items = [
        item for item in items
        if normalize_risk(item.get("risk_classification")) in {RISK_HIGH, RISK_MEDIUM}
    ]
    non_not_applied = [
        item for item in items
        if item.get("apply_status") != APPLY_NOT_APPLIED
    ]
    checks = [
        {"name": "no_high_medium_items", "status": STATUS_OK if not high_medium_items else STATUS_WARNING, "value": len(high_medium_items)},
        {"name": "all_checklist_apply_status_not_applied", "status": STATUS_OK if not non_not_applied else STATUS_WARNING, "value": len(non_not_applied)},
        {"name": "productive_change_false", "status": STATUS_OK if not productive_change else STATUS_WARNING, "value": productive_change},
        {"name": "no_network_default", "status": STATUS_OK, "value": True},
        {"name": "no_apply_function", "status": STATUS_OK, "value": True},
    ]
    status = STATUS_WARNING if any(item["status"] == STATUS_WARNING for item in checks) else (STATUS_OK if checklist_present else STATUS_NOT_AVAILABLE)
    return {
        "status": status,
        "warning_count": count_warnings(checks),
        "checks": checks,
        "high_medium_item_ids": [redact_text(item.get("checklist_id") or item.get("source_item_id"), max_len=180) for item in high_medium_items],
        "non_not_applied_item_ids": [redact_text(item.get("checklist_id") or item.get("source_item_id"), max_len=180) for item in non_not_applied],
    }


def load_inputs() -> Tuple[Dict[str, Any], Dict[str, str]]:
    data: Dict[str, Any] = {}
    statuses: Dict[str, str] = {}
    for key, path in (
        ("manual_checklist", INPUT_MANUAL_CHECKLIST),
        ("owner_review_pack", INPUT_OWNER_REVIEW_PACK),
        ("seo_report", INPUT_SEO_REPORT),
        ("performance_report", INPUT_PERFORMANCE_REPORT),
        ("master_report", INPUT_MASTER_REPORT),
    ):
        value, status = read_optional_json(path)
        data[key] = value
        statuses[key] = status
    homepage, homepage_status = read_optional_text(INPUT_HOMEPAGE_HTML, {".html", ".htm"})
    headers, headers_status = read_optional_text(INPUT_HEADERS_HOMEPAGE, {".txt"})
    robots, robots_status = read_optional_text(INPUT_ROBOTS, {".txt"})
    sitemap, sitemap_status = read_optional_text(INPUT_SITEMAP, {".xml"})
    data.update({"homepage_html": homepage, "headers_homepage": headers, "robots_txt": robots, "sitemap_xml": sitemap})
    statuses.update({"homepage_html": homepage_status, "headers_homepage": headers_status, "robots_txt": robots_status, "sitemap_xml": sitemap_status})
    return data, statuses


def build_validation(
    data: Dict[str, Any],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    manual_checklist = data.get("manual_checklist")
    checklist_present = isinstance(manual_checklist, dict)
    items = checklist_items(manual_checklist)

    homepage = parse_homepage(data.get("homepage_html") if isinstance(data.get("homepage_html"), str) else None)
    robots_local = parse_robots_local(data.get("robots_txt") if isinstance(data.get("robots_txt"), str) else None)
    sitemap_local = parse_sitemap_local(data.get("sitemap_xml") if isinstance(data.get("sitemap_xml"), str) else None)
    seo_validation = build_seo_validation(homepage, robots_local, sitemap_local, data.get("seo_report"))
    performance_validation = build_performance_validation(data.get("performance_report"))
    safety_validation = build_safety_validation(manual_checklist)

    validation_available = any(
        input_statuses.get(key) == "ok"
        for key in ("homepage_html", "robots_txt", "sitemap_xml", "seo_report", "performance_report")
    )
    validation_warning_count = (
        seo_validation.get("warning_count", 0)
        + performance_validation.get("warning_count", 0)
        + safety_validation.get("warning_count", 0)
    )
    safety_warning = safety_validation.get("status") == STATUS_WARNING
    if not checklist_present:
        status = STATUS_NOT_AVAILABLE
    elif safety_warning:
        status = STATUS_VALIDATION_WARNING
    elif not validation_available:
        status = STATUS_NOT_AVAILABLE
    else:
        status = STATUS_READY

    next_owner_steps: List[str] = []
    if not checklist_present:
        next_owner_steps.append("Run sentinel_manual_apply_checklist.py before post-manual validation.")
    if seo_validation.get("status") == STATUS_WARNING:
        next_owner_steps.append("Review SEO warnings before considering any manual publication complete.")
    if performance_validation.get("status") == STATUS_WARNING:
        next_owner_steps.append("Review performance warnings; do not infer that a manual SEO change caused them without evidence.")
    if safety_warning:
        next_owner_steps.append("Safety validation warning: investigate checklist risk/apply_status before any owner action.")
    if not next_owner_steps:
        next_owner_steps.append("Use this report as owner validation evidence; no Sentinel apply action is available.")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "validation_status": status,
        "read_only": True,
        "productive_change": False,
        "network_access": False,
        "apply_function": False,
        "secrets_output": False,
        "no_network_default": True,
        "no_apply_function": True,
        "forbidden_mutations": {
            "wordpress": False,
            "htaccess": False,
            "cloudflare": False,
            "nginx": False,
            "external_write": False,
            "cms_write": False,
        },
        "allowed_write_roots": [str(root) for root in ALLOWED_WRITE_ROOTS],
        "input_statuses": dict(sorted(input_statuses.items())),
        "checklist_items_count": len(items),
        "validation_available": validation_available,
        "validation_warning_count": validation_warning_count,
        "seo_validation": seo_validation,
        "performance_validation": performance_validation,
        "safety_validation": safety_validation,
        "next_owner_steps": next_owner_steps,
        "outputs": {
            "report_md": str(REPORT_MD),
            "report_json": str(REPORT_JSON),
            "validation_md": str(VALIDATION_MD),
            "validation_json": str(VALIDATION_JSON),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = [
        "# Post Manual Change Validation",
        "",
        f"- Generated (UTC): `{redact_text(report.get('generated_at_utc'))}`",
        f"- Status: `{redact_text(report.get('status'))}`",
        f"- Checklist items: `{report.get('checklist_items_count')}`",
        f"- Validation available: `{str(bool(report.get('validation_available'))).lower()}`",
        f"- Validation warning count: `{report.get('validation_warning_count')}`",
        "",
        "## SEO Validation",
        "",
        f"- Status: `{redact_text(report.get('seo_validation', {}).get('status'))}`",
        "",
        "| Check | Status | Value |",
        "|---|---|---|",
    ]
    for item in report.get("seo_validation", {}).get("checks", []):
        if isinstance(item, dict):
            lines.append(f"| `{redact_text(item.get('name'))}` | `{redact_text(item.get('status'))}` | `{redact_text(item.get('value'))}` |")
    lines.extend(
        [
            "",
            "## Performance Validation",
            "",
            f"- Status: `{redact_text(report.get('performance_validation', {}).get('status'))}`",
            "",
            "| Check | Status | Value |",
            "|---|---|---|",
        ]
    )
    for item in report.get("performance_validation", {}).get("checks", []):
        if isinstance(item, dict):
            lines.append(f"| `{redact_text(item.get('name'))}` | `{redact_text(item.get('status'))}` | `{redact_text(item.get('value'))}` |")
    lines.extend(
        [
            "",
            "## Safety Validation",
            "",
            f"- Status: `{redact_text(report.get('safety_validation', {}).get('status'))}`",
            "",
            "| Check | Status | Value |",
            "|---|---|---|",
        ]
    )
    for item in report.get("safety_validation", {}).get("checks", []):
        if isinstance(item, dict):
            lines.append(f"| `{redact_text(item.get('name'))}` | `{redact_text(item.get('status'))}` | `{redact_text(item.get('value'))}` |")
    lines.extend(["", "## Next Owner Steps", ""])
    for step in report.get("next_owner_steps", []):
        lines.append(f"- {redact_text(step)}")
    lines.extend(
        [
            "",
            "## Safety Boundaries",
            "",
            "- Keine Live-Aenderungen.",
            "- Kein Login, keine API, keine Netzwerkabfrage im Default-Modus.",
            "- Keine WordPress-, .htaccess-, Cloudflare- oder Nginx-Aenderung.",
            "- Keine Apply-Funktion.",
            "",
        ]
    )
    return "\n".join(lines)


def build_audit_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "timestamp_utc": report.get("generated_at_utc"),
            "schema_version": SCHEMA_VERSION,
            "event": "post_manual_validation_summary",
            "status": report.get("status"),
            "checklist_items_count": report.get("checklist_items_count"),
            "validation_available": bool(report.get("validation_available")),
            "seo_validation_status": report.get("seo_validation", {}).get("status"),
            "performance_validation_status": report.get("performance_validation", {}).get("status"),
            "safety_validation_status": report.get("safety_validation", {}).get("status"),
            "validation_warning_count": report.get("validation_warning_count"),
            "productive_change": bool(report.get("productive_change")),
            "network_access": bool(report.get("network_access")),
            "apply_function": bool(report.get("apply_function")),
        }
    ]


def run_self_tests() -> int:
    assert_allowed_write(REPORT_JSON)
    assert_allowed_write(VALIDATION_JSON)
    assert_allowed_write(AUDIT_JSONL)
    try:
        assert_allowed_write(PROJECT_DIR / "drafts/manual/not-allowed.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")
    assert redact_text("password=abc123") == "[redacted]"

    html = """<html><head><title>T</title><meta name="description" content="D">
    <link rel="canonical" href="https://electri-c-ity-studios-24-7.com/">
    <meta property="og:title" content="OG"><meta property="og:description" content="OGD">
    <meta name="twitter:title" content="TW"><meta name="twitter:description" content="TWD">
    </head><body></body></html>"""
    parsed = parse_homepage(html)
    assert parsed["title"] == "T"
    assert parsed["canonical"] == "https://electri-c-ity-studios-24-7.com/"

    checklist = {
        "productive_change": False,
        "checklist_items": [
            {"checklist_id": "ok", "risk_classification": "LOW", "apply_status": "not_applied"},
            {"checklist_id": "bad-risk", "risk_classification": "MEDIUM", "apply_status": "not_applied"},
            {"checklist_id": "bad-apply", "risk_classification": "LOW", "apply_status": "applied"},
        ],
    }
    data = {
        "manual_checklist": checklist,
        "homepage_html": html,
        "robots_txt": "User-agent: *\nAllow: /\nSitemap: https://electri-c-ity-studios-24-7.com/sitemap.xml\n",
        "sitemap_xml": "<urlset><url><loc>https://electri-c-ity-studios-24-7.com/</loc></url></urlset>",
        "seo_report": {"detected_homepage_seo": {"json_ld_count": 1}},
        "performance_report": {
            "image_optimization_status": "OK",
            "lazy_loading_status": "OK",
            "external_embed_risk": "OK",
            "render_blocking_risk": "OK",
            "cache_header_status": "HTML_NO_CACHE",
            "ai_radio_nowplaying_cache_status": "MICROCACHE_DEPLOYED",
            "origin_5xx_status": "DIAGNOSTIC_ONLY",
            "source_map_status": "OK",
        },
    }
    statuses = {key: "ok" for key in data}
    report = build_validation(data, statuses, generated_at="T")
    assert report["status"] == STATUS_VALIDATION_WARNING
    assert report["safety_validation"]["status"] == STATUS_WARNING
    assert report["productive_change"] is False
    assert report["network_access"] is False
    assert report["apply_function"] is False

    good_checklist = {"productive_change": False, "checklist_items": [{"checklist_id": "ok", "risk_classification": "LOW", "apply_status": "not_applied"}]}
    good = dict(data)
    good["manual_checklist"] = good_checklist
    good_report = build_validation(good, statuses, generated_at="T")
    assert good_report["status"] == STATUS_READY
    assert good_report["safety_validation"]["status"] == STATUS_OK

    missing = build_validation({}, {}, generated_at="T")
    assert missing["status"] == STATUS_NOT_AVAILABLE
    assert missing["checklist_items_count"] == 0
    assert missing["validation_available"] is False
    md = render_markdown(good_report)
    assert "Post Manual Change Validation" in md

    print("post-manual-validation self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Post Manual Change Validation (read-only; no apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety/unit tests.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()
    data, statuses = load_inputs()
    report = build_validation(data, statuses)
    markdown = render_markdown(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, markdown)
    write_json_atomic(VALIDATION_JSON, report)
    write_text_atomic(VALIDATION_MD, markdown)
    append_jsonl(AUDIT_JSONL, build_audit_records(report))
    print(f"Post manual validation report written: {REPORT_MD}")
    print(f"Post manual validation JSON written: {REPORT_JSON}")
    print(f"Post manual validation checklist written: {VALIDATION_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
