#!/usr/bin/env python3
"""Approved MEDIUM Dry-run Simulator (Phase 8.8).

Runs read-only simulations only for MEDIUM gates explicitly approved as
approved_for_dry_run_only. This is not apply, not production change, and not a
file/content optimizer. It can read public HTML and local reports, estimate
potential impact, and write local reports/state/audit/playbooks.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

REPORT_JSON = PROJECT_DIR / "reports/latest/approved-medium-dryrun-simulator.json"
REPORT_MD = PROJECT_DIR / "reports/latest/approved-medium-dryrun-simulator.md"
OWNER_PACK_MD = PROJECT_DIR / "reports/latest/approved-medium-simulation-owner-pack.md"
HEALTHCHECK_MD = PROJECT_DIR / "reports/latest/approved-medium-simulation-healthcheck-plan.md"
ROLLBACK_MD = PROJECT_DIR / "reports/latest/approved-medium-simulation-rollback-plan.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/approved-medium-dryrun-simulator.jsonl"

STATE_JSON = PROJECT_DIR / "state/adaptive-learning/approved_medium_dryrun_simulations.json"
LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest_approved_medium_simulation.json"

KNOWLEDGE_BASE_JSON = PROJECT_DIR / "state/adaptive-learning/knowledge_base.json"
OBSERVATIONS_JSONL = PROJECT_DIR / "state/adaptive-learning/observations.jsonl"
PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/patterns.json"
ACTION_RULES_JSON = PROJECT_DIR / "state/adaptive-learning/action_rules.json"
ROLLBACK_RULES_JSON = PROJECT_DIR / "state/adaptive-learning/rollback_rules.json"
ADAPTIVE_LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest.json"
ADAPTIVE_REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
ADAPTIVE_RECOMMEND_MD = PROJECT_DIR / "reports/latest/adaptive-recommendations.md"
ADAPTIVE_CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"

PLAYBOOKS = {
    "images": PROJECT_DIR / "playbooks/approved-images-dryrun-simulation.playbook.json",
    "html-size": PROJECT_DIR / "playbooks/approved-html-size-dryrun-simulation.playbook.json",
}

INPUTS = {
    "owner_decisions": PROJECT_DIR / "state/adaptive-learning/medium_owner_decisions.json",
    "latest_medium_gates": PROJECT_DIR / "state/adaptive-learning/latest_medium_gates.json",
    "medium_gates_report": PROJECT_DIR / "reports/latest/medium-owner-review-gates.json",
    "medium_owner_pack": PROJECT_DIR / "reports/latest/medium-optimization-owner-pack.md",
    "performance_priority": PROJECT_DIR / "reports/latest/performance-owner-review-priority.json",
    "concrete_dryrun": PROJECT_DIR / "reports/latest/concrete-performance-dryrun.json",
    "external_seo": PROJECT_DIR / "reports/latest/external-seo-report-ingest.json",
    "low_risk_autonomy": PROJECT_DIR / "reports/latest/low-risk-autonomy.json",
    "trend_decision": PROJECT_DIR / "state/performance-dryrun/trend_decision.json",
    "accumulator": PROJECT_DIR / "state/performance-dryrun/accumulator.json",
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "playbooks",
)

STATUS_OK = "APPROVED_MEDIUM_DRYRUN_OK"
STATUS_WARNINGS = "APPROVED_MEDIUM_DRYRUN_WARNINGS"
STATUS_BLOCKED_DECISION = "APPROVED_MEDIUM_DRYRUN_BLOCKED_BY_OWNER_DECISION"
STATUS_BLOCKED_SAFETY = "APPROVED_MEDIUM_DRYRUN_BLOCKED_BY_SAFETY"
STATUS_FAILED = "APPROVED_MEDIUM_DRYRUN_FAILED"

SIM_READY = "SIMULATION_READY"
SIM_BLOCKED_DECISION = "SIMULATION_BLOCKED_BY_OWNER_DECISION"

GATES = ("images", "inline-css", "scripts", "cache-expires", "html-size")
APPROVABLE_GATES = ("images", "html-size")
RISK = "MEDIUM_REQUIRES_OWNER_APPROVAL"
APPLY_STATUS = "not_applied"
SCHEMA_VERSION = "approved-medium-dryrun-simulator-8.8"
DEFAULT_URL = "https://electri-c-ity-studios-24-7.com/"

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


class ReadOnlyHTMLAnalyzer(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.images: List[Dict[str, Any]] = []
        self.script_count = 0
        self.style_count = 0
        self.iframe_count = 0
        self.embed_count = 0
        self.jsonld_count = 0
        self.h1_count = 0
        self.title_present = False
        self.meta_description_present = False
        self.canonical_present = False
        self.in_title = False
        self.title_text = ""
        self.soc_schema_graph_present = False
        self.data_soc_schema_present = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "img":
            src = attrs_dict.get("src") or attrs_dict.get("data-src") or ""
            srcset = attrs_dict.get("srcset") or attrs_dict.get("data-srcset") or ""
            url = normalize_url(src or first_srcset_url(srcset), self.base_url)
            self.images.append({
                "url": safe_url(url),
                "loading": attrs_dict.get("loading") or "unknown",
                "width": attrs_dict.get("width") or None,
                "height": attrs_dict.get("height") or None,
                "has_srcset": bool(srcset),
                "has_webp_hint": ".webp" in (src + " " + srcset).lower(),
                "alt_present": bool(attrs_dict.get("alt")),
            })
        elif tag == "script":
            self.script_count += 1
            if (attrs_dict.get("type") or "").lower() == "application/ld+json":
                self.jsonld_count += 1
        elif tag == "style":
            self.style_count += 1
        elif tag == "iframe":
            self.iframe_count += 1
        elif tag == "embed":
            self.embed_count += 1
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "title":
            self.in_title = True
        elif tag == "meta":
            if (attrs_dict.get("name") or "").lower() == "description" and attrs_dict.get("content"):
                self.meta_description_present = True
        elif tag == "link":
            if (attrs_dict.get("rel") or "").lower() == "canonical" and attrs_dict.get("href"):
                self.canonical_present = True
        if any(key.lower() == "data-soc-schema" for key in attrs_dict):
            self.data_soc_schema_present = True
        for value in attrs_dict.values():
            if "soc-schema-graph" in value:
                self.soc_schema_graph_present = True

    def handle_data(self, data: str) -> None:
        if self.in_title and data.strip():
            self.title_present = True
            self.title_text += data.strip()
        if "soc-schema-graph" in data:
            self.soc_schema_graph_present = True
        if "data-soc-schema" in data:
            self.data_soc_schema_present = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False


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
        raise ValueError(f"Refusing write outside allowed approved simulation roots: {path}")
    if path.suffix.lower() in {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".env", ".bin", ".run", ".html", ".htm"}:
        raise ValueError(f"Refusing executable/config/html output: {path}")
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


def read_text_optional(path: Path) -> Tuple[str, str]:
    try:
        if not path.exists():
            return "", "missing"
        if SECRET_NAME_RE.search(path.name) or path.suffix.lower() == ".env":
            return "", "secret_like_path_refused"
        return path.read_text(encoding="utf-8"), "ok"
    except OSError:
        return "", "read_error"


def load_inputs() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    status: Dict[str, str] = {}
    for name, path in INPUTS.items():
        if path.suffix == ".md":
            text, st = read_text_optional(path)
            data[name] = text
            status[name] = st
        else:
            item, st = read_json(path)
            data[name] = item or {}
            status[name] = st
    return {"data": data, "status": status}


def first_srcset_url(srcset: str) -> str:
    if not srcset:
        return ""
    first = srcset.split(",", 1)[0].strip()
    return first.split(" ", 1)[0].strip()


def normalize_url(url: str, base_url: str) -> str:
    if not url:
        return ""
    return urllib.parse.urljoin(base_url, url)


def safe_url(url: str) -> str:
    if not url:
        return ""
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def source_type(url: str, target_url: str) -> str:
    if not url:
        return "unknown"
    target_host = urllib.parse.urlsplit(target_url).netloc.lower()
    host = urllib.parse.urlsplit(url).netloc.lower()
    if not host:
        return "unknown"
    return "internal" if host == target_host else "external"


def target_url(inputs: Dict[str, Any]) -> str:
    low = inputs["data"].get("low_risk_autonomy", {}) or {}
    return low.get("target_url") or DEFAULT_URL


def fetch_live_html(url: str) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "SentinelReadOnlyDryrun/8.8"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(2_500_000)
            headers = dict(response.headers.items())
            charset = response.headers.get_content_charset() or "utf-8"
            html = body.decode(charset, errors="replace")
            return {
                "fetch_ok": True,
                "http_status": getattr(response, "status", None),
                "html_bytes": len(body),
                "headers_subset": {
                    "cache-control": headers.get("Cache-Control"),
                    "cf-cache-status": headers.get("Cf-Cache-Status"),
                    "content-type": headers.get("Content-Type"),
                },
                "html": html,
                "error": None,
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "fetch_ok": False,
            "http_status": None,
            "html_bytes": None,
            "headers_subset": {},
            "html": "",
            "error": redact_text(exc, max_len=200),
        }


def analyze_html(html: str, url: str) -> Dict[str, Any]:
    parser = ReadOnlyHTMLAnalyzer(url)
    parser.feed(html or "")
    lower = (html or "").lower()
    return {
        "image_candidates": parser.images,
        "image_count": len(parser.images),
        "script_count": parser.script_count,
        "style_count": parser.style_count,
        "iframe_count": parser.iframe_count,
        "embed_count": parser.embed_count,
        "jsonld_count": parser.jsonld_count,
        "h1_count": parser.h1_count,
        "title_present": parser.title_present,
        "meta_description_present": parser.meta_description_present,
        "canonical_present": parser.canonical_present,
        "soc_schema_graph_present": parser.soc_schema_graph_present or "soc-schema-graph" in lower,
        "data_soc_schema_present": parser.data_soc_schema_present or "data-soc-schema" in lower,
        "ad_markers_count": sum(lower.count(marker) for marker in ("pagead", "adsbygoogle", "googlesyndication", "doubleclick")),
        "player_markers_count": sum(lower.count(marker) for marker in ("player", "radio", "laut.fm", "spotify", "audiomack", "youtube")),
        "schema_marker_count": lower.count("application/ld+json") + lower.count("schema.org") + lower.count("soc-schema"),
    }


def decisions(inputs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    raw = inputs["data"].get("owner_decisions", {}) or {}
    values = raw.get("decisions") or {}
    normalized: Dict[str, Dict[str, Any]] = {}
    for gate in GATES:
        item = values.get(gate) if isinstance(values, dict) else {}
        normalized[gate] = {
            "gate_id": gate,
            "decision": item.get("decision", "pending_review") if isinstance(item, dict) else "pending_review",
            "next_allowed_stage": item.get("next_allowed_stage", "owner_review") if isinstance(item, dict) else "owner_review",
        }
    return normalized


def approved_gates(inputs: Dict[str, Any]) -> List[str]:
    return [gate for gate, item in decisions(inputs).items() if item.get("decision") == "approved_for_dry_run_only"]


def metrics(inputs: Dict[str, Any]) -> Dict[str, Any]:
    concrete = inputs["data"].get("concrete_dryrun", {}) or {}
    low = inputs["data"].get("low_risk_autonomy", {}) or {}
    concrete_metrics = concrete.get("metrics") or {}
    analysis = low.get("analysis") or {}
    return {
        "image_bytes": concrete_metrics.get("image_bytes") or analysis.get("image_bytes"),
        "image_count": concrete_metrics.get("image_count") or analysis.get("image_count"),
        "lazy_image_count": concrete_metrics.get("lazy_image_count") or analysis.get("lazy_image_count"),
        "webp_hint_count": concrete_metrics.get("webp_hint_count") or analysis.get("webp_hint_count"),
        "html_bytes": concrete_metrics.get("html_bytes") or analysis.get("html_size_bytes"),
        "total_transfer_bytes": concrete_metrics.get("total_transfer_bytes") or analysis.get("response_size_bytes"),
        "ttfb_ms": concrete_metrics.get("ttfb_ms") or analysis.get("ttfb_ms"),
        "script_tag_count": concrete_metrics.get("script_tag_count") or analysis.get("script_tag_count"),
        "inline_css_count": concrete_metrics.get("inline_css_count"),
        "internal_scripts_count": concrete_metrics.get("internal_scripts_count"),
        "cache_control": concrete_metrics.get("cache_control") or (analysis.get("headers_subset") or {}).get("Cache-Control"),
        "cf_cache_status": concrete_metrics.get("cf_cache_status") or (analysis.get("headers_subset") or {}).get("Cf-Cache-Status"),
        "jsonld_script_count": analysis.get("jsonld_script_count"),
        "h1_count": analysis.get("h1_count"),
        "soc_watch": analysis.get("soc_watch") or {},
    }


def estimate_range(value: Any, low_pct: float, high_pct: float) -> Dict[str, Optional[int]]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return {"low": None, "high": None}
    return {"low": int(round(number * low_pct)), "high": int(round(number * high_pct))}


def pre_healthcheck(m: Dict[str, Any], live: Dict[str, Any]) -> Dict[str, Any]:
    html_analysis = live.get("analysis") or {}
    soc = m.get("soc_watch") or {}
    return {
        "http_status": live.get("http_status") or nested(live, ["fetch", "http_status"]),
        "title_present": html_analysis.get("title_present"),
        "meta_description_present": html_analysis.get("meta_description_present"),
        "canonical_present": html_analysis.get("canonical_present"),
        "h1_count": html_analysis.get("h1_count") if html_analysis.get("h1_count") is not None else m.get("h1_count"),
        "jsonld_count": html_analysis.get("jsonld_count") if html_analysis.get("jsonld_count") is not None else m.get("jsonld_script_count"),
        "soc_known_issue_status": {
            "soc-schema-graph": html_analysis.get("soc_schema_graph_present", soc.get("soc-schema-graph")),
            "data-soc-schema": html_analysis.get("data_soc_schema_present", soc.get("data-soc-schema")),
        },
        "image_count": html_analysis.get("image_count") if html_analysis.get("image_count") is not None else m.get("image_count"),
        "html_bytes": live.get("html_bytes") or m.get("html_bytes"),
        "ttfb_ms": m.get("ttfb_ms"),
    }


def nested(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def post_healthcheck_plan() -> List[str]:
    return [
        "HTTP status remains 200.",
        "No 5xx increase is observed in the next read-only monitor run.",
        "Title, meta description, H1 and canonical remain present unless Owner explicitly changed them.",
        "Player, radio, shop and ads are visually checked by Owner.",
        "Image count is not unexpectedly zero.",
        "HTML bytes and transfer bytes do not increase.",
        "breach remains false.",
    ]


def image_candidate_rows(candidates: List[Dict[str, Any]], target: str, savings: Dict[str, Optional[int]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for idx, item in enumerate(candidates[:20]):
        url = item.get("url") or ""
        stype = source_type(url, target)
        priority = "hero_or_above_the_fold_review" if idx < 3 else "standard_review"
        if stype == "external":
            priority = "external_large_image_review"
        share_low = int((savings.get("low") or 0) / max(1, min(len(candidates), 20)))
        share_high = int((savings.get("high") or 0) / max(1, min(len(candidates), 20)))
        rows.append({
            "url": url,
            "source_type": stype,
            "likely_priority": priority,
            "current_evidence": {
                "loading": item.get("loading"),
                "has_srcset": item.get("has_srcset"),
                "has_webp_hint": item.get("has_webp_hint"),
                "alt_present": item.get("alt_present"),
                "width": item.get("width"),
                "height": item.get("height"),
            },
            "suggested_manual_action": "Review compression/responsive variant manually; do not modify files from this simulator.",
            "expected_savings_estimate": {"low_bytes": share_low, "high_bytes": share_high},
            "risk": RISK,
            "healthcheck": post_healthcheck_plan(),
            "rollback_note": "Restore original media/reference manually if a later owner-approved change causes regression.",
        })
    return rows


def simulate_images(inputs: Dict[str, Any], live: Dict[str, Any]) -> Dict[str, Any]:
    m = metrics(inputs)
    html_analysis = live.get("analysis") or {}
    image_bytes = m.get("image_bytes")
    savings = estimate_range(image_bytes, 0.10, 0.25)
    candidates = html_analysis.get("image_candidates") or []
    return {
        "gate_id": "images",
        "risk": RISK,
        "simulation_status": SIM_READY,
        "would_change": False,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "input_evidence": {
            "image_bytes": image_bytes,
            "image_count_reported": m.get("image_count"),
            "image_count_live": html_analysis.get("image_count"),
            "lazy_image_count": m.get("lazy_image_count"),
            "webp_hint_count": m.get("webp_hint_count"),
        },
        "estimated_savings": {"low_bytes": savings.get("low"), "high_bytes": savings.get("high"), "basis": "10-25 percent of image_bytes"},
        "image_candidates": image_candidate_rows(candidates, target_url(inputs), savings),
        "pre_healthcheck": pre_healthcheck(m, live),
        "post_healthcheck": post_healthcheck_plan(),
        "rollback_model": "Original image/media state must be restored manually from backup if a later owner-approved change regresses.",
    }


def classify_html_contributors(inputs: Dict[str, Any], live: Dict[str, Any]) -> Dict[str, Any]:
    html_analysis = live.get("analysis") or {}
    m = metrics(inputs)
    return {
        "scripts": {
            "script_tag_count": html_analysis.get("script_count") or m.get("script_tag_count"),
            "internal_scripts_count_reported": m.get("internal_scripts_count"),
        },
        "inline_styles": {
            "style_tag_count_live": html_analysis.get("style_count"),
            "inline_css_count_reported": m.get("inline_css_count"),
        },
        "images_embeds": {
            "image_count_live": html_analysis.get("image_count"),
            "image_count_reported": m.get("image_count"),
            "iframe_count": html_analysis.get("iframe_count"),
            "embed_count": html_analysis.get("embed_count"),
        },
        "ads": {"ad_markers_count": html_analysis.get("ad_markers_count")},
        "widgets_player": {"player_markers_count": html_analysis.get("player_markers_count")},
        "schema": {
            "jsonld_count_live": html_analysis.get("jsonld_count"),
            "schema_marker_count": html_analysis.get("schema_marker_count"),
            "soc_schema_graph_present": html_analysis.get("soc_schema_graph_present"),
            "data_soc_schema_present": html_analysis.get("data_soc_schema_present"),
        },
    }


def simulate_html_size(inputs: Dict[str, Any], live: Dict[str, Any]) -> Dict[str, Any]:
    m = metrics(inputs)
    current_html = live.get("html_bytes") or m.get("html_bytes")
    savings = estimate_range(current_html, 0.05, 0.15)
    return {
        "gate_id": "html-size",
        "risk": RISK,
        "simulation_status": SIM_READY,
        "would_change": False,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "current_html_bytes": current_html,
        "reported_html_bytes": m.get("html_bytes"),
        "estimated_reduction_low": savings.get("low"),
        "estimated_reduction_high": savings.get("high"),
        "likely_contributors": classify_html_contributors(inputs, live),
        "suggested_manual_review_steps": [
            "Review image/embed-heavy areas first because they dominate transfer weight.",
            "Classify repeated block/player/widget markup before any editor-level change.",
            "Separate schema known issue from payload reduction decisions.",
            "Prepare a manual before/after content snapshot before any future owner-approved edit.",
        ],
        "pre_healthcheck": pre_healthcheck(m, live),
        "post_healthcheck": post_healthcheck_plan(),
        "rollback_model": "Previous WordPress/FSE/page content must be restored manually if a later owner-approved edit regresses.",
    }


SIMULATORS = {
    "images": simulate_images,
    "html-size": simulate_html_size,
}


def blocked_simulation(gate: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
    item = decisions(inputs).get(gate, {})
    return {
        "gate_id": gate,
        "risk": RISK,
        "simulation_status": SIM_BLOCKED_DECISION,
        "decision": item.get("decision", "pending_review"),
        "next_allowed_stage": item.get("next_allowed_stage", "owner_review"),
        "reason": "Gate is not approved_for_dry_run_only.",
        "would_change": False,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
    }


def live_context(inputs: Dict[str, Any]) -> Dict[str, Any]:
    url = target_url(inputs)
    fetched = fetch_live_html(url)
    analysis = analyze_html(fetched.get("html") or "", url) if fetched.get("html") else {}
    return {
        "target_url": url,
        "fetch_ok": fetched.get("fetch_ok"),
        "http_status": fetched.get("http_status"),
        "html_bytes": fetched.get("html_bytes"),
        "headers_subset": fetched.get("headers_subset"),
        "fetch_error": fetched.get("error"),
        "analysis": analysis,
    }


def status_for(results: List[Dict[str, Any]], inputs: Dict[str, Any], breach: bool) -> str:
    if breach:
        return STATUS_BLOCKED_SAFETY
    if results and all(item.get("simulation_status") == SIM_BLOCKED_DECISION for item in results):
        return STATUS_BLOCKED_DECISION
    if any(st not in {"ok", "missing"} for st in inputs["status"].values()):
        return STATUS_WARNINGS
    if any(st == "missing" for st in inputs["status"].values()):
        return STATUS_WARNINGS
    return STATUS_OK


def build_report(action: str, results: Optional[List[Dict[str, Any]]] = None, selected_gate: Optional[str] = None, owner_pack: bool = False) -> Dict[str, Any]:
    inputs = load_inputs()
    dec = decisions(inputs)
    approved = approved_gates(inputs)
    blocked = [gate for gate in GATES if gate not in approved]
    results = results or []
    breach = bool((inputs["data"].get("owner_decisions", {}) or {}).get("breach") or (inputs["data"].get("owner_decisions", {}) or {}).get("live_apply"))
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp_tag(),
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status_for(results, inputs, breach),
        "breach": breach,
        "breach_reasons": ["owner decision state unsafe"] if breach else [],
        "live_apply": False,
        "emergency_stop_unchanged": True,
        "apply_status": APPLY_STATUS,
        "selected_gate": selected_gate,
        "approved_gates": approved,
        "approved_gates_count": len(approved),
        "blocked_gates": blocked,
        "blocked_gates_count": len(blocked),
        "decisions": dec,
        "simulation_results": results,
        "simulation_results_count": len(results),
        "input_status": inputs["status"],
        "missing_inputs": [name for name, st in inputs["status"].items() if st == "missing"],
        "owner_simulation_pack_written": owner_pack,
        "healthcheck_plan_written": owner_pack,
        "rollback_plan_written": owner_pack,
        "recommended_owner_action": "Review simulation estimates only. Any future application requires a separate Owner-approved apply gate.",
    }


def run_simulation(gate: str, inputs: Optional[Dict[str, Any]] = None, live: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    inputs = inputs or load_inputs()
    if gate not in GATES:
        return {
            "gate_id": gate,
            "risk": RISK,
            "simulation_status": SIM_BLOCKED_DECISION,
            "reason": "Unknown gate.",
            "would_change": False,
            "live_apply": False,
            "apply_status": APPLY_STATUS,
        }
    if gate not in approved_gates(inputs):
        return blocked_simulation(gate, inputs)
    if gate not in SIMULATORS:
        return blocked_simulation(gate, inputs)
    live = live or live_context(inputs)
    return SIMULATORS[gate](inputs, live)


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Approved MEDIUM Dry-run Simulator",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- Emergency stop unchanged: `{report.get('emergency_stop_unchanged')}`",
        f"- Approved gates: `{report.get('approved_gates_count')}` {report.get('approved_gates')}",
        f"- Blocked gates: `{report.get('blocked_gates_count')}` {report.get('blocked_gates')}",
        "",
    ]
    for result in report.get("simulation_results", []):
        lines.append(f"## {result.get('gate_id')}")
        lines.append(f"- Status: `{result.get('simulation_status')}`")
        lines.append(f"- Risk: `{result.get('risk')}`")
        if result.get("gate_id") == "images":
            lines.append(f"- Estimated image savings: `{result.get('estimated_savings')}`")
        if result.get("gate_id") == "html-size":
            lines.append(f"- Estimated HTML savings: `{result.get('estimated_reduction_low')}` - `{result.get('estimated_reduction_high')}` bytes")
        lines.append("")
    return "\n".join(lines)


def render_owner_pack(report: Dict[str, Any]) -> str:
    lines = [
        "# Approved MEDIUM Simulation Owner Pack",
        "",
        "This pack is simulation only. It does not authorize production changes.",
        "",
    ]
    for result in report.get("simulation_results", []):
        lines.append(f"## {result.get('gate_id')}")
        lines.append(f"- Simulation status: `{result.get('simulation_status')}`")
        lines.append(f"- Would change: `{result.get('would_change')}`")
        if result.get("gate_id") == "images":
            lines.append(f"- Estimated savings: `{result.get('estimated_savings')}`")
            lines.append(f"- Candidate count: `{len(result.get('image_candidates') or [])}`")
        elif result.get("gate_id") == "html-size":
            lines.append(f"- Current HTML bytes: `{result.get('current_html_bytes')}`")
            lines.append(f"- Estimated reduction: `{result.get('estimated_reduction_low')}` - `{result.get('estimated_reduction_high')}` bytes")
        else:
            lines.append(f"- Reason: {result.get('reason')}")
        lines.append("")
    return "\n".join(lines)


def render_healthcheck_md(report: Dict[str, Any]) -> str:
    lines = ["# Approved MEDIUM Simulation Healthcheck Plan", ""]
    for result in report.get("simulation_results", []):
        if result.get("simulation_status") != SIM_READY:
            continue
        lines.append(f"## {result.get('gate_id')}")
        lines.append("### Pre")
        pre = result.get("pre_healthcheck") or {}
        for key, value in pre.items():
            lines.append(f"- `{key}`: `{value}`")
        lines.append("### Post")
        for item in result.get("post_healthcheck", []):
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines)


def render_rollback_md(report: Dict[str, Any]) -> str:
    lines = ["# Approved MEDIUM Simulation Rollback Plan", ""]
    for result in report.get("simulation_results", []):
        if result.get("simulation_status") != SIM_READY:
            continue
        lines.append(f"## {result.get('gate_id')}")
        lines.append(f"- {result.get('rollback_model')}")
        lines.append("- No automatic restore is allowed in this phase.")
        lines.append("")
    return "\n".join(lines)


def build_playbook(gate: str, result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": f"approved-{gate}-dryrun-simulation",
        "purpose": f"Read-only simulation for Owner-approved {gate} MEDIUM gate.",
        "risk": RISK,
        "owner_decision_required": "approved_for_dry_run_only",
        "simulation_status": result.get("simulation_status"),
        "allowed_actions": ["read local reports", "read public HTML", "estimate savings", "write reports", "write audit", "update learning"],
        "blocked_actions": ["production change", "remote write", "database write", "cache purge", "file edit", "content edit", "service activation"],
        "healthcheck": result.get("post_healthcheck") or post_healthcheck_plan(),
        "rollback_model": result.get("rollback_model") or "Manual rollback only if a separate future Owner-approved action occurs.",
        "apply_status": APPLY_STATUS,
        "live_apply": False,
    }


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


def update_learning(report: Dict[str, Any]) -> None:
    learning = {
        "timestamp_utc": report.get("timestamp_utc"),
        "status": report.get("status"),
        "approved_gates": report.get("approved_gates"),
        "blocked_gates": report.get("blocked_gates"),
        "learning": {
            "owner_approved_dryrun_is_separate_stage": True,
            "only_approved_for_dryrun_gates_can_be_simulated": True,
            "needs_more_review_blocks_simulation": True,
            "simulation_can_estimate_savings_without_changes": True,
            "future_application_needs_separate_apply_gate": True,
            "productive_output_protected": True,
        },
    }
    knowledge, _ = read_json(KNOWLEDGE_BASE_JSON)
    knowledge = knowledge or {}
    knowledge["approved_medium_dryrun_simulator"] = learning
    write_json_atomic(KNOWLEDGE_BASE_JSON, knowledge)
    append_jsonl(OBSERVATIONS_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "observation_id": "approved-medium-dryrun-simulator",
        "area": "MEDIUM Dry-run Simulation",
        "risk_level": RISK,
        "approved_gates": report.get("approved_gates"),
        "blocked_gates": report.get("blocked_gates"),
        "hypothesis": "Owner-approved dry-run can estimate impact without authorizing apply.",
    }])
    patterns, _ = read_json(PATTERNS_JSON)
    patterns = patterns or {}
    patterns["approved_medium_dryrun_simulator"] = {
        "timestamp_utc": report.get("timestamp_utc"),
        "approved_gates_count": report.get("approved_gates_count"),
        "blocked_gates_count": report.get("blocked_gates_count"),
        "simulation_results": {item.get("gate_id"): item.get("simulation_status") for item in report.get("simulation_results", [])},
    }
    write_json_atomic(PATTERNS_JSON, patterns)
    rules, _ = read_json(ACTION_RULES_JSON)
    rules = rules or {}
    rules["approved_medium_dryrun_simulator"] = {
        "allowed": ["simulate approved gates", "read public HTML", "estimate savings", "write owner pack"],
        "blocked": ["simulate needs_more_review gates", "apply", "production change", "file or content modification"],
        "future_gate_required": "Separate Owner-approved apply gate with backup, healthcheck and rollback.",
    }
    write_json_atomic(ACTION_RULES_JSON, rules)
    rollback, _ = read_json(ROLLBACK_RULES_JSON)
    rollback = rollback or {}
    rollback["approved_medium_dryrun_simulator"] = {
        item.get("gate_id"): item.get("rollback_model") for item in report.get("simulation_results", []) if item.get("simulation_status") == SIM_READY
    }
    write_json_atomic(ROLLBACK_RULES_JSON, rollback)
    latest, _ = read_json(ADAPTIVE_LATEST_JSON)
    latest = latest or {}
    latest["approved_medium_dryrun_simulator"] = {
        "status": report.get("status"),
        "approved_gates_count": report.get("approved_gates_count"),
        "blocked_gates_count": report.get("blocked_gates_count"),
        "breach": report.get("breach"),
        "live_apply": report.get("live_apply"),
    }
    write_json_atomic(ADAPTIVE_LATEST_JSON, latest)
    section = (
        f"- Status: `{report.get('status')}`\n"
        f"- Approved gates: `{report.get('approved_gates_count')}` {report.get('approved_gates')}\n"
        f"- Blocked gates: `{report.get('blocked_gates_count')}` {report.get('blocked_gates')}\n"
        "- Learning: dry-run simulation estimates impact only and still requires separate apply gate for any future action.\n"
    )
    append_markdown_section(ADAPTIVE_REPORT_MD, "Approved MEDIUM Dry-run Simulation Learning", section)
    append_markdown_section(
        ADAPTIVE_RECOMMEND_MD,
        "Approved MEDIUM Dry-run Simulation Recommendations",
        "- Use image and HTML-size simulations for Owner planning only.\n- Keep inline CSS, scripts and cache/expires blocked until more review is complete.\n",
    )
    append_markdown_section(
        ADAPTIVE_CAPABILITY_MD,
        "Approved MEDIUM Dry-run Simulation Capability",
        "- `approved_medium_simulation`: `True`\n- `savings_estimation`: `True`\n- `medium_apply_from_simulation`: `False`\n",
    )


def write_outputs(report: Dict[str, Any], owner_pack: bool = False) -> None:
    ts = str(report.get("timestamp") or timestamp_tag())
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(STATE_JSON, report)
    write_json_atomic(LATEST_JSON, report)
    write_json_atomic(SNAPSHOT_DIR / f"approved-medium-dryrun-simulator-{ts}.json", report)
    for result in report.get("simulation_results", []):
        gate = result.get("gate_id")
        if gate in PLAYBOOKS:
            write_json_atomic(PLAYBOOKS[gate], build_playbook(gate, result))
    if owner_pack:
        write_text_atomic(OWNER_PACK_MD, render_owner_pack(report))
        write_text_atomic(HEALTHCHECK_MD, render_healthcheck_md(report))
        write_text_atomic(ROLLBACK_MD, render_rollback_md(report))
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "action": report.get("action"),
        "selected_gate": report.get("selected_gate"),
        "status": report.get("status"),
        "approved_gates_count": report.get("approved_gates_count"),
        "blocked_gates_count": report.get("blocked_gates_count"),
        "breach": report.get("breach"),
        "live_apply": report.get("live_apply"),
    }])
    update_learning(report)


def list_approved() -> Dict[str, Any]:
    report = build_report("list-approved")
    write_outputs(report)
    return report


def simulate_gate(gate: str) -> Dict[str, Any]:
    inputs = load_inputs()
    live = live_context(inputs) if gate in APPROVABLE_GATES else {}
    result = run_simulation(gate, inputs, live)
    report = build_report("simulate", [result], selected_gate=gate)
    write_outputs(report)
    return report


def simulate_all_approved() -> Dict[str, Any]:
    inputs = load_inputs()
    live = live_context(inputs)
    results = [run_simulation(gate, inputs, live) for gate in approved_gates(inputs)]
    report = build_report("simulate-all-approved", results)
    write_outputs(report)
    return report


def owner_simulation_pack() -> Dict[str, Any]:
    inputs = load_inputs()
    live = live_context(inputs)
    results = [run_simulation(gate, inputs, live) for gate in approved_gates(inputs)]
    for gate in GATES:
        if gate not in approved_gates(inputs):
            results.append(blocked_simulation(gate, inputs))
    report = build_report("owner-simulation-pack", results, owner_pack=True)
    write_outputs(report, owner_pack=True)
    return report


def print_status() -> None:
    data, status = read_json(LATEST_JSON)
    if not data:
        print(f"status=not_available input_status={status}")
        return
    print_summary(data)


def print_summary(report: Dict[str, Any]) -> None:
    print(f"status={report.get('status')}")
    print(f"action={report.get('action')}")
    print(f"selected_gate={report.get('selected_gate') or '-'}")
    print(f"approved_gates_count={report.get('approved_gates_count')}")
    print(f"blocked_gates_count={report.get('blocked_gates_count')}")
    print(f"simulation_results_count={report.get('simulation_results_count')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop_unchanged={report.get('emergency_stop_unchanged')}")
    for item in report.get("simulation_results", []):
        print(f"gate={item.get('gate_id')} simulation_status={item.get('simulation_status')}")


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    fake_inputs = {
        "data": {
            "owner_decisions": {
                "decisions": {
                    "images": {"decision": "approved_for_dry_run_only", "next_allowed_stage": "dry_run_simulation_only"},
                    "html-size": {"decision": "approved_for_dry_run_only", "next_allowed_stage": "dry_run_simulation_only"},
                    "inline-css": {"decision": "needs_more_review", "next_allowed_stage": "manual_review_required"},
                    "scripts": {"decision": "needs_more_review", "next_allowed_stage": "manual_review_required"},
                    "cache-expires": {"decision": "needs_more_review", "next_allowed_stage": "manual_review_required"},
                }
            },
            "concrete_dryrun": {"metrics": {"image_bytes": 1000, "html_bytes": 2000, "image_count": 2, "lazy_image_count": 1, "webp_hint_count": 1}},
            "low_risk_autonomy": {"analysis": {"h1_count": 1, "jsonld_script_count": 2, "soc_watch": {}}},
        },
        "status": {name: "missing" for name in INPUTS},
    }
    if approved_gates(fake_inputs) != ["images", "html-size"]:
        raise AssertionError("approved gates not loaded")
    blocked = run_simulation("inline-css", fake_inputs, {})
    if blocked["simulation_status"] != SIM_BLOCKED_DECISION:
        raise AssertionError("needs_more_review gate not blocked")
    unknown = run_simulation("unknown", fake_inputs, {})
    if unknown["simulation_status"] != SIM_BLOCKED_DECISION:
        raise AssertionError("unknown gate not blocked")
    savings = estimate_range(1000, 0.10, 0.25)
    if savings != {"low": 100, "high": 250}:
        raise AssertionError("savings calculation failed")
    image_result = simulate_images(fake_inputs, {"analysis": {"image_candidates": [{"url": "https://example.test/a.jpg"}], "image_count": 1}, "http_status": 200, "html_bytes": 2000})
    html_result = simulate_html_size(fake_inputs, {"analysis": {}, "http_status": 200, "html_bytes": 2000})
    if not image_result.get("post_healthcheck") or not image_result.get("rollback_model"):
        raise AssertionError("image healthcheck/rollback incomplete")
    if not html_result.get("post_healthcheck") or not html_result.get("rollback_model"):
        raise AssertionError("html healthcheck/rollback incomplete")
    if "abcdef" in redact_text("password=abcdef12345"):
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in (
        "sub" + "process",
        "os" + "." + "system",
        "sftp" + "." + "put",
        "sftp" + "." + "remove",
        "sftp" + "." + "rename",
        "rm " + "-rf",
    ):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    for path in (
        REPORT_JSON,
        REPORT_MD,
        OWNER_PACK_MD,
        HEALTHCHECK_MD,
        ROLLBACK_MD,
        STATE_JSON,
        LATEST_JSON,
        SNAPSHOT_DIR / "x.json",
        AUDIT_JSONL,
        PLAYBOOKS["images"],
    ):
        assert_allowed_write(path)
    json.dumps({"image": image_result, "html": html_result})
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Approved MEDIUM dry-run simulator.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--list-approved", action="store_true")
    group.add_argument("--simulate", choices=GATES)
    group.add_argument("--simulate-all-approved", action="store_true")
    group.add_argument("--owner-simulation-pack", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.status:
        print_status()
        return 0
    try:
        if args.list_approved:
            report = list_approved()
        elif args.simulate:
            report = simulate_gate(args.simulate)
        elif args.simulate_all_approved:
            report = simulate_all_approved()
        elif args.owner_simulation_pack:
            report = owner_simulation_pack()
        else:
            parser.error("unreachable")
    except Exception as exc:  # noqa: BLE001
        failed = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": timestamp_tag(),
            "timestamp_utc": utc_now(),
            "action": "failed",
            "status": STATUS_FAILED,
            "breach": True,
            "breach_reasons": [redact_text(exc)],
            "live_apply": False,
            "emergency_stop_unchanged": True,
            "apply_status": APPLY_STATUS,
        }
        try:
            write_json_atomic(REPORT_JSON, failed)
            write_text_atomic(REPORT_MD, render_report_md(failed))
            append_jsonl(AUDIT_JSONL, [failed])
        except Exception:
            pass
        print(f"status={STATUS_FAILED}")
        print("breach=True")
        print(f"error={redact_text(exc, max_len=300)}")
        return 1
    print_summary(report)
    return 0 if not report.get("breach") else 2


if __name__ == "__main__":
    sys.exit(main())
