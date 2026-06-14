#!/usr/bin/env python3
"""MEDIUM Images Next After Success Selector (Phase 8.14).

Read-only candidate selector for the next images canary. It does not optimize,
upload, purge, edit, or apply anything. It ranks known and live HTML image
candidates, blocks the previous under-threshold canary and the successful
Phase 8.13 canary, and writes owner review packs for the next separate recipe
phase.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
TARGET_URL = "https://electri-c-ity-studios-24-7.com/"
REMOTE_ROOT = "/wordpress"
PREVIOUS_FAILED_REMOTE = "/wordpress/wp-content/uploads/2023/08/Acid-Love-Cover-Art-1-2.webp"
PREVIOUS_FAILED_URL = "https://electri-c-ity-studios-24-7.com/wp-content/uploads/2023/08/Acid-Love-Cover-Art-1-2.webp"
PREVIOUS_SUCCESS_REMOTE = "/wordpress/wp-content/uploads/2025/11/Bildschirmfoto-vom-2025-11-26-15-21-16-1-scaled.webp"
PREVIOUS_SUCCESS_URL = "https://electri-c-ity-studios-24-7.com/wp-content/uploads/2025/11/Bildschirmfoto-vom-2025-11-26-15-21-16-1-scaled.webp"
UPLOAD_PREFIX = "/wp-content/uploads/"
SUPPORTED_FORMATS = {".webp": "webp", ".jpg": "jpg", ".jpeg": "jpg", ".png": "png"}

REPORT_JSON = PROJECT_DIR / "reports/latest/medium-images-next-after-success-selector.json"
REPORT_MD = PROJECT_DIR / "reports/latest/medium-images-next-after-success-selector.md"
OWNER_PACK_MD = PROJECT_DIR / "reports/latest/medium-images-next-after-success-owner-pack.md"
BACKUP_PLAN_MD = PROJECT_DIR / "reports/latest/medium-images-next-after-success-backup-plan.md"
RECIPE_PLAN_MD = PROJECT_DIR / "reports/latest/medium-images-next-after-success-recipe-plan.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/medium-images-next-after-success-selector.jsonl"

STATE_JSON = PROJECT_DIR / "state/adaptive-learning/medium_images_next_after_success_selector.json"
LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest_medium_images_next_after_success.json"

PLAYBOOK_SELECTOR = PROJECT_DIR / "playbooks/medium-images-next-after-success-selector.playbook.json"
PLAYBOOK_RECIPE = PROJECT_DIR / "playbooks/medium-images-next-after-success-recipe.playbook.json"

KNOWLEDGE_BASE_JSON = PROJECT_DIR / "state/adaptive-learning/knowledge_base.json"
OBSERVATIONS_JSONL = PROJECT_DIR / "state/adaptive-learning/observations.jsonl"
PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/patterns.json"
ACTION_RULES_JSON = PROJECT_DIR / "state/adaptive-learning/action_rules.json"
ADAPTIVE_LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest.json"
ADAPTIVE_REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
ADAPTIVE_RECOMMEND_MD = PROJECT_DIR / "reports/latest/adaptive-recommendations.md"
ADAPTIVE_CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"

INPUTS = {
    "new_canary_execution": PROJECT_DIR / "reports/latest/medium-images-new-canary-execution.json",
    "new_canary_validation": PROJECT_DIR / "reports/latest/medium-images-new-canary-validation.json",
    "previous_selector": PROJECT_DIR / "reports/latest/medium-images-next-canary-selector.json",
    "dryrun_report": PROJECT_DIR / "reports/latest/approved-medium-dryrun-simulator.json",
    "low_risk_autonomy": PROJECT_DIR / "reports/latest/low-risk-autonomy.json",
    "trend_decision": PROJECT_DIR / "state/performance-dryrun/trend_decision.json",
    "latest_new_canary_execution": PROJECT_DIR / "state/adaptive-learning/latest_medium_images_new_canary_execution.json",
    "latest_previous_next_canary": PROJECT_DIR / "state/adaptive-learning/latest_medium_images_next_canary.json",
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "playbooks",
)

SCHEMA_VERSION = "medium-images-next-after-success-selector-8.14"
STATUS_OK = "MEDIUM_IMAGES_NEXT_AFTER_SUCCESS_SELECTOR_OK"
STATUS_WARNINGS = "MEDIUM_IMAGES_NEXT_AFTER_SUCCESS_SELECTOR_WARNINGS"
STATUS_NO_SAFE = "MEDIUM_IMAGES_NEXT_AFTER_SUCCESS_NO_SAFE_CANDIDATE"
STATUS_BLOCKED = "MEDIUM_IMAGES_NEXT_AFTER_SUCCESS_BLOCKED_BY_SAFETY"
STATUS_FAILED = "MEDIUM_IMAGES_NEXT_AFTER_SUCCESS_FAILED"

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


class ImageHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.images: List[Dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "img":
            return
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        src = attrs_dict.get("src") or attrs_dict.get("data-src") or ""
        srcset = attrs_dict.get("srcset") or attrs_dict.get("data-srcset") or ""
        url = normalize_url(src or first_srcset_url(srcset), self.base_url)
        if not url:
            return
        self.images.append({
            "url": strip_url_query(url),
            "current_evidence": {
                "loading": attrs_dict.get("loading") or "unknown",
                "width": attrs_dict.get("width") or None,
                "height": attrs_dict.get("height") or None,
                "has_srcset": bool(srcset),
                "has_webp_hint": ".webp" in (src + " " + srcset).lower(),
                "alt_present": bool(attrs_dict.get("alt")),
            },
            "source": "live_html",
        })


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
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
        raise ValueError(f"Refusing write outside allowed next-canary roots: {path}")
    if path.suffix.lower() in {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".env", ".bin", ".run", ".php", ".html", ".htm"}:
        raise ValueError(f"Refusing executable/config/html output path: {path}")
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


def append_text_optional(path: Path, content: str) -> None:
    try:
        assert_allowed_write(path)
        assert_safe_content(path, content)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(content)
    except PermissionError:
        return


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


def load_inputs() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    status: Dict[str, str] = {}
    for name, path in INPUTS.items():
        item, st = read_json(path)
        data[name] = item or {}
        status[name] = st
    return {"data": data, "status": status}


def normalize_url(url: str, base_url: str) -> str:
    return urllib.parse.urljoin(base_url, url or "")


def strip_url_query(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def first_srcset_url(srcset: str) -> str:
    if not srcset:
        return ""
    first = srcset.split(",", 1)[0].strip()
    return first.split(" ", 1)[0].strip()


def url_to_remote_path(url: str) -> Optional[str]:
    parsed = urllib.parse.urlsplit(url)
    path = urllib.parse.unquote(parsed.path or "")
    if not path.startswith(UPLOAD_PREFIX):
        return None
    suffix = Path(path).suffix.lower()
    if suffix not in SUPPORTED_FORMATS:
        return None
    return REMOTE_ROOT + path


def source_type(url: str) -> str:
    host = urllib.parse.urlsplit(url).netloc.lower()
    return "internal" if host == "electri-c-ity-studios-24-7.com" else "external"


def image_format(url: str) -> str:
    return SUPPORTED_FORMATS.get(Path(urllib.parse.urlsplit(url).path).suffix.lower(), "unknown")


def fetch_live_images() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    request = urllib.request.Request(TARGET_URL, headers={"User-Agent": "SentinelNextCanarySelector/8.14"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            html = response.read(2_500_000).decode(response.headers.get_content_charset() or "utf-8", errors="replace")
            parser = ImageHTMLParser(TARGET_URL)
            parser.feed(html)
            return parser.images, {"fetch_ok": True, "http_status": getattr(response, "status", None), "html_bytes": len(html.encode("utf-8"))}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return [], {"fetch_ok": False, "error": redact_text(exc, max_len=300)}


def report_candidates(inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for source_name in ("dryrun_report",):
        data = inputs["data"].get(source_name, {}) or {}
        for item in data.get("simulation_results", []) or []:
            if not isinstance(item, dict) or item.get("gate_id") != "images":
                continue
            for candidate in item.get("image_candidates", []) or []:
                if isinstance(candidate, dict) and candidate.get("url"):
                    row = dict(candidate)
                    row["source"] = source_name
                    out.append(row)
    previous = inputs["data"].get("previous_selector", {}) or {}
    for candidate in previous.get("candidates", []) or []:
        if isinstance(candidate, dict) and candidate.get("url"):
            row = dict(candidate)
            row["source"] = "previous_selector"
            out.append(row)
    return out


def size_probe(url: str) -> Dict[str, Any]:
    headers = {"User-Agent": "SentinelNextCanarySizeProbe/8.14"}
    for method in ("HEAD", "GET"):
        try:
            req_headers = dict(headers)
            if method == "GET":
                req_headers["Range"] = "bytes=0-0"
            request = urllib.request.Request(url, method=method, headers=req_headers)
            with urllib.request.urlopen(request, timeout=12) as response:
                content_length = response.headers.get("Content-Length")
                if method == "GET" and response.headers.get("Content-Range"):
                    match = re.search(r"/(\d+)$", response.headers["Content-Range"])
                    if match:
                        content_length = match.group(1)
                try:
                    size = int(content_length) if content_length is not None else None
                except ValueError:
                    size = None
                return {
                    "ok": True,
                    "method": method,
                    "http_status": getattr(response, "status", None),
                    "size_bytes": size,
                    "content_type": response.headers.get("Content-Type"),
                }
        except Exception:
            continue
    return {"ok": False, "size_bytes": None, "content_type": None}


def estimate_savings(size: Optional[int], fmt: str) -> Tuple[Optional[int], Optional[int]]:
    if size is None:
        return None, None
    if fmt == "png":
        low, high = 0.08, 0.22
    elif fmt == "jpg":
        low, high = 0.05, 0.16
    elif fmt == "webp":
        low, high = 0.03, 0.10
    else:
        low, high = 0.0, 0.0
    return int(round(size * low)), int(round(size * high))


def estimate_savings_percent_low(size: Optional[int], low: Optional[int]) -> Optional[float]:
    if not size or low is None:
        return None
    return round((low / size) * 100, 3)


def previous_candidate_status(remote_path: Optional[str], url: str) -> str:
    if remote_path == PREVIOUS_FAILED_REMOTE or url == PREVIOUS_FAILED_URL:
        return "failed_under_threshold"
    if remote_path == PREVIOUS_SUCCESS_REMOTE or url == PREVIOUS_SUCCESS_URL:
        return "successful_uploaded"
    return "not_tested"


def merge_candidates(report_rows: List[Dict[str, Any]], live_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    occurrences: Dict[str, List[str]] = defaultdict(list)
    for row in report_rows + live_rows:
        url = strip_url_query(str(row.get("url") or ""))
        if not url:
            continue
        current = merged.setdefault(url, {"url": url, "sources": [], "raw_evidence": []})
        current["sources"].append(row.get("source") or "unknown")
        current["raw_evidence"].append(row.get("current_evidence") or {})
        priority = row.get("likely_priority")
        if priority:
            occurrences[url].append(str(priority))
        loading = (row.get("current_evidence") or {}).get("loading")
        if loading:
            occurrences[url].append(f"loading:{loading}")
    out: List[Dict[str, Any]] = []
    for url, item in merged.items():
        positions = occurrences.get(url, [])
        likely_position = "hero_or_above_the_fold" if any("hero_or_above" in value for value in positions) else "below_the_fold_or_standard"
        if any(value == "loading:unknown" for value in positions) and likely_position != "hero_or_above_the_fold":
            likely_position = "unknown_position"
        fmt = image_format(url)
        remote_path = url_to_remote_path(url)
        probe = size_probe(url)
        size = probe.get("size_bytes")
        low, high = estimate_savings(size, fmt)
        previous_status = previous_candidate_status(remote_path, url)
        out.append({
            "url": url,
            "remote_path": remote_path,
            "format": fmt,
            "size_bytes": size,
            "source_type": source_type(url),
            "likely_position": likely_position,
            "previous_candidate_status": previous_status,
            "is_previous_failed_candidate": previous_status == "failed_under_threshold",
            "is_previous_successful_candidate": previous_status == "successful_uploaded",
            "estimated_savings_low": low,
            "estimated_savings_high": high,
            "estimated_savings_percent_low": estimate_savings_percent_low(size, low),
            "http_probe": probe,
            "sources": sorted(set(item.get("sources", []))),
            "risk": "MEDIUM_REQUIRES_OWNER_APPROVAL",
        })
    return out


def classify_and_rank(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    larger_safe_exists = any(
        (c.get("size_bytes") or 0) >= 100_000
        and c.get("source_type") == "internal"
        and c.get("remote_path")
        and c.get("previous_candidate_status") == "not_tested"
        and c.get("likely_position") != "hero_or_above_the_fold"
        and c.get("format") != "unknown"
        and (c.get("estimated_savings_percent_low") or 0) >= 3.0
        for c in candidates
    )
    for c in candidates:
        blocked: List[str] = []
        if c.get("is_previous_failed_candidate"):
            blocked.append("previous_failed_under_threshold_candidate")
        if c.get("is_previous_successful_candidate"):
            blocked.append("previous_successful_canary_candidate")
        if c.get("source_type") != "internal":
            blocked.append("external_without_safe_local_path")
        if not c.get("remote_path"):
            blocked.append("missing_unambiguous_remote_path")
        if c.get("format") == "unknown":
            blocked.append("unknown_format")
        if c.get("likely_position") == "hero_or_above_the_fold":
            blocked.append("hero_or_above_the_fold_risk")
        size = c.get("size_bytes") or 0
        if size < 100_000 and larger_safe_exists:
            blocked.append("under_100kb")
        if (c.get("estimated_savings_percent_low") or 0) < 3.0:
            blocked.append("estimated_savings_under_3_percent")
        c["blocked_reason"] = ",".join(blocked) if blocked else ""
        c["blocked"] = bool(blocked)
        c["rank_score"] = rank_score(c)
        c["selected_candidate"] = False
    ranked = sorted(candidates, key=lambda item: (item["blocked"], -item["rank_score"], -(item.get("size_bytes") or 0), item["url"]))
    for c in ranked:
        if not c["blocked"]:
            c["selected_candidate"] = True
            break
    return ranked


def rank_score(c: Dict[str, Any]) -> float:
    score = 0.0
    size = c.get("size_bytes") or 0
    score += min(size / 4096, 120)
    if size >= 150_000:
        score += 35
    elif size >= 100_000:
        score += 20
    if c.get("source_type") == "internal":
        score += 25
    if c.get("remote_path"):
        score += 20
    if c.get("likely_position") == "below_the_fold_or_standard":
        score += 25
    if c.get("format") in {"jpg", "png", "webp"}:
        score += 10
    if c.get("format") == "png":
        score += 12
    elif c.get("format") == "jpg":
        score += 8
    elif c.get("format") == "webp":
        score += 4
    if c.get("estimated_savings_low") and c["estimated_savings_low"] > 3000:
        score += 10
    if c.get("is_previous_failed_candidate"):
        score -= 1000
    if c.get("is_previous_successful_candidate"):
        score -= 1000
    if (c.get("estimated_savings_percent_low") or 0) >= 3.0:
        score += 12
    if c.get("likely_position") == "hero_or_above_the_fold":
        score -= 500
    if c.get("blocked_reason"):
        score -= 250
    return round(score, 3)


def collect_ranked_candidates() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    inputs = load_inputs()
    live_rows, live_status = fetch_live_images()
    rows = merge_candidates(report_candidates(inputs), live_rows)
    ranked = classify_and_rank(rows)
    return {"inputs": inputs, "live_status": live_status}, ranked


def build_report(action: str, write_pack: bool = False) -> Dict[str, Any]:
    context, ranked = collect_ranked_candidates()
    inputs = context["inputs"]
    selected = next((c for c in ranked if c.get("selected_candidate")), None)
    blocked_count = sum(1 for c in ranked if c.get("blocked"))
    safe_count = sum(1 for c in ranked if not c.get("blocked"))
    breach_reasons = safety_reasons(inputs)
    if breach_reasons:
        status = STATUS_BLOCKED
        breach = True
    elif not selected:
        status = STATUS_NO_SAFE
        breach = False
    elif input_missing(inputs):
        status = STATUS_WARNINGS
        breach = False
    else:
        status = STATUS_OK
        breach = False
    timestamp = timestamp_tag()
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp,
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status,
        "breach": breach,
        "breach_reasons": breach_reasons,
        "live_apply": False,
        "global_live_autonomy": False,
        "emergency_stop_unchanged": True,
        "upload_executed": False,
        "optimization_executed": False,
        "candidates_count": len(ranked),
        "blocked_candidates_count": blocked_count,
        "safe_candidates_count": safe_count,
        "selected_candidate": selected,
        "candidates": ranked,
        "missing_inputs": input_missing(inputs),
        "input_status": inputs["status"],
        "live_html_status": context["live_status"],
        "owner_pack_written": write_pack,
        "backup_plan_written": write_pack,
        "recipe_plan_written": write_pack,
        "recommended_owner_action": recommended_owner_action(status, selected),
    }
    return report


def input_missing(inputs: Dict[str, Any]) -> List[str]:
    return [name for name, status in inputs["status"].items() if status != "ok"]


def safety_reasons(inputs: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    for name, data in inputs["data"].items():
        if isinstance(data, dict):
            if data.get("breach") is True:
                reasons.append(f"{name}_breach")
            if data.get("live_apply") is True:
                reasons.append(f"{name}_live_apply")
    return sorted(set(reasons))


def recommended_owner_action(status: str, selected: Optional[Dict[str, Any]]) -> str:
    if status == STATUS_BLOCKED:
        return "Do not proceed. Resolve safety blocker before selecting another canary."
    if not selected:
        return "No safe next image canary candidate found. Continue manual image review."
    return "Review the selected next canary candidate. A separate Canary Recipe phase is required before any upload."


def render_report_md(report: Dict[str, Any]) -> str:
    selected = report.get("selected_candidate") or {}
    lines = [
        "# MEDIUM Images Next After Success Selector",
        "",
        f"- status: `{report.get('status')}`",
        f"- candidates_count: `{report.get('candidates_count')}`",
        f"- safe_candidates_count: `{report.get('safe_candidates_count')}`",
        f"- blocked_candidates_count: `{report.get('blocked_candidates_count')}`",
        f"- breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        "",
        "No upload or optimization is performed in this phase.",
        "",
        "## Selected Candidate",
    ]
    if selected:
        lines.extend([
            f"- url: `{selected.get('url')}`",
            f"- remote_path: `{selected.get('remote_path')}`",
            f"- size_bytes: `{selected.get('size_bytes')}`",
            f"- format: `{selected.get('format')}`",
            f"- estimated_savings_low: `{selected.get('estimated_savings_low')}`",
            f"- estimated_savings_high: `{selected.get('estimated_savings_high')}`",
            f"- estimated_savings_percent_low: `{selected.get('estimated_savings_percent_low')}`",
            f"- rank_score: `{selected.get('rank_score')}`",
        ])
    else:
        lines.append("- none")
    lines.extend(["", "## Top Candidates"])
    for c in report.get("candidates", [])[:10]:
        lines.append(f"- `{c.get('rank_score')}` `{c.get('size_bytes')}` `{c.get('format')}` `{c.get('blocked_reason') or 'safe'}` {c.get('url')}")
    lines.extend(["", "## Owner Action", report.get("recommended_owner_action", "-"), ""])
    return "\n".join(lines)


def render_owner_pack_md(report: Dict[str, Any]) -> str:
    selected = report.get("selected_candidate") or {}
    return "\n".join([
        "# MEDIUM Images Next After Success Owner Pack",
        "",
        "This is read-only candidate selection. No upload and no optimization were performed.",
        "",
        f"- selected_url: `{selected.get('url', '-')}`",
        f"- selected_remote_path: `{selected.get('remote_path', '-')}`",
        f"- selected_size_bytes: `{selected.get('size_bytes', '-')}`",
        f"- estimated_savings_low: `{selected.get('estimated_savings_low', '-')}`",
        f"- estimated_savings_high: `{selected.get('estimated_savings_high', '-')}`",
        f"- estimated_savings_percent_low: `{selected.get('estimated_savings_percent_low', '-')}`",
        "",
        "A separate Canary Recipe phase must verify backup, tooling, local optimization, threshold, healthcheck and rollback before any upload.",
        "",
    ])


def render_backup_plan_md(report: Dict[str, Any]) -> str:
    selected = report.get("selected_candidate") or {}
    return "\n".join([
        "# MEDIUM Images Next After Success Backup Plan",
        "",
        f"- remote_path: `{selected.get('remote_path', '-')}`",
        "- backup required before any future canary recipe upload: `true`",
        "- backup must record SHA256, size, URL and local backup path.",
        "- upload must be blocked if backup hash cannot be verified.",
        "",
    ])


def render_recipe_plan_md(report: Dict[str, Any]) -> str:
    selected = report.get("selected_candidate") or {}
    fmt = selected.get("format", "-")
    if fmt == "webp":
        recipe = "webpinfo baseline, cwebp conservative encode, webpinfo output validation, minimum 3 percent savings."
    elif fmt in {"jpg", "png"}:
        recipe = "local conservative conversion/compression plan must be explicit in the next recipe phase; no format/filename change without Owner approval."
    else:
        recipe = "format unknown; recipe must not proceed."
    return "\n".join([
        "# MEDIUM Images Next After Success Recipe Plan",
        "",
        f"- candidate_format: `{fmt}`",
        f"- recipe_preview: {recipe}",
        "- no upload in this selector phase.",
        "- no other image or gate may be changed.",
        "",
    ])


def playbook_selector(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": "medium-images-next-after-success-selector",
        "phase": "8.14",
        "purpose": "Read-only selection of exactly one next image candidate after a successful canary.",
        "allowed_actions": ["read reports", "read live HTML", "HTTP HEAD/GET size probes", "write local reports"],
        "blocked_actions": ["upload", "optimization", "database writes", "content edits", "cache purge", "other gates"],
        "blocked_previous_candidates": [PREVIOUS_FAILED_REMOTE, PREVIOUS_SUCCESS_REMOTE],
        "selected_candidate": report.get("selected_candidate"),
        "live_apply": False,
    }


def playbook_recipe(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": "medium-images-next-after-success-recipe",
        "phase": "future",
        "purpose": "Template for the next separate canary recipe phase.",
        "selected_candidate": report.get("selected_candidate"),
        "required_before_upload": ["owner decision", "backup", "tooling", "local optimization", "pre-healthcheck", "minimum 3 percent savings", "rollback plan"],
        "blocked_now": True,
        "live_apply": False,
    }


def write_outputs(report: Dict[str, Any], write_pack: bool = False) -> None:
    snapshot = SNAPSHOT_DIR / f"medium-images-next-after-success-selector-{report['timestamp']}.json"
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(STATE_JSON, report)
    write_json_atomic(LATEST_JSON, report)
    write_json_atomic(snapshot, report)
    append_jsonl(AUDIT_JSONL, [report])
    write_json_atomic(PLAYBOOK_SELECTOR, playbook_selector(report))
    write_json_atomic(PLAYBOOK_RECIPE, playbook_recipe(report))
    if write_pack:
        write_text_atomic(OWNER_PACK_MD, render_owner_pack_md(report))
        write_text_atomic(BACKUP_PLAN_MD, render_backup_plan_md(report))
        write_text_atomic(RECIPE_PLAN_MD, render_recipe_plan_md(report))
    update_learning(report)


def update_json_file(path: Path, update: Dict[str, Any]) -> None:
    existing, status = read_json(path)
    data = existing if status == "ok" and isinstance(existing, dict) else {}
    data.update(update)
    write_json_atomic(path, data)


def update_learning(report: Dict[str, Any]) -> None:
    selected = report.get("selected_candidate") or {}
    timestamp = report.get("timestamp_utc") or utc_now()
    update_json_file(KNOWLEDGE_BASE_JSON, {
        "medium_images_next_after_success_selector": {
            "last_status": report.get("status"),
            "previous_failed_candidate_blocked": True,
            "previous_successful_candidate_blocked": True,
            "selected_remote_path": selected.get("remote_path"),
            "read_only_candidate_selection": True,
            "no_upload_without_separate_recipe_phase": True,
        }
    })
    update_json_file(PATTERNS_JSON, {
        "medium_images_next_after_success_pattern": {
            "under_threshold_candidates_not_reused": True,
            "successful_canary_candidates_not_reused": True,
            "one_candidate_after_success": True,
            "prefer_larger_below_the_fold_uploads": True,
            "last_seen": timestamp,
        }
    })
    update_json_file(ACTION_RULES_JSON, {
        "medium_images_next_after_success_rules": {
            "blocked_now": ["upload", "optimization", "remote write", "other gates"],
            "allowed_now": ["read-only collect", "rank", "owner pack", "backup plan", "recipe plan"],
        }
    })
    update_json_file(ADAPTIVE_LATEST_JSON, {
        "latest_medium_images_next_after_success_status": report.get("status"),
        "latest_medium_images_next_after_success_timestamp": timestamp,
        "latest_medium_images_next_after_success_remote_path": selected.get("remote_path"),
    })
    append_jsonl(OBSERVATIONS_JSONL, [{
        "timestamp_utc": timestamp,
        "source": SCHEMA_VERSION,
        "observation": "Next single image candidate selected read-only after successful canary; prior failed and successful candidates are blocked from reuse.",
        "status": report.get("status"),
        "selected_remote_path": selected.get("remote_path"),
        "breach": report.get("breach"),
    }])
    section = (
        "\n\n## Phase 8.14 MEDIUM Images Next After Success Selector\n"
        f"- status: `{report.get('status')}`\n"
        f"- selected_remote_path: `{selected.get('remote_path', '-')}`\n"
        "- Previous under-threshold and successful Canary files are blocked from reuse.\n"
        "- Candidate selection is read-only; a separate recipe phase is required before any upload.\n"
    )
    for path in (ADAPTIVE_REPORT_MD, ADAPTIVE_RECOMMEND_MD, ADAPTIVE_CAPABILITY_MD):
        append_text_optional(path, section)


def collect_candidates_action() -> Dict[str, Any]:
    report = build_report("collect-candidates")
    write_outputs(report)
    return report


def rank_candidates_action() -> Dict[str, Any]:
    report = build_report("rank-candidates")
    write_outputs(report)
    return report


def select_next_action() -> Dict[str, Any]:
    report = build_report("select-next")
    write_outputs(report)
    return report


def owner_pack_action() -> Dict[str, Any]:
    report = build_report("owner-pack", write_pack=True)
    write_outputs(report, write_pack=True)
    return report


def print_summary(report: Dict[str, Any]) -> None:
    selected = report.get("selected_candidate") or {}
    print(f"status={report.get('status')}")
    print(f"action={report.get('action')}")
    print(f"candidates_count={report.get('candidates_count')}")
    print(f"blocked_candidates_count={report.get('blocked_candidates_count')}")
    print(f"safe_candidates_count={report.get('safe_candidates_count')}")
    print(f"selected_url={selected.get('url') or '-'}")
    print(f"selected_remote_path={selected.get('remote_path') or '-'}")
    print(f"selected_size={selected.get('size_bytes') or '-'}")
    print(f"estimated_savings_low={selected.get('estimated_savings_low') or '-'}")
    print(f"estimated_savings_high={selected.get('estimated_savings_high') or '-'}")
    print(f"estimated_savings_percent_low={selected.get('estimated_savings_percent_low') or '-'}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop_unchanged={report.get('emergency_stop_unchanged')}")


def status_action() -> None:
    report, status = read_json(LATEST_JSON)
    if status != "ok" or not report:
        print(f"status=not_available input_status={status}")
        return
    print_summary(report)


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    rows = [
        {"url": PREVIOUS_FAILED_URL, "source_type": "internal", "likely_position": "below_the_fold_or_standard", "remote_path": PREVIOUS_FAILED_REMOTE, "format": "webp", "size_bytes": 200_000},
        {"url": PREVIOUS_SUCCESS_URL, "source_type": "internal", "likely_position": "below_the_fold_or_standard", "remote_path": PREVIOUS_SUCCESS_REMOTE, "format": "webp", "size_bytes": 200_000},
        {"url": "https://external.example/a.jpg", "source_type": "external", "likely_position": "below_the_fold_or_standard", "remote_path": None, "format": "jpg", "size_bytes": 500_000},
        {"url": "https://electri-c-ity-studios-24-7.com/wp-content/uploads/a.jpg", "source_type": "internal", "likely_position": "below_the_fold_or_standard", "remote_path": "/wordpress/wp-content/uploads/a.jpg", "format": "jpg", "size_bytes": 220_000},
        {"url": "https://electri-c-ity-studios-24-7.com/wp-content/uploads/hero.png", "source_type": "internal", "likely_position": "hero_or_above_the_fold", "remote_path": "/wordpress/wp-content/uploads/hero.png", "format": "png", "size_bytes": 600_000},
    ]
    for row in rows:
        row["previous_candidate_status"] = previous_candidate_status(row["remote_path"], row["url"])
        row["is_previous_failed_candidate"] = row["previous_candidate_status"] == "failed_under_threshold"
        row["is_previous_successful_candidate"] = row["previous_candidate_status"] == "successful_uploaded"
        row["estimated_savings_low"], row["estimated_savings_high"] = estimate_savings(row["size_bytes"], row["format"])
        row["estimated_savings_percent_low"] = estimate_savings_percent_low(row["size_bytes"], row["estimated_savings_low"])
    ranked = classify_and_rank(rows)
    selected = next((r for r in ranked if r.get("selected_candidate")), None)
    if not selected or not selected["url"].endswith("/a.jpg"):
        raise AssertionError("ranking did not select safe candidate")
    previous = next(r for r in ranked if r["url"] == PREVIOUS_FAILED_URL)
    if not previous["blocked"] or "previous_failed_under_threshold_candidate" not in previous["blocked_reason"]:
        raise AssertionError("previous failed candidate not blocked")
    successful = next(r for r in ranked if r["url"] == PREVIOUS_SUCCESS_URL)
    if not successful["blocked"] or "previous_successful_canary_candidate" not in successful["blocked_reason"]:
        raise AssertionError("previous successful candidate not blocked")
    external = next(r for r in ranked if r["source_type"] == "external")
    if not external["blocked"] or "external_without_safe_local_path" not in external["blocked_reason"]:
        raise AssertionError("external candidate not blocked")
    if "abcdef" in redact_text("password=abcdef12345"):
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in ("sub" + "process", "os" + "." + "system", "sftp" + "." + "put", "sftp" + "." + "remove", "sftp" + "." + "rename", "rm " + "-rf"):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    for path in (REPORT_JSON, REPORT_MD, OWNER_PACK_MD, BACKUP_PLAN_MD, RECIPE_PLAN_MD, STATE_JSON, LATEST_JSON, PLAYBOOK_SELECTOR, PLAYBOOK_RECIPE, SNAPSHOT_DIR / "x.json", AUDIT_JSONL):
        assert_allowed_write(path)
    json.dumps({"ranked": ranked})
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MEDIUM images next canary candidate selector.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--collect-candidates", action="store_true")
    group.add_argument("--rank-candidates", action="store_true")
    group.add_argument("--select-next", action="store_true")
    group.add_argument("--owner-pack", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.status:
        status_action()
        return 0
    try:
        if args.collect_candidates:
            report = collect_candidates_action()
        elif args.rank_candidates:
            report = rank_candidates_action()
        elif args.select_next:
            report = select_next_action()
        elif args.owner_pack:
            report = owner_pack_action()
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
            "breach_reasons": [redact_text(exc, max_len=300)],
            "live_apply": False,
            "global_live_autonomy": False,
            "emergency_stop_unchanged": True,
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
    raise SystemExit(main())
