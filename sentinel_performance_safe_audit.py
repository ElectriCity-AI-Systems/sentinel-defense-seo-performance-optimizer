#!/usr/bin/env python3
"""Sentinel Performance Safe Audit (Phase 1.7).

Read-only performance risk audit. Inspects local snapshots/reports only and
writes drafts/reports under the Sentinel project. It NEVER applies a change.

Hard safety guarantees (enforced structurally):
  * No live changes; no WordPress/.htaccess/Cloudflare/Nginx edits.
  * No external/network access — local files only (no network imports).
  * No secrets/cookies/authorization values are stored or emitted.
  * No apply function.
  * Writes only ever under:
        /srv/sentinel-defense/reports/latest
        /srv/sentinel-defense/drafts/performance

Every recommendation is advisory (e.g. "convert images to WebP",
"add lazy loading", "defer external embeds"); nothing is changed.
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
from urllib.parse import urlparse


PROJECT_DIR = Path("/srv/sentinel-defense")

# --- Output targets ---------------------------------------------------------
REPORT_MD = PROJECT_DIR / "reports/latest/performance-safe-audit-report.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/performance-safe-audit-report.json"
DRAFT_DIR = PROJECT_DIR / "drafts/performance"
NEXT_ACTIONS_MD = DRAFT_DIR / "performance-safe-next-actions.md"
EDITORIAL_REVIEW_MD = DRAFT_DIR / "performance-editorial-review.md"
EDITORIAL_REVIEW_JSON = DRAFT_DIR / "performance-editorial-review.json"

# --- Optional inputs (must never crash when missing) ------------------------
SEO_INPUT_DIR = PROJECT_DIR / "seo-inputs/latest"
INPUT_HOMEPAGE_HTML = SEO_INPUT_DIR / "homepage.html"
INPUT_HEADERS_HOMEPAGE = SEO_INPUT_DIR / "headers-homepage.txt"
INPUT_MASTER_REPORT = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
INPUT_SEO_OPTIMIZER_REPORT = PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.json"
INPUT_MICROCACHE_STATUS = PROJECT_DIR / "reports/latest/ai-radio-nowplaying-microcache-status.json"
INPUT_AI_RADIO_TIMEOUT = PROJECT_DIR / "reports/latest/ai-radio-api-timeout-diagnosis.json"
INPUT_SOURCEMAP_REPORT = PROJECT_DIR / "reports/latest/sourcemap-prevention-report.json"

# --- Allowed write roots (the only paths this module may ever write) --------
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/performance",
)

SCHEMA_VERSION = "performance-safe-audit-1.7"
OWN_DOMAIN_SUFFIX = "electri-c-ity-studios-24-7.com"

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)

# Risk classes (severity of the *eventual* change a recommendation implies).
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

NOT_AVAILABLE = "NOT_AVAILABLE"

# Editorial review groups.
GROUP_SAFE_QUICK_WIN = "SAFE_QUICK_WIN"
GROUP_REVIEW_ONLY = "REVIEW_ONLY"
GROUP_BLOCKED_HIGH_RISK = "BLOCKED_HIGH_RISK"

# Autonomy policy class per risk (aligned with sentinel_autonomy_policy.py).
AUTONOMY_CLASS_BY_RISK = {
    RISK_LOW: "LEVEL_1_DRAFT_ONLY",
    RISK_MEDIUM: "OWNER_APPROVAL_REQUIRED",
    RISK_HIGH: "BLOCKED_NOT_PERMITTED",
}

# Header names we are willing to surface (whitelist). Anything else — including
# Report-To / NEL / Speculation-Rules style values — is never echoed.
SAFE_HEADER_WHITELIST = {
    "cache-control",
    "content-type",
    "server",
    "cf-cache-status",
    "wpo-cache-status",
    "age",
    "vary",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "content-security-policy",
    "x-frame-options",
    "x-xss-protection",
}

# Image extensions considered "modern" vs "legacy" for WebP recommendations.
MODERN_IMAGE_FORMATS = {"webp", "avif", "svg"}
LEGACY_IMAGE_FORMATS = {"png", "jpg", "jpeg", "gif", "bmp", "tiff"}

EMBED_SIGNATURES = {
    "youtube": ("youtube.com", "youtu.be", "youtube-nocookie.com"),
    "opensea": ("opensea.io",),
    "radio": ("radio", "nowplaying", "stream", "icecast", "shoutcast", "azuracast"),
    "shop": ("shop", "woocommerce", "checkout", "stripe.com", "paypal.com"),
    "widget": ("widget", "embed", "iframe", "gtranslate", "disqus"),
}


# ===========================================================================
# Safety helpers (mirror the SEO safe optimizer conventions)
# ===========================================================================
def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(value: Any, default: str = "-", max_len: int = 300) -> str:
    if value is None:
        return default
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(
            f"Refusing to write outside allowed performance audit roots: {path}"
        )


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Any) -> None:
    write_text_atomic(
        path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )


def read_text_if_safe(path: Path, allowed_suffixes: Iterable[str], max_bytes: int = 3_000_000) -> Tuple[Optional[str], str]:
    suffixes = {item.lower() for item in allowed_suffixes}
    if not path:
        return None, "not_configured"
    if not path.exists():
        return None, "not_available"
    if not path.is_file():
        return None, "not_a_file"
    if path.suffix.lower() not in suffixes:
        return None, "unsupported_suffix"
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return None, "refused_secret_like_path"
    try:
        if path.stat().st_size > max_bytes:
            return None, "too_large"
        return path.read_text(encoding="utf-8", errors="replace"), "ok"
    except OSError as exc:
        return None, f"read_error:{exc.__class__.__name__}"


def read_optional_json(path: Path) -> Tuple[Optional[Any], str]:
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


def host_is_external(host: str) -> bool:
    host = (host or "").lower()
    if not host:
        return False
    return host != OWN_DOMAIN_SUFFIX and not host.endswith("." + OWN_DOMAIN_SUFFIX)


def extension_from_src(src: str) -> str:
    if not src:
        return ""
    path = urlparse(src).path if "//" in src or src.startswith("http") else src.split("?", 1)[0]
    path = path.split("?", 1)[0].split("#", 1)[0]
    if "." not in path:
        return ""
    return path.rsplit(".", 1)[-1].lower()[:8]


def classify_embed(url_or_text: str) -> List[str]:
    lowered = (url_or_text or "").lower()
    kinds = []
    for kind, needles in EMBED_SIGNATURES.items():
        if any(needle in lowered for needle in needles):
            kinds.append(kind)
    return kinds


# ===========================================================================
# HTML analysis (read-only, no network)
# ===========================================================================
class PerformanceHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.img_total = 0
        self.img_missing_lazy = 0
        self.img_missing_dimensions = 0
        self.image_formats: Dict[str, int] = {}
        self.iframe_total = 0
        self.embed_total = 0
        self.script_total = 0
        self.script_external = 0
        self.inline_script = 0
        self.inline_style = 0
        self.link_style = 0
        self.external_domains: Dict[str, int] = {}
        self.embed_kinds: Dict[str, int] = {}
        self._in_script = False
        self._current_script_has_src = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "img":
            self.img_total += 1
            loading = attr.get("loading", "").lower()
            if loading != "lazy":
                self.img_missing_lazy += 1
            if not attr.get("width") or not attr.get("height"):
                self.img_missing_dimensions += 1
            ext = extension_from_src(attr.get("src", "") or attr.get("data-src", ""))
            if ext:
                self.image_formats[ext] = self.image_formats.get(ext, 0) + 1
        elif tag == "iframe":
            self.iframe_total += 1
            self._track_external(attr.get("src", ""))
            for kind in classify_embed(attr.get("src", "")):
                self.embed_kinds[kind] = self.embed_kinds.get(kind, 0) + 1
        elif tag in {"embed", "object"}:
            self.embed_total += 1
            self._track_external(attr.get("src", "") or attr.get("data", ""))
        elif tag == "script":
            self.script_total += 1
            self._in_script = True
            src = attr.get("src", "")
            self._current_script_has_src = bool(src)
            if src:
                self._track_external(src, is_script=True)
                for kind in classify_embed(src):
                    self.embed_kinds[kind] = self.embed_kinds.get(kind, 0) + 1
        elif tag == "link":
            rel = attr.get("rel", "").lower()
            if "stylesheet" in rel:
                self.link_style += 1
        elif tag == "style":
            self.inline_style += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False
            self._current_script_has_src = False

    def handle_data(self, data: str) -> None:
        if self._in_script and not self._current_script_has_src and data.strip():
            self.inline_script += 1

    def _track_external(self, src: str, is_script: bool = False) -> None:
        if not src:
            return
        host = urlparse(src).hostname or ""
        if host and host_is_external(host):
            host = host.lower()[:80]
            self.external_domains[host] = self.external_domains.get(host, 0) + 1
            if is_script:
                self.script_external += 1


def analyze_homepage_html(html: Optional[str], status: str) -> Dict[str, Any]:
    if html is None:
        return {"available": False, "status": status}
    parser = PerformanceHtmlParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # never let a malformed snapshot crash the audit
        return {"available": False, "status": "parse_error"}

    # Sort/limit external domains deterministically; redact for safety.
    external_domains = sorted(parser.external_domains.items(), key=lambda kv: (-kv[1], kv[0]))
    external_domains_safe = [
        {"domain": redact_text(domain, max_len=80), "count": count}
        for domain, count in external_domains[:25]
    ]
    return {
        "available": True,
        "status": status,
        "img_total": parser.img_total,
        "img_missing_lazy": parser.img_missing_lazy,
        "img_missing_dimensions": parser.img_missing_dimensions,
        "image_formats": dict(sorted(parser.image_formats.items())),
        "iframe_total": parser.iframe_total,
        "embed_total": parser.embed_total,
        "script_total": parser.script_total,
        "script_external": parser.script_external,
        "inline_script_blocks": parser.inline_script,
        "inline_style_blocks": parser.inline_style,
        "stylesheet_links": parser.link_style,
        "external_domain_count": len(parser.external_domains),
        "external_domains": external_domains_safe,
        "embed_kinds": dict(sorted(parser.embed_kinds.items())),
    }


# ===========================================================================
# Header analysis (whitelist only, secret-safe)
# ===========================================================================
def analyze_headers(text: Optional[str], status: str) -> Dict[str, Any]:
    if text is None:
        return {"available": False, "status": status}
    headers: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if key not in SAFE_HEADER_WHITELIST:
            continue
        cleaned = redact_text(value.strip(), default="-", max_len=200)
        if cleaned and cleaned != "-":
            headers[key] = cleaned

    security_headers = {
        name: headers.get(name)
        for name in (
            "x-content-type-options",
            "strict-transport-security",
            "referrer-policy",
            "permissions-policy",
            "content-security-policy",
            "x-frame-options",
        )
        if headers.get(name)
    }
    return {
        "available": True,
        "status": status,
        "cache_control": headers.get("cache-control"),
        "content_type": headers.get("content-type"),
        "server": headers.get("server"),
        "cf_cache_status": headers.get("cf-cache-status"),
        "wpo_cache_status": headers.get("wpo-cache-status"),
        "age": headers.get("age"),
        "vary": headers.get("vary"),
        "security_headers_present": sorted(security_headers.keys()),
        "security_headers": security_headers,
    }


# ===========================================================================
# Performance risk classification (read-only)
# ===========================================================================
def classify_image_optimization(html: Dict[str, Any]) -> Dict[str, Any]:
    if not html.get("available"):
        return {"status": NOT_AVAILABLE, "risk": RISK_LOW}
    formats = html.get("image_formats", {})
    legacy = sum(count for ext, count in formats.items() if ext in LEGACY_IMAGE_FORMATS)
    modern = sum(count for ext, count in formats.items() if ext in MODERN_IMAGE_FORMATS)
    missing_dims = html.get("img_missing_dimensions", 0)
    if legacy > 0:
        status = "WEBP_RECOMMENDED"
    elif missing_dims > 0:
        status = "DIMENSIONS_RECOMMENDED"
    elif html.get("img_total", 0) > 0:
        status = "OK"
    else:
        status = "NO_IMAGES"
    return {
        "status": status,
        "risk": RISK_MEDIUM,  # image markup change is MEDIUM
        "legacy_format_images": legacy,
        "modern_format_images": modern,
        "images_missing_dimensions": missing_dims,
    }


def classify_lazy_loading(html: Dict[str, Any]) -> Dict[str, Any]:
    if not html.get("available"):
        return {"status": NOT_AVAILABLE, "risk": RISK_MEDIUM}
    missing = html.get("img_missing_lazy", 0)
    total = html.get("img_total", 0)
    if total == 0:
        status = "NO_IMAGES"
    elif missing > 0:
        status = "LAZY_LOADING_RECOMMENDED"
    else:
        status = "OK"
    return {
        "status": status,
        "risk": RISK_MEDIUM,
        "images_without_lazy": missing,
        "images_total": total,
    }


def classify_external_embed_risk(html: Dict[str, Any]) -> Dict[str, Any]:
    if not html.get("available"):
        return {"status": NOT_AVAILABLE, "risk": RISK_LOW}
    domain_count = html.get("external_domain_count", 0)
    embed_kinds = html.get("embed_kinds", {})
    iframe_total = html.get("iframe_total", 0)
    if domain_count == 0 and iframe_total == 0:
        status = "NO_EXTERNAL_EMBEDS"
    elif domain_count >= 8 or iframe_total >= 5:
        status = "MANY_EXTERNAL_EMBEDS"
    else:
        status = "EXTERNAL_EMBEDS_PRESENT"
    # Risk: deferring external embeds is content-level (MEDIUM); player/radio
    # code change would be HIGH and is only flagged, never recommended to apply.
    risk = RISK_MEDIUM
    if "radio" in embed_kinds:
        risk = RISK_HIGH  # touching player/radio code is HIGH; flag only
    return {
        "status": status,
        "risk": risk,
        "external_domain_count": domain_count,
        "iframe_total": iframe_total,
        "embed_kinds": embed_kinds,
        "note": "Embeds are only detected locally; never fetched or contacted.",
    }


def classify_cache_header(headers: Dict[str, Any]) -> Dict[str, Any]:
    if not headers.get("available"):
        return {"status": NOT_AVAILABLE, "risk": RISK_LOW}
    cache_control = (headers.get("cache_control") or "").lower()
    cf = headers.get("cf_cache_status")
    if not cache_control and not cf:
        status = "UNKNOWN"
    elif "no-cache" in cache_control or "no-store" in cache_control:
        status = "HTML_NO_CACHE"  # typical for logged-in/WP HTML; informational
    else:
        status = "CACHE_CONTROL_PRESENT"
    return {
        "status": status,
        "risk": RISK_LOW,  # reading/reporting cache headers is LOW
        "cache_control": headers.get("cache_control"),
        "cf_cache_status": cf,
        "wpo_cache_status": headers.get("wpo_cache_status"),
    }


def classify_render_blocking(html: Dict[str, Any]) -> Dict[str, Any]:
    if not html.get("available"):
        return {"status": NOT_AVAILABLE, "risk": RISK_HIGH}
    scripts = html.get("script_total", 0)
    inline = html.get("inline_script_blocks", 0)
    stylesheets = html.get("stylesheet_links", 0)
    if scripts >= 20 or inline >= 10:
        status = "HIGH_SCRIPT_COUNT_REVIEW"
    elif scripts >= 8:
        status = "MODERATE_SCRIPT_COUNT"
    else:
        status = "OK"
    return {
        "status": status,
        # JS-minify / defer-at-build is HIGH; we only flag, never apply.
        "risk": RISK_HIGH,
        "script_total": scripts,
        "inline_script_blocks": inline,
        "stylesheet_links": stylesheets,
    }


def derive_ai_radio_cache_status(
    microcache: Optional[Dict[str, Any]],
    master: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    deployed = None
    local_validation = None
    if isinstance(microcache, dict):
        deployed = microcache.get("microcache_deployed")
        local_validation = microcache.get("local_validation")
    if deployed is None and isinstance(master, dict):
        remediation = (
            master.get("ai_radio_timeout_diagnosis", {}).get("microcache_remediation")
            if isinstance(master.get("ai_radio_timeout_diagnosis"), dict)
            else None
        )
        if isinstance(remediation, dict):
            deployed = remediation.get("microcache_deployed")
            local_validation = remediation.get("local_validation")
    if deployed is True:
        status = "MICROCACHE_DEPLOYED"
    elif deployed is False:
        status = "MICROCACHE_NOT_DEPLOYED"
    else:
        status = NOT_AVAILABLE
    return {
        "status": status,
        "risk": RISK_HIGH,  # player/radio/origin cache changes are HIGH
        "local_validation": redact_text(local_validation) if local_validation else NOT_AVAILABLE,
    }


def derive_source_map_status(
    sourcemap: Optional[Dict[str, Any]],
    master: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    status = NOT_AVAILABLE
    if isinstance(sourcemap, dict) and sourcemap.get("status"):
        status = redact_text(sourcemap.get("status"))
    elif isinstance(master, dict) and master.get("sourcemap_prevention_status"):
        status = redact_text(master.get("sourcemap_prevention_status"))
    return {"status": status, "risk": RISK_HIGH}  # JS-minify domain is HIGH


def derive_origin_5xx_status(
    master: Optional[Dict[str, Any]],
    ai_radio: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    status = NOT_AVAILABLE
    if isinstance(master, dict):
        origin = master.get("website_origin_pressure_breakdown")
        if isinstance(origin, dict) and origin.get("status"):
            status = redact_text(origin.get("status"))
        elif master.get("ai_radio_timeout_status"):
            status = redact_text(master.get("ai_radio_timeout_status"))
    if status == NOT_AVAILABLE and isinstance(ai_radio, dict) and ai_radio.get("status"):
        status = redact_text(ai_radio.get("status"))
    return {"status": status, "risk": RISK_HIGH}  # Nginx/Cloudflare/origin is HIGH


# ===========================================================================
# Report assembly
# ===========================================================================
def collect_inputs() -> Dict[str, Any]:
    html_text, html_status = read_text_if_safe(INPUT_HOMEPAGE_HTML, {".html", ".htm"})
    headers_text, headers_status = read_text_if_safe(INPUT_HEADERS_HOMEPAGE, {".txt"})
    master_data, master_status = read_optional_json(INPUT_MASTER_REPORT)
    seo_data, seo_status = read_optional_json(INPUT_SEO_OPTIMIZER_REPORT)
    microcache_data, microcache_status = read_optional_json(INPUT_MICROCACHE_STATUS)
    ai_radio_data, ai_radio_status = read_optional_json(INPUT_AI_RADIO_TIMEOUT)
    sourcemap_data, sourcemap_status = read_optional_json(INPUT_SOURCEMAP_REPORT)
    return {
        "html": (html_text, html_status),
        "headers": (headers_text, headers_status),
        "master": (master_data if isinstance(master_data, dict) else None, master_status),
        "seo": (seo_data if isinstance(seo_data, dict) else None, seo_status),
        "microcache": (microcache_data if isinstance(microcache_data, dict) else None, microcache_status),
        "ai_radio": (ai_radio_data if isinstance(ai_radio_data, dict) else None, ai_radio_status),
        "sourcemap": (sourcemap_data if isinstance(sourcemap_data, dict) else None, sourcemap_status),
    }


def highest_risk(classifications: Iterable[Dict[str, Any]]) -> str:
    order = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2}
    best = RISK_LOW
    for c in classifications:
        risk = c.get("risk", RISK_LOW)
        if order.get(risk, 0) > order.get(best, 0):
            best = risk
    return best


def build_recommendations(
    image_opt: Dict[str, Any],
    lazy: Dict[str, Any],
    embeds: Dict[str, Any],
    render_blocking: Dict[str, Any],
) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    if image_opt.get("status") == "WEBP_RECOMMENDED":
        recs.append({
            "recommendation": "Convert legacy images (png/jpg) to WebP/AVIF where visually safe.",
            "risk": RISK_MEDIUM,
            "apply_status": "not_applied",
            "note": "Recommendation only — image markup change requires owner approval.",
        })
    if image_opt.get("images_missing_dimensions", 0) > 0:
        recs.append({
            "recommendation": "Add explicit width/height to images to reduce layout shift (CLS).",
            "risk": RISK_MEDIUM,
            "apply_status": "not_applied",
        })
    if lazy.get("status") == "LAZY_LOADING_RECOMMENDED":
        recs.append({
            "recommendation": 'Add loading="lazy" to below-the-fold images.',
            "risk": RISK_MEDIUM,
            "apply_status": "not_applied",
        })
    if embeds.get("status") in {"EXTERNAL_EMBEDS_PRESENT", "MANY_EXTERNAL_EMBEDS"}:
        recs.append({
            "recommendation": "Defer or lazy-load external embeds (YouTube/widgets) to cut render-blocking.",
            "risk": embeds.get("risk", RISK_MEDIUM),
            "apply_status": "not_applied",
            "note": "Player/radio code changes are HIGH risk and are flagged only, never applied.",
        })
    if render_blocking.get("status") in {"HIGH_SCRIPT_COUNT_REVIEW", "MODERATE_SCRIPT_COUNT"}:
        recs.append({
            "recommendation": "Review render-blocking scripts; consider defer/async (HIGH-risk build change — review only).",
            "risk": RISK_HIGH,
            "apply_status": "not_applied",
            "note": "JS minify / build changes are HIGH risk; never auto-applied.",
        })
    recs.append({
        "recommendation": "Keep all performance changes manual/review-only; Sentinel does not apply them.",
        "risk": RISK_LOW,
        "apply_status": "not_applied",
    })
    return recs


def build_report() -> Tuple[Dict[str, Any], str]:
    inputs = collect_inputs()
    html_text, html_status = inputs["html"]
    headers_text, headers_status = inputs["headers"]
    master_data = inputs["master"][0]
    microcache_data = inputs["microcache"][0]
    ai_radio_data = inputs["ai_radio"][0]
    sourcemap_data = inputs["sourcemap"][0]

    html_analysis = analyze_homepage_html(html_text, html_status)
    headers_analysis = analyze_headers(headers_text, headers_status)

    image_opt = classify_image_optimization(html_analysis)
    lazy = classify_lazy_loading(html_analysis)
    embeds = classify_external_embed_risk(html_analysis)
    cache_header = classify_cache_header(headers_analysis)
    render_blocking = classify_render_blocking(html_analysis)
    ai_radio_cache = derive_ai_radio_cache_status(microcache_data, master_data)
    source_map = derive_source_map_status(sourcemap_data, master_data)
    origin_5xx = derive_origin_5xx_status(master_data, ai_radio_data)

    classifications = {
        "image_optimization_status": image_opt,
        "lazy_loading_status": lazy,
        "external_embed_risk": embeds,
        "cache_header_status": cache_header,
        "render_blocking_risk": render_blocking,
        "ai_radio_nowplaying_cache_status": ai_radio_cache,
        "source_map_status": source_map,
        "origin_5xx_status": origin_5xx,
    }
    overall_highest_risk = highest_risk(classifications.values())

    recommendations = build_recommendations(image_opt, lazy, embeds, render_blocking)
    next_steps = [r["recommendation"] for r in recommendations]

    input_status = {
        "homepage_html": html_status,
        "headers_homepage": headers_status,
        "master_report": inputs["master"][1],
        "seo_optimizer_report": inputs["seo"][1],
        "microcache_status": inputs["microcache"][1],
        "ai_radio_timeout": inputs["ai_radio"][1],
        "sourcemap_report": inputs["sourcemap"][1],
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "read_only": True,
        "productive_change": False,
        "secrets_output": False,
        "network_access": False,
        "apply_function": False,
        "highest_risk": overall_highest_risk,
        "status": "READY_FOR_REVIEW" if html_analysis.get("available") or headers_analysis.get("available") else NOT_AVAILABLE,
        "allowed_write_roots": [str(r) for r in ALLOWED_WRITE_ROOTS],
        "forbidden_mutations": {
            "wordpress": False,
            "htaccess": False,
            "cloudflare": False,
            "nginx": False,
            "external_write": False,
        },
        "inputs": input_status,
        "html_analysis": html_analysis,
        "headers_analysis": headers_analysis,
        # Flat status fields (consumed by the Master performance summary).
        "image_optimization_status": image_opt.get("status"),
        "lazy_loading_status": lazy.get("status"),
        "external_embed_risk": embeds.get("status"),
        "cache_header_status": cache_header.get("status"),
        "render_blocking_risk": render_blocking.get("status"),
        "ai_radio_nowplaying_cache_status": ai_radio_cache.get("status"),
        "source_map_status": source_map.get("status"),
        "origin_5xx_status": origin_5xx.get("status"),
        "classifications": classifications,
        "recommendations": recommendations,
        "next_safe_performance_steps": next_steps,
        "report_outputs": [str(REPORT_MD), str(REPORT_JSON)],
        "draft_outputs": [str(NEXT_ACTIONS_MD)],
    }
    return report, render_next_actions(report)


def render_markdown(report: Dict[str, Any]) -> str:
    html = report.get("html_analysis", {})
    headers = report.get("headers_analysis", {})
    lines: List[str] = []
    lines.append("# Performance Safe Audit Report (Phase 1.7)")
    lines.append("")
    lines.append(f"- Generated (UTC): `{report['generated_at_utc']}`")
    lines.append(f"- Status: **{report['status']}** · Highest risk: **{report['highest_risk']}**")
    lines.append("- Mode: **read-only** (no live, productive or external change; no apply function)")
    lines.append("")

    lines.append("## Input Availability")
    lines.append("")
    for kind, status in report.get("inputs", {}).items():
        lines.append(f"- `{kind}`: {status}")
    lines.append("")

    lines.append("## Performance Risk Classification")
    lines.append("")
    lines.append("| Signal | Status | Risk |")
    lines.append("|---|---|---|")
    for key in (
        "image_optimization_status",
        "lazy_loading_status",
        "external_embed_risk",
        "cache_header_status",
        "render_blocking_risk",
        "ai_radio_nowplaying_cache_status",
        "source_map_status",
        "origin_5xx_status",
    ):
        cls = report.get("classifications", {}).get(key, {})
        lines.append(f"| {key} | `{report.get(key)}` | {cls.get('risk', '-')} |")
    lines.append("")

    if html.get("available"):
        lines.append("## HTML Analysis (read-only)")
        lines.append("")
        lines.append(f"- Images: {html.get('img_total')} (missing lazy: {html.get('img_missing_lazy')}, missing dimensions: {html.get('img_missing_dimensions')})")
        lines.append(f"- Image formats: {html.get('image_formats')}")
        lines.append(f"- iframes: {html.get('iframe_total')} · embeds/objects: {html.get('embed_total')} · scripts: {html.get('script_total')} (external: {html.get('script_external')})")
        lines.append(f"- Inline script blocks: {html.get('inline_script_blocks')} · inline style: {html.get('inline_style_blocks')} · stylesheet links: {html.get('stylesheet_links')}")
        lines.append(f"- External domains ({html.get('external_domain_count')}): {', '.join(d['domain'] for d in html.get('external_domains', [])[:12]) or '-'}")
        lines.append(f"- Detected embed kinds: {html.get('embed_kinds')}")
        lines.append("")
    else:
        lines.append("## HTML Analysis (read-only)")
        lines.append("")
        lines.append(f"- Not available (`{html.get('status')}`).")
        lines.append("")

    if headers.get("available"):
        lines.append("## Header Analysis (whitelist, secret-safe)")
        lines.append("")
        lines.append(f"- Cache-Control: `{headers.get('cache_control')}`")
        lines.append(f"- Content-Type: `{headers.get('content_type')}`")
        lines.append(f"- Server: `{headers.get('server')}` · CF-Cache-Status: `{headers.get('cf_cache_status')}` · WPO: `{headers.get('wpo_cache_status')}`")
        lines.append(f"- Security headers present: {headers.get('security_headers_present')}")
        lines.append("")
    else:
        lines.append("## Header Analysis (whitelist, secret-safe)")
        lines.append("")
        lines.append(f"- Not available (`{headers.get('status')}`).")
        lines.append("")

    lines.append("## Safe Recommendations (advisory only)")
    lines.append("")
    for rec in report.get("recommendations", []):
        lines.append(f"- [{rec.get('risk')}] {rec.get('recommendation')} (apply_status: {rec.get('apply_status')})")
    lines.append("")

    lines.append("## Safety")
    lines.append("")
    lines.append("- Read-only: no live, WordPress, .htaccess, Cloudflare, Nginx or external changes.")
    lines.append("- No apply function; every recommendation stays apply_status=not_applied.")
    lines.append("- External embeds are only detected locally; never fetched or contacted.")
    lines.append("- No secrets/cookies/authorization values are stored or emitted.")
    lines.append(
        "- Writes restricted to: " + ", ".join(f"`{r}`" for r in report["allowed_write_roots"]) + "."
    )
    lines.append("")
    return "\n".join(lines)


def render_next_actions(report: Dict[str, Any]) -> str:
    lines = ["# Performance Safe Next Actions (Draft — review only)", ""]
    lines.append(f"- Generated (UTC): `{report['generated_at_utc']}`")
    lines.append(f"- Highest risk: `{report['highest_risk']}`")
    lines.append("- These are advisory drafts. Nothing is applied. apply_status stays not_applied.")
    lines.append("")
    lines.append("## Recommended (manual / review-only)")
    lines.append("")
    for rec in report.get("recommendations", []):
        lines.append(f"- [{rec.get('risk')}] {rec.get('recommendation')}")
        if rec.get("note"):
            lines.append(f"  - note: {rec['note']}")
    lines.append("")
    lines.append("## Hard limits")
    lines.append("")
    lines.append("- No image files are modified; WebP conversion is a recommendation only.")
    lines.append("- No HTML/CMS/Nginx/Cloudflare/.htaccess changes are made.")
    lines.append("- HIGH-risk items (JS minify, service worker, player/radio code) are flagged, never applied.")
    lines.append("")
    return "\n".join(lines)


# ===========================================================================
# Performance Editorial Review (Phase 1.8)
# ===========================================================================
def read_audit_report(path: Path = REPORT_JSON) -> Tuple[Optional[Dict[str, Any]], str]:
    """Read the read-only performance audit report. Never raises."""
    data, status = read_optional_json(path)
    if status == "ok" and isinstance(data, dict):
        return data, "ok"
    return None, status


def _proposal(
    action_id: str,
    title: str,
    current_signal: Any,
    proposed_improvement: str,
    expected_benefit: str,
    risk: str,
    group: str,
    reason: str,
) -> Dict[str, Any]:
    return {
        "action_id": action_id,
        "title": title,
        "current_signal": redact_text(current_signal, default="-", max_len=120),
        "proposed_improvement": proposed_improvement,
        "expected_benefit": expected_benefit,
        "risk_classification": risk,
        "autonomy_policy_class": AUTONOMY_CLASS_BY_RISK.get(risk, "BLOCKED_NOT_PERMITTED"),
        "group": group,
        "manual_review_required": True,
        # Phase 1.8 is review-only: nothing is ever apply-ready here.
        "apply_status": "not_applied",
        "reason": reason,
    }


def build_editorial_review(audit: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a performance editorial decision template from the audit report.

    Review-only: every proposal stays apply_status=not_applied. A missing or
    unreadable audit report yields a NOT_AVAILABLE review (never crashes).
    """
    if not isinstance(audit, dict):
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at_utc": utc_now(),
            "status": NOT_AVAILABLE,
            "phase": "performance-editorial-review-1.8",
            "read_only": True,
            "productive_change": False,
            "apply_status": "not_applied",
            "recommendation": "run sentinel_performance_safe_audit.py to produce the audit first",
            "proposals": [],
            "groups": {
                GROUP_SAFE_QUICK_WIN: [],
                GROUP_REVIEW_ONLY: [],
                GROUP_BLOCKED_HIGH_RISK: [],
            },
            "summary": {
                "proposal_count": 0,
                "safe_quick_win_count": 0,
                "review_only_count": 0,
                "blocked_high_risk_count": 0,
                "high_risk_count": 0,
                "all_not_applied": True,
                "highest_risk": None,
            },
        }

    html = audit.get("html_analysis", {}) if isinstance(audit.get("html_analysis"), dict) else {}
    img_missing_lazy = html.get("img_missing_lazy", 0)
    img_missing_dims = html.get("img_missing_dimensions", 0)
    img_total = html.get("img_total", 0)
    external_domain_count = html.get("external_domain_count", 0)

    proposals: List[Dict[str, Any]] = []

    # 1) images_webp_status -------------------------------------------------
    image_status = audit.get("image_optimization_status")
    if image_status == "WEBP_RECOMMENDED":
        proposals.append(_proposal(
            "perf-images-webp",
            "Convert legacy images to WebP/AVIF",
            image_status,
            "Recommend converting png/jpg homepage images to WebP/AVIF where visually safe.",
            "Smaller image payloads, faster LCP.",
            RISK_MEDIUM,
            GROUP_REVIEW_ONLY,
            "Image format change is a CMS/media change (MEDIUM); needs editorial/visual review, not apply-ready.",
        ))
    else:
        proposals.append(_proposal(
            "perf-images-webp",
            "Image format optimization",
            image_status,
            "No change needed; homepage images already use modern formats.",
            "Maintain current optimized state.",
            RISK_LOW,
            GROUP_SAFE_QUICK_WIN,
            "Detected image formats are already modern; informational only.",
        ))

    # 2) missing_lazy_loading ----------------------------------------------
    if img_missing_lazy and img_missing_lazy > 0:
        proposals.append(_proposal(
            "perf-lazy-loading",
            "Add lazy loading to below-the-fold images",
            f"{img_missing_lazy} of {img_total} images without loading=lazy",
            'Recommend adding loading="lazy" to below-the-fold images.',
            "Defer offscreen image loads, lower initial bandwidth.",
            RISK_MEDIUM,
            GROUP_SAFE_QUICK_WIN,
            "Lazy loading is LOW/MEDIUM markup work but stays review-only and not apply-ready in this phase.",
        ))
    else:
        proposals.append(_proposal(
            "perf-lazy-loading",
            "Lazy loading coverage",
            audit.get("lazy_loading_status"),
            "No change needed; images already use lazy loading or none present.",
            "Maintain current state.",
            RISK_LOW,
            GROUP_SAFE_QUICK_WIN,
            "No non-lazy images detected; informational only.",
        ))

    # 3) missing_width_height ----------------------------------------------
    if img_missing_dims and img_missing_dims > 0:
        proposals.append(_proposal(
            "perf-width-height",
            "Add explicit width/height to images",
            f"{img_missing_dims} images without width/height",
            "Recommend adding explicit width/height attributes.",
            "Reduced layout shift (better CLS).",
            RISK_MEDIUM,
            GROUP_SAFE_QUICK_WIN,
            "Dimension attributes are low-risk markup, but stay review-only and not apply-ready.",
        ))
    else:
        proposals.append(_proposal(
            "perf-width-height",
            "Image dimension attributes",
            "all images have width/height" if img_total else audit.get("image_optimization_status"),
            "No change needed; images carry explicit dimensions.",
            "Maintain low CLS.",
            RISK_LOW,
            GROUP_SAFE_QUICK_WIN,
            "No images missing dimensions; informational only.",
        ))

    # 4) external_embeds ----------------------------------------------------
    embed_status = audit.get("external_embed_risk")
    if embed_status in {"EXTERNAL_EMBEDS_PRESENT", "MANY_EXTERNAL_EMBEDS"}:
        proposals.append(_proposal(
            "perf-external-embeds",
            "Defer / lazy-load external embeds",
            f"{embed_status} ({external_domain_count} external domains)",
            "Recommend deferring or lazy-loading external embeds (YouTube/widgets).",
            "Less render-blocking from third-party embeds.",
            RISK_MEDIUM,
            GROUP_REVIEW_ONLY,
            "External embeds touch third-party/player areas; review-only. Player/radio code changes remain HIGH and blocked.",
        ))
    else:
        proposals.append(_proposal(
            "perf-external-embeds",
            "External embed footprint",
            embed_status,
            "No deferral needed; few/no external embeds detected.",
            "Maintain current state.",
            RISK_LOW,
            GROUP_REVIEW_ONLY,
            "Embeds detected locally only, never contacted; informational.",
        ))

    # 5) high_script_count (render blocking) -------------------------------
    render_status = audit.get("render_blocking_risk")
    proposals.append(_proposal(
        "perf-high-script-count",
        "Render-blocking script reduction (JS minify/defer)",
        render_status,
        "Flag only: reducing/deferring/minifying scripts is a build-level change.",
        "Potentially faster first render.",
        RISK_HIGH,
        GROUP_BLOCKED_HIGH_RISK,
        "JS minify / build-level changes are HIGH risk and always blocked from autonomy.",
    ))

    # 6) cache_headers ------------------------------------------------------
    cache_status = audit.get("cache_header_status")
    proposals.append(_proposal(
        "perf-cache-headers",
        "Cache header review",
        cache_status,
        "Observe only; any header change is server/CDN level and out of scope for autonomy.",
        "Awareness of caching posture.",
        RISK_HIGH,
        GROUP_BLOCKED_HIGH_RISK,
        "Cache-Control is governed by Nginx/Cloudflare (HIGH); never changed here.",
    ))

    # 7) ai_radio_nowplaying_microcache ------------------------------------
    ai_cache_status = audit.get("ai_radio_nowplaying_cache_status")
    proposals.append(_proposal(
        "perf-ai-radio-microcache",
        "AI-Radio NowPlaying microcache",
        ai_cache_status,
        "Already deployed / monitor: observe 24h rolling window; no change.",
        "Stable NowPlaying latency without new rules.",
        RISK_HIGH,
        GROUP_BLOCKED_HIGH_RISK,
        "Player/radio/origin cache is HIGH; marked already-deployed/monitor-only, not modified.",
    ))

    # 8) source_map_status --------------------------------------------------
    source_map_status = audit.get("source_map_status")
    proposals.append(_proposal(
        "perf-source-map",
        "Source map / minify exposure",
        source_map_status,
        "Flag only: .map handling relates to JS minify/build; review-only.",
        "Awareness of source-map exposure.",
        RISK_HIGH,
        GROUP_BLOCKED_HIGH_RISK,
        "Source-map/minify domain is HIGH risk; always blocked from autonomy.",
    ))

    # 9) origin_5xx_status --------------------------------------------------
    origin_status = audit.get("origin_5xx_status")
    proposals.append(_proposal(
        "perf-origin-5xx",
        "Origin 5xx posture",
        origin_status,
        "Flag only: origin/edge handling is Nginx/Cloudflare scope; observe.",
        "Awareness of origin error posture.",
        RISK_HIGH,
        GROUP_BLOCKED_HIGH_RISK,
        "Origin/edge (Nginx/Cloudflare) changes are HIGH risk; never applied here.",
    ))

    groups = {GROUP_SAFE_QUICK_WIN: [], GROUP_REVIEW_ONLY: [], GROUP_BLOCKED_HIGH_RISK: []}
    for p in proposals:
        groups[p["group"]].append(p["action_id"])

    risk_order = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2}
    highest = RISK_LOW
    for p in proposals:
        if risk_order.get(p["risk_classification"], 0) > risk_order.get(highest, 0):
            highest = p["risk_classification"]

    high_risk_count = sum(1 for p in proposals if p["risk_classification"] == RISK_HIGH)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "READY_FOR_REVIEW",
        "phase": "performance-editorial-review-1.8",
        "read_only": True,
        "productive_change": False,
        "apply_status": "not_applied",
        "source_audit_report": str(REPORT_JSON),
        "source_audit_generated_at_utc": redact_text(audit.get("generated_at_utc"), default="-"),
        "forbidden_mutations": {
            "wordpress": False,
            "htaccess": False,
            "cloudflare": False,
            "nginx": False,
            "external_write": False,
        },
        "proposals": proposals,
        "groups": groups,
        "summary": {
            "proposal_count": len(proposals),
            "safe_quick_win_count": len(groups[GROUP_SAFE_QUICK_WIN]),
            "review_only_count": len(groups[GROUP_REVIEW_ONLY]),
            "blocked_high_risk_count": len(groups[GROUP_BLOCKED_HIGH_RISK]),
            "high_risk_count": high_risk_count,
            "all_not_applied": all(p["apply_status"] == "not_applied" for p in proposals),
            "highest_risk": highest,
        },
    }


def render_editorial_review_md(review: Dict[str, Any]) -> str:
    lines = ["# Performance Editorial Review (Phase 1.8 — review only)", ""]
    lines.append(f"- Generated (UTC): `{review.get('generated_at_utc')}`")
    lines.append(f"- Status: **{review.get('status')}**")
    if review.get("status") == NOT_AVAILABLE:
        lines.append(f"- {review.get('recommendation', 'audit report not available')}")
        lines.append("")
        return "\n".join(lines)
    summary = review.get("summary", {})
    lines.append(
        f"- Proposals: {summary.get('proposal_count')} "
        f"(safe_quick_win={summary.get('safe_quick_win_count')}, "
        f"review_only={summary.get('review_only_count')}, "
        f"blocked_high_risk={summary.get('blocked_high_risk_count')})"
    )
    lines.append(f"- Highest risk: **{summary.get('highest_risk')}** · all_not_applied: {summary.get('all_not_applied')}")
    lines.append("- Mode: review-only; every proposal stays apply_status=not_applied. No apply function.")
    lines.append("")

    for group in (GROUP_SAFE_QUICK_WIN, GROUP_REVIEW_ONLY, GROUP_BLOCKED_HIGH_RISK):
        members = [p for p in review.get("proposals", []) if p.get("group") == group]
        lines.append(f"## {group} ({len(members)})")
        lines.append("")
        if not members:
            lines.append("- (none)")
            lines.append("")
            continue
        for p in members:
            lines.append(f"### {p.get('title')} (`{p.get('action_id')}`)")
            lines.append("")
            lines.append(f"- Current signal: `{p.get('current_signal')}`")
            lines.append(f"- Proposed improvement: {p.get('proposed_improvement')}")
            lines.append(f"- Expected benefit: {p.get('expected_benefit')}")
            lines.append(f"- Risk: **{p.get('risk_classification')}** · Autonomy class: `{p.get('autonomy_policy_class')}`")
            lines.append(f"- Manual review required: {p.get('manual_review_required')} · apply_status: `{p.get('apply_status')}`")
            lines.append(f"- Reason: {p.get('reason')}")
            lines.append("")

    lines.append("## Safety")
    lines.append("")
    lines.append("- Review-only decision template; nothing is applied (apply_status=not_applied).")
    lines.append("- No WordPress/.htaccess/Cloudflare/Nginx/external change; no network access.")
    lines.append("- HIGH-risk items (JS minify, service worker, Nginx, Cloudflare, player/radio code) are always BLOCKED_HIGH_RISK.")
    lines.append("- No secrets/cookies/authorization values are stored or emitted.")
    lines.append("")
    return "\n".join(lines)


# ===========================================================================
# Self-tests
# ===========================================================================
def run_self_tests() -> int:
    # Write-path guard.
    assert_allowed_write(REPORT_JSON)
    assert_allowed_write(NEXT_ACTIONS_MD)
    for forbidden in (
        Path("/etc/nginx/perf.conf"),
        Path("/var/www/.htaccess"),
        Path("/srv/sentinel-defense/sentinel_master.py"),
        Path("/srv/sentinel-defense/drafts/seo/x.json"),
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")

    # HTML analysis on a small sample.
    sample = """<!doctype html><html><head>
    <script src="https://www.youtube.com/iframe_api"></script>
    <script>var inline=1;</script>
    <link rel="stylesheet" href="/style.css">
    </head><body>
    <img src="/a.png" width="100" height="50">
    <img src="/b.jpg" loading="lazy">
    <img src="https://cdn.gtranslate.net/c.webp" loading="lazy" width="10" height="10">
    <iframe src="https://www.youtube.com/embed/x"></iframe>
    <iframe src="https://opensea.io/collection/y"></iframe>
    <script src="/local.js"></script>
    </body></html>"""
    html = analyze_homepage_html(sample, "ok")
    assert html["available"] is True
    assert html["img_total"] == 3
    assert html["img_missing_lazy"] == 1  # only a.png lacks lazy
    assert html["img_missing_dimensions"] == 1  # b.jpg lacks width/height
    assert html["image_formats"].get("png") == 1
    assert html["image_formats"].get("jpg") == 1
    assert html["image_formats"].get("webp") == 1
    assert html["iframe_total"] == 2
    assert html["script_total"] == 3
    assert html["inline_script_blocks"] == 1
    assert "youtube" in html["embed_kinds"]
    assert "opensea" in html["embed_kinds"]
    # External vs own domain
    domains = {d["domain"] for d in html["external_domains"]}
    assert "www.youtube.com" in domains
    assert "opensea.io" in domains

    # Classification sanity.
    image_opt = classify_image_optimization(html)
    assert image_opt["status"] == "WEBP_RECOMMENDED"
    assert image_opt["risk"] == RISK_MEDIUM
    lazy = classify_lazy_loading(html)
    assert lazy["status"] == "LAZY_LOADING_RECOMMENDED"
    embeds = classify_external_embed_risk(html)
    assert embeds["status"] in {"EXTERNAL_EMBEDS_PRESENT", "MANY_EXTERNAL_EMBEDS"}

    # Header analysis: whitelist + secret redaction.
    sample_headers = (
        "Cache-Control: no-cache\n"
        "Content-Type: text/html; charset=UTF-8\n"
        "Server: cloudflare\n"
        "Cf-Cache-Status: HIT\n"
        "X-Content-Type-Options: nosniff\n"
        "Set-Cookie: session=abc123; Path=/\n"
        'Report-To: {"endpoints":[{"url":"https://a/report?s=SECRETTOKEN123"}]}\n'
        "Authorization: Bearer sk-should-never-appear\n"
    )
    h = analyze_headers(sample_headers, "ok")
    assert h["cache_control"] == "no-cache"
    assert h["cf_cache_status"] == "HIT"
    assert "x-content-type-options" in h["security_headers_present"]
    serialized = json.dumps(h)
    assert "abc123" not in serialized  # set-cookie not whitelisted
    assert "SECRETTOKEN123" not in serialized  # report-to not whitelisted
    assert "sk-should-never-appear" not in serialized  # authorization not whitelisted

    # Missing inputs must not crash.
    assert analyze_homepage_html(None, "not_available")["available"] is False
    assert analyze_headers(None, "not_available")["available"] is False
    data, status = read_optional_json(PROJECT_DIR / "reports/latest/__no_such__.json")
    assert data is None and status == "not_available"

    # Full report build does not crash and stays read-only.
    report, next_actions = build_report()
    assert report["productive_change"] is False
    assert report["read_only"] is True
    assert report["apply_function"] is False
    assert report["highest_risk"] in {RISK_LOW, RISK_MEDIUM, RISK_HIGH}
    assert all(rec["apply_status"] == "not_applied" for rec in report["recommendations"])
    assert "Performance Safe Next Actions" in next_actions
    md = render_markdown(report)
    assert "Performance Safe Audit Report" in md
    # No secret values leak into a tampered build.
    assert "Bearer" not in json.dumps(report) or "[redacted]" in json.dumps(report)

    # --- Editorial review (Phase 1.8) ----------------------------------
    review = build_editorial_review(report)
    assert review["status"] == "READY_FOR_REVIEW"
    assert review["productive_change"] is False
    assert review["apply_status"] == "not_applied"
    assert review["summary"]["all_not_applied"] is True
    # Every proposal stays not_applied and carries the required fields.
    required_fields = {
        "action_id", "title", "current_signal", "proposed_improvement",
        "expected_benefit", "risk_classification", "autonomy_policy_class",
        "manual_review_required", "apply_status", "reason",
    }
    for p in review["proposals"]:
        assert required_fields.issubset(p.keys()), p
        assert p["apply_status"] == "not_applied"
    # HIGH-risk proposals must be blocked.
    for p in review["proposals"]:
        if p["risk_classification"] == RISK_HIGH:
            assert p["group"] == GROUP_BLOCKED_HIGH_RISK
            assert p["autonomy_policy_class"] == "BLOCKED_NOT_PERMITTED"
    # HIGH-risk signals are present and blocked.
    blocked_ids = set(review["groups"][GROUP_BLOCKED_HIGH_RISK])
    for must_block in ("perf-high-script-count", "perf-source-map", "perf-origin-5xx", "perf-ai-radio-microcache"):
        assert must_block in blocked_ids, must_block
    # External embeds are REVIEW_ONLY (not auto-applied).
    embed = next(p for p in review["proposals"] if p["action_id"] == "perf-external-embeds")
    assert embed["group"] == GROUP_REVIEW_ONLY
    # Lazy loading is capped at MEDIUM and not apply-ready.
    lazy_p = next(p for p in review["proposals"] if p["action_id"] == "perf-lazy-loading")
    assert lazy_p["risk_classification"] in {RISK_LOW, RISK_MEDIUM}
    assert lazy_p["apply_status"] == "not_applied"
    review_md = render_editorial_review_md(review)
    assert "Performance Editorial Review" in review_md
    assert GROUP_BLOCKED_HIGH_RISK in review_md

    # Missing audit report must not crash the editorial review.
    na_review = build_editorial_review(None)
    assert na_review["status"] == NOT_AVAILABLE
    assert na_review["proposals"] == []
    assert na_review["summary"]["all_not_applied"] is True
    assert NOT_AVAILABLE in render_editorial_review_md(na_review)

    # No secrets leak into the editorial review serialization.
    assert "[redacted]" in json.dumps(review) or not SECRETISH_RE.search(
        json.dumps(review).replace("authorization", "").replace("Authorization", "")
    )

    print("performance-safe-audit self-tests: OK")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Performance Safe Audit (read-only)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety/unit tests.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()

    report, next_actions = build_report()

    # Phase 1.8: editorial decision template derived from the audit report.
    review = build_editorial_review(report)
    # Optional, non-status-changing summary embedded in the audit report.
    report["editorial_review_summary"] = {
        "status": review.get("status"),
        "proposal_count": review.get("summary", {}).get("proposal_count"),
        "safe_quick_win_count": review.get("summary", {}).get("safe_quick_win_count"),
        "review_only_count": review.get("summary", {}).get("review_only_count"),
        "blocked_high_risk_count": review.get("summary", {}).get("blocked_high_risk_count"),
        "all_not_applied": review.get("summary", {}).get("all_not_applied"),
        "outputs": [str(EDITORIAL_REVIEW_JSON), str(EDITORIAL_REVIEW_MD)],
    }

    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report))
    write_text_atomic(NEXT_ACTIONS_MD, next_actions)
    write_json_atomic(EDITORIAL_REVIEW_JSON, review)
    write_text_atomic(EDITORIAL_REVIEW_MD, render_editorial_review_md(review))
    print(f"Performance safe audit report (JSON): {REPORT_JSON}")
    print(f"Performance safe audit report (MD):   {REPORT_MD}")
    print(f"Performance safe next actions draft:  {NEXT_ACTIONS_MD}")
    print(f"Performance editorial review (JSON):  {EDITORIAL_REVIEW_JSON}")
    print(f"Performance editorial review (MD):    {EDITORIAL_REVIEW_MD}")
    print(
        f"status={report['status']} highest_risk={report['highest_risk']} "
        f"review={review['status']} (read-only, no apply function)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
