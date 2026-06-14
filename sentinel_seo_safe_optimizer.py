#!/usr/bin/env python3
"""Read-only Sentinel SEO Safe Optimizer.

The optimizer inspects only local, already available SEO artifacts and writes
reports/drafts under the Sentinel project. It never edits WordPress, Nginx,
Cloudflare, .htaccess, or any production configuration.

Note (Phase 1.5): Whether any of the drafts produced here may ever be applied
is decided centrally by the Autonomy Policy Layer in
``sentinel_autonomy_policy.py`` (policy-only / dry-run). This optimizer has no
hard dependency on that module and never applies changes itself.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen


PROJECT_DIR = Path("/srv/sentinel-defense")
REPORT_MD = PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.json"
DRAFT_DIR = PROJECT_DIR / "drafts/seo"
SEO_INPUT_DIR = PROJECT_DIR / "seo-inputs/latest"
META_DRAFT_JSON = DRAFT_DIR / "homepage-meta-draft.json"
SCHEMA_DRAFT_JSONLD = DRAFT_DIR / "homepage-schema-draft.jsonld"
NEXT_ACTIONS_MD = DRAFT_DIR / "safe-optimizer-next-actions.md"
META_IMPROVED_DRAFT_JSON = DRAFT_DIR / "homepage-meta-improved-draft.json"
OG_TWITTER_DRAFT_JSON = DRAFT_DIR / "homepage-og-twitter-draft.json"
INTERNAL_LINK_SUGGESTIONS_MD = DRAFT_DIR / "homepage-internal-link-suggestions.md"
CONTENT_OUTLINE_SUGGESTIONS_MD = DRAFT_DIR / "homepage-content-outline-suggestions.md"
EDITORIAL_REVIEW_MD = DRAFT_DIR / "homepage-editorial-review.md"
EDITORIAL_REVIEW_JSON = DRAFT_DIR / "homepage-editorial-review.json"
INPUT_HOMEPAGE_HTML = SEO_INPUT_DIR / "homepage.html"
INPUT_ROBOTS_TXT = SEO_INPUT_DIR / "robots.txt"
INPUT_SITEMAP_XML = SEO_INPUT_DIR / "sitemap.xml"
INPUT_HEADERS_HOMEPAGE = SEO_INPUT_DIR / "headers-homepage.txt"
INPUT_MANIFEST_JSON = SEO_INPUT_DIR / "fetch-manifest.json"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/seo",
    PROJECT_DIR / "seo-inputs/latest",
)

DEFAULT_HTML_CANDIDATES = (
    INPUT_HOMEPAGE_HTML,
    DRAFT_DIR / "homepage.html",
    DRAFT_DIR / "homepage-source.html",
    PROJECT_DIR / "reports/latest/homepage.html",
    PROJECT_DIR / "reports/latest/homepage-source.html",
    PROJECT_DIR / "reports/latest/site-homepage.html",
    PROJECT_DIR / "reports/latest/seo-homepage.html",
)
DEFAULT_ROBOTS_CANDIDATES = (
    INPUT_ROBOTS_TXT,
    DRAFT_DIR / "robots.txt",
    PROJECT_DIR / "reports/latest/robots.txt",
)
DEFAULT_SITEMAP_CANDIDATES = (
    INPUT_SITEMAP_XML,
    DRAFT_DIR / "sitemap.xml",
    DRAFT_DIR / "sitemap_index.xml",
    PROJECT_DIR / "reports/latest/sitemap.xml",
    PROJECT_DIR / "reports/latest/sitemap_index.xml",
)
DEFAULT_CONTEXT_REPORTS = (
    PROJECT_DIR / "reports/latest/sentinel-master-report.json",
    PROJECT_DIR / "reports/latest/sentinel-defense-report.json",
)

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"
RISK_VALUES = {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY}

DEFAULT_SITE_URL = "https://electri-c-ity-studios-24-7.com/"
DEFAULT_ROBOTS_URL = "https://electri-c-ity-studios-24-7.com/robots.txt"
DEFAULT_SITEMAP_URL = "https://electri-c-ity-studios-24-7.com/sitemap_index.xml"
DEFAULT_SITE_NAME = "Electri_C_ity Studios"
DEFAULT_RADIO_NAME = "Electri-City AI Electro Radio"
DEFAULT_DESCRIPTION = (
    "Electri_C_ity Studios verbindet AI Radio, elektronische Musik und digitale Tools "
    "in einer sicheren, reviewbaren Web-Präsenz."
)
IMPROVED_TITLE = "Electri_C_ity Studios | 24/7 AI Electro Radio"
IMPROVED_DESCRIPTION = (
    "Electri_C_ity Studios streams 24/7 AI electro radio with techno, progressive house, "
    "digital tools, NFT-inspired cover art and independent releases."
)

SECRETISH_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|credential)")
OWN_DOMAIN_SUFFIX = "electri-c-ity-studios-24-7.com"
MAX_FETCH_BYTES = 2_000_000
MAX_FETCH_TIMEOUT = 10.0
SAFE_RESPONSE_HEADER_DENYLIST = {
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authenticate",
    "www-authenticate",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def redact_text(value: Any, default: str = "-", max_len: int = 500) -> str:
    if value is None:
        return default
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def strip_url_query(value: Any) -> str:
    text = redact_text(value, default="")
    if not text or text == "[redacted]":
        return text
    parsed = urlparse(text)
    if not parsed.scheme and not parsed.netloc:
        return text.split("?", 1)[0].split("#", 1)[0]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def parse_count(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except ValueError:
            return 0
    return 0


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed Sentinel SEO output roots: {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def safe_public_url(url: str) -> Tuple[Optional[str], str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None, "unsupported_scheme"
    hostname = (parsed.hostname or "").lower()
    if hostname != OWN_DOMAIN_SUFFIX and not hostname.endswith("." + OWN_DOMAIN_SUFFIX):
        return None, "refused_non_own_domain"
    if parsed.username or parsed.password:
        return None, "refused_credentials_in_url"
    safe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
    return safe_url, "ok"


def clamp_timeout(value: float) -> float:
    if value <= 0:
        return 1.0
    return min(float(value), MAX_FETCH_TIMEOUT)


def sanitized_response_headers(headers: Any) -> List[Tuple[str, str]]:
    safe: List[Tuple[str, str]] = []
    for key, value in headers.items():
        lower = str(key).lower()
        if lower in SAFE_RESPONSE_HEADER_DENYLIST or SECRETISH_RE.search(lower):
            continue
        safe.append((str(key), redact_text(value, max_len=500)))
    return safe


def format_headers_snapshot(url: str, result: Dict[str, Any]) -> str:
    lines = [
        f"url: {strip_url_query(url)}",
        f"fetched_at_utc: {result.get('fetched_at_utc')}",
        f"method: {result.get('method')}",
        f"status: {result.get('status_code')}",
        f"final_url: {strip_url_query(result.get('final_url'))}",
    ]
    for key, value in result.get("headers", []):
        lines.append(f"{key}: {value}")
    lines.append("")
    return "\n".join(lines)


def fetch_public_snapshot(url: str, method: str, timeout: float) -> Dict[str, Any]:
    safe_url, url_status = safe_public_url(url)
    result: Dict[str, Any] = {
        "url": strip_url_query(url),
        "safe_url_status": url_status,
        "method": method,
        "fetched_at_utc": utc_now(),
        "ok": False,
        "status": "not_available",
        "status_code": None,
        "final_url": None,
        "headers": [],
        "bytes": 0,
        "truncated": False,
        "error": None,
    }
    if url_status != "ok" or not safe_url:
        result["error"] = url_status
        return result

    request = Request(
        safe_url,
        method=method,
        headers={
            "User-Agent": "SentinelSEOReadOnly/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml,text/plain;q=0.9,*/*;q=0.1",
        },
    )
    try:
        with urlopen(request, timeout=clamp_timeout(timeout)) as response:
            body = b"" if method == "HEAD" else response.read(MAX_FETCH_BYTES + 1)
            result.update(
                {
                    "ok": True,
                    "status": "ok",
                    "status_code": getattr(response, "status", None),
                    "final_url": strip_url_query(response.geturl()),
                    "headers": sanitized_response_headers(response.headers),
                    "bytes": min(len(body), MAX_FETCH_BYTES),
                    "truncated": len(body) > MAX_FETCH_BYTES,
                    "body": body[:MAX_FETCH_BYTES].decode("utf-8", errors="replace"),
                }
            )
    except HTTPError as exc:
        body = b""
        if method != "HEAD":
            try:
                body = exc.read(MAX_FETCH_BYTES + 1)
            except OSError:
                body = b""
        result.update(
            {
                "ok": False,
                "status": "http_error",
                "status_code": exc.code,
                "final_url": strip_url_query(exc.geturl()),
                "headers": sanitized_response_headers(exc.headers),
                "bytes": min(len(body), MAX_FETCH_BYTES),
                "truncated": len(body) > MAX_FETCH_BYTES,
                "body": body[:MAX_FETCH_BYTES].decode("utf-8", errors="replace"),
                "error": f"http_error:{exc.code}",
            }
        )
    except (URLError, TimeoutError, OSError) as exc:
        result["error"] = f"{exc.__class__.__name__}"
        result["status"] = "not_available"
    return result


def collect_inputs(args: argparse.Namespace) -> Dict[str, Any]:
    timeout = clamp_timeout(float(args.fetch_timeout))
    fetches = [
        {
            "kind": "homepage_html",
            "method": "GET",
            "url": args.homepage_url,
            "path": INPUT_HOMEPAGE_HTML,
        },
        {
            "kind": "robots_txt",
            "method": "GET",
            "url": args.robots_url,
            "path": INPUT_ROBOTS_TXT,
        },
        {
            "kind": "sitemap_xml",
            "method": "GET",
            "url": args.sitemap_url,
            "path": INPUT_SITEMAP_XML,
        },
        {
            "kind": "headers_homepage",
            "method": "HEAD",
            "url": args.homepage_url,
            "path": INPUT_HEADERS_HOMEPAGE,
        },
    ]
    manifest: Dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "mode": "collect-inputs",
        "read_only_fetch": True,
        "productive_change": False,
        "max_fetch_bytes": MAX_FETCH_BYTES,
        "timeout_seconds": timeout,
        "outputs_root": str(SEO_INPUT_DIR),
        "fetches": [],
    }
    for item in fetches:
        result = fetch_public_snapshot(str(item["url"]), str(item["method"]), timeout)
        body = result.pop("body", "")
        output_path = Path(item["path"])
        if item["method"] == "HEAD":
            write_text_atomic(output_path, format_headers_snapshot(str(item["url"]), result))
            written = True
        elif body:
            write_text_atomic(output_path, body)
            written = True
        else:
            written = False
        manifest["fetches"].append(
            {
                "kind": item["kind"],
                "method": item["method"],
                "url": strip_url_query(item["url"]),
                "output_path": str(output_path),
                "written": written,
                "ok": bool(result.get("ok")),
                "status": result.get("status"),
                "status_code": result.get("status_code"),
                "bytes": result.get("bytes"),
                "truncated": result.get("truncated"),
                "error": result.get("error"),
                "safe_url_status": result.get("safe_url_status"),
            }
        )
    write_json_atomic(INPUT_MANIFEST_JSON, manifest)
    return manifest


def read_text_if_safe(path: Path, allowed_suffixes: Iterable[str], max_bytes: int = 2_000_000) -> Tuple[Optional[str], str]:
    suffixes = {item.lower() for item in allowed_suffixes}
    if not path:
        return None, "not_configured"
    if not path.exists():
        return None, "not_available"
    if not path.is_file():
        return None, "not_a_file"
    if path.suffix.lower() not in suffixes:
        return None, "unsupported_suffix"
    lowered = str(path).lower()
    if ".env" in lowered or SECRETISH_RE.search(path.name):
        return None, "refused_secret_like_path"
    try:
        if path.stat().st_size > max_bytes:
            return None, "too_large"
        return path.read_text(encoding="utf-8", errors="replace"), "ok"
    except OSError as exc:
        return None, f"read_error:{exc.__class__.__name__}"


def first_existing(paths: Iterable[Path]) -> Optional[Path]:
    for path in paths:
        if path.exists() and path.is_file():
            return path
    return None


def file_freshness(path: Optional[Path]) -> Dict[str, Any]:
    if not path or not path.exists():
        return {"exists": False, "status": "not_available"}
    try:
        stat = path.stat()
    except OSError as exc:
        return {"exists": True, "status": f"stat_error:{exc.__class__.__name__}"}
    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    age_seconds = max(int((datetime.now(timezone.utc) - mtime).total_seconds()), 0)
    return {
        "exists": True,
        "status": "ok",
        "path": str(path),
        "size_bytes": stat.st_size,
        "mtime_utc": mtime.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "age_seconds": age_seconds,
    }


def read_fetch_manifest() -> Dict[str, Any]:
    data, status, exists = read_json_report(INPUT_MANIFEST_JSON)
    if exists and status == "ok":
        return data
    return {"present": False, "status": status, "path": str(INPUT_MANIFEST_JSON)}


def fetch_errors_from_manifest(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    errors = []
    fetches = manifest.get("fetches") if isinstance(manifest.get("fetches"), list) else []
    for item in fetches:
        if not isinstance(item, dict):
            continue
        if item.get("ok"):
            continue
        errors.append(
            {
                "kind": item.get("kind"),
                "url": strip_url_query(item.get("url")),
                "status": item.get("status"),
                "status_code": item.get("status_code"),
                "error": redact_text(item.get("error")),
                "written": bool(item.get("written")),
            }
        )
    return errors


def parse_headers_snapshot(text: Optional[str], status: str) -> Dict[str, Any]:
    if status != "ok" or text is None:
        return {"status": status, "cf_mitigated": "unknown", "http_status": None}
    result: Dict[str, Any] = {"status": "ok", "cf_mitigated": None, "http_status": None, "headers": {}}
    headers: Dict[str, str] = {}
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key_clean = key.strip().lower()
        value_clean = value.strip()
        if key_clean == "status":
            result["http_status"] = value_clean
        elif key_clean not in SAFE_RESPONSE_HEADER_DENYLIST and not SECRETISH_RE.search(key_clean):
            headers[key_clean] = redact_text(value_clean, max_len=300)
    result["headers"] = headers
    result["cf_mitigated"] = headers.get("cf-mitigated")
    result["server"] = headers.get("server")
    return result


def detected_homepage_seo(snapshot: Optional[HtmlSnapshot], headers: Dict[str, Any]) -> Dict[str, Any]:
    if snapshot is None:
        return {
            "available": False,
            "snapshot_likely_cloudflare_challenge": headers.get("cf_mitigated") == "challenge",
        }
    return {
        "available": True,
        "snapshot_likely_cloudflare_challenge": headers.get("cf_mitigated") == "challenge",
        "title": redact_text(snapshot.title),
        "title_length": len(snapshot.title),
        "meta_description_present": bool(snapshot.meta_description),
        "meta_description_length": len(snapshot.meta_description),
        "canonical": redact_text(snapshot.canonical),
        "open_graph_count": len(snapshot.open_graph),
        "twitter_card_count": len(snapshot.twitter_cards),
        "h1_count": len(snapshot.h1),
        "h2_count": len(snapshot.h2),
        "json_ld_count": len(snapshot.json_ld),
        "internal_link_count": len(set(snapshot.internal_links)),
        "image_count": len(snapshot.images),
        "images_missing_alt_count": len([image for image in snapshot.images if not image.get("alt")]),
    }


def current_homepage_seo(snapshot: Optional[HtmlSnapshot]) -> Dict[str, Any]:
    if snapshot is None:
        return {"available": False}
    internal_links = sorted(set(snapshot.internal_links))
    external_links = sorted(set(snapshot.external_links))
    images_missing_alt = [image for image in snapshot.images if not image.get("alt")]
    return {
        "available": True,
        "title": redact_text(snapshot.title),
        "title_length": len(snapshot.title),
        "meta_description": redact_text(snapshot.meta_description, max_len=700),
        "meta_description_length": len(snapshot.meta_description),
        "canonical": redact_text(snapshot.canonical),
        "open_graph": {key: redact_text(value, max_len=700) for key, value in sorted(snapshot.open_graph.items())},
        "twitter_cards": {key: redact_text(value, max_len=700) for key, value in sorted(snapshot.twitter_cards.items())},
        "h1": snapshot.h1[:12],
        "h2": snapshot.h2[:24],
        "internal_links_count": len(internal_links),
        "internal_links_sample": internal_links[:24],
        "external_links_count": len(external_links),
        "external_links_sample": external_links[:24],
        "image_count": len(snapshot.images),
        "images_with_alt_count": len(snapshot.images) - len(images_missing_alt),
        "images_missing_alt_count": len(images_missing_alt),
        "images_missing_alt_sample": images_missing_alt[:12],
        "json_ld_types": sorted(schema_type(item) for item in snapshot.json_ld if schema_type(item)),
        "json_ld_count": len(snapshot.json_ld),
    }


def improved_meta_draft(current: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "draft_only": True,
        "apply_status": "not_applied",
        "risk_classification": RISK_LOW,
        "brand": DEFAULT_SITE_NAME,
        "primary_domain": DEFAULT_SITE_URL,
        "current": {
            "title": current.get("title", "not_available"),
            "title_length": current.get("title_length"),
            "meta_description": current.get("meta_description", "not_available"),
            "meta_description_length": current.get("meta_description_length"),
            "canonical": current.get("canonical", "not_available"),
        },
        "improved": {
            "title": IMPROVED_TITLE,
            "title_length": len(IMPROVED_TITLE),
            "meta_description": IMPROVED_DESCRIPTION,
            "meta_description_length": len(IMPROVED_DESCRIPTION),
            "canonical": DEFAULT_SITE_URL,
        },
        "rules": {
            "title_max_characters_target": 60,
            "meta_description_target_range": "140-160",
            "keyword_stuffing": False,
            "brand_consistency": "Electri_C_ity Studios",
        },
        "positioning_terms": [
            "24/7 AI Electro Radio",
            "Electro",
            "Techno",
            "Progressive House",
            "AI-assisted music",
            "digital tools",
            "NFT-inspired cover art",
            "independent music releases",
        ],
        "review_notes": [
            "Draft only; do not apply automatically.",
            "Confirm final wording with editorial owner before WordPress/CMS publication.",
        ],
    }


def og_twitter_draft(current: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "draft_only": True,
        "apply_status": "not_applied",
        "risk_classification": RISK_LOW,
        "current_open_graph": current.get("open_graph", {}),
        "current_twitter_cards": current.get("twitter_cards", {}),
        "recommended_open_graph": {
            "og:type": "website",
            "og:site_name": DEFAULT_SITE_NAME,
            "og:title": "Electri_C_ity Studios 24/7 AI Electro Radio",
            "og:description": IMPROVED_DESCRIPTION,
            "og:url": DEFAULT_SITE_URL,
        },
        "recommended_twitter_cards": {
            "twitter:card": "summary_large_image",
            "twitter:title": "Electri_C_ity Studios 24/7 AI Electro Radio",
            "twitter:description": IMPROVED_DESCRIPTION,
        },
        "image_guidance": [
            "Use a stable, crawlable cover-art image only after confirming rights and dimensions.",
            "Avoid changing social images automatically from Sentinel.",
        ],
    }


def improved_schema_draft(site_url: str = DEFAULT_SITE_URL) -> Dict[str, Any]:
    org_id = site_url.rstrip("/") + "/#organization"
    website_id = site_url.rstrip("/") + "/#website"
    radio_id = site_url.rstrip("/") + "/#radio"
    music_id = site_url.rstrip("/") + "/#musicgroup"
    creative_id = site_url.rstrip("/") + "/#creativework"
    tools_template_id = site_url.rstrip("/") + "/#software-template"
    return {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "WebSite",
                "@id": website_id,
                "url": site_url,
                "name": DEFAULT_SITE_NAME,
                "description": IMPROVED_DESCRIPTION,
                "publisher": {"@id": org_id},
                "inLanguage": "en",
            },
            {
                "@type": "Organization",
                "@id": org_id,
                "name": DEFAULT_SITE_NAME,
                "url": site_url,
                "description": "Independent studio for AI-assisted electronic music, digital tools and visual cover-art concepts.",
            },
            {
                "@type": "RadioStation",
                "@id": radio_id,
                "name": DEFAULT_RADIO_NAME,
                "url": "https://ai-radio.electri-c-ity-studios-24-7.com/",
                "genre": ["Electro", "Techno", "Progressive House"],
                "parentOrganization": {"@id": org_id},
            },
            {
                "@type": "MusicGroup",
                "@id": music_id,
                "name": DEFAULT_SITE_NAME,
                "url": site_url,
                "genre": ["Electro", "Techno", "Progressive House"],
            },
            {
                "@type": "CreativeWork",
                "@id": creative_id,
                "name": "NFT-inspired cover art and AI-assisted music releases",
                "creator": {"@id": org_id},
                "about": ["AI-assisted music", "NFT-inspired cover art", "independent music releases"],
                "url": site_url,
            },
            {
                "@type": "SoftwareApplication",
                "@id": tools_template_id,
                "name": "Electri_C_ity Studios Digital Tools",
                "applicationCategory": "MultimediaApplication",
                "operatingSystem": "Web",
                "url": site_url,
                "publisher": {"@id": org_id},
                "additionalType": "Draft template only; remove or specialize before publication.",
            },
        ],
        "draft_only": True,
        "apply_status": "not_applied",
        "risk_classification": RISK_REVIEW_ONLY,
        "review_notes": [
            "Review visible page content before publishing schema.",
            "SoftwareApplication is included as an optional template only.",
            "Do not add prices, offers, reviews, or ratings unless visible and verified.",
        ],
    }


def internal_link_suggestions(current: Dict[str, Any]) -> List[Dict[str, str]]:
    current_links = set(current.get("internal_links_sample") or [])
    suggestions = [
        {
            "target": "/",
            "anchor": "Electri_C_ity Studios home",
            "reason": "Keep the homepage as the canonical brand hub.",
        },
        {
            "target": "https://ai-radio.electri-c-ity-studios-24-7.com/",
            "anchor": "24/7 AI Electro Radio",
            "reason": "Connect the homepage to the radio experience without changing streaming paths.",
        },
        {
            "target": "/music/",
            "anchor": "independent electro and techno releases",
            "reason": "Create a crawlable hub for independent releases if this page exists or is planned.",
        },
        {
            "target": "/tools/",
            "anchor": "digital music and creative tools",
            "reason": "Support the digital tools positioning with a clear internal destination.",
        },
        {
            "target": "/cover-art/",
            "anchor": "NFT-inspired cover art",
            "reason": "Separate visual art concepts from music/radio content for clearer topical structure.",
        },
        {
            "target": "/blog/",
            "anchor": "studio notes and release updates",
            "reason": "Use blog structure for long-form updates, release context and tutorials.",
        },
    ]
    for item in suggestions:
        item["risk_classification"] = RISK_REVIEW_ONLY if item["target"] not in current_links else RISK_LOW
        item["apply_status"] = "not_applied"
    return suggestions


def content_outline_suggestions() -> List[Dict[str, Any]]:
    return [
        {
            "section": "Hero",
            "suggested_h1": "Electri_C_ity Studios 24/7 AI Electro Radio",
            "supporting_copy": "AI-assisted electro, techno and progressive house with independent releases, digital tools and cover-art concepts.",
            "risk_classification": RISK_LOW,
        },
        {
            "section": "Radio",
            "suggested_h2": "24/7 AI Electro Radio",
            "topics": ["now playing", "station link", "genre focus", "stale-safe player status"],
            "risk_classification": RISK_LOW,
        },
        {
            "section": "Music",
            "suggested_h2": "Independent electro and techno releases",
            "topics": ["release cards", "artist notes", "progressive house influences"],
            "risk_classification": RISK_LOW,
        },
        {
            "section": "Digital Tools",
            "suggested_h2": "Digital tools for music and creative workflows",
            "topics": ["tool descriptions", "safe demos", "documentation links"],
            "risk_classification": RISK_REVIEW_ONLY,
        },
        {
            "section": "Cover Art",
            "suggested_h2": "NFT-inspired cover art",
            "topics": ["visual identity", "rights-safe image selection", "release artwork"],
            "risk_classification": RISK_REVIEW_ONLY,
        },
        {
            "section": "Blog Structure",
            "suggested_h2": "Studio notes, release updates and production logs",
            "topics": ["one H1 per post", "publish/update dates", "author or studio owner", "internal links to releases/tools/radio"],
            "risk_classification": RISK_LOW,
        },
    ]


def render_internal_link_suggestions(suggestions: List[Dict[str, str]]) -> str:
    lines = [
        "# Homepage Internal Link Suggestions",
        "",
        "Draft only. Verify that each target exists before adding links in WordPress or any CMS.",
        "",
        "| Target | Anchor | Risk | Reason |",
        "|---|---|---|---|",
    ]
    for item in suggestions:
        lines.append(
            f"| `{item['target']}` | {item['anchor']} | `{item['risk_classification']}` | {item['reason']} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_content_outline_suggestions(sections: List[Dict[str, Any]]) -> str:
    lines = [
        "# Homepage Content Outline Suggestions",
        "",
        "Draft only. These are editorial structure suggestions, not live changes.",
        "",
    ]
    for item in sections:
        lines.append(f"## {item['section']}")
        if item.get("suggested_h1"):
            lines.append(f"- Suggested H1: {item['suggested_h1']}")
        if item.get("suggested_h2"):
            lines.append(f"- Suggested H2: {item['suggested_h2']}")
        if item.get("supporting_copy"):
            lines.append(f"- Supporting copy: {item['supporting_copy']}")
        topics = item.get("topics") if isinstance(item.get("topics"), list) else []
        if topics:
            lines.append(f"- Topics: {', '.join(str(topic) for topic in topics)}")
        lines.append(f"- Risk: `{item['risk_classification']}`")
        lines.append("")
    return "\n".join(lines)


def read_json_draft(path: Path) -> Tuple[Dict[str, Any], str]:
    if not path.exists():
        return {}, "not_available"
    if path.suffix.lower() not in {".json", ".jsonld"}:
        return {}, "unsupported_suffix"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, f"read_error:{exc.__class__.__name__}"
    return data if isinstance(data, dict) else {}, "ok"


def read_markdown_draft(path: Path) -> Tuple[str, str]:
    text, status = read_text_if_safe(path, {".md"}, max_bytes=500_000)
    return text or "", status


def parse_internal_link_suggestions(text: str) -> List[Dict[str, Any]]:
    suggestions: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("| `") or line.startswith("| `Target`"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 4:
            continue
        target = cells[0].strip("` ")
        anchor = cells[1].strip()
        risk = cells[2].strip("` ")
        reason = cells[3].strip()
        suggestions.append({"target": target, "anchor": anchor, "risk": risk, "reason": reason})
    return suggestions


def parse_content_outline(text: str) -> List[Dict[str, Any]]:
    sections: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("## "):
            current = {"section": line[3:].strip()}
            sections.append(current)
        elif current is not None and line.startswith("- "):
            if ":" in line:
                key, value = line[2:].split(":", 1)
                current[key.strip().lower().replace(" ", "_")] = value.strip().strip("`")
    return sections


def normalize_link_target(target: str) -> str:
    if not target:
        return ""
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return strip_url_query(target).rstrip("/") + ("/" if parsed.path in {"", "/"} else "")
    if target.startswith("/"):
        return (DEFAULT_SITE_URL.rstrip("/") + target).rstrip("/") + ("/" if target.endswith("/") else "")
    return target


def snapshot_known_targets(current: Dict[str, Any], sitemap: Dict[str, Any]) -> Dict[str, Any]:
    known = set()
    homepage_links = current.get("internal_links_sample") if isinstance(current.get("internal_links_sample"), list) else []
    sitemap_urls = sitemap.get("sample_urls") if isinstance(sitemap.get("sample_urls"), list) else []
    for value in homepage_links + sitemap_urls + [DEFAULT_SITE_URL]:
        normalized = normalize_link_target(str(value))
        if normalized:
            known.add(normalized)
            known.add(normalized.rstrip("/"))
    return {
        "known_targets": sorted(known),
        "source_policy": "Only homepage snapshot internal links and sitemap snapshot URLs count as existing.",
    }


def link_target_exists(target: str, known_targets: Iterable[str]) -> bool:
    normalized = normalize_link_target(target)
    known = set(known_targets)
    return normalized in known or normalized.rstrip("/") in known


def review_item(
    proposal_id: str,
    category: str,
    current_value: Any,
    proposed_value: Any,
    recommendation: str,
    risk: str,
    reason: str,
    manual_review_required: bool = True,
) -> Dict[str, Any]:
    if risk not in {RISK_LOW, RISK_REVIEW_ONLY}:
        risk = RISK_REVIEW_ONLY
    if recommendation not in {"keep", "improve", "review_only", "do_not_apply"}:
        recommendation = "review_only"
    return {
        "proposal_id": proposal_id,
        "category": category,
        "current_value": current_value,
        "proposed_value": proposed_value,
        "recommendation": recommendation,
        "risk_classification": risk,
        "apply_status": "not_applied",
        "reason": redact_text(reason, max_len=900),
        "manual_review_required": bool(manual_review_required),
    }


def build_editorial_review(
    current: Dict[str, Any],
    sitemap: Dict[str, Any],
) -> Dict[str, Any]:
    meta, meta_status = read_json_draft(META_IMPROVED_DRAFT_JSON)
    og_twitter, og_status = read_json_draft(OG_TWITTER_DRAFT_JSON)
    schema, schema_status = read_json_draft(SCHEMA_DRAFT_JSONLD)
    links_md, links_status = read_markdown_draft(INTERNAL_LINK_SUGGESTIONS_MD)
    outline_md, outline_status = read_markdown_draft(CONTENT_OUTLINE_SUGGESTIONS_MD)

    known = snapshot_known_targets(current, sitemap)
    link_suggestions = parse_internal_link_suggestions(links_md) if links_status == "ok" else []
    outline_sections = parse_content_outline(outline_md) if outline_status == "ok" else []
    proposals: List[Dict[str, Any]] = []

    improved = meta.get("improved") if isinstance(meta.get("improved"), dict) else {}
    current_meta = meta.get("current") if isinstance(meta.get("current"), dict) else {}
    if meta_status == "ok":
        proposed_title = improved.get("title")
        current_title = current_meta.get("title") or current.get("title")
        proposals.append(
            review_item(
                "title",
                "Title",
                current_title,
                proposed_title,
                "improve" if proposed_title and proposed_title != current_title else "keep",
                RISK_LOW,
                "Proposed title is shorter, brand-consistent, and focused on 24/7 AI Electro Radio.",
            )
        )
        proposed_description = improved.get("meta_description")
        current_description = current_meta.get("meta_description") or current.get("meta_description")
        proposals.append(
            review_item(
                "meta_description",
                "Meta Description",
                current_description,
                proposed_description,
                "improve" if proposed_description and proposed_description != current_description else "keep",
                RISK_LOW,
                "Proposed description is within the 140-160 character target and avoids keyword stuffing.",
            )
        )
    else:
        proposals.append(
            review_item(
                "meta_draft_missing",
                "Meta",
                "not_available",
                "not_available",
                "review_only",
                RISK_REVIEW_ONLY,
                f"Meta improved draft is {meta_status}.",
            )
        )

    if og_status == "ok":
        proposals.append(
            review_item(
                "open_graph",
                "OpenGraph",
                og_twitter.get("current_open_graph", {}),
                og_twitter.get("recommended_open_graph", {}),
                "improve",
                RISK_LOW,
                "Recommended OpenGraph fields align social previews with the improved AI radio positioning.",
            )
        )
        proposals.append(
            review_item(
                "twitter_cards",
                "Twitter Cards",
                og_twitter.get("current_twitter_cards", {}),
                og_twitter.get("recommended_twitter_cards", {}),
                "improve",
                RISK_LOW,
                "Recommended Twitter Card fields mirror OpenGraph wording and remain draft-only.",
            )
        )
    else:
        proposals.append(review_item("social_draft_missing", "Social", "not_available", "not_available", "review_only", RISK_REVIEW_ONLY, f"OG/Twitter draft is {og_status}."))

    if schema_status == "ok":
        proposals.append(
            review_item(
                "schema",
                "Schema",
                current.get("json_ld_types", []),
                [item.get("@type") for item in schema.get("@graph", []) if isinstance(item, dict)],
                "review_only",
                RISK_REVIEW_ONLY,
                "Schema adds entity meaning but must be checked against visible page content before publication.",
            )
        )
    else:
        proposals.append(review_item("schema_draft_missing", "Schema", "not_available", "not_available", "review_only", RISK_REVIEW_ONLY, f"Schema draft is {schema_status}."))

    if link_suggestions:
        for index, item in enumerate(link_suggestions, start=1):
            exists = link_target_exists(str(item.get("target", "")), known["known_targets"])
            proposals.append(
                review_item(
                    f"internal_link_{index}",
                    "Internal Links",
                    "found_in_snapshot" if exists else "not_found_in_snapshot",
                    {"target": item.get("target"), "anchor": item.get("anchor")},
                    "improve" if exists else "review_only",
                    RISK_LOW if exists else RISK_REVIEW_ONLY,
                    (
                        "Target is present in homepage or sitemap snapshot."
                        if exists
                        else "Target was not found in homepage or sitemap snapshot; verify before adding."
                    ),
                )
            )
    else:
        proposals.append(review_item("internal_links_missing", "Internal Links", "not_available", "not_available", "review_only", RISK_REVIEW_ONLY, f"Internal link suggestions draft is {links_status}."))

    if outline_sections:
        proposals.append(
            review_item(
                "content_outline",
                "Content Outline",
                current.get("h2", []),
                outline_sections,
                "review_only",
                RISK_REVIEW_ONLY,
                "Outline is editorial guidance; it should be manually reviewed against current homepage design and content strategy.",
            )
        )
    else:
        proposals.append(review_item("content_outline_missing", "Content Outline", "not_available", "not_available", "review_only", RISK_REVIEW_ONLY, f"Content outline draft is {outline_status}."))

    return {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "phase": "1.4",
        "status": "READY_FOR_EDITORIAL_REVIEW",
        "productive_change": False,
        "apply_status": "not_applied",
        "manual_review_required": True,
        "forbidden_mutations": {
            "wordpress": False,
            "htaccess": False,
            "cloudflare": False,
            "nginx": False,
            "external_write": False,
        },
        "input_drafts": {
            str(META_IMPROVED_DRAFT_JSON): meta_status,
            str(OG_TWITTER_DRAFT_JSON): og_status,
            str(SCHEMA_DRAFT_JSONLD): schema_status,
            str(INTERNAL_LINK_SUGGESTIONS_MD): links_status,
            str(CONTENT_OUTLINE_SUGGESTIONS_MD): outline_status,
        },
        "link_target_policy": known,
        "proposals": proposals,
        "summary": {
            "proposal_count": len(proposals),
            "review_only_count": len([item for item in proposals if item.get("recommendation") == "review_only"]),
            "improve_count": len([item for item in proposals if item.get("recommendation") == "improve"]),
            "high_risk_count": 0,
            "all_not_applied": all(item.get("apply_status") == "not_applied" for item in proposals),
        },
    }


def render_editorial_review(review: Dict[str, Any]) -> str:
    lines = [
        "# Homepage Editorial Review",
        "",
        f"**Generated:** `{redact_text(review.get('generated_at_utc'))}` UTC",
        "",
        "## Summary",
        "",
        f"- Status: `{redact_text(review.get('status'))}`",
        f"- Productive Change: `{str(bool(review.get('productive_change'))).lower()}`",
        f"- Apply Status: `{redact_text(review.get('apply_status'))}`",
        f"- Manual Review Required: `{str(bool(review.get('manual_review_required'))).lower()}`",
        f"- Proposal Count: `{redact_text(review.get('summary', {}).get('proposal_count'))}`",
        f"- High Risk Count: `{redact_text(review.get('summary', {}).get('high_risk_count'))}`",
        "",
        "## Proposals",
        "",
        "| Proposal | Category | Recommendation | Risk | Apply | Manual Review | Reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in review.get("proposals", []):
        if not isinstance(item, dict):
            continue
        reason = redact_text(item.get("reason")).replace("|", "\\|")
        lines.append(
            f"| `{redact_text(item.get('proposal_id'))}` | `{redact_text(item.get('category'))}` | "
            f"`{redact_text(item.get('recommendation'))}` | `{redact_text(item.get('risk_classification'))}` | "
            f"`{redact_text(item.get('apply_status'))}` | `{str(bool(item.get('manual_review_required'))).lower()}` | "
            f"{reason} |"
        )
    lines.extend(
        [
            "",
            "## Link Target Policy",
            "",
            "- Existenz wird nur anerkannt, wenn ein Ziel im Sitemap-Snapshot oder Homepage-Snapshot vorkommt.",
            "- Nicht gefundene Ziele bleiben REVIEW_ONLY.",
            "",
            "## Safety",
            "",
            "- Keine Live-SEO-Aenderung.",
            "- Keine WordPress-, .htaccess-, Cloudflare- oder Nginx-Aenderung.",
            "- Alle Vorschlaege bleiben `not_applied`.",
            "",
        ]
    )
    return "\n".join(lines)


def missing_homepage_seo(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    missing_statuses = {"missing", "partial", "invalid", "duplicate", "too_short", "too_long", "low_count"}
    return [
        {
            "signal": item.get("signal"),
            "status": item.get("status"),
            "risk": item.get("risk"),
            "recommendation": item.get("recommendation"),
        }
        for item in findings
        if item.get("status") in missing_statuses
    ]


def risk_classification(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    order = {RISK_LOW: 1, RISK_MEDIUM: 2, RISK_HIGH: 3, RISK_REVIEW_ONLY: 4}
    counts = {risk: 0 for risk in sorted(RISK_VALUES)}
    highest = RISK_LOW
    for item in findings:
        risk = item.get("risk") if item.get("risk") in RISK_VALUES else RISK_REVIEW_ONLY
        counts[str(risk)] += 1
        if order[str(risk)] > order[highest]:
            highest = str(risk)
    return {
        "highest_risk": highest,
        "counts": counts,
        "policy": "Draft-only SEO recommendations; REVIEW_ONLY means manual editorial/technical review before publication.",
    }


@dataclass
class HtmlSnapshot:
    title: str = ""
    meta_description: str = ""
    canonical: str = ""
    open_graph: Dict[str, str] = field(default_factory=dict)
    twitter_cards: Dict[str, str] = field(default_factory=dict)
    h1: List[str] = field(default_factory=list)
    h2: List[str] = field(default_factory=list)
    internal_links: List[str] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)
    images: List[Dict[str, str]] = field(default_factory=list)
    json_ld: List[Dict[str, Any]] = field(default_factory=list)
    json_ld_errors: List[str] = field(default_factory=list)


class SeoHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.snapshot = HtmlSnapshot()
        self._capture_tag: Optional[str] = None
        self._capture_chunks: List[str] = []
        self._script_type = ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr = {name.lower(): (value or "") for name, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._capture_tag = "title"
            self._capture_chunks = []
            return
        if tag in {"h1", "h2"}:
            self._capture_tag = tag
            self._capture_chunks = []
            return
        if tag == "meta":
            name = attr.get("name", "").lower()
            prop = attr.get("property", "").lower()
            content = redact_text(attr.get("content", ""), default="")
            if name == "description":
                self.snapshot.meta_description = content
            elif prop.startswith("og:"):
                self.snapshot.open_graph[prop] = content
            elif name.startswith("twitter:"):
                self.snapshot.twitter_cards[name] = content
            return
        if tag == "link" and attr.get("rel", "").lower() == "canonical":
            self.snapshot.canonical = strip_url_query(attr.get("href", ""))
            return
        if tag == "a":
            href = strip_url_query(attr.get("href", ""))
            if not href:
                return
            parsed = urlparse(href)
            if not parsed.netloc or parsed.netloc.endswith("electri-c-ity-studios-24-7.com"):
                self.snapshot.internal_links.append(href)
            else:
                self.snapshot.external_links.append(href)
            return
        if tag == "img":
            self.snapshot.images.append(
                {
                    "src": strip_url_query(attr.get("src", "")),
                    "alt": redact_text(attr.get("alt", ""), default=""),
                }
            )
            return
        if tag == "script":
            self._script_type = attr.get("type", "").lower()
            if self._script_type == "application/ld+json":
                self._capture_tag = "jsonld"
                self._capture_chunks = []

    def handle_data(self, data: str) -> None:
        if self._capture_tag:
            self._capture_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._capture_tag == "title" and tag == "title":
            self.snapshot.title = redact_text(" ".join(self._capture_chunks), default="")
            self._capture_tag = None
        elif self._capture_tag in {"h1", "h2"} and tag == self._capture_tag:
            text = redact_text(" ".join(self._capture_chunks), default="")
            if text and text != "-":
                getattr(self.snapshot, tag).append(text)
            self._capture_tag = None
        elif self._capture_tag == "jsonld" and tag == "script":
            raw = "\n".join(self._capture_chunks).strip()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                self.snapshot.json_ld_errors.append(f"jsonld_parse_error:{exc.__class__.__name__}")
            else:
                if isinstance(parsed, list):
                    self.snapshot.json_ld.extend(item for item in parsed if isinstance(item, dict))
                elif isinstance(parsed, dict):
                    self.snapshot.json_ld.append(parsed)
            self._capture_tag = None
            self._script_type = ""


def parse_html(html: str) -> HtmlSnapshot:
    parser = SeoHtmlParser()
    parser.feed(html)
    parser.close()
    return parser.snapshot


def classify_risk(signal: str, status: str, *, html_available: bool = True) -> str:
    status = status.lower()
    signal = signal.lower()
    if not html_available or status in {"unknown", "not_available"}:
        return RISK_REVIEW_ONLY
    if "noindex" in signal or "disallow_all" in signal or status == "blocking":
        return RISK_HIGH
    if status in {"missing", "invalid", "duplicate", "too_short", "too_long"}:
        return RISK_MEDIUM
    if status in {"partial", "weak", "low_count"}:
        return RISK_LOW
    return RISK_LOW


def finding(signal: str, status: str, message: str, recommendation: str, risk: Optional[str] = None, *, html_available: bool = True) -> Dict[str, Any]:
    risk_value = risk or classify_risk(signal, status, html_available=html_available)
    if risk_value not in RISK_VALUES:
        risk_value = RISK_REVIEW_ONLY
    return {
        "signal": signal,
        "status": status,
        "risk": risk_value,
        "message": redact_text(message, max_len=700),
        "recommendation": redact_text(recommendation, max_len=700),
    }


def analyze_html(snapshot: Optional[HtmlSnapshot], html_status: str) -> List[Dict[str, Any]]:
    html_available = snapshot is not None and html_status == "ok"
    if not html_available or snapshot is None:
        return [
            finding(
                "html_input",
                html_status,
                "No local homepage HTML artifact was available for structural SEO analysis.",
                "Provide a reviewed static homepage HTML export under drafts/seo/homepage.html for deeper read-only analysis.",
                RISK_REVIEW_ONLY,
                html_available=False,
            )
        ]

    findings: List[Dict[str, Any]] = []
    title_len = len(snapshot.title)
    if not snapshot.title:
        findings.append(finding("title", "missing", "Title tag is missing.", "Draft a concise homepage title before any CMS change."))
    elif title_len < 25:
        findings.append(finding("title", "too_short", f"Title length is {title_len}.", "Expand title with brand and primary offer."))
    elif title_len > 65:
        findings.append(finding("title", "too_long", f"Title length is {title_len}.", "Shorten title to avoid SERP truncation."))
    else:
        findings.append(finding("title", "ok", f"Title length is {title_len}.", "Keep title stable unless brand positioning changes."))

    desc_len = len(snapshot.meta_description)
    if not snapshot.meta_description:
        findings.append(finding("meta_description", "missing", "Meta description is missing.", "Draft a 140-160 character description."))
    elif desc_len < 90:
        findings.append(finding("meta_description", "too_short", f"Meta description length is {desc_len}.", "Add a more complete user-facing summary."))
    elif desc_len > 170:
        findings.append(finding("meta_description", "too_long", f"Meta description length is {desc_len}.", "Shorten description for search snippets."))
    else:
        findings.append(finding("meta_description", "ok", f"Meta description length is {desc_len}.", "Keep description stable."))

    if not snapshot.canonical:
        findings.append(finding("canonical", "missing", "Canonical URL is missing.", "Draft a self-referencing canonical for the homepage."))
    elif "electri-c-ity-studios-24-7.com" not in snapshot.canonical:
        findings.append(finding("canonical", "invalid", "Canonical points outside the expected own domain.", "Review canonical before any change.", RISK_HIGH))
    else:
        findings.append(finding("canonical", "ok", "Canonical URL points to the own domain.", "No action unless URL strategy changes."))

    required_og = {"og:title", "og:description", "og:url", "og:type"}
    missing_og = sorted(required_og - set(snapshot.open_graph))
    findings.append(
        finding(
            "open_graph",
            "partial" if missing_og else "ok",
            f"Missing OpenGraph fields: {', '.join(missing_og) if missing_og else 'none'}.",
            "Add missing OpenGraph fields in a reviewed CMS/meta update." if missing_og else "OpenGraph basics are present.",
            RISK_LOW,
        )
    )

    required_twitter = {"twitter:card", "twitter:title", "twitter:description"}
    missing_twitter = sorted(required_twitter - set(snapshot.twitter_cards))
    findings.append(
        finding(
            "twitter_cards",
            "partial" if missing_twitter else "ok",
            f"Missing Twitter Card fields: {', '.join(missing_twitter) if missing_twitter else 'none'}.",
            "Add summary card fields in a reviewed CMS/meta update." if missing_twitter else "Twitter Card basics are present.",
            RISK_LOW,
        )
    )

    if not snapshot.h1:
        findings.append(finding("h1_structure", "missing", "No H1 found.", "Use one descriptive H1 for the homepage."))
    elif len(snapshot.h1) > 1:
        findings.append(finding("h1_structure", "duplicate", f"{len(snapshot.h1)} H1 elements found.", "Review heading hierarchy and keep one primary H1."))
    else:
        findings.append(finding("h1_structure", "ok", "One H1 found.", "Keep H1 aligned with page intent."))

    findings.append(
        finding(
            "h2_structure",
            "low_count" if len(snapshot.h2) < 2 else "ok",
            f"{len(snapshot.h2)} H2 elements found.",
            "Use H2 sections for radio, music, tools, and posts." if len(snapshot.h2) < 2 else "H2 structure is present.",
            RISK_LOW,
        )
    )

    internal_count = len(set(snapshot.internal_links))
    findings.append(
        finding(
            "internal_links",
            "low_count" if internal_count < 5 else "ok",
            f"{internal_count} unique internal links found.",
            "Add contextual links to radio, tools, blog, and key landing pages." if internal_count < 5 else "Internal links are present.",
            RISK_LOW,
        )
    )

    images_with_missing_alt = [image for image in snapshot.images if not image.get("alt")]
    findings.append(
        finding(
            "image_alt_text",
            "partial" if images_with_missing_alt else "ok",
            f"{len(images_with_missing_alt)} of {len(snapshot.images)} images have missing alt text.",
            "Add descriptive alt text for meaningful images; decorative images can remain empty if intentional."
            if images_with_missing_alt
            else "Image alt coverage is acceptable from HTML.",
            RISK_LOW if len(images_with_missing_alt) <= 3 else RISK_MEDIUM,
        )
    )

    schema_types = sorted(schema_type(item) for item in snapshot.json_ld if schema_type(item))
    findings.append(
        finding(
            "schema_json_ld",
            "missing" if not schema_types else "ok",
            f"Detected JSON-LD types: {', '.join(schema_types) if schema_types else 'none'}.",
            "Review the generated schema draft for WebSite, Organization, RadioStation, MusicGroup, and SoftwareApplication."
            if not schema_types
            else "Review whether schema coverage matches the current content model.",
            RISK_LOW,
        )
    )
    return findings


def schema_type(item: Dict[str, Any]) -> str:
    value = item.get("@type")
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value) if value else ""


AI_TRAINING_BOTS = {
    "amazonbot",
    "applebot-extended",
    "bytespider",
    "ccbot",
    "claudebot",
    "cloudflarebrowserrenderingcrawler",
    "google-extended",
    "gptbot",
    "meta-externalagent",
}


def parse_content_signal(value: str) -> Dict[str, str]:
    signals: Dict[str, str] = {}
    for part in value.split(","):
        if "=" not in part:
            continue
        key, raw_value = part.split("=", 1)
        key = key.strip().lower()
        signal_value = raw_value.strip().lower()
        if key:
            signals[key] = signal_value
    return signals


def parse_robots_groups(text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    groups: List[Dict[str, Any]] = []
    sitemap_directives: List[str] = []
    current: Optional[Dict[str, Any]] = None

    def ensure_group() -> Dict[str, Any]:
        nonlocal current
        if current is None:
            current = {"user_agents": [], "allow": [], "disallow": [], "content_signals": {}}
            groups.append(current)
        return current

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        key = key.strip().lower()
        value = raw_value.strip()
        if key == "sitemap":
            sitemap_directives.append(strip_url_query(value))
            continue
        if key == "user-agent":
            if current is None or current.get("allow") or current.get("disallow") or current.get("content_signals"):
                current = {"user_agents": [], "allow": [], "disallow": [], "content_signals": {}}
                groups.append(current)
            current["user_agents"].append(value.lower())
            continue
        group = ensure_group()
        if key == "allow":
            group["allow"].append(value)
        elif key == "disallow":
            group["disallow"].append(value)
        elif key == "content-signal":
            group["content_signals"].update(parse_content_signal(value))
    return groups, sitemap_directives


def analyze_robots(text: Optional[str], status: str) -> Dict[str, Any]:
    if status != "ok" or text is None:
        return {
            "status": status,
            "risk": RISK_REVIEW_ONLY,
            "disallow_all": "unknown",
            "robots_public_crawl_allowed": "unknown",
            "robots_search_signal_allowed": "unknown",
            "robots_ai_training_restricted": "unknown",
            "robots_wordpress_admin_protected": "unknown",
            "robots_full_site_block": "unknown",
            "sitemap_directives": [],
            "recommendation": "No local robots.txt artifact available; verify robots.txt manually before SEO changes.",
        }

    groups, sitemap_directives = parse_robots_groups(text)
    wildcard_groups = [
        group for group in groups if any(agent.strip() == "*" for agent in group.get("user_agents", []))
    ]
    wildcard_allows = [
        value.strip()
        for group in wildcard_groups
        for value in group.get("allow", [])
    ]
    wildcard_disallows = [
        value.strip()
        for group in wildcard_groups
        for value in group.get("disallow", [])
    ]
    wildcard_content_signals: Dict[str, str] = {}
    for group in wildcard_groups:
        signals = group.get("content_signals")
        if isinstance(signals, dict):
            wildcard_content_signals.update({str(k).lower(): str(v).lower() for k, v in signals.items()})

    wildcard_disallow_root = any(value == "/" for value in wildcard_disallows)
    wildcard_allow_root = any(value in {"", "/"} for value in wildcard_allows)
    robots_full_site_block = wildcard_disallow_root and not wildcard_allow_root
    robots_public_crawl_allowed = not robots_full_site_block
    robots_search_signal_allowed = wildcard_content_signals.get("search") == "yes"
    robots_ai_training_restricted = wildcard_content_signals.get("ai-train") == "no"

    ai_bot_blocks: List[str] = []
    for group in groups:
        agents = [str(agent).lower().strip() for agent in group.get("user_agents", [])]
        disallows = [str(value).strip() for value in group.get("disallow", [])]
        if any(agent in AI_TRAINING_BOTS for agent in agents) and any(value == "/" for value in disallows):
            ai_bot_blocks.extend(agent for agent in agents if agent in AI_TRAINING_BOTS)
            robots_ai_training_restricted = True

    robots_wordpress_admin_protected = (
        any(value == "/wp-admin/" for value in wildcard_disallows)
        and any(value == "/wp-admin/admin-ajax.php" for value in wildcard_allows)
    )

    if robots_full_site_block:
        recommendation = "robots.txt appears to disallow public crawling for User-agent: *; review immediately before changing anything."
        report_status = "blocking"
        risk = RISK_HIGH
    else:
        recommendation = (
            "Public crawling appears allowed; AI-training crawlers are selectively restricted; "
            "WordPress admin paths are protected."
            if robots_ai_training_restricted or robots_wordpress_admin_protected
            else "robots.txt does not show a full-site public crawl block."
        )
        report_status = "ok"
        risk = RISK_LOW

    return {
        "status": report_status,
        "risk": risk,
        "disallow_all": robots_full_site_block,
        "robots_public_crawl_allowed": robots_public_crawl_allowed,
        "robots_search_signal_allowed": robots_search_signal_allowed,
        "robots_ai_training_restricted": robots_ai_training_restricted,
        "robots_wordpress_admin_protected": robots_wordpress_admin_protected,
        "robots_full_site_block": robots_full_site_block,
        "wildcard_allow": wildcard_allows,
        "wildcard_disallow": wildcard_disallows,
        "content_signals": wildcard_content_signals,
        "ai_bot_blocks": sorted(set(ai_bot_blocks)),
        "sitemap_directives": sitemap_directives,
        "sitemap_present": bool(sitemap_directives),
        "recommendation": recommendation,
    }


def analyze_sitemap(text: Optional[str], status: str) -> Dict[str, Any]:
    if status != "ok" or text is None:
        return {
            "status": status,
            "risk": RISK_REVIEW_ONLY,
            "url_count": None,
            "recommendation": "No local sitemap artifact available; verify sitemap_index.xml manually before SEO changes.",
        }
    urls = re.findall(r"<loc>\s*([^<]+)\s*</loc>", text, flags=re.IGNORECASE)
    return {
        "status": "ok" if urls else "empty_or_unparsed",
        "risk": RISK_LOW if urls else RISK_MEDIUM,
        "url_count": len(urls),
        "sample_urls": [strip_url_query(url) for url in urls[:10]],
        "recommendation": "Sitemap artifact contains URLs." if urls else "Sitemap artifact has no parsed <loc> URLs; review sitemap generation.",
    }


def safe_context_from_reports(paths: Iterable[Path]) -> Dict[str, Any]:
    context: Dict[str, Any] = {}
    for path in paths:
        data, status, exists = read_json_report(path)
        context[path.name] = {"exists": exists, "status": status}
        if data:
            context[path.name].update(
                {
                    "website_status": redact_text(data.get("website_status")),
                    "overall_master_status": redact_text(data.get("overall_master_status")),
                    "action_status": redact_text(data.get("action_status")),
                }
            )
    return context


def read_json_report(path: Path) -> Tuple[Dict[str, Any], str, bool]:
    if not path.exists():
        return {}, "not_available", False
    if path.suffix.lower() != ".json":
        return {}, "unsupported_suffix", True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, f"read_error:{exc.__class__.__name__}", True
    return data if isinstance(data, dict) else {}, "ok", True


def build_meta_draft(site_url: str = DEFAULT_SITE_URL) -> Dict[str, Any]:
    return {
        "draft_only": True,
        "risk_classification": RISK_REVIEW_ONLY,
        "apply_status": "not_applied",
        "title": "Electri_C_ity Studios 24/7 | AI Radio, Music and Digital Tools",
        "meta_description": DEFAULT_DESCRIPTION,
        "canonical": site_url,
        "open_graph": {
            "og:type": "website",
            "og:site_name": DEFAULT_SITE_NAME,
            "og:title": "Electri_C_ity Studios 24/7",
            "og:description": DEFAULT_DESCRIPTION,
            "og:url": site_url,
        },
        "twitter": {
            "twitter:card": "summary_large_image",
            "twitter:title": "Electri_C_ity Studios 24/7",
            "twitter:description": DEFAULT_DESCRIPTION,
        },
        "review_notes": [
            "Draft only. Do not paste into WordPress without editorial review.",
            "Confirm brand spelling, target pages, and image URLs before use.",
        ],
    }


def build_schema_draft(site_url: str = DEFAULT_SITE_URL) -> Dict[str, Any]:
    org_id = site_url.rstrip("/") + "/#organization"
    website_id = site_url.rstrip("/") + "/#website"
    radio_id = site_url.rstrip("/") + "/#radio"
    music_id = site_url.rstrip("/") + "/#musicgroup"
    tools_id = site_url.rstrip("/") + "/#software"
    return {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "WebSite",
                "@id": website_id,
                "url": site_url,
                "name": DEFAULT_SITE_NAME,
                "publisher": {"@id": org_id},
                "inLanguage": "en",
            },
            {
                "@type": "Organization",
                "@id": org_id,
                "name": DEFAULT_SITE_NAME,
                "url": site_url,
            },
            {
                "@type": "RadioStation",
                "@id": radio_id,
                "name": DEFAULT_RADIO_NAME,
                "url": "https://ai-radio.electri-c-ity-studios-24-7.com/",
                "parentOrganization": {"@id": org_id},
            },
            {
                "@type": "MusicGroup",
                "@id": music_id,
                "name": DEFAULT_SITE_NAME,
                "url": site_url,
            },
            {
                "@type": "SoftwareApplication",
                "@id": tools_id,
                "name": "Electri_C_ity Studios Digital Tools",
                "applicationCategory": "MultimediaApplication",
                "operatingSystem": "Web",
                "url": site_url,
                "publisher": {"@id": org_id},
            },
        ],
        "draft_only": True,
        "risk_classification": RISK_REVIEW_ONLY,
        "review_notes": [
            "Review entity names, URLs, sameAs profiles, and service availability before publication.",
            "Do not add Product offers, prices, or ratings unless they are accurate and visible on-page.",
        ],
    }


def schema_recommendations() -> List[Dict[str, Any]]:
    return [
        {
            "schema": "WebSite",
            "risk": RISK_LOW,
            "recommendation": "Use WebSite schema for the canonical homepage entity and publisher linkage.",
        },
        {
            "schema": "Organization",
            "risk": RISK_REVIEW_ONLY,
            "recommendation": "Add Organization schema only after confirming official name, logo URL, and sameAs profiles.",
        },
        {
            "schema": "RadioStation",
            "risk": RISK_REVIEW_ONLY,
            "recommendation": "Use RadioStation schema for the AI radio presence after confirming stream URL and public station page.",
        },
        {
            "schema": "MusicGroup",
            "risk": RISK_REVIEW_ONLY,
            "recommendation": "Use MusicGroup schema only where the page presents an actual artist/group entity.",
        },
        {
            "schema": "Product/SoftwareApplication",
            "risk": RISK_REVIEW_ONLY,
            "recommendation": "Prefer SoftwareApplication for digital tools; avoid offers/ratings without visible proof.",
        },
        {
            "schema": "BlogPosting",
            "risk": RISK_LOW,
            "recommendation": "For blog posts, use one H1, publication date, author/editorial owner, summary, internal links, and article schema.",
        },
    ]


def build_next_actions(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = [
        {
            "action_id": "review_homepage_meta_draft",
            "risk": RISK_LOW,
            "status": "draft_only",
            "description": "Review homepage-meta-draft.json for title, description, canonical, OpenGraph, and Twitter fields.",
        },
        {
            "action_id": "review_schema_draft",
            "risk": RISK_REVIEW_ONLY,
            "status": "draft_only",
            "description": "Review homepage-schema-draft.jsonld before any CMS publication.",
        },
        {
            "action_id": "provide_local_homepage_html",
            "risk": RISK_REVIEW_ONLY,
            "status": "optional",
            "description": "Place a reviewed static homepage HTML export at drafts/seo/homepage.html for deeper analysis.",
        },
    ]
    if any(item["signal"] == "robots_txt" and item["risk"] == RISK_HIGH for item in findings):
        actions.insert(
            0,
            {
                "action_id": "review_robots_block",
                "risk": RISK_HIGH,
                "status": "review_only",
                "description": "Review robots.txt full-site block signal before any SEO publication.",
            },
        )
    return actions


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel SEO Safe Optimizer Report",
        "",
        f"**Generated:** `{redact_text(report.get('generated_at_utc'))}` UTC",
        "",
        "## Safety",
        "",
        f"- Productive Change: `{str(bool(report.get('productive_change'))).lower()}`",
        f"- WordPress Mutation: `{str(bool(report.get('wordpress_mutation'))).lower()}`",
        f"- .htaccess Mutation: `{str(bool(report.get('htaccess_mutation'))).lower()}`",
        f"- Cloudflare Mutation: `{str(bool(report.get('cloudflare_mutation'))).lower()}`",
        f"- Nginx Mutation: `{str(bool(report.get('nginx_mutation'))).lower()}`",
        f"- Secrets Output: `{str(bool(report.get('secrets_output'))).lower()}`",
        "",
        "## Inputs",
        "",
        "| Input | Path | Status |",
        "|---|---|---|",
    ]
    for item in report.get("inputs", []):
        lines.append(f"| `{item['kind']}` | `{redact_text(item.get('path'))}` | `{redact_text(item.get('status'))}` |")

    risk = report.get("risk_classification") if isinstance(report.get("risk_classification"), dict) else {}
    lines.extend(
        [
            "",
            "## Input Freshness",
            "",
            "| Input | Exists | Status | Age Seconds | Size Bytes |",
            "|---|---|---|---:|---:|",
        ]
    )
    freshness = report.get("input_freshness") if isinstance(report.get("input_freshness"), dict) else {}
    for key, value in freshness.items():
        if not isinstance(value, dict):
            continue
        lines.append(
            f"| `{key}` | `{str(bool(value.get('exists'))).lower()}` | `{redact_text(value.get('status'))}` | "
            f"{redact_text(value.get('age_seconds'))} | {redact_text(value.get('size_bytes'))} |"
        )

    fetch_errors = report.get("fetch_errors") if isinstance(report.get("fetch_errors"), list) else []
    lines.extend(["", "## Fetch Errors", ""])
    if fetch_errors:
        lines.extend(["| Kind | Status | HTTP | Error |", "|---|---|---:|---|"])
        for item in fetch_errors:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| `{redact_text(item.get('kind'))}` | `{redact_text(item.get('status'))}` | "
                f"{redact_text(item.get('status_code'))} | `{redact_text(item.get('error'))}` |"
            )
    else:
        lines.append("- None recorded.")

    robots = report.get("robots") if isinstance(report.get("robots"), dict) else {}
    lines.extend(
        [
            "",
            "## Robots.txt Analysis",
            "",
            f"- Public crawl allowed: `{redact_text(robots.get('robots_public_crawl_allowed'))}`",
            f"- Search signal allowed: `{redact_text(robots.get('robots_search_signal_allowed'))}`",
            f"- AI training restricted: `{redact_text(robots.get('robots_ai_training_restricted'))}`",
            f"- WordPress admin protected: `{redact_text(robots.get('robots_wordpress_admin_protected'))}`",
            f"- Full-site block: `{redact_text(robots.get('robots_full_site_block'))}`",
            f"- Sitemap present: `{redact_text(robots.get('sitemap_present'))}`",
            f"- Recommendation: {redact_text(robots.get('recommendation'))}",
        ]
    )

    detected = report.get("detected_homepage_seo") if isinstance(report.get("detected_homepage_seo"), dict) else {}
    lines.extend(
        [
            "",
            "## Detected Homepage SEO",
            "",
            f"- Available: `{str(bool(detected.get('available'))).lower()}`",
            f"- Snapshot likely Cloudflare challenge: `{str(bool(detected.get('snapshot_likely_cloudflare_challenge'))).lower()}`",
            f"- Title: `{redact_text(detected.get('title'))}`",
            f"- Title length: `{redact_text(detected.get('title_length'))}`",
            f"- Meta description present: `{str(bool(detected.get('meta_description_present'))).lower()}`",
            f"- Canonical: `{redact_text(detected.get('canonical'))}`",
            f"- OG/Twitter counts: `{redact_text(detected.get('open_graph_count'))}` / `{redact_text(detected.get('twitter_card_count'))}`",
            f"- H1/H2 counts: `{redact_text(detected.get('h1_count'))}` / `{redact_text(detected.get('h2_count'))}`",
            f"- Internal links: `{redact_text(detected.get('internal_link_count'))}`",
            f"- Images missing alt: `{redact_text(detected.get('images_missing_alt_count'))}`",
            "",
            "## Detected Current SEO Snapshot",
            "",
        ]
    )
    current = report.get("detected_current_seo") if isinstance(report.get("detected_current_seo"), dict) else {}
    lines.extend(
        [
            f"- Current title: `{redact_text(current.get('title'))}`",
            f"- Current title length: `{redact_text(current.get('title_length'))}`",
            f"- Current meta description: `{redact_text(current.get('meta_description'), max_len=260)}`",
            f"- Current meta description length: `{redact_text(current.get('meta_description_length'))}`",
            f"- Current canonical: `{redact_text(current.get('canonical'))}`",
            f"- Current H1: `{'; '.join(str(item) for item in current.get('h1', [])[:3]) if current.get('h1') else '-'}`",
            f"- Current H2 count: `{len(current.get('h2', [])) if isinstance(current.get('h2'), list) else '-'}`",
            f"- Internal/external links: `{redact_text(current.get('internal_links_count'))}` / `{redact_text(current.get('external_links_count'))}`",
            f"- Images with/without alt: `{redact_text(current.get('images_with_alt_count'))}` / `{redact_text(current.get('images_missing_alt_count'))}`",
            f"- JSON-LD types: `{', '.join(str(item) for item in current.get('json_ld_types', [])) if current.get('json_ld_types') else '-'}`",
            "",
            "## Improved Drafts Summary",
            "",
            "| Draft | Risk | Apply Status | Notes |",
            "|---|---|---|---|",
        ]
    )
    draft_summary = report.get("improved_drafts_summary") if isinstance(report.get("improved_drafts_summary"), dict) else {}
    for key, item in draft_summary.items():
        if not isinstance(item, dict):
            continue
        notes = []
        if item.get("title"):
            notes.append(f"title={item.get('title')}")
        if item.get("title_length"):
            notes.append(f"title_len={item.get('title_length')}")
        if item.get("meta_description_length"):
            notes.append(f"desc_len={item.get('meta_description_length')}")
        if item.get("types"):
            notes.append("types=" + ",".join(str(t) for t in item.get("types", [])))
        if item.get("count") is not None:
            notes.append(f"count={item.get('count')}")
        lines.append(
            f"| `{key}` | `{redact_text(item.get('risk_classification'))}` | "
            f"`{redact_text(item.get('apply_status', 'not_applied'))}` | "
            f"{redact_text('; '.join(notes), default='-').replace('|', '\\|')} |"
        )

    lines.extend(["", "## Safe Next Steps", ""])
    for item in report.get("safe_next_steps", []):
        lines.append(f"- {redact_text(item)}")

    lines.extend(
        [
            "",
            "## Missing Homepage SEO",
            "",
        ]
    )
    missing = report.get("missing_homepage_seo") if isinstance(report.get("missing_homepage_seo"), list) else []
    if missing:
        lines.extend(["| Signal | Status | Risk | Recommendation |", "|---|---|---|---|"])
        for item in missing:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| `{redact_text(item.get('signal'))}` | `{redact_text(item.get('status'))}` | "
                f"`{redact_text(item.get('risk'))}` | {redact_text(item.get('recommendation')).replace('|', '\\|')} |"
            )
    else:
        lines.append("- No missing homepage SEO signals detected in the local snapshot.")

    lines.extend(
        [
            "",
            "## Risk Classification",
            "",
            f"- Highest Risk: `{redact_text(risk.get('highest_risk'))}`",
            f"- Counts: `{json.dumps(risk.get('counts', {}), sort_keys=True)}`",
            f"- Policy: {redact_text(risk.get('policy'))}",
        ]
    )

    lines.extend(["", "## Findings", "", "| Signal | Status | Risk | Recommendation |", "|---|---|---|---|"])
    for item in report.get("findings", []):
        lines.append(
            f"| `{redact_text(item.get('signal'))}` | `{redact_text(item.get('status'))}` | "
            f"`{redact_text(item.get('risk'))}` | {redact_text(item.get('recommendation')).replace('|', '\\|')} |"
        )

    lines.extend(["", "## Schema Recommendations", "", "| Schema | Risk | Recommendation |", "|---|---|---|"])
    for item in report.get("schema_recommendations", []):
        lines.append(f"| `{item['schema']}` | `{item['risk']}` | {item['recommendation']} |")

    lines.extend(["", "## Draft Outputs", ""])
    for item in report.get("draft_outputs", []):
        lines.append(f"- `{item}`")

    lines.extend(
        [
            "",
            "## Next Actions",
            "",
        ]
    )
    for item in report.get("next_actions", []):
        lines.append(f"- `{item['action_id']}` ({item['risk']}): {item['description']}")

    lines.extend(
        [
            "",
            "## Boundaries",
            "",
            "- Keine produktiven Aenderungen.",
            "- Keine WordPress-, .htaccess-, Cloudflare- oder Nginx-Aenderungen.",
            "- Drafts sind review-only und nicht automatisch anwendbar.",
            "",
        ]
    )
    return "\n".join(lines)


def render_next_actions_md(actions: List[Dict[str, Any]]) -> str:
    lines = [
        "# SEO Safe Optimizer Next Actions",
        "",
        "All actions are draft-only and require manual editorial/technical review.",
        "",
    ]
    for item in actions:
        lines.append(f"- `{item['action_id']}` [{item['risk']} / {item['status']}]: {item['description']}")
    lines.append("")
    return "\n".join(lines)


def build_report(args: argparse.Namespace) -> Tuple[
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
    str,
    Dict[str, Any],
    Dict[str, Any],
    str,
    str,
    Dict[str, Any],
    str,
]:
    html_path = args.html if args.html else first_existing(DEFAULT_HTML_CANDIDATES)
    robots_path = args.robots if args.robots else first_existing(DEFAULT_ROBOTS_CANDIDATES)
    sitemap_path = args.sitemap if args.sitemap else first_existing(DEFAULT_SITEMAP_CANDIDATES)
    headers_path = INPUT_HEADERS_HOMEPAGE if INPUT_HEADERS_HOMEPAGE.exists() else None

    html_text, html_status = read_text_if_safe(html_path, {".html", ".htm"}) if html_path else (None, "not_available")
    robots_text, robots_status = read_text_if_safe(robots_path, {".txt"}) if robots_path else (None, "not_available")
    sitemap_text, sitemap_status = read_text_if_safe(sitemap_path, {".xml"}) if sitemap_path else (None, "not_available")
    headers_text, headers_status = read_text_if_safe(headers_path, {".txt"}) if headers_path else (None, "not_available")
    headers_analysis = parse_headers_snapshot(headers_text, headers_status)
    manifest = read_fetch_manifest()

    snapshot = parse_html(html_text) if html_text is not None and html_status == "ok" else None
    findings = analyze_html(snapshot, html_status)
    if headers_analysis.get("cf_mitigated") == "challenge":
        findings.append(
            finding(
                "homepage_snapshot_cloudflare_challenge",
                "not_available",
                "Homepage snapshot was mitigated by Cloudflare challenge and may not represent the real rendered homepage.",
                "Use a reviewed local HTML export or browser-rendered snapshot for final SEO decisions.",
                RISK_REVIEW_ONLY,
                html_available=False,
            )
        )

    robots_analysis = analyze_robots(robots_text, robots_status)
    findings.append(
        finding(
            "robots_txt",
            str(robots_analysis["status"]),
            "robots.txt local artifact analysis.",
            str(robots_analysis["recommendation"]),
            str(robots_analysis["risk"]),
            html_available=robots_status == "ok",
        )
    )

    sitemap_analysis = analyze_sitemap(sitemap_text, sitemap_status)
    findings.append(
        finding(
            "sitemap",
            str(sitemap_analysis["status"]),
            "sitemap local artifact analysis.",
            str(sitemap_analysis["recommendation"]),
            str(sitemap_analysis["risk"]),
            html_available=sitemap_status == "ok",
        )
    )

    meta_draft = build_meta_draft()
    current_seo = current_homepage_seo(snapshot)
    meta_improved = improved_meta_draft(current_seo)
    og_twitter = og_twitter_draft(current_seo)
    schema_draft = improved_schema_draft()
    link_suggestions = internal_link_suggestions(current_seo)
    outline_suggestions = content_outline_suggestions()
    actions = build_next_actions(findings)
    link_suggestions_md = render_internal_link_suggestions(link_suggestions)
    outline_suggestions_md = render_content_outline_suggestions(outline_suggestions)
    editorial_review = build_editorial_review(current_seo, sitemap_analysis)
    editorial_review_md = render_editorial_review(editorial_review)
    report = {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "status": "READY_FOR_REVIEW",
        "productive_change": False,
        "wordpress_mutation": False,
        "htaccess_mutation": False,
        "cloudflare_mutation": False,
        "nginx_mutation": False,
        "secrets_output": False,
        "read_only": True,
        "risk_values": sorted(RISK_VALUES),
        "inputs": [
            {"kind": "html", "path": str(html_path) if html_path else None, "status": html_status},
            {"kind": "robots", "path": str(robots_path) if robots_path else None, "status": robots_status},
            {"kind": "sitemap", "path": str(sitemap_path) if sitemap_path else None, "status": sitemap_status},
            {"kind": "headers_homepage", "path": str(headers_path) if headers_path else None, "status": headers_status},
        ],
        "input_sources": {
            "homepage_html": {"path": str(html_path) if html_path else None, "status": html_status},
            "robots_txt": {"path": str(robots_path) if robots_path else None, "status": robots_status},
            "sitemap_xml": {"path": str(sitemap_path) if sitemap_path else None, "status": sitemap_status},
            "headers_homepage": {"path": str(headers_path) if headers_path else None, "status": headers_status},
            "fetch_manifest": {"path": str(INPUT_MANIFEST_JSON), "status": manifest.get("status", "ok") if manifest else "not_available"},
        },
        "input_freshness": {
            "homepage_html": file_freshness(html_path),
            "robots_txt": file_freshness(robots_path),
            "sitemap_xml": file_freshness(sitemap_path),
            "headers_homepage": file_freshness(headers_path),
            "fetch_manifest": file_freshness(INPUT_MANIFEST_JSON),
        },
        "fetch_errors": fetch_errors_from_manifest(manifest),
        "headers_homepage": headers_analysis,
        "detected_homepage_seo": detected_homepage_seo(snapshot, headers_analysis),
        "detected_current_seo": current_seo,
        "missing_homepage_seo": missing_homepage_seo(findings),
        "risk_classification": risk_classification(findings),
        "improved_drafts_summary": {
            "homepage_meta_improved_draft": {
                "path": str(META_IMPROVED_DRAFT_JSON),
                "risk_classification": meta_improved["risk_classification"],
                "apply_status": meta_improved["apply_status"],
                "title": meta_improved["improved"]["title"],
                "title_length": meta_improved["improved"]["title_length"],
                "meta_description_length": meta_improved["improved"]["meta_description_length"],
            },
            "homepage_og_twitter_draft": {
                "path": str(OG_TWITTER_DRAFT_JSON),
                "risk_classification": og_twitter["risk_classification"],
                "apply_status": og_twitter["apply_status"],
            },
            "homepage_schema_draft": {
                "path": str(SCHEMA_DRAFT_JSONLD),
                "risk_classification": schema_draft["risk_classification"],
                "apply_status": schema_draft["apply_status"],
                "types": [item.get("@type") for item in schema_draft.get("@graph", []) if isinstance(item, dict)],
            },
            "internal_link_suggestions": {
                "path": str(INTERNAL_LINK_SUGGESTIONS_MD),
                "count": len(link_suggestions),
                "risk_values": sorted(set(item["risk_classification"] for item in link_suggestions)),
            },
            "content_outline_suggestions": {
                "path": str(CONTENT_OUTLINE_SUGGESTIONS_MD),
                "count": len(outline_suggestions),
                "risk_values": sorted(set(item["risk_classification"] for item in outline_suggestions)),
            },
            "editorial_review": {
                "path": str(EDITORIAL_REVIEW_JSON),
                "proposal_count": editorial_review.get("summary", {}).get("proposal_count"),
                "review_only_count": editorial_review.get("summary", {}).get("review_only_count"),
                "high_risk_count": editorial_review.get("summary", {}).get("high_risk_count"),
                "apply_status": editorial_review.get("apply_status"),
            },
        },
        "safe_next_steps": [
            "Review improved meta and social drafts with an editorial owner.",
            "Use homepage-editorial-review.md/json as the manual approval checklist.",
            "Verify suggested internal-link targets exist before any CMS edit.",
            "Validate schema draft against visible on-page content before publication.",
            "Keep all changes manual/review-only; Sentinel does not apply SEO changes.",
        ],
        "html_summary": {
            "title": redact_text(snapshot.title) if snapshot else "not_available",
            "meta_description_present": bool(snapshot and snapshot.meta_description),
            "canonical": redact_text(snapshot.canonical) if snapshot else "not_available",
            "h1_count": len(snapshot.h1) if snapshot else None,
            "h2_count": len(snapshot.h2) if snapshot else None,
            "internal_link_count": len(set(snapshot.internal_links)) if snapshot else None,
            "image_count": len(snapshot.images) if snapshot else None,
            "json_ld_count": len(snapshot.json_ld) if snapshot else None,
        },
        "robots": robots_analysis,
        "sitemap": sitemap_analysis,
        "context_reports": safe_context_from_reports(DEFAULT_CONTEXT_REPORTS),
        "findings": findings,
        "schema_recommendations": schema_recommendations(),
        "next_actions": actions,
        "draft_outputs": [
            str(META_DRAFT_JSON),
            str(META_IMPROVED_DRAFT_JSON),
            str(OG_TWITTER_DRAFT_JSON),
            str(SCHEMA_DRAFT_JSONLD),
            str(NEXT_ACTIONS_MD),
            str(INTERNAL_LINK_SUGGESTIONS_MD),
            str(CONTENT_OUTLINE_SUGGESTIONS_MD),
            str(EDITORIAL_REVIEW_MD),
            str(EDITORIAL_REVIEW_JSON),
        ],
        "report_outputs": [
            str(REPORT_MD),
            str(REPORT_JSON),
        ],
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
    }
    return (
        report,
        meta_draft,
        schema_draft,
        render_next_actions_md(actions),
        meta_improved,
        og_twitter,
        link_suggestions_md,
        outline_suggestions_md,
        editorial_review,
        editorial_review_md,
    )


def run_self_tests() -> int:
    assert classify_risk("title", "missing") == RISK_MEDIUM
    assert classify_risk("robots_disallow_all", "blocking") == RISK_HIGH
    assert classify_risk("html_input", "not_available", html_available=False) == RISK_REVIEW_ONLY
    assert classify_risk("open_graph", "partial") == RISK_LOW
    assert_allowed_write(SEO_INPUT_DIR / "homepage.html")
    try:
        assert_allowed_write(Path("/etc/nginx/seo-test.conf"))
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden path write check failed")

    minimal = """<!doctype html>
    <html><head>
    <title>Electri_C_ity Studios 24/7 AI Radio</title>
    <meta name="description" content="Electri_C_ity Studios test description for safe SEO parsing without publication.">
    <link rel="canonical" href="https://electri-c-ity-studios-24-7.com/?x=1">
    <meta property="og:title" content="Electri_C_ity Studios">
    <meta name="twitter:card" content="summary">
    <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"Test"}</script>
    </head><body><h1>Main</h1><h2>Radio</h2><a href="/radio">Radio</a><img src="/x.jpg"></body></html>"""
    snapshot = parse_html(minimal)
    assert snapshot.title == "Electri_C_ity Studios 24/7 AI Radio"
    assert snapshot.canonical == "https://electri-c-ity-studios-24-7.com/"
    assert len(snapshot.h1) == 1
    assert len(snapshot.h2) == 1
    assert len(snapshot.json_ld) == 1
    parsed_findings = analyze_html(snapshot, "ok")
    assert any(item["signal"] == "image_alt_text" for item in parsed_findings)

    robots_full_block = analyze_robots("User-agent: *\nDisallow: /\n", "ok")
    assert robots_full_block["robots_full_site_block"] is True
    assert robots_full_block["risk"] == RISK_HIGH

    robots_wp_admin = analyze_robots(
        "User-agent: *\nAllow: /\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n",
        "ok",
    )
    assert robots_wp_admin["robots_full_site_block"] is False
    assert robots_wp_admin["risk"] != RISK_HIGH
    assert robots_wp_admin["robots_wordpress_admin_protected"] is True

    robots_ai_bot = analyze_robots("User-agent: GPTBot\nDisallow: /\n", "ok")
    assert robots_ai_bot["robots_full_site_block"] is False
    assert robots_ai_bot["robots_ai_training_restricted"] is True
    assert robots_ai_bot["risk"] != RISK_HIGH

    robots_content_signal = analyze_robots(
        "User-agent: *\nContent-Signal: search=yes,ai-train=no\nAllow: /\n"
        "Sitemap: https://electri-c-ity-studios-24-7.com/sitemap_index.xml\n",
        "ok",
    )
    assert robots_content_signal["robots_search_signal_allowed"] is True
    assert robots_content_signal["robots_ai_training_restricted"] is True
    assert robots_content_signal["robots_full_site_block"] is False
    assert robots_content_signal["sitemap_present"] is True

    class Args:
        html = PROJECT_DIR / "drafts/seo/does-not-exist.html"
        robots = PROJECT_DIR / "drafts/seo/does-not-exist-robots.txt"
        sitemap = PROJECT_DIR / "drafts/seo/does-not-exist-sitemap.xml"

    (
        report,
        _,
        _,
        _,
        meta_improved,
        og_twitter,
        link_md,
        outline_md,
        editorial_review,
        editorial_review_md,
    ) = build_report(Args())
    input_statuses = {item["kind"]: item["status"] for item in report["inputs"]}
    assert input_statuses["html"] == "not_available"
    assert input_statuses["robots"] == "not_available"
    assert input_statuses["sitemap"] == "not_available"
    assert report["productive_change"] is False
    assert report["findings"]
    assert "risk_classification" in report
    assert meta_improved["risk_classification"] == RISK_LOW
    assert og_twitter["risk_classification"] == RISK_LOW
    assert "Draft only" in link_md
    assert "Draft only" in outline_md
    assert editorial_review["apply_status"] == "not_applied"
    assert editorial_review["summary"]["high_risk_count"] == 0
    assert editorial_review["summary"]["all_not_applied"] is True
    assert "Homepage Editorial Review" in editorial_review_md
    assert read_json_draft(DRAFT_DIR / "missing-editorial-test.json")[1] == "not_available"
    assert read_markdown_draft(DRAFT_DIR / "missing-editorial-test.md")[1] == "not_available"
    for item in editorial_review["proposals"]:
        assert item["apply_status"] == "not_applied"
        assert item["risk_classification"] in {RISK_LOW, RISK_REVIEW_ONLY}
    for item in report["improved_drafts_summary"].values():
        if "risk_classification" in item:
            assert item.get("risk_classification") in {RISK_LOW, RISK_REVIEW_ONLY}
        if "risk_values" in item:
            assert set(item.get("risk_values", [])).issubset({RISK_LOW, RISK_REVIEW_ONLY})
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only Sentinel SEO Safe Optimizer.")
    parser.add_argument("--html", type=Path, default=None, help="Optional local homepage HTML artifact")
    parser.add_argument("--robots", type=Path, default=None, help="Optional local robots.txt artifact")
    parser.add_argument("--sitemap", type=Path, default=None, help="Optional local sitemap XML artifact")
    parser.add_argument("--collect-inputs", action="store_true", help="Fetch read-only public SEO snapshots into seo-inputs/latest")
    parser.add_argument("--homepage-url", default=DEFAULT_SITE_URL)
    parser.add_argument("--robots-url", default=DEFAULT_ROBOTS_URL)
    parser.add_argument("--sitemap-url", default=DEFAULT_SITEMAP_URL)
    parser.add_argument("--fetch-timeout", type=float, default=MAX_FETCH_TIMEOUT)
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety/unit tests")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()
    if args.collect_inputs:
        manifest = collect_inputs(args)
        failures = [item for item in manifest.get("fetches", []) if not item.get("ok")]
        print(
            "SEO input collection completed: "
            f"{len(manifest.get('fetches', []))} attempted, {len(failures)} unavailable"
        )
        return 0

    (
        report,
        meta_draft,
        schema_draft,
        next_actions,
        meta_improved,
        og_twitter,
        link_suggestions_md,
        outline_suggestions_md,
        editorial_review,
        editorial_review_md,
    ) = build_report(args)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report))
    write_json_atomic(META_DRAFT_JSON, meta_draft)
    write_json_atomic(META_IMPROVED_DRAFT_JSON, meta_improved)
    write_json_atomic(OG_TWITTER_DRAFT_JSON, og_twitter)
    write_json_atomic(SCHEMA_DRAFT_JSONLD, schema_draft)
    write_text_atomic(NEXT_ACTIONS_MD, next_actions)
    write_text_atomic(INTERNAL_LINK_SUGGESTIONS_MD, link_suggestions_md)
    write_text_atomic(CONTENT_OUTLINE_SUGGESTIONS_MD, outline_suggestions_md)
    write_json_atomic(EDITORIAL_REVIEW_JSON, editorial_review)
    write_text_atomic(EDITORIAL_REVIEW_MD, editorial_review_md)
    print(f"SEO Safe Optimizer report written: {REPORT_MD}")
    print(f"SEO Safe Optimizer JSON written: {REPORT_JSON}")
    print(f"SEO drafts written under: {DRAFT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
