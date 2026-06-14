#!/usr/bin/env python3
"""Concrete SEO & Performance Optimization Pack (Phase 6.0).

Generates concrete owner-review SEO and performance drafts for Electri_C_ity
Studios. It never performs live changes, network calls, API calls, WordPress
logins, Cloudflare changes, Nginx changes, .htaccess edits, installations, or
activation. All output is local Markdown/JSON for manual owner review.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

INPUT_PATHS = {
    "sentinel_master_json": PROJECT_DIR / "reports/latest/sentinel-master-report.json",
    "sentinel_master_md": PROJECT_DIR / "reports/latest/sentinel-master-report.md",
    "master_critical_cause": PROJECT_DIR / "reports/latest/master-critical-cause-snapshot.json",
    "rolling_window_decay": PROJECT_DIR / "reports/latest/rolling-window-decay-observer.json",
    "low_growth_readiness": PROJECT_DIR / "reports/latest/low-growth-readiness-timeline.json",
    "manual_website_recheck_gate": PROJECT_DIR / "reports/latest/manual-website-recheck-gate.json",
    "low_risk_policy_boundary": PROJECT_DIR / "reports/latest/low-risk-policy-boundary-draft.json",
    "safe_end_summary": PROJECT_DIR / "reports/latest/safe-end-summary.json",
    "safe_end_archive_integrity": PROJECT_DIR / "reports/latest/safe-end-archive-integrity-verifier.json",
    "seo_safe_optimizer": PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.json",
    "performance_safe_audit": PROJECT_DIR / "reports/latest/performance-safe-audit-report.json",
    "ai_radio_timeout": PROJECT_DIR / "reports/latest/ai-radio-api-timeout-diagnosis.json",
    "ai_radio_microcache": PROJECT_DIR / "reports/latest/ai-radio-nowplaying-microcache-status.json",
    "sourcemap_prevention": PROJECT_DIR / "reports/latest/sourcemap-prevention-report.json",
    "homepage_meta_improved": PROJECT_DIR / "drafts/seo/homepage-meta-improved-draft.json",
    "homepage_og_twitter": PROJECT_DIR / "drafts/seo/homepage-og-twitter-draft.json",
    "homepage_schema": PROJECT_DIR / "drafts/seo/homepage-schema-draft.jsonld",
    "homepage_editorial_review": PROJECT_DIR / "drafts/seo/homepage-editorial-review.json",
}

REPORT_JSON = PROJECT_DIR / "reports/latest/concrete-seo-performance-optimizer.json"
REPORT_MD = PROJECT_DIR / "reports/latest/concrete-seo-performance-optimizer.md"
OWNER_CHECKLIST_MD = PROJECT_DIR / "drafts/owner/concrete-seo-owner-apply-checklist.md"
WORDPRESS_COPY_MD = PROJECT_DIR / "drafts/owner/wordpress-seo-copy-paste-pack.md"
JSONLD_SCHEMA_MD = PROJECT_DIR / "drafts/owner/wordpress-jsonld-schema-pack.md"
PERFORMANCE_PACK_MD = PROJECT_DIR / "drafts/owner/performance-optimization-owner-pack.md"
INTERNAL_LINKING_MD = PROJECT_DIR / "drafts/owner/internal-linking-owner-pack.md"
IMAGE_PACK_MD = PROJECT_DIR / "drafts/owner/image-alt-lazyload-owner-pack.md"
ORIGIN_5XX_PACK_MD = PROJECT_DIR / "drafts/owner/origin-5xx-owner-action-pack.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/concrete-seo-performance-optimizer.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/concrete-seo-performance-optimizer.md"
AUDIT_JSONL = PROJECT_DIR / "audit/concrete-seo-performance-optimizer.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (
    REPORT_JSON,
    REPORT_MD,
    OWNER_CHECKLIST_MD,
    WORDPRESS_COPY_MD,
    JSONLD_SCHEMA_MD,
    PERFORMANCE_PACK_MD,
    INTERNAL_LINKING_MD,
    IMAGE_PACK_MD,
    ORIGIN_5XX_PACK_MD,
    SNAPSHOT_JSON,
    SNAPSHOT_MD,
    AUDIT_JSONL,
)

SCHEMA_VERSION = "concrete-seo-performance-optimizer-6.0"
APPLY_STATUS = "not_applied"

STATUS_READY = "CONCRETE_OPTIMIZER_PACK_READY_LOCKED"
STATUS_PARTIAL = "CONCRETE_OPTIMIZER_PARTIAL_INPUTS"
STATUS_BLOCKED_BY_BREACH = "CONCRETE_OPTIMIZER_BLOCKED_BY_BREACH"
STATUS_BREACH = "CONCRETE_OPTIMIZER_BREACH"

CATEGORY_DRAFT_ONLY = "DRAFT_ONLY"
CATEGORY_COPY_PASTE = "COPY_PASTE_OWNER_APPLY"
CATEGORY_OWNER_REVIEW = "OWNER_REVIEW_REQUIRED"
CATEGORY_DIAGNOSTIC = "DIAGNOSTIC_ONLY"
CATEGORY_DO_NOT_AUTO = "DO_NOT_APPLY_AUTOMATICALLY"

FORBIDDEN_SUFFIXES = {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".env", ".bin", ".run"}
SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
FORBIDDEN_APPLY_COMMAND_RE = re.compile(
    r"(?i)\b("
    r"cloudflare\s+api|cfcli|wp\s+|wp-cli|nginx\s+reload|nginx\s+-s|"
    r"systemctl|crontab|apply-safe|consolidate-apply-safe|"
    r"kubectl|docker\s+exec|ssh\s+|scp\s+|sftp\s+|curl\s+|wget\s+"
    r")\b"
)

BRAND = "Electri_C_ity Studios"
DOMAIN = "https://electri-c-ity-studios-24-7.com/"
RADIO_ENDPOINT = "/api/nowplaying/electri-city-ai-electro-radio"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def parse_count(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def read_json_file(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
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
    if not isinstance(data, dict):
        return None, "json_root_not_object"
    return data, "ok"


def read_text_file(path: Path, max_chars: int = 250_000) -> Tuple[str, str]:
    if SECRET_NAME_RE.search(path.name) or path.suffix.lower() == ".env":
        return "", "secret_like_path_refused"
    try:
        if not path.exists():
            return "", "missing"
        return path.read_text(encoding="utf-8")[:max_chars], "ok"
    except OSError:
        return "", "read_error"


def assert_allowed_write(path: Path) -> None:
    if path not in ALLOWED_OUTPUT_PATHS and not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed optimizer roots: {path}")
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError(f"Refusing executable/install artifact output: {path}")
    if SECRET_NAME_RE.search(path.name):
        raise ValueError(f"Refusing secret-like output path: {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    if SECRET_ASSIGNMENT_RE.search(content) or LONG_HEX_RE.search(content):
        raise ValueError(f"Refusing secret-like content in {path}")
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError(f"Refusing forbidden executable suffix: {path}")
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
            if SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text):
                raise ValueError("Refusing secret-like audit content")
            handle.write(text + "\n")


def safe_get(data: Optional[Dict[str, Any]], key: str, default: Any = None) -> Any:
    if isinstance(data, dict):
        return data.get(key, default)
    return default


def find_first(data: Any, keys: Iterable[str]) -> Any:
    if isinstance(data, dict):
        for key in keys:
            if key in data and data[key] not in (None, ""):
                return data[key]
        for value in data.values():
            found = find_first(value, keys)
            if found not in (None, ""):
                return found
    elif isinstance(data, list):
        for item in data:
            found = find_first(item, keys)
            if found not in (None, ""):
                return found
    return None


def build_seo_values(inputs: Dict[str, Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    meta = inputs.get("homepage_meta_improved") or {}
    og = inputs.get("homepage_og_twitter") or {}
    detected = safe_get(inputs.get("seo_safe_optimizer"), "detected_current_seo", {})
    title = redact_text(
        find_first(meta, ("title", "proposed_title", "homepage_title")),
        default=f"{BRAND} | 24/7 AI Electro Radio",
        max_len=80,
    )
    if title == "-":
        title = f"{BRAND} | 24/7 AI Electro Radio"
    description = redact_text(
        find_first(meta, ("meta_description", "description", "proposed_meta_description")),
        default=(
            "Listen to 24/7 AI-assisted electro, techno and progressive house from "
            "Electri_C_ity Studios, with releases, tools and NFT-inspired cover art."
        ),
        max_len=220,
    )
    if description == "-":
        description = (
            "Listen to 24/7 AI-assisted electro, techno and progressive house from "
            "Electri_C_ity Studios, with releases, tools and NFT-inspired cover art."
        )
    canonical = redact_text(safe_get(detected if isinstance(detected, dict) else {}, "canonical"), default=DOMAIN, max_len=200)
    if canonical == "-":
        canonical = DOMAIN
    og_title = redact_text(find_first(og, ("og_title", "open_graph_title", "title")), default=f"{BRAND} - 24/7 AI Electro Radio", max_len=100)
    og_description = redact_text(find_first(og, ("og_description", "open_graph_description", "description")), default=description, max_len=220)
    twitter_title = redact_text(find_first(og, ("twitter_title", "twitter_card_title")), default=og_title, max_len=100)
    twitter_description = redact_text(find_first(og, ("twitter_description", "twitter_card_description")), default=og_description, max_len=220)
    return {
        "homepage_title": title,
        "meta_description": description,
        "canonical": canonical,
        "og_title": og_title if og_title != "-" else f"{BRAND} - 24/7 AI Electro Radio",
        "og_description": og_description if og_description != "-" else description,
        "twitter_title": twitter_title if twitter_title != "-" else f"{BRAND} - 24/7 AI Electro Radio",
        "twitter_description": twitter_description if twitter_description != "-" else description,
        "h1": BRAND,
        "h2": [
            "24/7 AI Electro Radio",
            "AI-assisted electro, techno and progressive house",
            "Independent releases and NFT-inspired cover art",
            "Digital tools for music and creative workflows",
            "Studio notes, release updates and production logs",
        ],
        "entity_clusters": [
            "24/7 AI Electro Radio",
            "AI-assisted music",
            "electro",
            "techno",
            "progressive house",
            "independent music releases",
            "digital music tools",
            "NFT-inspired cover art",
            "online radio",
            "music production workflow",
        ],
    }


def recommendation(
    rec_id: str,
    title: str,
    category: str,
    impact_area: str,
    priority: int,
    owner_action: str,
    copy_paste_payload: Any = "",
    validation: str = "Owner manually reviews generated draft and checks the public page after applying changes.",
    rollback_note: str = "Revert the manually edited field to the previous value in WordPress/SEO plugin if needed.",
) -> Dict[str, Any]:
    return {
        "recommendation_id": rec_id,
        "title": title,
        "risk_category": category,
        "impact_area": impact_area,
        "priority": priority,
        "owner_action": owner_action,
        "copy_paste_payload": copy_paste_payload,
        "validation_steps": validation,
        "rollback_note": rollback_note,
        "apply_status": APPLY_STATUS,
    }


def build_recommendations(seo: Dict[str, Any], inputs: Dict[str, Optional[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    latest_5xx = parse_count(safe_get(inputs.get("manual_website_recheck_gate"), "latest_5xx_total"))
    latest_504 = parse_count(safe_get(inputs.get("manual_website_recheck_gate"), "latest_504_total"))
    delta_5xx = parse_count(safe_get(inputs.get("manual_website_recheck_gate"), "latest_delta_5xx"))
    delta_504 = parse_count(safe_get(inputs.get("manual_website_recheck_gate"), "latest_delta_504"))
    return [
        recommendation(
            "SEO-001",
            "Set optimized homepage title",
            CATEGORY_COPY_PASTE,
            "SEO",
            1,
            "Paste the title into the homepage SEO title field after owner review.",
            seo["homepage_title"],
            "Confirm the browser title and search snippet preview use the reviewed title.",
        ),
        recommendation(
            "SEO-002",
            "Set optimized homepage meta description",
            CATEGORY_COPY_PASTE,
            "SEO",
            2,
            "Paste the meta description into the homepage SEO description field after owner review.",
            seo["meta_description"],
            "Confirm the search snippet preview remains readable and not keyword-stuffed.",
        ),
        recommendation(
            "SEO-003",
            "Align H1/H2 structure with brand and radio focus",
            CATEGORY_OWNER_REVIEW,
            "SEO",
            3,
            "Use one H1 for the brand and H2 sections for radio, releases, tools, cover art and blog structure.",
            {"h1": seo["h1"], "h2": seo["h2"]},
            "Inspect the rendered homepage headings after manual content edits.",
        ),
        recommendation(
            "SEO-004",
            "Set OpenGraph title and description",
            CATEGORY_COPY_PASTE,
            "SEO",
            4,
            "Paste reviewed OpenGraph fields into the SEO/social plugin.",
            {"og_title": seo["og_title"], "og_description": seo["og_description"]},
            "Use a social preview tool manually after publishing, without Sentinel automation.",
        ),
        recommendation(
            "SEO-005",
            "Set Twitter card title and description",
            CATEGORY_COPY_PASTE,
            "SEO",
            5,
            "Paste reviewed Twitter card fields into the SEO/social plugin.",
            {"twitter_title": seo["twitter_title"], "twitter_description": seo["twitter_description"]},
            "Review the Twitter/X card preview manually after publishing.",
        ),
        recommendation(
            "SCHEMA-001",
            "Review and paste Organization/WebSite/RadioStation JSON-LD",
            CATEGORY_OWNER_REVIEW,
            "SEO",
            6,
            "Review the schema pack and paste approved JSON-LD into a Custom HTML block or SEO plugin field.",
            "See drafts/owner/wordpress-jsonld-schema-pack.md",
            "Validate with a structured data testing tool manually after publication.",
            "Remove the manually added Custom HTML/schema block if validation fails.",
        ),
        recommendation(
            "LINK-001",
            "Add internal links from homepage sections",
            CATEGORY_OWNER_REVIEW,
            "SEO",
            7,
            "Only add links whose target page exists or is intentionally created by the owner.",
            "See drafts/owner/internal-linking-owner-pack.md",
            "Click each link manually after publication and confirm it lands on the intended page.",
            "Remove or update the manually added link if the target is not available.",
        ),
        recommendation(
            "IMG-001",
            "Add descriptive alt text to hero and cover-art images",
            CATEGORY_COPY_PASTE,
            "Performance",
            8,
            "Copy reviewed alt text into WordPress media fields for visible images.",
            "See drafts/owner/image-alt-lazyload-owner-pack.md",
            "Inspect images manually and confirm alt text is accurate, not stuffed.",
        ),
        recommendation(
            "PERF-001",
            "Reserve image width and height",
            CATEGORY_OWNER_REVIEW,
            "Performance",
            9,
            "Check theme/media output for explicit image dimensions to reduce layout shift.",
            "Checklist only",
            "Run a manual page inspection or Lighthouse review after owner changes.",
        ),
        recommendation(
            "PERF-002",
            "Lazy-load below-the-fold images and embeds",
            CATEGORY_OWNER_REVIEW,
            "Performance",
            10,
            "Apply lazy loading only to below-the-fold media after visual review.",
            "Checklist only",
            "Verify hero media still loads eagerly and layout remains stable.",
        ),
        recommendation(
            "PERF-003",
            "Review external embeds for deferred loading",
            CATEGORY_OWNER_REVIEW,
            "Performance",
            11,
            "Replace heavy embeds with click-to-load placeholders only after owner review.",
            "Checklist only",
            "Confirm player/radio/shop embeds still function after manual changes.",
        ),
        recommendation(
            "PERF-004",
            "Use WebP/AVIF for large visual assets",
            CATEGORY_OWNER_REVIEW,
            "Performance",
            12,
            "Prefer WebP/AVIF variants for large non-transparent images while preserving originals.",
            "Checklist only",
            "Confirm browser fallback remains available for older clients.",
        ),
        recommendation(
            "ORIGIN-001",
            "Continue 24h rolling-window observation before new mitigation",
            CATEGORY_DIAGNOSTIC,
            "Stability",
            13,
            (
                f"Current manual recheck gate shows 5xx={latest_5xx}, 504={latest_504}, "
                f"delta_5xx={delta_5xx}, delta_504={delta_504}. Observe before applying new rules."
            ),
            "Diagnostic only",
            "Compare next read-only Sentinel reports; do not infer OK automatically from this module.",
            "No rollback needed because this recommendation changes nothing.",
        ),
        recommendation(
            "ORIGIN-002",
            "Prioritize origin timeout review over WAF changes",
            CATEGORY_DIAGNOSTIC,
            "Stability",
            14,
            "Manually review origin/PHP/WordPress/AzuraCast logs for 5xx/504 paths; do not create WAF rules from this pack.",
            "Diagnostic only",
            "Confirm the top failing paths in Sentinel reports before any separate manual remediation.",
            "No rollback needed because this recommendation changes nothing.",
        ),
        recommendation(
            "CACHE-001",
            "Keep NowPlaying microcache under observation",
            CATEGORY_DIAGNOSTIC,
            "Performance",
            15,
            "Microcache is documented as deployed/HIT-confirmed when the status report is present; observe whether 504 counts decay.",
            "Diagnostic only",
            "Check future Sentinel rolling-window deltas. No automatic Nginx or Cloudflare change.",
            "No rollback needed because this pack changes nothing.",
        ),
        recommendation(
            "NOAUTO-001",
            "Do not automatically change Cloudflare, Nginx, .htaccess, JS minify or radio player code",
            CATEGORY_DO_NOT_AUTO,
            "Safety",
            16,
            "Treat those actions as separate owner-approved maintenance, not as optimizer output.",
            "Policy note",
            "Confirm all generated files contain draft/checklist text only.",
            "No rollback needed because this pack changes nothing.",
        ),
    ]


def build_jsonld_payloads(seo: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        "organization": {
            "@context": "https://schema.org",
            "@type": "Organization",
            "name": BRAND,
            "url": DOMAIN,
            "description": "Independent AI-assisted music, 24/7 electro radio, digital tools and NFT-inspired cover art.",
            "sameAs": [
                "https://instagram.com/electri_c_ity_studios_24_7",
                "https://soundcloud.com/pierre-bob-stephan-777",
                "https://open.spotify.com/artist/2sAEWBduOLZcEZfRl3WAK0",
            ],
        },
        "website": {
            "@context": "https://schema.org",
            "@type": "WebSite",
            "name": BRAND,
            "url": DOMAIN,
            "description": seo["meta_description"],
            "inLanguage": "en",
        },
        "radio_station": {
            "@context": "https://schema.org",
            "@type": "RadioStation",
            "name": "Electri_C_ity Studios 24/7 AI Electro Radio",
            "url": "https://ai-radio.electri-c-ity-studios-24-7.com/",
            "genre": ["Electro", "Techno", "Progressive House", "AI-assisted music"],
            "parentOrganization": {"@type": "Organization", "name": BRAND, "url": DOMAIN},
        },
        "music_group": {
            "@context": "https://schema.org",
            "@type": "MusicGroup",
            "name": BRAND,
            "url": DOMAIN,
            "genre": ["Electro", "Techno", "Progressive House"],
            "description": "Independent electronic music project with AI-assisted production workflows and digital visual concepts.",
        },
        "creative_work": {
            "@context": "https://schema.org",
            "@type": "CreativeWork",
            "name": "Electri_C_ity Studios cover art and digital music tools",
            "creator": {"@type": "Organization", "name": BRAND},
            "url": DOMAIN,
            "about": ["AI-assisted music", "NFT-inspired cover art", "digital tools", "electronic music"],
        },
        "breadcrumb_list": {
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "Home", "item": DOMAIN},
            ],
        },
        "faq_page": {
            "@context": "https://schema.org",
            "@type": "FAQPage",
            "mainEntity": [
                {
                    "@type": "Question",
                    "name": "What is Electri_C_ity Studios?",
                    "acceptedAnswer": {
                        "@type": "Answer",
                        "text": "Electri_C_ity Studios is an independent electronic music project focused on 24/7 AI-assisted electro radio, releases, digital tools and cover-art concepts.",
                    },
                },
                {
                    "@type": "Question",
                    "name": "What styles does the 24/7 AI Electro Radio focus on?",
                    "acceptedAnswer": {
                        "@type": "Answer",
                        "text": "The station focuses on electro, techno, progressive house and AI-assisted electronic music workflows.",
                    },
                },
            ],
        },
    }


def internal_link_suggestions() -> List[Dict[str, str]]:
    return [
        {"target": "/", "anchor": "Electri_C_ity Studios", "placement": "Homepage hero or footer", "status": "exists_or_verify"},
        {"target": "https://ai-radio.electri-c-ity-studios-24-7.com/", "anchor": "24/7 AI Electro Radio", "placement": "Radio section", "status": "external_subdomain_verify"},
        {"target": "/music/", "anchor": "independent electro and techno releases", "placement": "Music section", "status": "target_may_need_creation"},
        {"target": "/releases/", "anchor": "latest Electri_C_ity Studios releases", "placement": "Release cards", "status": "target_may_need_creation"},
        {"target": "/tools/", "anchor": "digital tools for music creators", "placement": "Digital tools section", "status": "target_may_need_creation"},
        {"target": "/cover-art/", "anchor": "NFT-inspired cover art", "placement": "Cover art section", "status": "target_may_need_creation"},
        {"target": "/blog/", "anchor": "studio notes and production logs", "placement": "Blog teaser", "status": "target_may_need_creation"},
        {"target": "/about/", "anchor": "about Electri_C_ity Studios", "placement": "About/brand paragraph", "status": "target_may_need_creation"},
        {"target": "/contact/", "anchor": "contact Electri_C_ity Studios", "placement": "Footer or collaboration CTA", "status": "target_may_need_creation"},
        {"target": "/radio/nowplaying/", "anchor": "now playing on AI Electro Radio", "placement": "Radio section", "status": "target_may_need_creation"},
    ]


def image_suggestions() -> List[Dict[str, str]]:
    return [
        {"asset": "Homepage hero image", "alt": "Electri_C_ity Studios 24/7 AI Electro Radio visual for electro, techno and progressive house", "title": "Electri_C_ity Studios AI Electro Radio", "filename": "electri-city-studios-ai-electro-radio-hero.webp", "priority": "high"},
        {"asset": "Radio/player visual", "alt": "24/7 AI Electro Radio player by Electri_C_ity Studios", "title": "24/7 AI Electro Radio", "filename": "ai-electro-radio-player.webp", "priority": "high"},
        {"asset": "Cover art gallery image", "alt": "NFT-inspired electronic music cover art by Electri_C_ity Studios", "title": "NFT-inspired cover art", "filename": "electri-city-studios-cover-art.webp", "priority": "medium"},
        {"asset": "Digital tools screenshot", "alt": "Digital music workflow tool concept from Electri_C_ity Studios", "title": "Digital music workflow tool", "filename": "electri-city-digital-music-tool.webp", "priority": "medium"},
        {"asset": "Release artwork", "alt": "Independent electro and techno release artwork by Electri_C_ity Studios", "title": "Independent electronic release artwork", "filename": "electri-city-independent-release-artwork.webp", "priority": "medium"},
        {"asset": "Blog/production image", "alt": "AI-assisted electronic music production workflow notes", "title": "AI-assisted music production notes", "filename": "ai-assisted-electronic-music-production.webp", "priority": "low"},
    ]


def owner_checklist(recommendations: List[Dict[str, Any]]) -> str:
    lines = [
        "# Concrete SEO Owner Apply Checklist",
        "",
        "> Manual owner checklist only. Sentinel does not log in, publish, install, activate, reload, or apply.",
        "",
        "## Safety Before Editing",
        "",
        "- [ ] Confirm Emergency Stop remains active in Sentinel safety reports.",
        "- [ ] Confirm this checklist is used for manual review only.",
        "- [ ] Confirm no Cloudflare, Nginx, .htaccess, systemd, crontab or automated WordPress action is being performed by Sentinel.",
        "",
        "## Prioritized Items",
        "",
    ]
    for rec in sorted(recommendations, key=lambda item: parse_count(item.get("priority"))):
        lines.extend(
            [
                f"- [ ] **{redact_text(rec.get('recommendation_id'))}: {redact_text(rec.get('title'))}**",
                f"  - Category: `{redact_text(rec.get('risk_category'))}`",
                f"  - Owner action: {redact_text(rec.get('owner_action'), max_len=900)}",
                f"  - Validation: {redact_text(rec.get('validation_steps'), max_len=900)}",
                f"  - Apply status: `{APPLY_STATUS}`",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def wordpress_copy_pack(seo: Dict[str, Any]) -> str:
    lines = [
        "# WordPress SEO Copy/Paste Pack",
        "",
        "> Manual owner copy/paste only. Do not use automation from this file.",
        "",
        "## Homepage SEO Fields",
        "",
        f"- SEO title: `{seo['homepage_title']}`",
        f"- Meta description: `{seo['meta_description']}`",
        f"- Canonical URL: `{seo['canonical']}`",
        "",
        "## Social Fields",
        "",
        f"- OpenGraph title: `{seo['og_title']}`",
        f"- OpenGraph description: `{seo['og_description']}`",
        f"- Twitter card title: `{seo['twitter_title']}`",
        f"- Twitter card description: `{seo['twitter_description']}`",
        "",
        "## Headings",
        "",
        f"- H1: `{seo['h1']}`",
    ]
    for heading in seo["h2"]:
        lines.append(f"- H2: `{heading}`")
    lines.extend(
        [
            "",
            "## Entity / Topic Cluster",
            "",
        ]
    )
    for entity in seo["entity_clusters"]:
        lines.append(f"- {entity}")
    lines.extend(
        [
            "",
            "## Branding Sentences",
            "",
            "- Electri_C_ity Studios connects 24/7 AI-assisted electro radio with independent electronic releases, digital tools and visual cover-art concepts.",
            "- The studio focuses on electro, techno and progressive house workflows with a practical, independent creator perspective.",
            "- The 24/7 AI Electro Radio is the always-on listening layer for the Electri_C_ity Studios ecosystem.",
            "",
        ]
    )
    return "\n".join(lines)


def jsonld_pack(seo: Dict[str, Any]) -> str:
    payloads = build_jsonld_payloads(seo)
    lines = [
        "# WordPress JSON-LD Schema Pack",
        "",
        "> Review-only JSON-LD. Paste manually only after owner review and schema validation.",
        "",
    ]
    for name, payload in payloads.items():
        title = name.replace("_", " ").title()
        lines.extend(
            [
                f"## {title}",
                "",
                "```json",
                json.dumps(payload, ensure_ascii=False, indent=2),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def performance_pack(inputs: Dict[str, Optional[Dict[str, Any]]]) -> str:
    perf = inputs.get("performance_safe_audit") or {}
    highest_risk = redact_text(perf.get("highest_risk"), default="UNKNOWN")
    source_map_status = redact_text(perf.get("source_map_status"), default="UNKNOWN")
    microcache = inputs.get("ai_radio_microcache") or {}
    microcache_status = "deployed and HIT-confirmed" if microcache.get("microcache_deployed") else "not confirmed in input"
    lines = [
        "# Performance Optimization Owner Pack",
        "",
        "> Manual review only. This pack does not change caches, minify settings, Cloudflare, Nginx or WordPress files.",
        "",
        f"- Current performance audit highest risk: `{highest_risk}`",
        f"- SourceMap status: `{source_map_status}`",
        f"- NowPlaying microcache status: `{microcache_status}`",
        "",
        "## Lazy Loading",
        "",
        "- Use lazy loading for below-the-fold images.",
        "- Use lazy loading or click-to-load placeholders for non-critical iframe embeds.",
        "- Keep the hero image and critical radio/player surface eager if it is first-viewport content.",
        "",
        "## Embeds and Players",
        "",
        "- Review YouTube, shop, streaming and social widgets as the most likely render-blocking areas.",
        "- Defer heavy embeds only when the owner confirms the initial page still communicates the radio/music offer.",
        "- Treat player/radio code changes as owner-review-required, not automatic.",
        "",
        "## Images",
        "",
        "- Add explicit width and height to large images to reduce layout shift.",
        "- Prefer WebP/AVIF variants for large photos and artwork while preserving fallback originals.",
        "- Compress cover-art previews separately from downloadable or archival artwork.",
        "",
        "## Cache / Minify",
        "",
        "- Review WordPress cache/minify settings manually; do not change JS minify automatically.",
        "- Do not apply Nginx or Cloudflare cache changes from this pack.",
        "- Keep the existing NowPlaying microcache under observation before introducing additional infrastructure changes.",
        "",
    ]
    return "\n".join(lines)


def internal_linking_pack() -> str:
    lines = [
        "# Internal Linking Owner Pack",
        "",
        "> Manual owner review only. Add a link only when the target exists or the owner intentionally creates it.",
        "",
        "| Priority | Target | Anchor Text | Placement | Status |",
        "|---:|---|---|---|---|",
    ]
    for idx, item in enumerate(internal_link_suggestions(), start=1):
        lines.append(
            f"| {idx} | `{item['target']}` | {item['anchor']} | {item['placement']} | `{item['status']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def image_pack() -> str:
    lines = [
        "# Image Alt / Lazyload Owner Pack",
        "",
        "> Manual media-library guidance only. Do not bulk-edit media from this file.",
        "",
        "| Priority | Asset | Alt Text Draft | Title Draft | Filename Suggestion |",
        "|---|---|---|---|---|",
    ]
    for item in image_suggestions():
        lines.append(
            f"| `{item['priority']}` | {item['asset']} | {item['alt']} | {item['title']} | `{item['filename']}` |"
        )
    lines.extend(
        [
            "",
            "## Lazyload Notes",
            "",
            "- Hero image: keep eager if it is the first visual signal.",
            "- Below-the-fold cover art and blog images: lazy loading is usually appropriate.",
            "- Iframes: consider click-to-load placeholders after owner review.",
            "- Avoid generic alt text; describe the visible image and its page context.",
            "",
        ]
    )
    return "\n".join(lines)


def origin_5xx_pack(inputs: Dict[str, Optional[Dict[str, Any]]]) -> str:
    gate = inputs.get("manual_website_recheck_gate") or {}
    critical = inputs.get("master_critical_cause") or {}
    ai = inputs.get("ai_radio_timeout") or {}
    lines = [
        "# Origin 5xx / 504 Owner Action Pack",
        "",
        "> Diagnostic-only. This pack does not create WAF rules, Cloudflare changes, Nginx changes, restarts or applies.",
        "",
        f"- Master critical cause: `{redact_text(critical.get('critical_snapshot_status'), default='UNKNOWN')}`",
        f"- Critical caused by autonomy: `{bool(critical.get('critical_caused_by_autonomy', False))}`",
        f"- Critical caused by website/origin: `{bool(critical.get('critical_caused_by_website', False))}`",
        f"- Recheck gate: `{redact_text(gate.get('gate_status'), default='UNKNOWN')}`",
        f"- Manual recheck recommended: `{bool(gate.get('manual_recheck_recommended', False))}`",
        f"- Latest 5xx total: `{parse_count(gate.get('latest_5xx_total'))}`",
        f"- Latest 504 total: `{parse_count(gate.get('latest_504_total'))}`",
        f"- Latest 5xx delta: `{parse_count(gate.get('latest_delta_5xx'))}`",
        f"- Latest 504 delta: `{parse_count(gate.get('latest_delta_504'))}`",
        f"- AI timeout status: `{redact_text(ai.get('status'), default='UNKNOWN')}`",
        "",
        "## Manual Diagnostic Priorities",
        "",
        f"1. Review the owner-controlled origin logs for `{RADIO_ENDPOINT}` and `/api/time` around 504 bursts.",
        "2. Separate Cloudflare cache/challenge symptoms from origin timeout symptoms.",
        "3. Confirm the NowPlaying microcache remains HIT-confirmed before changing any infrastructure.",
        "4. Keep observing if rolling-window deltas remain zero or low.",
        "5. If growth returns, prioritize origin/PHP/WordPress/AzuraCast investigation before any WAF idea.",
        "",
        "## Do Not Apply Automatically",
        "",
        "- Do not add WAF rules from this pack.",
        "- Do not change Cloudflare cache settings from this pack.",
        "- Do not reload or edit Nginx from this pack.",
        "- Do not change .htaccess from this pack.",
        "- Do not restart services from this pack.",
        "",
    ]
    return "\n".join(lines)


def detect_output_breach_text(text: str) -> List[str]:
    reasons: List[str] = []
    if SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text):
        reasons.append("secret-like output detected")
    for line in text.splitlines():
        if not FORBIDDEN_APPLY_COMMAND_RE.search(line):
            continue
        lower = line.lower()
        if "do not" in lower or " no " in f" {lower} " or "not " in lower or "never" in lower:
            continue
        reasons.append("forbidden apply/install/network command detected in output")
        break
    return reasons


def detect_input_breaches(inputs: Dict[str, Optional[Dict[str, Any]]]) -> List[str]:
    reasons: List[str] = []
    for name, data in inputs.items():
        if not isinstance(data, dict):
            continue
        for key in (
            "live_apply",
            "install_allowed_now",
            "policy_activation_allowed",
            "low_risk_autonomy_allowed_now",
            "can_install_timer_now",
            "systemd_file_written",
            "crontab_file_written",
            "executable_install_script_generated",
        ):
            if bool(data.get(key, False)):
                reasons.append(f"{name}:{key}=true")
        apply_status = data.get("apply_status")
        if apply_status is not None and str(apply_status) != APPLY_STATUS:
            reasons.append(f"{name}:apply_status != not_applied")
        for key, value in data.items():
            if key.lower().endswith("breach") and bool(value):
                reasons.append(f"{name}:{key}=true")
    return sorted(set(reasons))


def determine_status(input_statuses: Dict[str, str], breach_reasons: List[str]) -> Tuple[str, bool]:
    if breach_reasons:
        return STATUS_BLOCKED_BY_BREACH, True
    required = ("safe_end_summary", "safe_end_archive_integrity")
    if any(input_statuses.get(name) != "ok" for name in required):
        return STATUS_PARTIAL, False
    if any(status not in ("ok", "missing") for status in input_statuses.values()):
        return STATUS_PARTIAL, False
    return STATUS_READY, False


def pack_paths() -> Dict[str, str]:
    return {
        "owner_checklist": str(OWNER_CHECKLIST_MD),
        "wordpress_copy_paste_pack": str(WORDPRESS_COPY_MD),
        "jsonld_schema_pack": str(JSONLD_SCHEMA_MD),
        "performance_pack": str(PERFORMANCE_PACK_MD),
        "internal_linking_pack": str(INTERNAL_LINKING_MD),
        "image_pack": str(IMAGE_PACK_MD),
        "origin_5xx_pack": str(ORIGIN_5XX_PACK_MD),
    }


def category_counts(recommendations: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        CATEGORY_DRAFT_ONLY: 0,
        CATEGORY_COPY_PASTE: 0,
        CATEGORY_OWNER_REVIEW: 0,
        CATEGORY_DIAGNOSTIC: 0,
        CATEGORY_DO_NOT_AUTO: 0,
    }
    for rec in recommendations:
        category = str(rec.get("risk_category"))
        if category in counts:
            counts[category] += 1
    return counts


def build_report(generated_at: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[Path, str]]:
    generated = generated_at or utc_now()
    inputs: Dict[str, Optional[Dict[str, Any]]] = {}
    input_statuses: Dict[str, str] = {}
    for name, path in INPUT_PATHS.items():
        if path.suffix.lower() == ".json":
            data, status = read_json_file(path)
            inputs[name] = data
            input_statuses[name] = status
        else:
            _text, status = read_text_file(path)
            inputs[name] = None
            input_statuses[name] = status

    seo = build_seo_values(inputs)
    recommendations = build_recommendations(seo, inputs)
    counts = category_counts(recommendations)
    top_10 = sorted(recommendations, key=lambda item: parse_count(item.get("priority")))[:10]

    output_texts = {
        OWNER_CHECKLIST_MD: owner_checklist(recommendations),
        WORDPRESS_COPY_MD: wordpress_copy_pack(seo),
        JSONLD_SCHEMA_MD: jsonld_pack(seo),
        PERFORMANCE_PACK_MD: performance_pack(inputs),
        INTERNAL_LINKING_MD: internal_linking_pack(),
        IMAGE_PACK_MD: image_pack(),
        ORIGIN_5XX_PACK_MD: origin_5xx_pack(inputs),
    }

    breach_reasons = detect_input_breaches(inputs)
    for path, text in output_texts.items():
        for reason in detect_output_breach_text(text):
            breach_reasons.append(f"{path.name}:{reason}")
    for path in output_texts:
        try:
            assert_allowed_write(path)
        except ValueError as exc:
            breach_reasons.append(str(exc))
    breach_reasons = sorted(set(breach_reasons))
    status, breach = determine_status(input_statuses, breach_reasons)

    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": generated,
        "optimizer_status": status,
        "seo_pack_created": True,
        "performance_pack_created": True,
        "wordpress_copy_paste_pack_created": True,
        "jsonld_pack_created": True,
        "internal_linking_pack_created": True,
        "image_pack_created": True,
        "origin_5xx_pack_created": True,
        "total_recommendations": len(recommendations),
        "draft_only_count": counts[CATEGORY_DRAFT_ONLY],
        "copy_paste_owner_apply_count": counts[CATEGORY_COPY_PASTE],
        "owner_review_required_count": counts[CATEGORY_OWNER_REVIEW],
        "diagnostic_only_count": counts[CATEGORY_DIAGNOSTIC],
        "do_not_apply_automatically_count": counts[CATEGORY_DO_NOT_AUTO],
        "live_apply": False,
        "install_allowed_now": False,
        "policy_activation_allowed": False,
        "low_risk_autonomy_allowed_now": False,
        "apply_status": APPLY_STATUS,
        "optimizer_breach": breach,
        "optimizer_breach_reasons": breach_reasons,
        "read_only": True,
        "network_access": False,
        "api_access": False,
        "wordpress_login": False,
        "cloudflare_change": False,
        "nginx_change": False,
        "htaccess_change": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "executable_artifact_generated": False,
        "safe_end_status": redact_text(safe_get(inputs.get("safe_end_summary"), "safe_end_status"), default="NOT_AVAILABLE"),
        "safe_end_archive_integrity_status": redact_text(safe_get(inputs.get("safe_end_archive_integrity"), "integrity_status"), default="NOT_AVAILABLE"),
        "manual_website_recheck_gate_status": redact_text(safe_get(inputs.get("manual_website_recheck_gate"), "gate_status"), default="NOT_AVAILABLE"),
        "website_recheck_recommended": bool(safe_get(inputs.get("manual_website_recheck_gate"), "manual_recheck_recommended", False)),
        "latest_5xx_total": parse_count(safe_get(inputs.get("manual_website_recheck_gate"), "latest_5xx_total")),
        "latest_504_total": parse_count(safe_get(inputs.get("manual_website_recheck_gate"), "latest_504_total")),
        "latest_delta_5xx": parse_count(safe_get(inputs.get("manual_website_recheck_gate"), "latest_delta_5xx")),
        "latest_delta_504": parse_count(safe_get(inputs.get("manual_website_recheck_gate"), "latest_delta_504")),
        "seo_fields": seo,
        "recommendations": recommendations,
        "top_10_recommendations": top_10,
        "generated_files": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
            **pack_paths(),
        },
        "input_statuses": input_statuses,
        "recommended_owner_action": (
            "Review concrete SEO/performance drafts manually. Do not enable autonomy, install timers, or run live apply."
            if not breach
            else "Do not proceed. Resolve optimizer breach before using drafts."
        ),
    }
    output_texts[REPORT_MD] = render_markdown(report)
    output_texts[SNAPSHOT_MD] = output_texts[REPORT_MD]
    return report, output_texts


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Concrete SEO & Performance Optimizer",
        "",
        "> Phase 6.0 creates concrete owner-review drafts. No live apply, no installation, no activation.",
        "",
        f"- Timestamp UTC: `{report.get('timestamp_utc')}`",
        f"- Optimizer status: `{report.get('optimizer_status')}`",
        f"- Total recommendations: `{report.get('total_recommendations')}`",
        f"- Copy/Paste owner apply: `{report.get('copy_paste_owner_apply_count')}`",
        f"- Owner review required: `{report.get('owner_review_required_count')}`",
        f"- Diagnostic only: `{report.get('diagnostic_only_count')}`",
        f"- Do not apply automatically: `{report.get('do_not_apply_automatically_count')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Policy activation allowed: `{report.get('policy_activation_allowed')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Optimizer breach: `{report.get('optimizer_breach')}`",
        "",
        "## Generated Owner Packs",
        "",
    ]
    for key, path in pack_paths().items():
        lines.append(f"- {key}: `{path}`")
    lines.extend(["", "## Top 10 Concrete Recommendations", ""])
    for rec in report.get("top_10_recommendations", []):
        lines.append(
            f"{rec.get('priority')}. **{redact_text(rec.get('title'))}** "
            f"(`{redact_text(rec.get('risk_category'))}`): {redact_text(rec.get('owner_action'), max_len=900)}"
        )
    lines.extend(
        [
            "",
            "## Website / Origin Context",
            "",
            f"- Manual website recheck gate: `{report.get('manual_website_recheck_gate_status')}`",
            f"- Website recheck recommended: `{report.get('website_recheck_recommended')}`",
            f"- Latest 5xx total: `{report.get('latest_5xx_total')}`",
            f"- Latest 504 total: `{report.get('latest_504_total')}`",
            f"- Latest 5xx delta: `{report.get('latest_delta_5xx')}`",
            f"- Latest 504 delta: `{report.get('latest_delta_504')}`",
            "",
            "## Safety Statement",
            "",
            "- No WordPress, Cloudflare, Nginx, .htaccess, systemd, crontab or API change was made.",
            "- Generated content is owner-review and manual copy/paste only.",
            "- Live apply remains false and apply_status remains not_applied.",
            "",
        ]
    )
    if report.get("optimizer_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in report.get("optimizer_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=600)}")
        lines.append("")
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("timestamp_utc"),
        "schema_version": SCHEMA_VERSION,
        "optimizer_status": report.get("optimizer_status"),
        "total_recommendations": report.get("total_recommendations"),
        "copy_paste_owner_apply_count": report.get("copy_paste_owner_apply_count"),
        "diagnostic_only_count": report.get("diagnostic_only_count"),
        "live_apply": False,
        "install_allowed_now": False,
        "policy_activation_allowed": False,
        "low_risk_autonomy_allowed_now": False,
        "apply_status": APPLY_STATUS,
        "optimizer_breach": report.get("optimizer_breach"),
    }


def write_outputs(report: Dict[str, Any], output_texts: Dict[Path, str]) -> None:
    for path, content in output_texts.items():
        write_text_atomic(path, content)
    write_json_atomic(REPORT_JSON, report)
    write_json_atomic(SNAPSHOT_JSON, report)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def run_self_test() -> int:
    input_statuses = {"safe_end_summary": "ok", "safe_end_archive_integrity": "ok"}
    status, breach = determine_status(input_statuses, [])
    if status != STATUS_READY or breach:
        raise AssertionError("ready locked status failed")
    status, breach = determine_status({"safe_end_summary": "missing", "safe_end_archive_integrity": "ok"}, [])
    if status != STATUS_PARTIAL or breach:
        raise AssertionError("missing inputs should be partial")
    for reason in (
        "live_apply=true",
        "install_allowed_now=true",
        "policy_activation_allowed=true",
        "low_risk_autonomy_allowed_now=true",
        "apply_status != not_applied",
        "forbidden apply command detected",
        "executable artifact generated",
        "secret-like output detected",
    ):
        status, breach = determine_status(input_statuses, [reason])
        if status != STATUS_BLOCKED_BY_BREACH or not breach:
            raise AssertionError(f"breach reason failed: {reason}")
    if detect_output_breach_text("systemctl enable something"):
        pass
    else:
        raise AssertionError("forbidden command detection failed")
    if not detect_output_breach_text("password=abcd1234"):
        raise AssertionError("secret output detection failed")
    recs = build_recommendations(build_seo_values({}), {})
    counts = category_counts(recs)
    if counts[CATEGORY_COPY_PASTE] < 1 or counts[CATEGORY_DIAGNOSTIC] < 1:
        raise AssertionError("recommendation counts failed")
    for path in ALLOWED_OUTPUT_PATHS:
        assert_allowed_write(path)
    print("self-test ok")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate concrete SEO and performance owner-review packs.")
    parser.add_argument("--self-test", action="store_true", help="Run local self-tests without writing reports.")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    report, output_texts = build_report()
    write_outputs(report, output_texts)
    print(f"optimizer_status={report.get('optimizer_status')}")
    print(f"optimizer_breach={report.get('optimizer_breach')}")
    print(f"total_recommendations={report.get('total_recommendations')}")
    print(f"report={REPORT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
