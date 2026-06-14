#!/usr/bin/env python3
"""Sentinel Owner Review Pack (Phase 2.4).

Builds a clear owner-facing review/copy-paste pack from the Draft Execution
Planner. It applies nothing live and offers no apply mode.
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

# Optional local inputs only.
INPUT_EXECUTION_PLAN = PROJECT_DIR / "drafts/execution/draft-execution-plan.json"
INPUT_EXECUTION_REPORT = PROJECT_DIR / "reports/latest/draft-execution-plan-report.json"
INPUT_SEO_META = PROJECT_DIR / "drafts/seo/homepage-meta-improved-draft.json"
INPUT_SEO_SOCIAL = PROJECT_DIR / "drafts/seo/homepage-og-twitter-draft.json"
INPUT_SEO_SCHEMA = PROJECT_DIR / "drafts/seo/homepage-schema-draft.jsonld"
INPUT_AUTONOMY_POLICY = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"

# Outputs.
REVIEW_DIR = PROJECT_DIR / "drafts/review"
REVIEW_PACK_MD = REVIEW_DIR / "owner-review-pack.md"
REVIEW_PACK_JSON = REVIEW_DIR / "owner-review-pack.json"
REPORT_MD = PROJECT_DIR / "reports/latest/owner-review-pack-report.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/owner-review-pack-report.json"
AUDIT_JSONL = PROJECT_DIR / "audit/owner-review-pack.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/review",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "owner-review-pack-2.4"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"
APPLY_NOT_APPLIED = "not_applied"

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)

SECTION_ORDER = {
    "SEO Title": 10,
    "Meta Description": 20,
    "OpenGraph": 30,
    "Twitter Cards": 40,
    "Internal Link Draft": 50,
    "Image/WebP Status": 60,
    "Image Width/Height Checklist": 70,
}


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(value: Any, default: str = "-", max_len: int = 600) -> str:
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
        raise ValueError(f"Refusing to write outside allowed owner review roots: {path}")


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
    if path.suffix.lower() not in {".json", ".jsonld"}:
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


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY}:
        return risk
    return RISK_REVIEW_ONLY


def slug(value: Any) -> str:
    text = str(value or "unknown").lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "unknown"


def execution_items_from(data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("execution_items"), list):
        return []
    return [item for item in data["execution_items"] if isinstance(item, dict)]


def excluded_items_from(data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("excluded_items"), list):
        return []
    return [item for item in data["excluded_items"] if isinstance(item, dict)]


def ready_for_copy(item: Dict[str, Any]) -> Tuple[bool, str]:
    if normalize_risk(item.get("risk_classification")) != RISK_LOW:
        return False, "risk_classification is not LOW"
    if item.get("apply_status") != APPLY_NOT_APPLIED:
        return False, "apply_status is not not_applied"
    if item.get("copy_paste_payload") is None:
        return False, "copy_paste_payload is not available"
    return True, "LOW not_applied draft item with manual copy payload"


def section_for_draft_type(draft_type: Any) -> str:
    draft_type_text = str(draft_type or "")
    return {
        "seo_title_draft": "SEO Title",
        "seo_meta_description_draft": "Meta Description",
        "open_graph_draft": "OpenGraph",
        "twitter_card_draft": "Twitter Cards",
        "internal_link_draft": "Internal Link Draft",
        "image_webp_status_check": "Image/WebP Status",
        "image_width_height_check": "Image Width/Height Checklist",
    }.get(draft_type_text, "Manual Draft")


def where_to_apply_manually(section: str) -> str:
    mapping = {
        "SEO Title": "Owner CMS/SEO plugin homepage title field, after manual login by the owner. Sentinel does not log in.",
        "Meta Description": "Owner CMS/SEO plugin homepage meta description field, after manual login by the owner. Sentinel does not write CMS data.",
        "OpenGraph": "Owner CMS/social metadata settings for the homepage. Keep existing image fields unless separately reviewed.",
        "Twitter Cards": "Owner CMS/social metadata settings for Twitter/X card fields. Keep existing image fields unless separately reviewed.",
        "Internal Link Draft": "Owner homepage editor or editorial checklist, only if the link is natural and contextual.",
        "Image/WebP Status": "Owner performance review notes. This is a status/checklist item, not an asset conversion.",
        "Image Width/Height Checklist": "Owner performance review notes. This is a checklist item, not a markup edit.",
    }
    return mapping.get(section, "Owner manual review notes only; Sentinel does not apply changes.")


def split_payload(payload: Any) -> Tuple[Any, Any]:
    if not isinstance(payload, dict):
        return None, payload
    if "proposed_value" in payload or "current_value" in payload:
        return payload.get("current_value"), payload.get("proposed_value")
    if "target" in payload or "anchor" in payload:
        return None, {"target": payload.get("target"), "anchor": payload.get("anchor")}
    if "checklist" in payload:
        return None, {"checklist": payload.get("checklist"), "check_title": payload.get("check_title")}
    return None, payload


def pre_check_for(section: str, item: Dict[str, Any]) -> List[str]:
    base = [
        "Confirm this is manual review only.",
        "Confirm no WordPress, .htaccess, Cloudflare, Nginx, API, or file write is performed by Sentinel.",
        "Confirm apply_status is not_applied.",
    ]
    specific = {
        "SEO Title": ["Confirm proposed title is non-empty and approximately 60 characters or less."],
        "Meta Description": ["Confirm proposed description is non-empty and approximately 140-160 characters when possible."],
        "OpenGraph": ["Confirm required OpenGraph fields are present and match homepage positioning."],
        "Twitter Cards": ["Confirm Twitter card fields mirror the approved social wording."],
        "Internal Link Draft": ["Confirm the link target was found in homepage or sitemap snapshot."],
        "Image/WebP Status": ["Confirm this is a status check only; do not convert assets from this pack."],
        "Image Width/Height Checklist": ["Confirm this is a status check only; do not edit markup from this pack."],
    }
    return base + specific.get(section, [])


def post_check_for(section: str) -> List[str]:
    base = [
        "Keep the owner decision outside Sentinel until explicitly reviewed.",
        "Do not mark the item applied in Sentinel.",
        "If manually used later, rerun Sentinel reports to observe only.",
    ]
    specific = {
        "SEO Title": ["After any future manual CMS edit, verify rendered title in a fresh HTML snapshot."],
        "Meta Description": ["After any future manual CMS edit, verify rendered meta description in a fresh HTML snapshot."],
        "OpenGraph": ["After any future manual CMS edit, verify social metadata in a fresh HTML snapshot."],
        "Twitter Cards": ["After any future manual CMS edit, verify Twitter card metadata in a fresh HTML snapshot."],
        "Internal Link Draft": ["After any future manual CMS edit, verify link exists and is contextual in a fresh HTML snapshot."],
        "Image/WebP Status": ["After future manual asset work, rerun performance audit; this pack does not change assets."],
        "Image Width/Height Checklist": ["After future manual markup work, rerun performance audit; this pack does not change markup."],
    }
    return base + specific.get(section, [])


def review_item_from_execution(item: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    is_ready, reason = ready_for_copy(item)
    if not is_ready:
        return None, {
            "item_id": redact_text(item.get("execution_id"), max_len=180),
            "title": redact_text(item.get("title"), max_len=220),
            "draft_type": redact_text(item.get("draft_type"), max_len=120),
            "risk_classification": normalize_risk(item.get("risk_classification")),
            "apply_status": redact_text(item.get("apply_status"), max_len=80),
            "excluded_reason": reason,
        }

    section = section_for_draft_type(item.get("draft_type"))
    payload = sanitize_value(item.get("copy_paste_payload"))
    current_value, proposed_value = split_payload(payload)
    review_item = {
        "item_id": redact_text(item.get("execution_id"), max_len=180),
        "queue_id": redact_text(item.get("queue_id"), max_len=180),
        "section": section,
        "title": redact_text(item.get("title"), max_len=220),
        "current_value": sanitize_value(current_value),
        "proposed_value": sanitize_value(proposed_value),
        "copy_paste_payload": payload,
        "where_to_apply_manually": where_to_apply_manually(section),
        "pre_check": pre_check_for(section, item),
        "post_check": post_check_for(section),
        "rollback_note": redact_text(item.get("rollback_note"), max_len=500),
        "risk_classification": RISK_LOW,
        "apply_status": APPLY_NOT_APPLIED,
        "owner_decision_required": True,
        "ready_for_copy": True,
        "source_execution_id": redact_text(item.get("execution_id"), max_len=180),
        "reason": redact_text(item.get("reason"), max_len=700),
    }
    return review_item, None


def make_excluded_from_execution_excluded(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "item_id": redact_text(item.get("queue_id") or item.get("execution_id"), max_len=180),
        "title": redact_text(item.get("title"), max_len=220),
        "risk_classification": normalize_risk(item.get("risk_classification")),
        "queue_status": redact_text(item.get("queue_status"), max_len=120),
        "apply_status": redact_text(item.get("apply_status"), max_len=80),
        "excluded_reason": redact_text(item.get("excluded_reason"), max_len=500),
        "ready_for_copy": False,
    }


def load_context() -> Tuple[Dict[str, Any], Dict[str, str]]:
    context: Dict[str, Any] = {}
    statuses: Dict[str, str] = {}
    for key, path in (
        ("execution_plan", INPUT_EXECUTION_PLAN),
        ("execution_report", INPUT_EXECUTION_REPORT),
        ("seo_meta", INPUT_SEO_META),
        ("seo_social", INPUT_SEO_SOCIAL),
        ("seo_schema", INPUT_SEO_SCHEMA),
        ("autonomy_policy", INPUT_AUTONOMY_POLICY),
    ):
        data, status = read_optional_json(path)
        context[key] = data
        statuses[key] = status
    return context, statuses


def build_pack(
    execution_plan: Optional[Any],
    execution_plan_status: str,
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    execution_items = execution_items_from(execution_plan)
    inherited_excluded_items = excluded_items_from(execution_plan)

    review_items: List[Dict[str, Any]] = []
    excluded_items: List[Dict[str, Any]] = []
    for item in execution_items:
        review_item, excluded = review_item_from_execution(item)
        if review_item is not None:
            review_items.append(review_item)
        if excluded is not None:
            excluded_items.append(excluded)
    excluded_items.extend(make_excluded_from_execution_excluded(item) for item in inherited_excluded_items)
    review_items.sort(key=lambda item: (SECTION_ORDER.get(str(item.get("section")), 999), str(item.get("item_id"))))

    ready_for_copy_count = len([item for item in review_items if item.get("ready_for_copy")])
    ready_for_owner_review_count = len(review_items)
    not_applied_count = len([item for item in review_items if item.get("apply_status") == APPLY_NOT_APPLIED])
    other_apply_status_count = len(review_items) - not_applied_count
    high_or_medium_ready_count = len(
        [
            item for item in review_items
            if item.get("ready_for_copy") and normalize_risk(item.get("risk_classification")) in {RISK_HIGH, RISK_MEDIUM, RISK_REVIEW_ONLY}
        ]
    )
    review_pack_breach = other_apply_status_count > 0 or high_or_medium_ready_count > 0
    status = "NOT_AVAILABLE" if execution_plan_status != "ok" else "READY_FOR_OWNER_REVIEW"
    if execution_plan_status == "ok" and not review_items:
        status = "NO_READY_REVIEW_ITEMS"
    if review_pack_breach:
        status = "POLICY_BREACH"

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "read_only": True,
        "productive_change": False,
        "network_access": False,
        "apply_function": False,
        "secrets_output": False,
        "apply_status": APPLY_NOT_APPLIED,
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
        "review_items_count": len(review_items),
        "ready_for_owner_review_count": ready_for_owner_review_count,
        "ready_for_copy_count": ready_for_copy_count,
        "excluded_count": len(excluded_items),
        "high_or_medium_ready_count": high_or_medium_ready_count,
        "review_pack_breach": review_pack_breach,
        "apply_status_summary": {
            "all_not_applied": other_apply_status_count == 0,
            "not_applied_count": not_applied_count,
            "other_apply_status_count": other_apply_status_count,
        },
        "review_items": review_items,
        "excluded_items": excluded_items,
        "safety_notes": [
            "No live changes.",
            "No WordPress login, API call, CMS write, .htaccess edit, Cloudflare change, Nginx change, network access, or external write.",
            "Copy-paste payloads are manual owner-review material only.",
            "HIGH, MEDIUM, and REVIEW_ONLY items are never ready_for_copy.",
            "All items remain apply_status=not_applied.",
        ],
        "outputs": {
            "review_pack_md": str(REVIEW_PACK_MD),
            "review_pack_json": str(REVIEW_PACK_JSON),
            "report_md": str(REPORT_MD),
            "report_json": str(REPORT_JSON),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(pack: Dict[str, Any]) -> str:
    lines: List[str] = [
        "# Owner Review Pack",
        "",
        f"- Generated (UTC): `{redact_text(pack.get('generated_at_utc'))}`",
        f"- Status: `{redact_text(pack.get('status'))}`",
        f"- Review items: `{pack.get('review_items_count')}`",
        f"- Ready for owner review: `{pack.get('ready_for_owner_review_count')}`",
        f"- Ready for copy: `{pack.get('ready_for_copy_count')}`",
        f"- Excluded: `{pack.get('excluded_count')}`",
        f"- Review pack breach: `{str(bool(pack.get('review_pack_breach'))).lower()}`",
        f"- Apply status: `{redact_text(pack.get('apply_status'))}`",
        "",
        "## Safety",
        "",
    ]
    for note in pack.get("safety_notes", []):
        lines.append(f"- {redact_text(note)}")
    lines.append("")

    review_items = pack.get("review_items") if isinstance(pack.get("review_items"), list) else []
    if not review_items:
        lines.extend(["## Review Items", "", "- (none)", ""])
    current_section = None
    for item in review_items:
        if not isinstance(item, dict):
            continue
        section = str(item.get("section", "Manual Draft"))
        if section != current_section:
            lines.extend([f"## {redact_text(section)}", ""])
            current_section = section
        lines.extend(
            [
                f"### `{redact_text(item.get('item_id'))}`",
                "",
                f"- Title: {redact_text(item.get('title'))}",
                f"- Risk: `{redact_text(item.get('risk_classification'))}`",
                f"- Apply status: `{redact_text(item.get('apply_status'))}`",
                f"- Ready for copy: `{str(bool(item.get('ready_for_copy'))).lower()}`",
                f"- Owner decision required: `{str(bool(item.get('owner_decision_required'))).lower()}`",
                f"- Where to apply manually: {redact_text(item.get('where_to_apply_manually'), max_len=900)}",
                "",
            ]
        )
        if item.get("current_value") not in (None, "", {}, []):
            lines.extend(
                [
                    "**Current value:**",
                    "",
                    "```json",
                    json.dumps(sanitize_value(item.get("current_value")), ensure_ascii=False, indent=2, sort_keys=True),
                    "```",
                    "",
                ]
            )
        lines.extend(
            [
                "**Proposed / copy-paste payload:**",
                "",
                "```json",
                json.dumps(sanitize_value(item.get("copy_paste_payload")), ensure_ascii=False, indent=2, sort_keys=True),
                "```",
                "",
                "**Pre-check:**",
                "",
            ]
        )
        for step in item.get("pre_check", []):
            lines.append(f"- {redact_text(step)}")
        lines.extend(["", "**Post-check:**", ""])
        for step in item.get("post_check", []):
            lines.append(f"- {redact_text(step)}")
        lines.extend(["", f"Rollback note: {redact_text(item.get('rollback_note'))}", ""])

    lines.extend(["## Excluded Items", ""])
    excluded_items = pack.get("excluded_items") if isinstance(pack.get("excluded_items"), list) else []
    if not excluded_items:
        lines.append("- (none)")
    else:
        lines.append("| Item | Risk | Apply | Ready for copy | Reason |")
        lines.append("|---|---|---|---|---|")
        for item in excluded_items:
            if not isinstance(item, dict):
                continue
            reason = redact_text(item.get("excluded_reason"), max_len=300).replace("|", "\\|")
            lines.append(
                f"| `{redact_text(item.get('item_id'))}` | `{redact_text(item.get('risk_classification'))}` | "
                f"`{redact_text(item.get('apply_status'))}` | `{str(bool(item.get('ready_for_copy'))).lower()}` | {reason} |"
            )
    lines.append("")
    return "\n".join(lines)


def build_audit_records(pack: Dict[str, Any]) -> List[Dict[str, Any]]:
    records = [
        {
            "timestamp_utc": pack.get("generated_at_utc"),
            "schema_version": SCHEMA_VERSION,
            "event": "owner_review_pack_summary",
            "status": pack.get("status"),
            "review_items_count": pack.get("review_items_count"),
            "ready_for_owner_review_count": pack.get("ready_for_owner_review_count"),
            "ready_for_copy_count": pack.get("ready_for_copy_count"),
            "excluded_count": pack.get("excluded_count"),
            "review_pack_breach": bool(pack.get("review_pack_breach")),
            "apply_status_summary": pack.get("apply_status_summary"),
        }
    ]
    for item in pack.get("review_items", []):
        if not isinstance(item, dict):
            continue
        records.append(
            {
                "timestamp_utc": pack.get("generated_at_utc"),
                "schema_version": SCHEMA_VERSION,
                "event": "owner_review_item",
                "item_id": item.get("item_id"),
                "section": item.get("section"),
                "risk_classification": item.get("risk_classification"),
                "apply_status": item.get("apply_status"),
                "ready_for_copy": bool(item.get("ready_for_copy")),
            }
        )
    return records


def build_from_files() -> Dict[str, Any]:
    context, statuses = load_context()
    execution_plan = context.get("execution_plan")
    execution_plan_status = statuses.get("execution_plan", "not_available")
    return build_pack(execution_plan, execution_plan_status, statuses)


def run_self_tests() -> int:
    assert_allowed_write(REVIEW_PACK_JSON)
    assert_allowed_write(REPORT_JSON)
    assert_allowed_write(AUDIT_JSONL)
    try:
        assert_allowed_write(PROJECT_DIR / "drafts/execution/not-allowed.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")
    assert redact_text("Bearer abc123 token") == "[redacted]"

    execution_plan = {
        "execution_items": [
            {
                "execution_id": "draft_exec:seo-title",
                "queue_id": "approval:seo:title",
                "title": "Title: improve",
                "draft_type": "seo_title_draft",
                "risk_classification": "LOW",
                "apply_status": "not_applied",
                "copy_paste_payload": {"current_value": "Old", "proposed_value": "New"},
                "rollback_note": "Discard draft.",
                "reason": "LOW draft.",
            },
            {
                "execution_id": "draft_exec:seo-meta",
                "queue_id": "approval:seo:meta_description",
                "title": "Meta Description: improve",
                "draft_type": "seo_meta_description_draft",
                "risk_classification": "LOW",
                "apply_status": "not_applied",
                "copy_paste_payload": {"current_value": "Old desc", "proposed_value": "New desc"},
                "rollback_note": "Discard draft.",
                "reason": "LOW draft.",
            },
            {
                "execution_id": "draft_exec:bad-medium",
                "queue_id": "approval:bad:medium",
                "title": "Medium",
                "draft_type": "seo_title_draft",
                "risk_classification": "MEDIUM",
                "apply_status": "not_applied",
                "copy_paste_payload": {"proposed_value": "No"},
            },
            {
                "execution_id": "draft_exec:bad-applied",
                "queue_id": "approval:bad:applied",
                "title": "Applied",
                "draft_type": "seo_title_draft",
                "risk_classification": "LOW",
                "apply_status": "applied",
                "copy_paste_payload": {"proposed_value": "No"},
            },
        ],
        "excluded_items": [
            {
                "queue_id": "approval:high",
                "title": "High",
                "risk_classification": "HIGH",
                "apply_status": "not_applied",
                "excluded_reason": "blocked",
            }
        ],
    }
    pack = build_pack(execution_plan, "ok", {"execution_plan": "ok"}, generated_at="T")
    assert pack["review_items_count"] == 2
    assert pack["ready_for_copy_count"] == 2
    assert pack["excluded_count"] == 3
    assert pack["review_pack_breach"] is False
    assert pack["apply_status_summary"]["all_not_applied"] is True
    assert all(item["apply_status"] == "not_applied" for item in pack["review_items"])
    assert all(item["risk_classification"] == "LOW" for item in pack["review_items"])
    assert not any(item.get("ready_for_copy") for item in pack["excluded_items"])
    md = render_markdown(pack)
    assert "Owner Review Pack" in md

    missing = build_pack(None, "not_available", {"execution_plan": "not_available"}, generated_at="T")
    assert missing["status"] == "NOT_AVAILABLE"
    assert missing["review_items_count"] == 0
    assert missing["ready_for_copy_count"] == 0
    assert missing["apply_status_summary"]["all_not_applied"] is True

    print("owner-review-pack self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Owner Review Pack (read-only; no apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety/unit tests.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()

    pack = build_from_files()
    markdown = render_markdown(pack)
    write_json_atomic(REVIEW_PACK_JSON, pack)
    write_text_atomic(REVIEW_PACK_MD, markdown)
    write_json_atomic(REPORT_JSON, pack)
    write_text_atomic(REPORT_MD, markdown)
    append_jsonl(AUDIT_JSONL, build_audit_records(pack))
    print(f"Owner review pack written: {REVIEW_PACK_MD}")
    print(f"Owner review pack JSON written: {REVIEW_PACK_JSON}")
    print(f"Owner review report written: {REPORT_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
