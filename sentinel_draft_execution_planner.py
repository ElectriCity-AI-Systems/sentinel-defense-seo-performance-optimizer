#!/usr/bin/env python3
"""Sentinel Draft Execution Planner (Phase 2.3).

Reads the Owner Approval Queue and turns LOW approved_for_draft_only items into
manual draft plans. It never logs in, never calls an API, never writes a CMS,
and never mutates WordPress, .htaccess, Cloudflare, or Nginx.
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

# Inputs. All are optional and local only.
INPUT_APPROVAL_QUEUE = PROJECT_DIR / "drafts/approval/owner-approval-queue.json"
INPUT_SEO_META = PROJECT_DIR / "drafts/seo/homepage-meta-improved-draft.json"
INPUT_SEO_SOCIAL = PROJECT_DIR / "drafts/seo/homepage-og-twitter-draft.json"
INPUT_SEO_SCHEMA = PROJECT_DIR / "drafts/seo/homepage-schema-draft.jsonld"
INPUT_SEO_EDITORIAL = PROJECT_DIR / "drafts/seo/homepage-editorial-review.json"
INPUT_PERFORMANCE_REVIEW = PROJECT_DIR / "drafts/performance/performance-editorial-review.json"
INPUT_ROADMAP_REPORT = PROJECT_DIR / "reports/latest/safe-improvement-roadmap-report.json"
INPUT_AUTONOMY_POLICY = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"

# Outputs.
DRAFT_DIR = PROJECT_DIR / "drafts/execution"
DRAFT_PLAN_MD = DRAFT_DIR / "draft-execution-plan.md"
DRAFT_PLAN_JSON = DRAFT_DIR / "draft-execution-plan.json"
REPORT_MD = PROJECT_DIR / "reports/latest/draft-execution-plan-report.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/draft-execution-plan-report.json"
AUDIT_JSONL = PROJECT_DIR / "audit/draft-execution-planner.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/execution",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "draft-execution-planner-2.3"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

QUEUE_APPROVED_FOR_DRAFT_ONLY = "approved_for_draft_only"
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


def redact_text(value: Any, default: str = "-", max_len: int = 500) -> str:
    if value is None:
        return default
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def sanitize_value(value: Any, *, max_len: int = 1200) -> Any:
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
    if isinstance(value, (str, int, float, bool)) or value is None:
        return redact_text(value, default="", max_len=max_len) if isinstance(value, str) or value is None else value
    return redact_text(value, default="", max_len=max_len)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed execution roots: {path}")


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


def queue_items_from(data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    items = data.get("queue_items")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def roadmap_items_from(data: Optional[Any]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("roadmap_items"), list):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for item in data["roadmap_items"]:
        if isinstance(item, dict) and item.get("roadmap_id"):
            result[str(item["roadmap_id"])] = item
    return result


def proposals_by_id(data: Optional[Any]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("proposals"), list):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for item in data["proposals"]:
        if not isinstance(item, dict):
            continue
        proposal_id = item.get("proposal_id")
        if proposal_id:
            result[str(proposal_id)] = item
    return result


def performance_proposals_by_title(data: Optional[Any]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("proposals"), list):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for item in data["proposals"]:
        if isinstance(item, dict) and item.get("title"):
            result[slug(item["title"])] = item
    return result


def queue_item_safe(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "queue_id": redact_text(item.get("queue_id"), max_len=160),
        "roadmap_id": redact_text(item.get("roadmap_id"), max_len=160),
        "source": redact_text(item.get("source"), max_len=120),
        "title": redact_text(item.get("title"), max_len=200),
        "impact_area": redact_text(item.get("impact_area"), max_len=80),
        "queue_status": redact_text(item.get("queue_status"), max_len=80),
        "risk_classification": normalize_risk(item.get("risk_classification")),
        "apply_status": redact_text(item.get("apply_status"), max_len=80),
    }


def eligibility_reason(item: Dict[str, Any]) -> Tuple[bool, str]:
    if item.get("queue_status") != QUEUE_APPROVED_FOR_DRAFT_ONLY:
        return False, "queue_status is not approved_for_draft_only"
    if normalize_risk(item.get("risk_classification")) != RISK_LOW:
        return False, "risk_classification is not LOW"
    if item.get("apply_status") != APPLY_NOT_APPLIED:
        return False, "apply_status is not not_applied"
    return True, "LOW approved_for_draft_only item with apply_status=not_applied"


def base_plan_item(item: Dict[str, Any], draft_type: str, reason: str) -> Dict[str, Any]:
    roadmap_id = redact_text(item.get("roadmap_id"), max_len=160)
    return {
        "execution_id": f"draft_exec:{slug(roadmap_id)}",
        "queue_id": redact_text(item.get("queue_id"), max_len=160),
        "source": redact_text(item.get("source"), max_len=120),
        "title": redact_text(item.get("title"), max_len=200),
        "draft_type": draft_type,
        "manual_steps": [],
        "copy_paste_payload": None,
        "validation_steps": [],
        "rollback_note": "Discard the manual draft/checklist entry; Sentinel made no live change.",
        "risk_classification": RISK_LOW,
        "apply_status": APPLY_NOT_APPLIED,
        "owner_review_required": False,
        "reason": redact_text(reason, max_len=700),
    }


def seo_proposal_id(roadmap_id: str) -> str:
    if ":" in roadmap_id:
        return roadmap_id.split(":", 1)[1]
    return roadmap_id


def seo_title_plan(item: Dict[str, Any], meta: Optional[Any], reason: str) -> Dict[str, Any]:
    plan = base_plan_item(item, "seo_title_draft", reason)
    improved = meta.get("improved", {}) if isinstance(meta, dict) else {}
    current = meta.get("current", {}) if isinstance(meta, dict) else {}
    value = improved.get("title")
    plan["manual_steps"] = [
        "Copy this title into the owner-controlled SEO draft checklist only.",
        "Keep the current title nearby for comparison.",
        "Do not publish or write CMS data from Sentinel.",
    ]
    plan["copy_paste_payload"] = sanitize_value(
        {
            "field": "homepage_title",
            "current_value": current.get("title"),
            "proposed_value": value,
        }
    )
    plan["validation_steps"] = [
        "Confirm the proposed title is present and non-empty.",
        "Confirm approximate title length is 60 characters or less.",
        "Confirm brand spelling is Electri_C_ity Studios.",
    ]
    return plan


def seo_meta_description_plan(item: Dict[str, Any], meta: Optional[Any], reason: str) -> Dict[str, Any]:
    plan = base_plan_item(item, "seo_meta_description_draft", reason)
    improved = meta.get("improved", {}) if isinstance(meta, dict) else {}
    current = meta.get("current", {}) if isinstance(meta, dict) else {}
    plan["manual_steps"] = [
        "Copy this description into the owner-controlled SEO draft checklist only.",
        "Review wording for factual accuracy before any future manual publication.",
        "Do not publish or write CMS data from Sentinel.",
    ]
    plan["copy_paste_payload"] = sanitize_value(
        {
            "field": "homepage_meta_description",
            "current_value": current.get("meta_description"),
            "proposed_value": improved.get("meta_description"),
        }
    )
    plan["validation_steps"] = [
        "Confirm the description is approximately 140-160 characters when possible.",
        "Confirm it avoids keyword stuffing.",
        "Confirm it accurately mentions AI electro radio, digital tools, cover art, and releases.",
    ]
    return plan


def social_plan(item: Dict[str, Any], social: Optional[Any], proposal_id: str, reason: str) -> Dict[str, Any]:
    is_twitter = proposal_id == "twitter_cards"
    draft_type = "twitter_card_draft" if is_twitter else "open_graph_draft"
    plan = base_plan_item(item, draft_type, reason)
    current_key = "current_twitter_cards" if is_twitter else "current_open_graph"
    recommended_key = "recommended_twitter_cards" if is_twitter else "recommended_open_graph"
    label = "Twitter Card" if is_twitter else "OpenGraph"
    current = social.get(current_key, {}) if isinstance(social, dict) else {}
    recommended = social.get(recommended_key, {}) if isinstance(social, dict) else {}
    plan["manual_steps"] = [
        f"Copy the recommended {label} values into the owner-controlled social metadata draft checklist.",
        "Keep this as draft guidance only; Sentinel does not write metadata.",
        "Preserve any existing image field unless separately reviewed.",
    ]
    plan["copy_paste_payload"] = sanitize_value(
        {
            "metadata_type": label,
            "current_value": current,
            "proposed_value": recommended,
        }
    )
    plan["validation_steps"] = [
        "Confirm required social preview fields are non-empty.",
        "Confirm URL remains the primary homepage URL.",
        "Confirm wording matches the Title/Meta draft.",
    ]
    return plan


def internal_link_plan(
    item: Dict[str, Any],
    proposal: Optional[Dict[str, Any]],
    reason: str,
) -> Dict[str, Any]:
    plan = base_plan_item(item, "internal_link_draft", reason)
    proposed = proposal.get("proposed_value", {}) if isinstance(proposal, dict) else {}
    plan["manual_steps"] = [
        "Copy this link suggestion into the owner-controlled editorial checklist only.",
        "Use it only where the surrounding homepage copy naturally supports the link.",
        "Do not create pages or links from Sentinel.",
    ]
    plan["copy_paste_payload"] = sanitize_value(
        {
            "target": proposed.get("target") if isinstance(proposed, dict) else None,
            "anchor": proposed.get("anchor") if isinstance(proposed, dict) else None,
            "existence_basis": "found in homepage or sitemap snapshot",
        }
    )
    plan["validation_steps"] = [
        "Confirm the target was found in the homepage or sitemap snapshot.",
        "Confirm anchor text is natural and not keyword-stuffed.",
        "Confirm the link would be contextual, not a sitewide forced insert.",
    ]
    return plan


def schema_plan(item: Dict[str, Any], schema: Optional[Any], reason: str) -> Dict[str, Any]:
    plan = base_plan_item(item, "schema_jsonld_draft", reason)
    plan["manual_steps"] = [
        "Copy this JSON-LD only into an owner-controlled schema review document.",
        "Validate entity claims against visible page content before any future publication.",
        "Do not inject schema from Sentinel.",
    ]
    plan["copy_paste_payload"] = sanitize_value(schema if isinstance(schema, dict) else {})
    plan["validation_steps"] = [
        "Confirm @context and @graph are present.",
        "Confirm WebSite, Organization, RadioStation, MusicGroup, and CreativeWork claims are factual.",
        "Confirm no schema value contains credentials, private contact data, or unverified claims.",
    ]
    return plan


def performance_checklist_plan(
    item: Dict[str, Any],
    proposal: Optional[Dict[str, Any]],
    draft_type: str,
    reason: str,
) -> Dict[str, Any]:
    plan = base_plan_item(item, draft_type, reason)
    title = redact_text(item.get("title"), max_len=200)
    proposal_reason = redact_text(proposal.get("reason") if isinstance(proposal, dict) else reason, max_len=700)
    if draft_type == "image_webp_status_check":
        checklist = [
            "Confirm current homepage image formats are already modern where detected.",
            "Do not convert images from this planner.",
            "If future legacy images appear, create a separate reviewed image optimization draft.",
        ]
    elif draft_type == "image_width_height_check":
        checklist = [
            "Confirm detected homepage images have width and height attributes where applicable.",
            "Do not edit image markup from this planner.",
            "If future missing dimensions appear, prepare a separate manual markup draft.",
        ]
    elif draft_type == "lazy_loading_checklist":
        checklist = [
            "Identify below-the-fold images only in a manual draft review.",
            "Use loading=\"lazy\" only where the owner confirms it will not affect above-the-fold rendering.",
            "Do not edit markup from this planner.",
        ]
    else:
        checklist = ["Review this LOW performance item manually; Sentinel performs no edit."]
    plan["manual_steps"] = [
        "Copy the checklist into the owner-controlled performance draft notes.",
        "Use it as manual verification only.",
        "Do not change WordPress, Nginx, Cloudflare, or assets from Sentinel.",
    ]
    plan["copy_paste_payload"] = sanitize_value(
        {
            "check_title": title,
            "checklist": checklist,
            "source_reason": proposal_reason,
        }
    )
    plan["validation_steps"] = [
        "Confirm this is a checklist-only item.",
        "Confirm no file path or production configuration is changed.",
        "Confirm apply_status remains not_applied.",
    ]
    return plan


def generic_low_plan(item: Dict[str, Any], reason: str) -> Dict[str, Any]:
    plan = base_plan_item(item, "manual_draft_checklist", reason)
    plan["manual_steps"] = [
        "Create a manual draft note for this LOW approved queue item.",
        "Use the queue title and reason as context only.",
        "Do not perform a live change from Sentinel.",
    ]
    plan["copy_paste_payload"] = sanitize_value(
        {
            "queue_id": item.get("queue_id"),
            "title": item.get("title"),
            "reason": reason,
        }
    )
    plan["validation_steps"] = [
        "Confirm this item is LOW and approved_for_draft_only.",
        "Confirm no Apply function is involved.",
        "Confirm owner-facing draft stays not_applied.",
    ]
    return plan


def plan_for_item(
    item: Dict[str, Any],
    context: Dict[str, Any],
    roadmap_by_id: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    roadmap_id = str(item.get("roadmap_id", ""))
    proposal_id = seo_proposal_id(roadmap_id)
    roadmap_reason = roadmap_by_id.get(roadmap_id, {}).get("reason")
    reason = str(roadmap_reason or item.get("reason") or "LOW draft-only queue item.")

    if proposal_id == "title":
        return seo_title_plan(item, context.get("seo_meta"), reason)
    if proposal_id == "meta_description":
        return seo_meta_description_plan(item, context.get("seo_meta"), reason)
    if proposal_id in {"open_graph", "twitter_cards"}:
        return social_plan(item, context.get("seo_social"), proposal_id, reason)
    if proposal_id.startswith("internal_link_"):
        proposal = context.get("seo_editorial_by_id", {}).get(proposal_id)
        return internal_link_plan(item, proposal, reason)
    if proposal_id == "schema":
        return schema_plan(item, context.get("seo_schema"), reason)

    title_slug = slug(item.get("title"))
    perf_proposal = context.get("performance_by_title", {}).get(title_slug)
    if "webp" in roadmap_id or "format" in title_slug or "optimization" in title_slug:
        return performance_checklist_plan(item, perf_proposal, "image_webp_status_check", reason)
    if "width" in roadmap_id or "height" in roadmap_id or "dimension" in title_slug:
        return performance_checklist_plan(item, perf_proposal, "image_width_height_check", reason)
    if "lazy" in roadmap_id or "lazy" in title_slug:
        return performance_checklist_plan(item, perf_proposal, "lazy_loading_checklist", reason)

    return generic_low_plan(item, reason)


def make_excluded_item(item: Dict[str, Any], reason: str) -> Dict[str, Any]:
    safe = queue_item_safe(item)
    safe["excluded_reason"] = redact_text(reason, max_len=400)
    safe["apply_status"] = redact_text(item.get("apply_status"), max_len=80)
    return safe


def load_context() -> Tuple[Dict[str, Any], Dict[str, str]]:
    inputs: Dict[str, str] = {}
    context: Dict[str, Any] = {}

    for key, path in (
        ("approval_queue", INPUT_APPROVAL_QUEUE),
        ("seo_meta", INPUT_SEO_META),
        ("seo_social", INPUT_SEO_SOCIAL),
        ("seo_schema", INPUT_SEO_SCHEMA),
        ("seo_editorial", INPUT_SEO_EDITORIAL),
        ("performance_review", INPUT_PERFORMANCE_REVIEW),
        ("roadmap_report", INPUT_ROADMAP_REPORT),
        ("autonomy_policy", INPUT_AUTONOMY_POLICY),
    ):
        data, status = read_optional_json(path)
        inputs[key] = status
        context[key] = data

    context["seo_editorial_by_id"] = proposals_by_id(context.get("seo_editorial"))
    context["performance_by_title"] = performance_proposals_by_title(context.get("performance_review"))
    context["roadmap_by_id"] = roadmap_items_from(context.get("roadmap_report"))
    return context, inputs


def build_plan(
    queue_data: Optional[Any],
    queue_status: str,
    context: Dict[str, Any],
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    queue_items = queue_items_from(queue_data)
    roadmap_by_id = context.get("roadmap_by_id") if isinstance(context.get("roadmap_by_id"), dict) else {}
    execution_items: List[Dict[str, Any]] = []
    excluded_items: List[Dict[str, Any]] = []

    for item in queue_items:
        eligible, reason = eligibility_reason(item)
        if eligible:
            planned = plan_for_item(item, context, roadmap_by_id)
            planned["queue_filter_reason"] = reason
            execution_items.append(planned)
        else:
            excluded_items.append(make_excluded_item(item, reason))

    not_applied_count = len([i for i in execution_items if i.get("apply_status") == APPLY_NOT_APPLIED])
    other_apply_status_count = len(execution_items) - not_applied_count
    high_included_count = len([i for i in execution_items if i.get("risk_classification") == RISK_HIGH])
    ready_for_manual_copy_count = len([i for i in execution_items if i.get("copy_paste_payload") is not None])
    planner_breach = other_apply_status_count > 0 or high_included_count > 0

    status = "NOT_AVAILABLE" if queue_status != "ok" else "READY_FOR_MANUAL_DRAFT"
    if queue_status == "ok" and not execution_items:
        status = "NO_ELIGIBLE_DRAFT_ITEMS"
    if planner_breach:
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
        "queue_filter": {
            "required_queue_status": QUEUE_APPROVED_FOR_DRAFT_ONLY,
            "required_risk_classification": RISK_LOW,
            "required_apply_status": APPLY_NOT_APPLIED,
        },
        "queue_items_count": len(queue_items),
        "execution_items_count": len(execution_items),
        "excluded_items_count": len(excluded_items),
        "ready_for_manual_copy_count": ready_for_manual_copy_count,
        "high_included_count": high_included_count,
        "planner_breach": planner_breach,
        "apply_status_summary": {
            "not_applied_count": not_applied_count,
            "other_apply_status_count": other_apply_status_count,
            "all_not_applied": other_apply_status_count == 0,
        },
        "execution_items": execution_items,
        "excluded_items": excluded_items,
        "safety_notes": [
            "No live changes.",
            "No WordPress, .htaccess, Cloudflare, Nginx, API, network, or CMS write.",
            "All generated execution items stay apply_status=not_applied.",
            "copy_paste_payload is manual draft material only.",
            "MEDIUM, HIGH, and REVIEW_ONLY items are excluded from execution planning.",
        ],
        "outputs": {
            "draft_plan_md": str(DRAFT_PLAN_MD),
            "draft_plan_json": str(DRAFT_PLAN_JSON),
            "report_md": str(REPORT_MD),
            "report_json": str(REPORT_JSON),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(plan: Dict[str, Any]) -> str:
    lines: List[str] = [
        "# Draft Execution Plan",
        "",
        f"- Generated (UTC): `{redact_text(plan.get('generated_at_utc'))}`",
        f"- Status: `{redact_text(plan.get('status'))}`",
        f"- Execution items: `{plan.get('execution_items_count')}`",
        f"- Excluded items: `{plan.get('excluded_items_count')}`",
        f"- Ready for manual copy: `{plan.get('ready_for_manual_copy_count')}`",
        f"- Planner breach: `{str(bool(plan.get('planner_breach'))).lower()}`",
        f"- Apply status: `{redact_text(plan.get('apply_status'))}`",
        "",
        "## Safety",
        "",
    ]
    for note in plan.get("safety_notes", []):
        lines.append(f"- {redact_text(note)}")
    lines.extend(
        [
            "",
            "## Execution Items",
            "",
        ]
    )
    execution_items = plan.get("execution_items") if isinstance(plan.get("execution_items"), list) else []
    if not execution_items:
        lines.append("- (none)")
        lines.append("")
    for item in execution_items:
        if not isinstance(item, dict):
            continue
        lines.extend(
            [
                f"### `{redact_text(item.get('execution_id'))}`",
                "",
                f"- Queue ID: `{redact_text(item.get('queue_id'))}`",
                f"- Source: `{redact_text(item.get('source'))}`",
                f"- Title: {redact_text(item.get('title'))}",
                f"- Draft type: `{redact_text(item.get('draft_type'))}`",
                f"- Risk: `{redact_text(item.get('risk_classification'))}`",
                f"- Apply status: `{redact_text(item.get('apply_status'))}`",
                f"- Owner review required: `{str(bool(item.get('owner_review_required'))).lower()}`",
                f"- Reason: {redact_text(item.get('reason'))}",
                "",
                "**Manual steps:**",
                "",
            ]
        )
        for step in item.get("manual_steps", []):
            lines.append(f"- {redact_text(step)}")
        payload = item.get("copy_paste_payload")
        if payload is not None:
            lines.extend(
                [
                    "",
                    "**Copy/paste payload:**",
                    "",
                    "```json",
                    json.dumps(sanitize_value(payload), ensure_ascii=False, indent=2, sort_keys=True),
                    "```",
                ]
            )
        lines.extend(["", "**Validation steps:**", ""])
        for step in item.get("validation_steps", []):
            lines.append(f"- {redact_text(step)}")
        lines.extend(["", f"Rollback note: {redact_text(item.get('rollback_note'))}", ""])

    lines.extend(["## Excluded Items", ""])
    excluded = plan.get("excluded_items") if isinstance(plan.get("excluded_items"), list) else []
    if not excluded:
        lines.append("- (none)")
    else:
        lines.append("| Queue ID | Risk | Queue Status | Apply Status | Reason |")
        lines.append("|---|---|---|---|---|")
        for item in excluded:
            if not isinstance(item, dict):
                continue
            reason = redact_text(item.get("excluded_reason"), max_len=300).replace("|", "\\|")
            lines.append(
                f"| `{redact_text(item.get('queue_id'))}` | `{redact_text(item.get('risk_classification'))}` | "
                f"`{redact_text(item.get('queue_status'))}` | `{redact_text(item.get('apply_status'))}` | {reason} |"
            )
    lines.append("")
    return "\n".join(lines)


def build_audit_records(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = [
        {
            "timestamp_utc": plan.get("generated_at_utc"),
            "schema_version": SCHEMA_VERSION,
            "event": "draft_execution_planner_summary",
            "status": plan.get("status"),
            "execution_items_count": plan.get("execution_items_count"),
            "excluded_items_count": plan.get("excluded_items_count"),
            "ready_for_manual_copy_count": plan.get("ready_for_manual_copy_count"),
            "planner_breach": bool(plan.get("planner_breach")),
            "apply_status_summary": plan.get("apply_status_summary"),
        }
    ]
    for item in plan.get("execution_items", []):
        if not isinstance(item, dict):
            continue
        records.append(
            {
                "timestamp_utc": plan.get("generated_at_utc"),
                "schema_version": SCHEMA_VERSION,
                "event": "draft_execution_item",
                "execution_id": item.get("execution_id"),
                "queue_id": item.get("queue_id"),
                "draft_type": item.get("draft_type"),
                "risk_classification": item.get("risk_classification"),
                "apply_status": item.get("apply_status"),
            }
        )
    return records


def build_from_files() -> Dict[str, Any]:
    context, input_statuses = load_context()
    queue_data = context.get("approval_queue")
    queue_status = input_statuses.get("approval_queue", "not_available")
    return build_plan(queue_data, queue_status, context, input_statuses)


def run_self_tests() -> int:
    assert_allowed_write(DRAFT_PLAN_JSON)
    assert_allowed_write(REPORT_JSON)
    assert_allowed_write(AUDIT_JSONL)
    try:
        assert_allowed_write(PROJECT_DIR / "drafts/seo/not-allowed.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")

    assert redact_text("token=abc123") == "[redacted]"

    queue = {
        "queue_items": [
            {
                "queue_id": "approval:seo:title",
                "roadmap_id": "seo:title",
                "source": "seo_editorial_review",
                "title": "Title: improve",
                "risk_classification": "LOW",
                "queue_status": "approved_for_draft_only",
                "apply_status": "not_applied",
            },
            {
                "queue_id": "approval:seo:meta_description",
                "roadmap_id": "seo:meta_description",
                "source": "seo_editorial_review",
                "title": "Meta Description: improve",
                "risk_classification": "LOW",
                "queue_status": "approved_for_draft_only",
                "apply_status": "not_applied",
            },
            {
                "queue_id": "approval:perf:lazy",
                "roadmap_id": "perf:lazy-loading",
                "source": "performance_editorial_review",
                "title": "Add lazy loading to below-the-fold images",
                "risk_classification": "MEDIUM",
                "queue_status": "approved_for_draft_only",
                "apply_status": "not_applied",
            },
            {
                "queue_id": "approval:seo:schema",
                "roadmap_id": "seo:schema",
                "source": "seo_editorial_review",
                "title": "Schema",
                "risk_classification": "REVIEW_ONLY",
                "queue_status": "pending_owner_review",
                "apply_status": "not_applied",
            },
            {
                "queue_id": "approval:perf:high",
                "roadmap_id": "perf:origin",
                "source": "performance_editorial_review",
                "title": "Origin 5xx posture",
                "risk_classification": "HIGH",
                "queue_status": "blocked_high_risk",
                "apply_status": "not_applied",
            },
            {
                "queue_id": "approval:bad:applied",
                "roadmap_id": "bad:applied",
                "source": "test",
                "title": "Bad applied",
                "risk_classification": "LOW",
                "queue_status": "approved_for_draft_only",
                "apply_status": "applied",
            },
        ]
    }
    context = {
        "seo_meta": {
            "current": {"title": "Current", "meta_description": "Current description"},
            "improved": {"title": "Electri_C_ity Studios | 24/7 AI Electro Radio", "meta_description": "Safe draft description."},
        },
        "seo_social": {},
        "seo_schema": {"@context": "https://schema.org", "@graph": []},
        "seo_editorial_by_id": {},
        "performance_by_title": {},
        "roadmap_by_id": {
            "seo:title": {"reason": "Title is LOW."},
            "seo:meta_description": {"reason": "Meta is LOW."},
        },
    }
    statuses = {"approval_queue": "ok"}
    plan = build_plan(queue, "ok", context, statuses, generated_at="T")
    assert plan["execution_items_count"] == 2
    assert plan["excluded_items_count"] == 4
    assert plan["ready_for_manual_copy_count"] == 2
    assert plan["planner_breach"] is False
    assert plan["apply_status_summary"]["all_not_applied"] is True
    assert all(item["apply_status"] == "not_applied" for item in plan["execution_items"])
    assert all(item["risk_classification"] == "LOW" for item in plan["execution_items"])
    assert any(item["queue_id"] == "approval:perf:lazy" for item in plan["excluded_items"])
    assert any(item["queue_id"] == "approval:seo:schema" for item in plan["excluded_items"])
    md = render_markdown(plan)
    assert "Draft Execution Plan" in md
    assert "[redacted]" not in json.dumps(plan)

    missing = build_plan(None, "not_available", {}, {"approval_queue": "not_available"}, generated_at="T")
    assert missing["status"] == "NOT_AVAILABLE"
    assert missing["execution_items"] == []
    assert missing["excluded_items"] == []
    assert missing["apply_status_summary"]["all_not_applied"] is True

    print("draft-execution-planner self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Draft Execution Planner (read-only; no apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety/unit tests.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()

    plan = build_from_files()
    markdown = render_markdown(plan)
    write_json_atomic(DRAFT_PLAN_JSON, plan)
    write_text_atomic(DRAFT_PLAN_MD, markdown)
    write_json_atomic(REPORT_JSON, plan)
    write_text_atomic(REPORT_MD, markdown)
    append_jsonl(AUDIT_JSONL, build_audit_records(plan))
    print(f"Draft execution plan written: {DRAFT_PLAN_MD}")
    print(f"Draft execution plan JSON written: {DRAFT_PLAN_JSON}")
    print(f"Draft execution report written: {REPORT_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
