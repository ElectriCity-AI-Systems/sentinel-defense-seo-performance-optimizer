#!/usr/bin/env python3
"""Sentinel Manual Apply Checklist (Phase 2.5).

Builds a manual owner checklist from the Owner Review Pack. Despite the name,
this module never applies anything: no WordPress login, no browser automation,
no API calls, no network access, and no production writes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

# Optional local inputs only.
INPUT_REVIEW_PACK = PROJECT_DIR / "drafts/review/owner-review-pack.json"
INPUT_REVIEW_PACK_REPORT = PROJECT_DIR / "reports/latest/owner-review-pack-report.json"
INPUT_MASTER_REPORT = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

# Outputs.
MANUAL_DIR = PROJECT_DIR / "drafts/manual"
CHECKLIST_MD = MANUAL_DIR / "manual-apply-checklist.md"
CHECKLIST_JSON = MANUAL_DIR / "manual-apply-checklist.json"
REPORT_MD = PROJECT_DIR / "reports/latest/manual-apply-checklist-report.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/manual-apply-checklist-report.json"
AUDIT_JSONL = PROJECT_DIR / "audit/manual-apply-checklist.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/manual",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "manual-apply-checklist-2.5"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"
APPLY_NOT_APPLIED = "not_applied"

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)

SECTION_LABELS = {
    "SEO Title": "SEO Title in Yoast/WordPress pruefen",
    "Meta Description": "Meta Description in Yoast/WordPress pruefen",
    "OpenGraph": "OpenGraph-Felder pruefen",
    "Twitter Cards": "Twitter Card-Felder pruefen",
    "Internal Link Draft": "Internen Link manuell pruefen",
    "Image/WebP Status": "Image/WebP-Status pruefen",
    "Image Width/Height Checklist": "Image Width/Height manuell pruefen",
}

SECTION_ORDER = {
    "SEO Title in Yoast/WordPress pruefen": 10,
    "Meta Description in Yoast/WordPress pruefen": 20,
    "OpenGraph-Felder pruefen": 30,
    "Twitter Card-Felder pruefen": 40,
    "Internen Link manuell pruefen": 50,
    "Image/WebP-Status pruefen": 60,
    "Image Width/Height manuell pruefen": 70,
}


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


def sanitize_value(value: Any, *, max_len: int = 2500) -> Any:
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
        raise ValueError(f"Refusing to write outside allowed manual checklist roots: {path}")


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


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY}:
        return risk
    return RISK_REVIEW_ONLY


def slug(value: Any) -> str:
    text = str(value or "unknown").lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "unknown"


def review_items_from(data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("review_items"), list):
        return []
    return [item for item in data["review_items"] if isinstance(item, dict)]


def excluded_items_from(data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("excluded_items"), list):
        return []
    return [item for item in data["excluded_items"] if isinstance(item, dict)]


def is_eligible(item: Dict[str, Any]) -> Tuple[bool, str]:
    if item.get("ready_for_copy") is not True:
        return False, "ready_for_copy is not true"
    if normalize_risk(item.get("risk_classification")) != RISK_LOW:
        return False, "risk_classification is not LOW"
    if item.get("apply_status") != APPLY_NOT_APPLIED:
        return False, "apply_status is not not_applied"
    return True, "LOW ready_for_copy item with apply_status=not_applied"


def checklist_section(section: Any) -> str:
    section_text = str(section or "")
    return SECTION_LABELS.get(section_text, "Manuellen Draft pruefen")


def manual_action_for(section: str) -> str:
    mapping = {
        "SEO Title in Yoast/WordPress pruefen": "Den vorgeschlagenen Homepage-Titel manuell in Yoast/WordPress pruefen, aber nicht durch Sentinel anwenden.",
        "Meta Description in Yoast/WordPress pruefen": "Die vorgeschlagene Meta Description manuell in Yoast/WordPress pruefen, aber nicht durch Sentinel anwenden.",
        "OpenGraph-Felder pruefen": "Die OpenGraph-Felder manuell mit den vorhandenen Social-Metadaten vergleichen.",
        "Twitter Card-Felder pruefen": "Die Twitter/X Card-Felder manuell mit den vorhandenen Social-Metadaten vergleichen.",
        "Internen Link manuell pruefen": "Den vorgeschlagenen internen Link manuell auf Kontext, Ziel und Anchor pruefen.",
        "Image/WebP-Status pruefen": "Den Bildformat-Status manuell als erledigt/weiter beobachten markieren; keine Asset-Konvertierung ausfuehren.",
        "Image Width/Height manuell pruefen": "Die Width/Height-Checkliste manuell pruefen; keine Markup-Aenderung ausfuehren.",
    }
    return mapping.get(section, "Dieses Item manuell pruefen; Sentinel fuehrt keine Aenderung aus.")


def manual_apply_steps_for(section: str) -> List[str]:
    common_start = [
        "Owner oeffnet das CMS/Tool manuell ausserhalb von Sentinel.",
        "Owner vergleicht Current Value und Proposed Payload.",
        "Owner entscheidet manuell; Sentinel bleibt not_applied.",
    ]
    mapping = {
        "SEO Title in Yoast/WordPress pruefen": [
            "In Yoast/WordPress das Homepage-SEO-Title-Feld suchen.",
            "Vorschlag nur nach Owner-Freigabe manuell uebernehmen.",
            "Nicht aus Sentinel heraus speichern oder publizieren.",
        ],
        "Meta Description in Yoast/WordPress pruefen": [
            "In Yoast/WordPress das Homepage-Meta-Description-Feld suchen.",
            "Vorschlag auf Laenge, Genauigkeit und Ton pruefen.",
            "Nicht aus Sentinel heraus speichern oder publizieren.",
        ],
        "OpenGraph-Felder pruefen": [
            "Social/OpenGraph-Einstellungen fuer die Homepage manuell oeffnen.",
            "Textfelder gegen den Payload vergleichen; bestehende Bildfelder separat pruefen.",
            "Nicht aus Sentinel heraus speichern oder publizieren.",
        ],
        "Twitter Card-Felder pruefen": [
            "Twitter/X Card-Einstellungen fuer die Homepage manuell oeffnen.",
            "Textfelder gegen den Payload vergleichen; bestehende Bildfelder separat pruefen.",
            "Nicht aus Sentinel heraus speichern oder publizieren.",
        ],
        "Internen Link manuell pruefen": [
            "Homepage-Abschnitt manuell bestimmen, in dem der Link natuerlich passt.",
            "Anchor und Ziel mit dem Payload vergleichen.",
            "Keinen Link einfuegen, wenn Ziel oder Kontext unsicher ist.",
        ],
        "Image/WebP-Status pruefen": [
            "Performance-Notizen manuell oeffnen.",
            "Statuscheck aus dem Payload uebernehmen, falls Owner ihn bestaetigt.",
            "Keine Bilddatei konvertieren oder ersetzen.",
        ],
        "Image Width/Height manuell pruefen": [
            "Performance-Notizen manuell oeffnen.",
            "Width/Height-Check aus dem Payload uebernehmen, falls Owner ihn bestaetigt.",
            "Kein Markup bearbeiten.",
        ],
    }
    return common_start + mapping.get(section, ["Manuell pruefen; keine automatische Aenderung."])


def make_checklist_item(item: Dict[str, Any]) -> Dict[str, Any]:
    section = checklist_section(item.get("section"))
    source_item_id = redact_text(item.get("item_id"), max_len=180)
    pre_check = item.get("pre_check") if isinstance(item.get("pre_check"), list) else []
    post_check = item.get("post_check") if isinstance(item.get("post_check"), list) else []
    return {
        "checklist_id": f"manual_check:{slug(source_item_id)}",
        "source_item_id": source_item_id,
        "section": section,
        "manual_action": manual_action_for(section),
        "copy_paste_payload": sanitize_value(item.get("copy_paste_payload")),
        "pre_check": [redact_text(step, max_len=900) for step in pre_check],
        "manual_apply_steps": manual_apply_steps_for(section),
        "post_check": [redact_text(step, max_len=900) for step in post_check],
        "rollback_note": redact_text(item.get("rollback_note"), max_len=700),
        "status_checkbox": "unchecked",
        "apply_status": APPLY_NOT_APPLIED,
        "risk_classification": RISK_LOW,
        "owner_decision_required": True,
        "ready_for_manual_apply_review": True,
        "source_title": redact_text(item.get("title"), max_len=240),
        "reason": redact_text(item.get("reason"), max_len=700),
    }


def make_excluded_item(item: Dict[str, Any], reason: str) -> Dict[str, Any]:
    return {
        "source_item_id": redact_text(item.get("item_id") or item.get("queue_id") or item.get("checklist_id"), max_len=180),
        "section": redact_text(item.get("section"), max_len=120),
        "title": redact_text(item.get("title"), max_len=240),
        "risk_classification": normalize_risk(item.get("risk_classification")),
        "apply_status": redact_text(item.get("apply_status"), max_len=80),
        "ready_for_copy": bool(item.get("ready_for_copy", False)),
        "excluded_reason": redact_text(reason or item.get("excluded_reason"), max_len=600),
    }


def build_checklist(
    review_pack: Optional[Any],
    review_pack_status: str,
    input_statuses: Dict[str, str],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    review_items = review_items_from(review_pack)
    inherited_excluded = excluded_items_from(review_pack)
    checklist_items: List[Dict[str, Any]] = []
    excluded_items: List[Dict[str, Any]] = []

    for item in review_items:
        eligible, reason = is_eligible(item)
        if eligible:
            checklist_items.append(make_checklist_item(item))
        else:
            excluded_items.append(make_excluded_item(item, reason))
    for item in inherited_excluded:
        excluded_items.append(make_excluded_item(item, item.get("excluded_reason", "excluded upstream by owner review pack")))

    checklist_items.sort(key=lambda item: (SECTION_ORDER.get(str(item.get("section")), 999), str(item.get("checklist_id"))))

    not_applied_count = len([item for item in checklist_items if item.get("apply_status") == APPLY_NOT_APPLIED])
    other_apply_status_count = len(checklist_items) - not_applied_count
    high_medium_included_count = len(
        [
            item for item in checklist_items
            if normalize_risk(item.get("risk_classification")) in {RISK_HIGH, RISK_MEDIUM}
        ]
    )
    review_only_included_count = len(
        [item for item in checklist_items if normalize_risk(item.get("risk_classification")) == RISK_REVIEW_ONLY]
    )
    productive_change = False
    checklist_breach = bool(productive_change) or other_apply_status_count > 0 or high_medium_included_count > 0 or review_only_included_count > 0

    status = "NOT_AVAILABLE" if review_pack_status != "ok" else "READY_FOR_MANUAL_APPLY_REVIEW"
    if review_pack_status == "ok" and not checklist_items:
        status = "NO_ELIGIBLE_MANUAL_ITEMS"
    if checklist_breach:
        status = "POLICY_BREACH"

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "read_only": True,
        "productive_change": productive_change,
        "network_access": False,
        "browser_automation": False,
        "wordpress_login": False,
        "api_access": False,
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
        "filter": {
            "ready_for_copy": True,
            "risk_classification": RISK_LOW,
            "apply_status": APPLY_NOT_APPLIED,
        },
        "checklist_items_count": len(checklist_items),
        "ready_for_manual_apply_review_count": len(checklist_items),
        "excluded_count": len(excluded_items),
        "high_medium_included_count": high_medium_included_count,
        "review_only_included_count": review_only_included_count,
        "checklist_breach": checklist_breach,
        "apply_status_summary": {
            "all_not_applied": other_apply_status_count == 0,
            "not_applied_count": not_applied_count,
            "other_apply_status_count": other_apply_status_count,
        },
        "checklist_items": checklist_items,
        "excluded_items": excluded_items,
        "safety_notes": [
            "No live changes.",
            "No WordPress login, no browser automation, no API call, no network access, and no production write.",
            "This is a manual owner checklist only.",
            "HIGH, MEDIUM, and REVIEW_ONLY items are excluded.",
            "All checklist items remain apply_status=not_applied and status_checkbox=unchecked.",
        ],
        "outputs": {
            "checklist_md": str(CHECKLIST_MD),
            "checklist_json": str(CHECKLIST_JSON),
            "report_md": str(REPORT_MD),
            "report_json": str(REPORT_JSON),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def load_context() -> Tuple[Dict[str, Any], Dict[str, str]]:
    statuses: Dict[str, str] = {}
    context: Dict[str, Any] = {}
    review_pack, review_status = read_optional_json(INPUT_REVIEW_PACK)
    if review_status != "ok":
        report_pack, report_status = read_optional_json(INPUT_REVIEW_PACK_REPORT)
        if report_status == "ok":
            review_pack = report_pack
            review_status = "ok"
        statuses["owner_review_pack_report"] = report_status
    else:
        statuses["owner_review_pack_report"] = "not_used"
    statuses["owner_review_pack"] = review_status
    master, master_status = read_optional_json(INPUT_MASTER_REPORT)
    context["owner_review_pack"] = review_pack
    context["sentinel_master"] = master
    statuses["sentinel_master"] = master_status
    return context, statuses


def render_markdown(checklist: Dict[str, Any]) -> str:
    lines: List[str] = [
        "# Manual Apply Checklist",
        "",
        f"- Generated (UTC): `{redact_text(checklist.get('generated_at_utc'))}`",
        f"- Status: `{redact_text(checklist.get('status'))}`",
        f"- Checklist items: `{checklist.get('checklist_items_count')}`",
        f"- Ready for manual apply review: `{checklist.get('ready_for_manual_apply_review_count')}`",
        f"- Excluded: `{checklist.get('excluded_count')}`",
        f"- High/Medium included: `{checklist.get('high_medium_included_count')}`",
        f"- Checklist breach: `{str(bool(checklist.get('checklist_breach'))).lower()}`",
        f"- Apply status: `{redact_text(checklist.get('apply_status'))}`",
        "",
        "## Safety",
        "",
    ]
    for note in checklist.get("safety_notes", []):
        lines.append(f"- {redact_text(note)}")
    lines.append("")

    items = checklist.get("checklist_items") if isinstance(checklist.get("checklist_items"), list) else []
    if not items:
        lines.extend(["## Checklist Items", "", "- (none)", ""])
    current_section = None
    for item in items:
        if not isinstance(item, dict):
            continue
        section = str(item.get("section", "Manual Item"))
        if section != current_section:
            lines.extend([f"## {redact_text(section)}", ""])
            current_section = section
        lines.extend(
            [
                f"### [ ] `{redact_text(item.get('checklist_id'))}`",
                "",
                f"- Source item: `{redact_text(item.get('source_item_id'))}`",
                f"- Manual action: {redact_text(item.get('manual_action'), max_len=1000)}",
                f"- Risk: `{redact_text(item.get('risk_classification'))}`",
                f"- Apply status: `{redact_text(item.get('apply_status'))}`",
                f"- Status checkbox: `{redact_text(item.get('status_checkbox'))}`",
                f"- Owner decision required: `{str(bool(item.get('owner_decision_required'))).lower()}`",
                "",
                "**Copy-paste payload:**",
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
        lines.extend(["", "**Manual apply review steps:**", ""])
        for step in item.get("manual_apply_steps", []):
            lines.append(f"- {redact_text(step)}")
        lines.extend(["", "**Post-check:**", ""])
        for step in item.get("post_check", []):
            lines.append(f"- {redact_text(step)}")
        lines.extend(["", f"Rollback note: {redact_text(item.get('rollback_note'))}", ""])

    lines.extend(["## Excluded Items", ""])
    excluded = checklist.get("excluded_items") if isinstance(checklist.get("excluded_items"), list) else []
    if not excluded:
        lines.append("- (none)")
    else:
        lines.append("| Source item | Risk | Apply | Ready for copy | Reason |")
        lines.append("|---|---|---|---|---|")
        for item in excluded:
            if not isinstance(item, dict):
                continue
            reason = redact_text(item.get("excluded_reason"), max_len=300).replace("|", "\\|")
            lines.append(
                f"| `{redact_text(item.get('source_item_id'))}` | `{redact_text(item.get('risk_classification'))}` | "
                f"`{redact_text(item.get('apply_status'))}` | `{str(bool(item.get('ready_for_copy'))).lower()}` | {reason} |"
            )
    lines.append("")
    return "\n".join(lines)


def build_audit_records(checklist: Dict[str, Any]) -> List[Dict[str, Any]]:
    records = [
        {
            "timestamp_utc": checklist.get("generated_at_utc"),
            "schema_version": SCHEMA_VERSION,
            "event": "manual_apply_checklist_summary",
            "status": checklist.get("status"),
            "checklist_items_count": checklist.get("checklist_items_count"),
            "ready_for_manual_apply_review_count": checklist.get("ready_for_manual_apply_review_count"),
            "excluded_count": checklist.get("excluded_count"),
            "high_medium_included_count": checklist.get("high_medium_included_count"),
            "checklist_breach": bool(checklist.get("checklist_breach")),
            "apply_status_summary": checklist.get("apply_status_summary"),
        }
    ]
    for item in checklist.get("checklist_items", []):
        if not isinstance(item, dict):
            continue
        records.append(
            {
                "timestamp_utc": checklist.get("generated_at_utc"),
                "schema_version": SCHEMA_VERSION,
                "event": "manual_apply_checklist_item",
                "checklist_id": item.get("checklist_id"),
                "source_item_id": item.get("source_item_id"),
                "section": item.get("section"),
                "risk_classification": item.get("risk_classification"),
                "apply_status": item.get("apply_status"),
                "status_checkbox": item.get("status_checkbox"),
            }
        )
    return records


def build_from_files() -> Dict[str, Any]:
    context, statuses = load_context()
    return build_checklist(
        context.get("owner_review_pack"),
        statuses.get("owner_review_pack", "not_available"),
        statuses,
    )


def run_self_tests() -> int:
    assert_allowed_write(CHECKLIST_JSON)
    assert_allowed_write(REPORT_JSON)
    assert_allowed_write(AUDIT_JSONL)
    try:
        assert_allowed_write(PROJECT_DIR / "drafts/review/not-allowed.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")
    assert redact_text("api_key=abc123") == "[redacted]"

    pack = {
        "review_items": [
            {
                "item_id": "draft_exec:seo-title",
                "section": "SEO Title",
                "title": "Title: improve",
                "risk_classification": "LOW",
                "apply_status": "not_applied",
                "ready_for_copy": True,
                "copy_paste_payload": {"current_value": "Old", "proposed_value": "New"},
                "pre_check": ["pre"],
                "post_check": ["post"],
                "rollback_note": "Discard draft.",
                "reason": "LOW.",
            },
            {
                "item_id": "draft_exec:seo-meta",
                "section": "Meta Description",
                "title": "Meta",
                "risk_classification": "LOW",
                "apply_status": "not_applied",
                "ready_for_copy": True,
                "copy_paste_payload": {"current_value": "Old", "proposed_value": "New"},
            },
            {
                "item_id": "draft_exec:medium",
                "section": "SEO Title",
                "title": "Medium",
                "risk_classification": "MEDIUM",
                "apply_status": "not_applied",
                "ready_for_copy": True,
                "copy_paste_payload": {"proposed_value": "No"},
            },
            {
                "item_id": "draft_exec:review",
                "section": "SEO Title",
                "title": "Review only",
                "risk_classification": "REVIEW_ONLY",
                "apply_status": "not_applied",
                "ready_for_copy": True,
                "copy_paste_payload": {"proposed_value": "No"},
            },
            {
                "item_id": "draft_exec:applied",
                "section": "SEO Title",
                "title": "Applied",
                "risk_classification": "LOW",
                "apply_status": "applied",
                "ready_for_copy": True,
                "copy_paste_payload": {"proposed_value": "No"},
            },
        ],
        "excluded_items": [
            {
                "item_id": "upstream:high",
                "title": "High",
                "risk_classification": "HIGH",
                "apply_status": "not_applied",
                "ready_for_copy": False,
                "excluded_reason": "blocked",
            }
        ],
    }
    checklist = build_checklist(pack, "ok", {"owner_review_pack": "ok"}, generated_at="T")
    assert checklist["checklist_items_count"] == 2
    assert checklist["ready_for_manual_apply_review_count"] == 2
    assert checklist["excluded_count"] == 4
    assert checklist["high_medium_included_count"] == 0
    assert checklist["review_only_included_count"] == 0
    assert checklist["checklist_breach"] is False
    assert checklist["apply_status_summary"]["all_not_applied"] is True
    assert all(item["apply_status"] == "not_applied" for item in checklist["checklist_items"])
    assert all(item["risk_classification"] == "LOW" for item in checklist["checklist_items"])
    assert all(item["status_checkbox"] == "unchecked" for item in checklist["checklist_items"])
    md = render_markdown(checklist)
    assert "Manual Apply Checklist" in md

    missing = build_checklist(None, "not_available", {"owner_review_pack": "not_available"}, generated_at="T")
    assert missing["status"] == "NOT_AVAILABLE"
    assert missing["checklist_items_count"] == 0
    assert missing["excluded_count"] == 0
    assert missing["apply_status_summary"]["all_not_applied"] is True

    print("manual-apply-checklist self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Manual Apply Checklist (read-only; no apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety/unit tests.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()

    checklist = build_from_files()
    markdown = render_markdown(checklist)
    write_json_atomic(CHECKLIST_JSON, checklist)
    write_text_atomic(CHECKLIST_MD, markdown)
    write_json_atomic(REPORT_JSON, checklist)
    write_text_atomic(REPORT_MD, markdown)
    append_jsonl(AUDIT_JSONL, build_audit_records(checklist))
    print(f"Manual apply checklist written: {CHECKLIST_MD}")
    print(f"Manual apply checklist JSON written: {CHECKLIST_JSON}")
    print(f"Manual apply checklist report written: {REPORT_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
