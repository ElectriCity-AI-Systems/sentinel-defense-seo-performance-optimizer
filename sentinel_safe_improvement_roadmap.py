#!/usr/bin/env python3
"""Sentinel Safe Improvement Roadmap (Phase 1.9).

Merges the existing read-only SEO and Performance reviews into one prioritized,
safe improvement roadmap. It changes nothing live.

Hard safety guarantees (enforced structurally):
  * No live changes; no WordPress/.htaccess/Cloudflare/Nginx edits.
  * No external/network access — local files only (no network imports).
  * No secrets/cookies/authorization values are stored or emitted.
  * No apply function; every roadmap item stays apply_status=not_applied.
  * Writes only ever under:
        /srv/sentinel-defense/reports/latest
        /srv/sentinel-defense/drafts/roadmap
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

# --- Output targets ---------------------------------------------------------
REPORT_MD = PROJECT_DIR / "reports/latest/safe-improvement-roadmap-report.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/safe-improvement-roadmap-report.json"
DRAFT_DIR = PROJECT_DIR / "drafts/roadmap"
DRAFT_MD = DRAFT_DIR / "safe-improvement-roadmap.md"
DRAFT_JSON = DRAFT_DIR / "safe-improvement-roadmap.json"

# --- Optional inputs (must never crash when missing) ------------------------
INPUT_SEO_EDITORIAL = PROJECT_DIR / "drafts/seo/homepage-editorial-review.json"
INPUT_PERF_EDITORIAL = PROJECT_DIR / "drafts/performance/performance-editorial-review.json"
INPUT_SEO_OPTIMIZER = PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.json"
INPUT_PERF_AUDIT = PROJECT_DIR / "reports/latest/performance-safe-audit-report.json"
INPUT_AUTONOMY_POLICY = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"
INPUT_MASTER_REPORT = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

# --- Allowed write roots (the only paths this module may ever write) --------
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/roadmap",
)

SCHEMA_VERSION = "safe-improvement-roadmap-1.9"

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)

# Risk classes.
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

# Roadmap groups.
GROUP_NEXT_SAFE_DRAFTS = "NEXT_SAFE_DRAFTS"
GROUP_OWNER_REVIEW_REQUIRED = "OWNER_REVIEW_REQUIRED"
GROUP_BLOCKED_HIGH_RISK = "BLOCKED_HIGH_RISK"
GROUP_MONITOR_ONLY = "MONITOR_ONLY"

ALL_GROUPS = (
    GROUP_NEXT_SAFE_DRAFTS,
    GROUP_OWNER_REVIEW_REQUIRED,
    GROUP_MONITOR_ONLY,
    GROUP_BLOCKED_HIGH_RISK,
)

# Autonomy policy class per risk (aligned with sentinel_autonomy_policy.py).
AUTONOMY_CLASS_BY_RISK = {
    RISK_LOW: "LEVEL_1_DRAFT_ONLY",
    RISK_REVIEW_ONLY: "OWNER_APPROVAL_REQUIRED",
    RISK_MEDIUM: "OWNER_APPROVAL_REQUIRED",
    RISK_HIGH: "BLOCKED_NOT_PERMITTED",
}

# Impact areas.
AREA_SEO = "SEO"
AREA_PERFORMANCE = "Performance"
AREA_STABILITY = "Stability"
AREA_CONTENT = "Content"
AREA_TECHNICAL = "Technical"

# SEO category -> impact area.
SEO_AREA_BY_CATEGORY = {
    "title": AREA_SEO,
    "meta description": AREA_SEO,
    "opengraph": AREA_SEO,
    "twitter cards": AREA_SEO,
    "schema": AREA_SEO,
    "internal links": AREA_SEO,
    "content outline": AREA_CONTENT,
}

# Performance source id -> (impact area, monitor_only?).
PERF_AREA_BY_ID = {
    "perf-images-webp": (AREA_PERFORMANCE, False),
    "perf-lazy-loading": (AREA_PERFORMANCE, False),
    "perf-width-height": (AREA_PERFORMANCE, False),
    "perf-external-embeds": (AREA_PERFORMANCE, False),
    "perf-high-script-count": (AREA_TECHNICAL, False),
    "perf-cache-headers": (AREA_TECHNICAL, False),
    "perf-source-map": (AREA_TECHNICAL, False),
    "perf-ai-radio-microcache": (AREA_STABILITY, True),
    "perf-origin-5xx": (AREA_STABILITY, True),
}

RISK_ORDER = {RISK_LOW: 0, RISK_REVIEW_ONLY: 1, RISK_MEDIUM: 2, RISK_HIGH: 3}
GROUP_ORDER = {
    GROUP_NEXT_SAFE_DRAFTS: 0,
    GROUP_OWNER_REVIEW_REQUIRED: 1,
    GROUP_MONITOR_ONLY: 2,
    GROUP_BLOCKED_HIGH_RISK: 3,
}
BENEFIT_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


# ===========================================================================
# Safety helpers
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
            f"Refusing to write outside allowed roadmap roots: {path}"
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


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in (RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY):
        return risk
    # Unknown -> conservative.
    return RISK_HIGH


# ===========================================================================
# Roadmap item construction
# ===========================================================================
def benefit_weight(risk: str, group: str) -> str:
    if group == GROUP_MONITOR_ONLY:
        return "LOW"
    if risk == RISK_LOW:
        return "HIGH"  # safe and valuable
    if risk in (RISK_MEDIUM, RISK_REVIEW_ONLY):
        return "MEDIUM"
    return "HIGH"  # HIGH risk often high impact, but stays blocked


def decide_group(risk: str, monitor_only: bool) -> str:
    if monitor_only:
        return GROUP_MONITOR_ONLY
    if risk == RISK_HIGH:
        return GROUP_BLOCKED_HIGH_RISK
    if risk in (RISK_MEDIUM, RISK_REVIEW_ONLY):
        return GROUP_OWNER_REVIEW_REQUIRED
    return GROUP_NEXT_SAFE_DRAFTS  # LOW


def make_item(
    roadmap_id: str,
    source: str,
    title: str,
    impact_area: str,
    expected_benefit: str,
    risk: str,
    suggested_next_step: str,
    manual_review_required: bool,
    reason: str,
    monitor_only: bool = False,
) -> Dict[str, Any]:
    risk = normalize_risk(risk)
    group = decide_group(risk, monitor_only)
    # Hard safety: HIGH always blocked from autonomy and from apply.
    autonomy_class = AUTONOMY_CLASS_BY_RISK.get(risk, "BLOCKED_NOT_PERMITTED")
    if risk == RISK_HIGH:
        autonomy_class = "BLOCKED_NOT_PERMITTED"
    return {
        "roadmap_id": roadmap_id,
        "source": source,
        "title": redact_text(title, default="-", max_len=160),
        "impact_area": impact_area,
        "expected_benefit": redact_text(expected_benefit, default="-", max_len=200),
        "benefit_weight": benefit_weight(risk, group),
        "risk_classification": risk,
        "autonomy_policy_class": autonomy_class,
        "group": group,
        "suggested_next_step": redact_text(suggested_next_step, default="-", max_len=240),
        "manual_review_required": bool(manual_review_required),
        # Phase 1.9 is roadmap-only: nothing is ever apply-ready.
        "apply_status": "not_applied",
        "reason": redact_text(reason, default="-", max_len=300),
    }


def items_from_seo(seo_review: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(seo_review, dict):
        return []
    proposals = seo_review.get("proposals")
    if not isinstance(proposals, list):
        return []
    items: List[Dict[str, Any]] = []
    for p in proposals:
        if not isinstance(p, dict):
            continue
        proposal_id = str(p.get("proposal_id", "unknown"))
        category = str(p.get("category", "")).strip()
        recommendation = str(p.get("recommendation", "")).strip()
        risk = normalize_risk(p.get("risk_classification"))
        area = SEO_AREA_BY_CATEGORY.get(category.lower(), AREA_SEO)
        if recommendation == "improve":
            benefit = f"Improve {category} for clearer SEO/social signals."
            step = "Prepare draft and route to owner editorial review (no live change)."
        else:
            benefit = f"Clarify/validate {category} before any change."
            step = "Manual editorial/technical review before any change."
        items.append(make_item(
            roadmap_id=f"seo:{proposal_id}",
            source="seo_editorial_review",
            title=f"{category}: {recommendation or 'review'}",
            impact_area=area,
            expected_benefit=benefit,
            risk=risk,
            suggested_next_step=step,
            manual_review_required=bool(p.get("manual_review_required", True)),
            reason=p.get("reason", ""),
        ))
    return items


def items_from_performance(perf_review: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(perf_review, dict):
        return []
    proposals = perf_review.get("proposals")
    if not isinstance(proposals, list):
        return []
    items: List[Dict[str, Any]] = []
    for p in proposals:
        if not isinstance(p, dict):
            continue
        action_id = str(p.get("action_id", "unknown"))
        area, monitor_only = PERF_AREA_BY_ID.get(action_id, (AREA_PERFORMANCE, False))
        risk = normalize_risk(p.get("risk_classification"))
        step = p.get("proposed_improvement") or "Review only."
        if monitor_only:
            step = "Monitor only; no change." if action_id == "perf-ai-radio-microcache" else "Diagnostic only; no change."
        items.append(make_item(
            roadmap_id=f"perf:{action_id}",
            source="performance_editorial_review",
            title=str(p.get("title", action_id)),
            impact_area=area,
            expected_benefit=p.get("expected_benefit", "-"),
            risk=risk,
            suggested_next_step=step,
            manual_review_required=bool(p.get("manual_review_required", True)),
            reason=p.get("reason", ""),
            monitor_only=monitor_only,
        ))
    return items


def priority_key(item: Dict[str, Any]) -> Tuple[int, int, int, str]:
    return (
        GROUP_ORDER.get(item["group"], 9),
        BENEFIT_ORDER.get(item["benefit_weight"], 9),
        RISK_ORDER.get(item["risk_classification"], 9),
        item["roadmap_id"],
    )


# ===========================================================================
# Report assembly
# ===========================================================================
def collect_inputs() -> Dict[str, Any]:
    seo_review, seo_status = read_optional_json(INPUT_SEO_EDITORIAL)
    perf_review, perf_status = read_optional_json(INPUT_PERF_EDITORIAL)
    autonomy, autonomy_status = read_optional_json(INPUT_AUTONOMY_POLICY)
    master, master_status = read_optional_json(INPUT_MASTER_REPORT)
    seo_opt, seo_opt_status = read_optional_json(INPUT_SEO_OPTIMIZER)
    perf_audit, perf_audit_status = read_optional_json(INPUT_PERF_AUDIT)
    return {
        "seo_review": (seo_review if isinstance(seo_review, dict) else None, seo_status),
        "perf_review": (perf_review if isinstance(perf_review, dict) else None, perf_status),
        "autonomy": (autonomy if isinstance(autonomy, dict) else None, autonomy_status),
        "master": (master if isinstance(master, dict) else None, master_status),
        "seo_optimizer": (seo_opt if isinstance(seo_opt, dict) else None, seo_opt_status),
        "perf_audit": (perf_audit if isinstance(perf_audit, dict) else None, perf_audit_status),
    }


def build_roadmap() -> Dict[str, Any]:
    inputs = collect_inputs()
    seo_review = inputs["seo_review"][0]
    perf_review = inputs["perf_review"][0]
    autonomy = inputs["autonomy"][0]
    master = inputs["master"][0]

    items = items_from_seo(seo_review) + items_from_performance(perf_review)
    items.sort(key=priority_key)

    groups: Dict[str, List[str]] = {g: [] for g in ALL_GROUPS}
    area_counts: Dict[str, int] = {}
    for item in items:
        groups[item["group"]].append(item["roadmap_id"])
        area_counts[item["impact_area"]] = area_counts.get(item["impact_area"], 0) + 1

    next_safe_items = [i for i in items if i["group"] == GROUP_NEXT_SAFE_DRAFTS]
    top_5_next_safe_steps = [
        {"roadmap_id": i["roadmap_id"], "suggested_next_step": i["suggested_next_step"]}
        for i in next_safe_items[:5]
    ]

    high_risk_count = sum(1 for i in items if i["risk_classification"] == RISK_HIGH)

    input_status = {
        "seo_editorial_review": inputs["seo_review"][1],
        "performance_editorial_review": inputs["perf_review"][1],
        "autonomy_policy_report": inputs["autonomy"][1],
        "master_report": inputs["master"][1],
        "seo_safe_optimizer_report": inputs["seo_optimizer"][1],
        "performance_safe_audit_report": inputs["perf_audit"][1],
    }

    context = {
        "current_autonomy_level": redact_text(autonomy.get("current_autonomy_level"), default="-") if isinstance(autonomy, dict) else "-",
        "autonomy_policy_only": bool(autonomy.get("policy_only")) if isinstance(autonomy, dict) else None,
        "master_overall_status": redact_text(master.get("overall_master_status"), default="-") if isinstance(master, dict) else "-",
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "read_only": True,
        "productive_change": False,
        "secrets_output": False,
        "network_access": False,
        "apply_function": False,
        "status": "READY_FOR_REVIEW" if items else "NOT_AVAILABLE",
        "allowed_write_roots": [str(r) for r in ALLOWED_WRITE_ROOTS],
        "forbidden_mutations": {
            "wordpress": False,
            "htaccess": False,
            "cloudflare": False,
            "nginx": False,
            "external_write": False,
        },
        "inputs": input_status,
        "context": context,
        "roadmap_items": items,
        "groups": groups,
        "impact_area_counts": area_counts,
        "summary": {
            "roadmap_item_count": len(items),
            "next_safe_count": len(groups[GROUP_NEXT_SAFE_DRAFTS]),
            "owner_review_count": len(groups[GROUP_OWNER_REVIEW_REQUIRED]),
            "blocked_high_count": len(groups[GROUP_BLOCKED_HIGH_RISK]),
            "monitor_only_count": len(groups[GROUP_MONITOR_ONLY]),
            "high_risk_count": high_risk_count,
            "all_not_applied": all(i["apply_status"] == "not_applied" for i in items),
        },
        "top_5_next_safe_steps": top_5_next_safe_steps,
        "report_outputs": [str(REPORT_MD), str(REPORT_JSON)],
        "draft_outputs": [str(DRAFT_MD), str(DRAFT_JSON)],
    }
    return report


def render_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines: List[str] = []
    lines.append("# Safe Improvement Roadmap (Phase 1.9 — review only)")
    lines.append("")
    lines.append(f"- Generated (UTC): `{report['generated_at_utc']}`")
    lines.append(f"- Status: **{report['status']}**")
    lines.append(
        f"- Items: {summary.get('roadmap_item_count')} "
        f"(next_safe={summary.get('next_safe_count')}, "
        f"owner_review={summary.get('owner_review_count')}, "
        f"monitor_only={summary.get('monitor_only_count')}, "
        f"blocked_high={summary.get('blocked_high_count')})"
    )
    lines.append(f"- all_not_applied: {summary.get('all_not_applied')} · HIGH-risk: {summary.get('high_risk_count')}")
    lines.append("- Mode: roadmap/review-only; nothing is applied (apply_status=not_applied). No apply function.")
    lines.append("")

    ctx = report.get("context", {})
    lines.append("## Context")
    lines.append("")
    lines.append(f"- Autonomy level: `{ctx.get('current_autonomy_level')}` · policy_only: `{ctx.get('autonomy_policy_only')}`")
    lines.append(f"- Master overall status: `{ctx.get('master_overall_status')}`")
    lines.append("")

    lines.append("## Input Availability")
    lines.append("")
    for kind, status in report.get("inputs", {}).items():
        lines.append(f"- `{kind}`: {status}")
    lines.append("")

    lines.append("## Top 5 Next Safe Steps")
    lines.append("")
    top = report.get("top_5_next_safe_steps", [])
    if top:
        for entry in top:
            lines.append(f"- `{entry['roadmap_id']}`: {entry['suggested_next_step']}")
    else:
        lines.append("- (none)")
    lines.append("")

    for group in ALL_GROUPS:
        members = [i for i in report.get("roadmap_items", []) if i["group"] == group]
        lines.append(f"## {group} ({len(members)})")
        lines.append("")
        if not members:
            lines.append("- (none)")
            lines.append("")
            continue
        lines.append("| roadmap_id | source | impact | risk | autonomy | apply_status |")
        lines.append("|---|---|---|---|---|---|")
        for i in members:
            lines.append(
                f"| `{i['roadmap_id']}` | {i['source']} | {i['impact_area']} | "
                f"{i['risk_classification']} | `{i['autonomy_policy_class']}` | {i['apply_status']} |"
            )
        lines.append("")

    lines.append("## Safety")
    lines.append("")
    lines.append("- Roadmap/review-only; nothing applied (apply_status=not_applied). No apply function.")
    lines.append("- No WordPress/.htaccess/Cloudflare/Nginx/external change; no network access.")
    lines.append("- HIGH stays BLOCKED_HIGH_RISK; MEDIUM/REVIEW_ONLY stays OWNER_REVIEW_REQUIRED; LOW stays draft/review.")
    lines.append("- AI-Radio microcache and origin 5xx are MONITOR_ONLY (monitor/diagnostic, never changed here).")
    lines.append("- No secrets/cookies/authorization values are stored or emitted.")
    lines.append(
        "- Writes restricted to: " + ", ".join(f"`{r}`" for r in report["allowed_write_roots"]) + "."
    )
    lines.append("")
    return "\n".join(lines)


# ===========================================================================
# Self-tests
# ===========================================================================
def run_self_tests() -> int:
    # Write-path guard.
    assert_allowed_write(REPORT_JSON)
    assert_allowed_write(DRAFT_JSON)
    for forbidden in (
        Path("/etc/nginx/road.conf"),
        Path("/var/www/.htaccess"),
        Path("/srv/sentinel-defense/sentinel_master.py"),
        Path("/srv/sentinel-defense/drafts/seo/x.json"),
        Path("/srv/sentinel-defense/drafts/performance/y.json"),
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")

    # Grouping rules.
    assert decide_group(RISK_HIGH, False) == GROUP_BLOCKED_HIGH_RISK
    assert decide_group(RISK_MEDIUM, False) == GROUP_OWNER_REVIEW_REQUIRED
    assert decide_group(RISK_REVIEW_ONLY, False) == GROUP_OWNER_REVIEW_REQUIRED
    assert decide_group(RISK_LOW, False) == GROUP_NEXT_SAFE_DRAFTS
    assert decide_group(RISK_HIGH, True) == GROUP_MONITOR_ONLY  # monitor overrides group

    # A HIGH item is always blocked from autonomy and never applied.
    high_item = make_item("x", "s", "t", AREA_TECHNICAL, "b", RISK_HIGH, "step", True, "r")
    assert high_item["group"] == GROUP_BLOCKED_HIGH_RISK
    assert high_item["autonomy_policy_class"] == "BLOCKED_NOT_PERMITTED"
    assert high_item["apply_status"] == "not_applied"

    # MEDIUM requires owner review; LOW is next-safe-draft only.
    med_item = make_item("y", "s", "t", AREA_PERFORMANCE, "b", RISK_MEDIUM, "step", True, "r")
    assert med_item["group"] == GROUP_OWNER_REVIEW_REQUIRED
    assert med_item["apply_status"] == "not_applied"
    low_item = make_item("z", "s", "t", AREA_SEO, "b", RISK_LOW, "step", True, "r")
    assert low_item["group"] == GROUP_NEXT_SAFE_DRAFTS
    assert low_item["apply_status"] == "not_applied"

    # Synthetic SEO + Performance reviews -> items.
    seo_review = {
        "proposals": [
            {"proposal_id": "title", "category": "Title", "recommendation": "improve",
             "risk_classification": "LOW", "manual_review_required": True, "reason": "shorter title"},
            {"proposal_id": "schema", "category": "Schema", "recommendation": "review_only",
             "risk_classification": "REVIEW_ONLY", "manual_review_required": True, "reason": "validate schema"},
        ]
    }
    perf_review = {
        "proposals": [
            {"action_id": "perf-lazy-loading", "title": "Lazy", "expected_benefit": "defer offscreen",
             "risk_classification": "MEDIUM", "manual_review_required": True, "reason": "markup",
             "proposed_improvement": "add lazy"},
            {"action_id": "perf-high-script-count", "title": "Scripts", "expected_benefit": "faster render",
             "risk_classification": "HIGH", "manual_review_required": True, "reason": "build change",
             "proposed_improvement": "defer scripts"},
            {"action_id": "perf-ai-radio-microcache", "title": "Microcache", "expected_benefit": "stable",
             "risk_classification": "HIGH", "manual_review_required": True, "reason": "radio",
             "proposed_improvement": "monitor"},
            {"action_id": "perf-origin-5xx", "title": "Origin 5xx", "expected_benefit": "awareness",
             "risk_classification": "HIGH", "manual_review_required": True, "reason": "nginx",
             "proposed_improvement": "observe"},
        ]
    }
    seo_items = items_from_seo(seo_review)
    perf_items = items_from_performance(perf_review)
    assert len(seo_items) == 2
    assert len(perf_items) == 4

    # HIGH stays blocked; monitor items go MONITOR_ONLY but remain blocked from apply.
    by_id = {i["roadmap_id"]: i for i in (seo_items + perf_items)}
    assert by_id["perf:perf-high-script-count"]["group"] == GROUP_BLOCKED_HIGH_RISK
    micro = by_id["perf:perf-ai-radio-microcache"]
    assert micro["group"] == GROUP_MONITOR_ONLY
    assert micro["risk_classification"] == RISK_HIGH
    assert micro["autonomy_policy_class"] == "BLOCKED_NOT_PERMITTED"
    assert micro["apply_status"] == "not_applied"
    origin = by_id["perf:perf-origin-5xx"]
    assert origin["group"] == GROUP_MONITOR_ONLY
    assert origin["apply_status"] == "not_applied"
    assert by_id["seo:title"]["group"] == GROUP_NEXT_SAFE_DRAFTS
    assert by_id["seo:schema"]["group"] == GROUP_OWNER_REVIEW_REQUIRED
    assert by_id["perf:perf-lazy-loading"]["group"] == GROUP_OWNER_REVIEW_REQUIRED

    # Every item stays not_applied; every HIGH stays blocked.
    for i in (seo_items + perf_items):
        assert i["apply_status"] == "not_applied"
        if i["risk_classification"] == RISK_HIGH:
            assert i["autonomy_policy_class"] == "BLOCKED_NOT_PERMITTED"
            assert i["group"] in {GROUP_BLOCKED_HIGH_RISK, GROUP_MONITOR_ONLY}

    # Missing inputs must not crash.
    assert items_from_seo(None) == []
    assert items_from_performance(None) == []
    assert items_from_seo({"proposals": "broken"}) == []

    # Full build does not crash and stays read-only.
    report = build_roadmap()
    assert report["productive_change"] is False
    assert report["apply_function"] is False
    assert report["summary"]["all_not_applied"] is True
    assert set(report["groups"].keys()) == set(ALL_GROUPS)
    md = render_markdown(report)
    assert "Safe Improvement Roadmap" in md

    # Secret-bearing free text gets redacted.
    secret_item = make_item("s", "src", "Authorization: Bearer abc123", AREA_SEO, "b", RISK_LOW, "step", True, "Token=xyz")
    assert secret_item["title"] == "[redacted]"
    assert secret_item["reason"] == "[redacted]"

    print("safe-improvement-roadmap self-tests: OK")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Safe Improvement Roadmap (read-only)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety/unit tests.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()

    report = build_roadmap()
    md = render_markdown(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, md)
    write_json_atomic(DRAFT_JSON, report)
    write_text_atomic(DRAFT_MD, md)
    print(f"Safe improvement roadmap report (JSON): {REPORT_JSON}")
    print(f"Safe improvement roadmap report (MD):   {REPORT_MD}")
    print(f"Safe improvement roadmap draft (JSON):  {DRAFT_JSON}")
    print(f"Safe improvement roadmap draft (MD):    {DRAFT_MD}")
    s = report["summary"]
    print(
        f"status={report['status']} items={s['roadmap_item_count']} "
        f"next_safe={s['next_safe_count']} owner_review={s['owner_review_count']} "
        f"monitor_only={s['monitor_only_count']} blocked_high={s['blocked_high_count']} "
        "(read-only, no apply function)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
