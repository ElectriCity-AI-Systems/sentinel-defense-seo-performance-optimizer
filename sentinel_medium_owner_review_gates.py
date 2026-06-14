#!/usr/bin/env python3
"""MEDIUM Owner-Review Optimization Gates (Phase 8.6).

Prepares concrete owner-review gates for SEO and performance optimizations.
It writes only local reports, state, snapshots, audit logs, playbooks, and
owner-review packs. It never performs production changes and exposes no apply
mode.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

REPORT_JSON = PROJECT_DIR / "reports/latest/medium-owner-review-gates.json"
REPORT_MD = PROJECT_DIR / "reports/latest/medium-owner-review-gates.md"
OWNER_PACK_MD = PROJECT_DIR / "reports/latest/medium-optimization-owner-pack.md"
HEALTHCHECK_MD = PROJECT_DIR / "reports/latest/medium-optimization-healthcheck-plan.md"
ROLLBACK_MD = PROJECT_DIR / "reports/latest/medium-optimization-rollback-plan.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/medium-owner-review-gates.jsonl"

STATE_JSON = PROJECT_DIR / "state/adaptive-learning/medium_owner_review_gates.json"
LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest_medium_gates.json"

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
    "images": PROJECT_DIR / "playbooks/medium-images-optimization-review.playbook.json",
    "inline-css": PROJECT_DIR / "playbooks/medium-inline-css-review.playbook.json",
    "scripts": PROJECT_DIR / "playbooks/medium-scripts-review.playbook.json",
    "cache-expires": PROJECT_DIR / "playbooks/medium-cache-expires-review.playbook.json",
    "html-size": PROJECT_DIR / "playbooks/medium-html-size-review.playbook.json",
}

INPUTS = {
    "performance_trend": PROJECT_DIR / "reports/latest/performance-trend-accumulator.json",
    "performance_priority": PROJECT_DIR / "reports/latest/performance-owner-review-priority.json",
    "concrete_dryrun": PROJECT_DIR / "reports/latest/concrete-performance-dryrun.json",
    "concrete_owner_pack": PROJECT_DIR / "reports/latest/concrete-performance-owner-review-pack.md",
    "external_seo": PROJECT_DIR / "reports/latest/external-seo-report-ingest.json",
    "global_checker": PROJECT_DIR / "reports/latest/global-checker-ingest.json",
    "low_risk_autonomy": PROJECT_DIR / "reports/latest/low-risk-autonomy.json",
    "trend_decision": PROJECT_DIR / "state/performance-dryrun/trend_decision.json",
    "accumulator": PROJECT_DIR / "state/performance-dryrun/accumulator.json",
    "knowledge_base": KNOWLEDGE_BASE_JSON,
    "action_rules": ACTION_RULES_JSON,
    "rollback_rules": ROLLBACK_RULES_JSON,
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "playbooks",
)

STATUS_OK = "MEDIUM_OWNER_REVIEW_GATES_OK"
STATUS_WARNINGS = "MEDIUM_OWNER_REVIEW_GATES_WARNINGS"
STATUS_BLOCKED = "MEDIUM_OWNER_REVIEW_GATES_BLOCKED_BY_SAFETY"
STATUS_FAILED = "MEDIUM_OWNER_REVIEW_GATES_FAILED"

RISK = "MEDIUM_REQUIRES_OWNER_APPROVAL"
APPLY_STATUS = "not_applied"
SCHEMA_VERSION = "medium-owner-review-gates-8.6"
GATES = ("images", "inline-css", "scripts", "cache-expires", "html-size")

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


def redact_text(value: Any, default: str = "-", max_len: int = 1000) -> str:
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
        raise ValueError(f"Refusing write outside allowed medium owner-review roots: {path}")
    if path.suffix.lower() in {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".env", ".bin", ".run"}:
        raise ValueError(f"Refusing executable/install output: {path}")
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


def metric(inputs: Dict[str, Any], key: str, default: Any = None) -> Any:
    perf = inputs["data"].get("performance_trend", {}) or {}
    concrete = inputs["data"].get("concrete_dryrun", {}) or {}
    low = inputs["data"].get("low_risk_autonomy", {}) or {}
    for source in (perf.get("metrics") or {}, concrete.get("metrics") or {}, low.get("analysis") or {}):
        if key in source and source.get(key) is not None:
            return source.get(key)
    return default


def trend_context(inputs: Dict[str, Any]) -> Dict[str, Any]:
    perf = inputs["data"].get("performance_trend", {}) or {}
    trend = inputs["data"].get("trend_decision", {}) or {}
    return {
        "trend_status": perf.get("trend_status") or trend.get("trend_status") or "not_available",
        "history_points": perf.get("history_points") or trend.get("history_points") or 0,
        "breach": bool(perf.get("breach") or trend.get("breach")),
        "live_apply": bool(perf.get("live_apply") or False),
        "emergency_stop_unchanged": perf.get("emergency_stop_unchanged", True),
    }


def confidence(inputs: Dict[str, Any], base: float = 0.74) -> float:
    context = trend_context(inputs)
    score = base
    if context["trend_status"] == "STABLE":
        score += 0.12
    if int(context.get("history_points") or 0) >= 5:
        score += 0.06
    if context.get("breach"):
        score -= 0.3
    return round(max(0.0, min(0.98, score)), 2)


def common_pre_healthcheck() -> List[str]:
    return [
        "Read-only HTTP status check returns 200.",
        "Record current SEO score, performance score, schema health score and known issues.",
        "Record current HTML bytes, script count, image count, cache headers and 5xx/504 context.",
        "Confirm live_apply=false and write emergency stop remains active.",
    ]


def common_blocked_actions() -> List[str]:
    return [
        "automatic production change",
        "database write",
        "remote file write",
        "cache purge",
        "CDN/security-rule change",
        "webserver config change",
        "access-rule file change",
        "editor/template/post/page modification",
        "theme or plugin code modification",
    ]


def gate_images(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "gate_id": "images",
        "risk_level": RISK,
        "evidence": {
            "image_bytes": metric(inputs, "image_bytes"),
            "image_count": metric(inputs, "image_count"),
            "lazy_image_count": metric(inputs, "lazy_image_count"),
            "webp_hint_count": metric(inputs, "webp_hint_count"),
        },
        "expected_benefit": "Lower transfer weight and faster render for visual-heavy entry points without changing layout intent.",
        "required_owner_approval": True,
        "exact_manual_review_steps": [
            "Identify hero, cover-art, shop, player and radio visuals from the page source or media library.",
            "Sort candidates by visual importance and likely byte size.",
            "Prepare alternate compressed image variants manually and compare visual quality.",
            "Confirm above-the-fold image handling before considering any future owner-approved change.",
        ],
        "pre_healthcheck": common_pre_healthcheck(),
        "post_healthcheck": [
            "HTTP status remains 200.",
            "Image count is not accidentally zero.",
            "Layout remains visually intact on desktop and mobile.",
            "HTML bytes decrease or stay stable.",
            "Known schema issue does not worsen.",
        ],
        "rollback_plan": [
            "Restore original image or media-library item from backup.",
            "Revert any manual image reference changed during owner-approved work.",
            "Run read-only SEO/performance healthcheck after rollback.",
        ],
        "blocked_auto_actions": common_blocked_actions() + ["image conversion", "media upload"],
        "bot_learning": "Images are the highest byte-share review candidate, but media changes remain MEDIUM owner-approved work.",
        "confidence_score": confidence(inputs, 0.78),
        "status": "OWNER_REVIEW_GATE_READY",
        "apply_status": APPLY_STATUS,
        "live_apply": False,
    }


def gate_inline_css(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "gate_id": "inline-css",
        "risk_level": RISK,
        "evidence": {
            "inline_css_count": metric(inputs, "inline_css_count"),
            "stylesheet_count": metric(inputs, "stylesheet_count"),
            "likely_sources": ["WordPress blocks", "FSE output", "plugin output"],
        },
        "expected_benefit": "Reduce generated HTML/CSS overhead and improve maintainability if repeated style blocks are consolidated.",
        "required_owner_approval": True,
        "exact_manual_review_steps": [
            "Group repeated inline style patterns from read-only HTML snapshots.",
            "Classify likely source as block, template, editor content or plugin output.",
            "Prefer setting-level cleanup over code edits if a safe owner-approved path exists.",
            "Do not touch editor/template output without separate owner review.",
        ],
        "pre_healthcheck": common_pre_healthcheck(),
        "post_healthcheck": [
            "HTTP status remains 200.",
            "Primary layout is visible and not shifted.",
            "H1, title, meta description and canonical remain present.",
            "JSON-LD count and known schema state do not worsen.",
        ],
        "rollback_plan": [
            "Restore prior block/template/editor state manually from saved copy.",
            "Re-run read-only HTML and SEO checks.",
            "Mark the gate blocked if layout or SEO signals degrade.",
        ],
        "blocked_auto_actions": common_blocked_actions() + ["style rewrite"],
        "bot_learning": "High inline CSS count is actionable evidence, but source classification is required before any owner-approved change.",
        "confidence_score": confidence(inputs, 0.76),
        "status": "OWNER_REVIEW_GATE_READY",
        "apply_status": APPLY_STATUS,
        "live_apply": False,
    }


def gate_scripts(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "gate_id": "scripts",
        "risk_level": RISK,
        "evidence": {
            "internal_scripts_count": metric(inputs, "internal_scripts_count"),
            "script_tag_count": metric(inputs, "script_tag_count"),
            "large_inline_script_count": metric(inputs, "large_inline_script_count"),
            "external_resource_host_count": metric(inputs, "external_resource_host_count"),
        },
        "expected_benefit": "Reduce blocking or redundant script overhead while protecting player, radio, ads, shop and embed behavior.",
        "required_owner_approval": True,
        "exact_manual_review_steps": [
            "Create a script inventory grouped by source and purpose.",
            "Separate critical player/radio/shop/ad/embed scripts from optional scripts.",
            "Mark defer/lazy-load candidates for manual testing only.",
            "Do not alter player or monetization behavior automatically.",
        ],
        "pre_healthcheck": common_pre_healthcheck(),
        "post_healthcheck": [
            "HTTP status remains 200.",
            "Player, radio, ads, analytics and embeds are manually checked.",
            "No visible JavaScript failure is reported during manual browser review.",
            "SEO tags and schema counts remain present.",
        ],
        "rollback_plan": [
            "Restore the prior script setting manually.",
            "Re-enable any manually disabled script source.",
            "Run read-only healthcheck and manual functional review after rollback.",
        ],
        "blocked_auto_actions": common_blocked_actions() + ["script rewrite", "player code change"],
        "bot_learning": "Script reduction may help performance but must be tested manually because core interactive features can break.",
        "confidence_score": confidence(inputs, 0.75),
        "status": "OWNER_REVIEW_GATE_READY",
        "apply_status": APPLY_STATUS,
        "live_apply": False,
    }


def gate_cache_expires(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "gate_id": "cache-expires",
        "risk_level": RISK,
        "evidence": {
            "cache_control": metric(inputs, "cache_control"),
            "cf_cache_status": metric(inputs, "cf_cache_status"),
            "expires_tag_missing": bool((inputs["data"].get("external_seo", {}) or {}).get("findings")) and any(
                item.get("finding_id") == "expires_tag_missing" for item in (inputs["data"].get("external_seo", {}) or {}).get("findings", [])
            ),
            "global_p90_latency_ms": metric(inputs, "global_p90_latency_ms"),
            "global_p90_ttfb_ms": metric(inputs, "global_p90_ttfb_ms"),
        },
        "expected_benefit": "Clarify cache policy for static assets while avoiding stale HTML and avoiding broad infrastructure changes.",
        "required_owner_approval": True,
        "exact_manual_review_steps": [
            "Separate HTML caching signals from static asset caching signals.",
            "Compare cache headers across several read-only runs.",
            "Prepare a narrow owner-reviewed header strategy only if repeated evidence supports it.",
            "Do not create broad security, CDN, or webserver changes from this gate.",
        ],
        "pre_healthcheck": common_pre_healthcheck(),
        "post_healthcheck": [
            "HTTP status remains 200.",
            "No 5xx/504 increase after any future owner-approved change.",
            "No stale homepage HTML is served.",
            "HIT/MISS/REVALIDATED states are interpreted separately by resource type.",
        ],
        "rollback_plan": [
            "Manually revert the owner-approved cache/header rule.",
            "Recheck public HTML freshness and cache headers.",
            "Keep read-only monitoring active; do not purge automatically.",
        ],
        "blocked_auto_actions": common_blocked_actions() + ["header rule deployment"],
        "bot_learning": "Cache/expires review requires resource-type separation and repeated evidence; no broad automatic rule is allowed.",
        "confidence_score": confidence(inputs, 0.73),
        "status": "OWNER_REVIEW_GATE_READY",
        "apply_status": APPLY_STATUS,
        "live_apply": False,
    }


def gate_html_size(inputs: Dict[str, Any]) -> Dict[str, Any]:
    total = metric(inputs, "total_transfer_bytes")
    html = metric(inputs, "html_bytes")
    return {
        "gate_id": "html-size",
        "risk_level": RISK,
        "evidence": {
            "html_bytes": html,
            "total_transfer_bytes": total,
            "image_bytes": metric(inputs, "image_bytes"),
            "inline_css_count": metric(inputs, "inline_css_count"),
            "script_tag_count": metric(inputs, "script_tag_count"),
        },
        "expected_benefit": "Lower generated HTML payload by identifying oversized embeds, ad blocks, galleries, player markup, or repeated blocks.",
        "required_owner_approval": True,
        "exact_manual_review_steps": [
            "Split HTML payload into image, script, inline-style and generated-content drivers.",
            "Review embed, ad, gallery, player and repeated-block sections manually.",
            "Create a manual reduction candidate list without editing content.",
            "Keep FSE, post and page edits outside automation.",
        ],
        "pre_healthcheck": common_pre_healthcheck(),
        "post_healthcheck": [
            "HTTP status remains 200.",
            "SEO title, meta description, canonical, H1 and social tags remain present.",
            "Player, radio, shop and ads remain functional after any future owner-approved edit.",
            "HTML size decreases or stays stable without worsening schema duplicate state.",
        ],
        "rollback_plan": [
            "Restore previous page/editor/template content manually from saved copy.",
            "Re-run read-only SEO and performance checks.",
            "If score or function regresses, mark this gate blocked pending review.",
        ],
        "blocked_auto_actions": common_blocked_actions() + ["content rewrite"],
        "bot_learning": "HTML size is a real optimization target, but most reductions touch productive output and must remain owner-reviewed.",
        "confidence_score": confidence(inputs, 0.77),
        "status": "OWNER_REVIEW_GATE_READY",
        "apply_status": APPLY_STATUS,
        "live_apply": False,
    }


GATE_BUILDERS = {
    "images": gate_images,
    "inline-css": gate_inline_css,
    "scripts": gate_scripts,
    "cache-expires": gate_cache_expires,
    "html-size": gate_html_size,
}


def aggregate_status(gates: List[Dict[str, Any]], inputs: Dict[str, Any], breach: bool) -> str:
    if breach or trend_context(inputs).get("breach"):
        return STATUS_BLOCKED
    if any(status not in {"ok", "missing"} for status in inputs["status"].values()):
        return STATUS_WARNINGS
    if any(status == "missing" for status in inputs["status"].values()):
        return STATUS_WARNINGS
    if not gates:
        return STATUS_WARNINGS
    return STATUS_OK


def build_gate(gate_id: str, inputs: Optional[Dict[str, Any]] = None) -> Tuple[Optional[Dict[str, Any]], bool, List[str]]:
    inputs = inputs or load_inputs()
    if gate_id not in GATE_BUILDERS:
        return None, True, [f"unknown gate: {gate_id}"]
    gate = GATE_BUILDERS[gate_id](inputs)
    return gate, False, []


def build_bundle(action: str, selected_gate: Optional[str] = None, owner_pack: bool = False) -> Dict[str, Any]:
    ts = timestamp_tag()
    inputs = load_inputs()
    breach = False
    reasons: List[str] = []
    if selected_gate:
        gate, gate_breach, gate_reasons = build_gate(selected_gate, inputs)
        gates = [gate] if gate else []
        breach = breach or gate_breach
        reasons.extend(gate_reasons)
    else:
        gates = [GATE_BUILDERS[name](inputs) for name in GATES]
    context = trend_context(inputs)
    breach = breach or bool(context.get("breach") or context.get("live_apply"))
    if context.get("live_apply"):
        reasons.append("live_apply detected")
    status = aggregate_status(gates, inputs, breach)
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": ts,
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status,
        "breach": breach,
        "breach_reasons": reasons,
        "live_apply": False,
        "emergency_stop_unchanged": bool(context.get("emergency_stop_unchanged", True)),
        "apply_status": APPLY_STATUS,
        "selected_gate": selected_gate,
        "gates_count": len(gates),
        "gates": gates,
        "gate_status_by_id": {gate.get("gate_id"): gate.get("status") for gate in gates},
        "risk_summary": dict(Counter(gate.get("risk_level") for gate in gates)),
        "trend_context": context,
        "input_status": inputs["status"],
        "missing_inputs": [name for name, status_value in inputs["status"].items() if status_value == "missing"],
        "owner_review_pack_written": owner_pack,
        "healthcheck_plan_written": owner_pack,
        "rollback_plan_written": owner_pack,
        "recommended_owner_action": "Review MEDIUM optimization gates manually. Do not perform productive changes from this module.",
    }
    return {"report": report, "inputs": inputs}


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# MEDIUM Owner Review Gates",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- Emergency stop unchanged: `{report.get('emergency_stop_unchanged')}`",
        f"- Gates: `{report.get('gates_count')}`",
        f"- Trend: `{(report.get('trend_context') or {}).get('trend_status')}`",
        f"- History points: `{(report.get('trend_context') or {}).get('history_points')}`",
        "",
    ]
    for gate in report.get("gates", []):
        lines.append(f"## {gate.get('gate_id')}")
        lines.append(f"- Risk: `{gate.get('risk_level')}`")
        lines.append(f"- Status: `{gate.get('status')}`")
        lines.append(f"- Confidence: `{gate.get('confidence_score')}`")
        lines.append(f"- Benefit: {gate.get('expected_benefit')}")
        lines.append("")
    return "\n".join(lines)


def render_owner_pack(report: Dict[str, Any]) -> str:
    lines = [
        "# MEDIUM Optimization Owner Pack",
        "",
        "All gates are owner-review only. No productive change is authorized here.",
        "",
    ]
    for gate in report.get("gates", []):
        lines.append(f"## {gate.get('gate_id')}")
        lines.append(f"- Risk: `{gate.get('risk_level')}`")
        lines.append(f"- Expected benefit: {gate.get('expected_benefit')}")
        lines.append("- Evidence:")
        for key, value in (gate.get("evidence") or {}).items():
            lines.append(f"  - `{key}`: `{value}`")
        lines.append("- Manual review steps:")
        for item in gate.get("exact_manual_review_steps", []):
            lines.append(f"  - {item}")
        lines.append("")
    return "\n".join(lines)


def render_healthcheck_md(report: Dict[str, Any]) -> str:
    lines = ["# MEDIUM Optimization Healthcheck Plan", ""]
    for gate in report.get("gates", []):
        lines.append(f"## {gate.get('gate_id')}")
        lines.append("### Pre")
        for item in gate.get("pre_healthcheck", []):
            lines.append(f"- {item}")
        lines.append("### Post")
        for item in gate.get("post_healthcheck", []):
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines)


def render_rollback_md(report: Dict[str, Any]) -> str:
    lines = ["# MEDIUM Optimization Rollback Plan", ""]
    for gate in report.get("gates", []):
        lines.append(f"## {gate.get('gate_id')}")
        for item in gate.get("rollback_plan", []):
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines)


def build_playbook(gate: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": f"medium-{gate.get('gate_id')}-optimization-review",
        "purpose": f"Owner-review gate for {gate.get('gate_id')} optimization planning.",
        "risk_level": RISK,
        "owner_review_required": True,
        "allowed_actions": ["read local reports", "write owner-review pack", "write healthcheck plan", "write rollback plan", "write audit"],
        "blocked_actions": gate.get("blocked_auto_actions", []),
        "evidence": gate.get("evidence", {}),
        "manual_review_steps": gate.get("exact_manual_review_steps", []),
        "pre_healthcheck": gate.get("pre_healthcheck", []),
        "post_healthcheck": gate.get("post_healthcheck", []),
        "rollback_plan": gate.get("rollback_plan", []),
        "disable_conditions": ["breach=true", "REGRESSION", "secret-like output", "unexpected production change"],
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
        "gates_count": report.get("gates_count"),
        "trend_context": report.get("trend_context"),
        "learning": {
            "bot_may_prioritize_medium": True,
            "bot_may_prepare_owner_review_packs": True,
            "bot_may_prepare_healthcheck_and_rollback_plans": True,
            "separate_apply_gate_required_later": True,
            "medium_auto_apply_forbidden": True,
            "regression_blocks_further_automation": True,
            "stable_trends_increase_confidence": True,
            "productive_output_protected": True,
        },
    }
    knowledge, _ = read_json(KNOWLEDGE_BASE_JSON)
    knowledge = knowledge or {}
    knowledge["medium_owner_review_gates"] = learning
    write_json_atomic(KNOWLEDGE_BASE_JSON, knowledge)
    append_jsonl(OBSERVATIONS_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "observation_id": "medium-owner-review-gates",
        "area": "SEO/Performance Optimization",
        "risk_level": RISK,
        "confidence_score": 0.86 if (report.get("trend_context") or {}).get("trend_status") == "STABLE" else 0.74,
        "symptoms": [gate.get("gate_id") for gate in report.get("gates", [])],
        "hypothesis": "Stable trend evidence supports owner-review prioritization, not automatic production changes.",
        "gates_count": report.get("gates_count"),
    }])
    patterns, _ = read_json(PATTERNS_JSON)
    patterns = patterns or {}
    patterns["medium_owner_review_gates"] = {
        "timestamp_utc": report.get("timestamp_utc"),
        "trend_status": (report.get("trend_context") or {}).get("trend_status"),
        "history_points": (report.get("trend_context") or {}).get("history_points"),
        "gates": [gate.get("gate_id") for gate in report.get("gates", [])],
    }
    write_json_atomic(PATTERNS_JSON, patterns)
    rules, _ = read_json(ACTION_RULES_JSON)
    rules = rules or {}
    rules["medium_owner_review_gates"] = {
        "allowed": ["prioritize MEDIUM tasks", "write owner-review pack", "write healthcheck plan", "write rollback plan"],
        "forbidden": ["automatic production change", "remote write", "database write", "cache purge", "code or content edit"],
        "future_gate_required": "A separate Owner-approved apply gate is required before any MEDIUM action.",
    }
    write_json_atomic(ACTION_RULES_JSON, rules)
    rollback, _ = read_json(ROLLBACK_RULES_JSON)
    rollback = rollback or {}
    rollback["medium_owner_review_gates"] = {
        gate.get("gate_id"): gate.get("rollback_plan", []) for gate in report.get("gates", [])
    }
    write_json_atomic(ROLLBACK_RULES_JSON, rollback)
    latest, _ = read_json(ADAPTIVE_LATEST_JSON)
    latest = latest or {}
    latest["medium_owner_review_gates"] = {
        "status": report.get("status"),
        "gates_count": report.get("gates_count"),
        "breach": report.get("breach"),
        "trend_status": (report.get("trend_context") or {}).get("trend_status"),
    }
    write_json_atomic(ADAPTIVE_LATEST_JSON, latest)
    section = (
        f"- Status: `{report.get('status')}`\n"
        f"- Gates: `{report.get('gates_count')}`\n"
        f"- Trend: `{(report.get('trend_context') or {}).get('trend_status')}`\n"
        "- Learning: MEDIUM optimization planning is allowed, but production changes require a separate Owner-approved gate.\n"
    )
    append_markdown_section(ADAPTIVE_REPORT_MD, "MEDIUM Owner Review Gates Learning", section)
    append_markdown_section(
        ADAPTIVE_RECOMMEND_MD,
        "MEDIUM Owner Review Gates Recommendations",
        "- Review images, inline CSS, scripts, cache/expires and HTML size in that order.\n- Keep all actions owner-approved and review-only in this phase.\n",
    )
    append_markdown_section(
        ADAPTIVE_CAPABILITY_MD,
        "MEDIUM Owner Review Gates Capability",
        "- `medium_gate_prioritization`: `True`\n- `healthcheck_plan_generation`: `True`\n- `rollback_plan_generation`: `True`\n- `medium_auto_apply`: `False`\n",
    )


def write_outputs(bundle: Dict[str, Any], owner_pack: bool = False) -> None:
    report = bundle["report"]
    ts = str(report.get("timestamp") or timestamp_tag())
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(STATE_JSON, report)
    write_json_atomic(LATEST_JSON, report)
    write_json_atomic(SNAPSHOT_DIR / f"medium-owner-review-gates-{ts}.json", report)
    for gate in report.get("gates", []):
        path = PLAYBOOKS.get(gate.get("gate_id"))
        if path:
            write_json_atomic(path, build_playbook(gate))
    if owner_pack:
        write_text_atomic(OWNER_PACK_MD, render_owner_pack(report))
        write_text_atomic(HEALTHCHECK_MD, render_healthcheck_md(report))
        write_text_atomic(ROLLBACK_MD, render_rollback_md(report))
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "action": report.get("action"),
        "status": report.get("status"),
        "selected_gate": report.get("selected_gate"),
        "gates_count": report.get("gates_count"),
        "breach": report.get("breach"),
        "live_apply": report.get("live_apply"),
    }])
    update_learning(report)


def build_gates() -> Dict[str, Any]:
    bundle = build_bundle("build-gates")
    write_outputs(bundle)
    return bundle["report"]


def gate_action(gate_id: str) -> Dict[str, Any]:
    bundle = build_bundle("gate", selected_gate=gate_id)
    write_outputs(bundle)
    return bundle["report"]


def owner_review_pack() -> Dict[str, Any]:
    bundle = build_bundle("owner-review-pack", owner_pack=True)
    write_outputs(bundle, owner_pack=True)
    return bundle["report"]


def print_status() -> None:
    data, status = read_json(LATEST_JSON)
    if not data:
        print(f"status=not_available input_status={status}")
        return
    print(f"status={data.get('status')}")
    print(f"gates_count={data.get('gates_count')}")
    print(f"breach={data.get('breach')}")
    print(f"live_apply={data.get('live_apply')}")
    print(f"emergency_stop_unchanged={data.get('emergency_stop_unchanged')}")
    print(f"owner_review_pack_written={data.get('owner_review_pack_written')}")
    for gate in data.get("gates", []):
        print(f"gate={gate.get('gate_id')} status={gate.get('status')} risk={gate.get('risk_level')} confidence={gate.get('confidence_score')}")


def print_summary(report: Dict[str, Any]) -> None:
    print(f"status={report.get('status')}")
    print(f"action={report.get('action')}")
    print(f"selected_gate={report.get('selected_gate') or '-'}")
    print(f"gates_count={report.get('gates_count')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop_unchanged={report.get('emergency_stop_unchanged')}")
    for gate in report.get("gates", []):
        print(f"gate={gate.get('gate_id')} status={gate.get('status')} risk={gate.get('risk_level')}")


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    missing = {"data": {}, "status": {}}
    for name in INPUTS:
        missing["data"][name] = {} if not name.endswith("pack") else ""
        missing["status"][name] = "missing"
    all_gates = [GATE_BUILDERS[name](missing) for name in GATES]
    if len(all_gates) != 5:
        raise AssertionError("not all gates generated")
    if any(gate.get("risk_level") != RISK for gate in all_gates):
        raise AssertionError("non-MEDIUM risk classification")
    unknown_gate, breach, _ = build_gate("unknown", missing)
    if unknown_gate is not None or not breach:
        raise AssertionError("unknown gate not blocked")
    for gate in all_gates:
        if not gate.get("pre_healthcheck") or not gate.get("post_healthcheck"):
            raise AssertionError("healthcheck plan incomplete")
        if not gate.get("rollback_plan"):
            raise AssertionError("rollback plan incomplete")
        blocked = " ".join(gate.get("blocked_auto_actions", [])).lower()
        if "automatic production change" not in blocked:
            raise AssertionError("high-risk auto action not blocked")
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
    json.dumps({"gates": all_gates})
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MEDIUM owner-review optimization gates.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--build-gates", action="store_true")
    group.add_argument("--gate", choices=GATES)
    group.add_argument("--owner-review-pack", action="store_true")
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
        if args.build_gates:
            report = build_gates()
        elif args.gate:
            report = gate_action(args.gate)
        elif args.owner_review_pack:
            report = owner_review_pack()
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
