#!/usr/bin/env python3
"""Approved MEDIUM Apply Preflight Gate (Phase 8.9).

This module checks whether a later Owner-approved MEDIUM apply-preparation gate
could be safely considered for gates that were already owner-approved for
dry-run simulation and simulated successfully. It does not apply, optimize,
upload, purge, edit, or install anything.
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

REPORT_JSON = PROJECT_DIR / "reports/latest/approved-medium-apply-preflight.json"
REPORT_MD = PROJECT_DIR / "reports/latest/approved-medium-apply-preflight.md"
OWNER_PACK_MD = PROJECT_DIR / "reports/latest/approved-medium-apply-owner-review-pack.md"
HEALTHCHECK_MD = PROJECT_DIR / "reports/latest/approved-medium-apply-healthcheck-sequence.md"
ROLLBACK_MD = PROJECT_DIR / "reports/latest/approved-medium-apply-rollback-requirements.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/approved-medium-apply-preflight.jsonl"

STATE_JSON = PROJECT_DIR / "state/adaptive-learning/approved_medium_apply_preflight.json"
LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest_approved_medium_apply_preflight.json"

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
    "images": PROJECT_DIR / "playbooks/approved-images-apply-preflight.playbook.json",
    "html-size": PROJECT_DIR / "playbooks/approved-html-size-apply-preflight.playbook.json",
}

INPUTS = {
    "owner_decisions": PROJECT_DIR / "state/adaptive-learning/medium_owner_decisions.json",
    "simulations_state": PROJECT_DIR / "state/adaptive-learning/approved_medium_dryrun_simulations.json",
    "latest_simulation": PROJECT_DIR / "state/adaptive-learning/latest_approved_medium_simulation.json",
    "simulation_report": PROJECT_DIR / "reports/latest/approved-medium-dryrun-simulator.json",
    "simulation_owner_pack": PROJECT_DIR / "reports/latest/approved-medium-simulation-owner-pack.md",
    "simulation_healthcheck_plan": PROJECT_DIR / "reports/latest/approved-medium-simulation-healthcheck-plan.md",
    "simulation_rollback_plan": PROJECT_DIR / "reports/latest/approved-medium-simulation-rollback-plan.md",
    "medium_healthcheck_plan": PROJECT_DIR / "reports/latest/medium-optimization-healthcheck-plan.md",
    "medium_rollback_plan": PROJECT_DIR / "reports/latest/medium-optimization-rollback-plan.md",
    "performance_accumulator": PROJECT_DIR / "reports/latest/performance-trend-accumulator.json",
    "trend_decision": PROJECT_DIR / "state/performance-dryrun/trend_decision.json",
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "playbooks",
)

STATUS_OK = "APPROVED_MEDIUM_APPLY_PREFLIGHT_OK"
STATUS_WARNINGS = "APPROVED_MEDIUM_APPLY_PREFLIGHT_WARNINGS"
STATUS_BLOCKED = "APPROVED_MEDIUM_APPLY_PREFLIGHT_BLOCKED_BY_SAFETY"
STATUS_FAILED = "APPROVED_MEDIUM_APPLY_PREFLIGHT_FAILED"

PREFLIGHT_READY = "APPLY_PREFLIGHT_READY_FOR_OWNER_REVIEW"
PREFLIGHT_NOT_READY = "APPLY_PREFLIGHT_NOT_READY"
PREFLIGHT_BLOCKED_DECISION = "APPLY_PREFLIGHT_BLOCKED_BY_OWNER_DECISION"
PREFLIGHT_BLOCKED_SAFETY = "APPLY_PREFLIGHT_BLOCKED_BY_SAFETY"

SIM_READY = "SIMULATION_READY"
APPLY_STATUS = "not_applied"
RISK = "MEDIUM_REQUIRES_OWNER_APPROVAL"
SCHEMA_VERSION = "approved-medium-apply-preflight-8.9"

GATES = ("images", "inline-css", "scripts", "cache-expires", "html-size")
ELIGIBLE_GATES = ("images", "html-size")
NOT_ELIGIBLE_GATES = ("inline-css", "scripts", "cache-expires")

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
        raise ValueError(f"Refusing write outside allowed apply-preflight roots: {path}")
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


def append_text(path: Path, section: str) -> None:
    assert_allowed_write(path)
    assert_safe_content(path, section)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(section)


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


def decisions(inputs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    raw = inputs["data"].get("owner_decisions", {}) or {}
    raw_decisions = raw.get("decisions") if isinstance(raw, dict) else {}
    out: Dict[str, Dict[str, Any]] = {}
    for gate in GATES:
        item = raw_decisions.get(gate, {}) if isinstance(raw_decisions, dict) else {}
        out[gate] = {
            "gate_id": gate,
            "decision": item.get("decision", "pending_review") if isinstance(item, dict) else "pending_review",
            "next_allowed_stage": item.get("next_allowed_stage", "owner_review") if isinstance(item, dict) else "owner_review",
        }
    return out


def simulation_results(inputs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    candidates = [
        inputs["data"].get("latest_simulation", {}),
        inputs["data"].get("simulations_state", {}),
        inputs["data"].get("simulation_report", {}),
    ]
    results: Dict[str, Dict[str, Any]] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        for item in candidate.get("simulation_results", []) or []:
            if isinstance(item, dict) and item.get("gate_id"):
                results[item["gate_id"]] = item
    return results


def trend_status(inputs: Dict[str, Any]) -> str:
    decision = inputs["data"].get("trend_decision", {}) or {}
    accumulator = inputs["data"].get("performance_accumulator", {}) or {}
    return str(decision.get("trend_status") or accumulator.get("trend_status") or accumulator.get("trend") or "UNKNOWN")


def trend_is_stable_or_ok(inputs: Dict[str, Any]) -> bool:
    return trend_status(inputs) in {"STABLE", "OK", "PERFORMANCE_TREND_ACCUMULATOR_OK"}


def upstream_breach_reasons(inputs: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    checks = {
        "owner_decisions": inputs["data"].get("owner_decisions", {}),
        "simulations_state": inputs["data"].get("simulations_state", {}),
        "latest_simulation": inputs["data"].get("latest_simulation", {}),
        "simulation_report": inputs["data"].get("simulation_report", {}),
        "performance_accumulator": inputs["data"].get("performance_accumulator", {}),
        "trend_decision": inputs["data"].get("trend_decision", {}),
    }
    for name, data in checks.items():
        if not isinstance(data, dict):
            continue
        if data.get("breach") is True or data.get("live_apply") is True or data.get("apply_status") not in (None, APPLY_STATUS):
            reasons.append(f"{name}_unsafe_flag")
        if data.get("status") in {"PERFORMANCE_TREND_ACCUMULATOR_REGRESSION"} or data.get("trend_status") == "REGRESSION":
            reasons.append(f"{name}_regression")
    return sorted(set(reasons))


def text_plan_present(inputs: Dict[str, Any], keys: Iterable[str]) -> bool:
    for key in keys:
        if inputs["status"].get(key) == "ok" and str(inputs["data"].get(key) or "").strip():
            return True
    return False


def estimate_present(sim: Dict[str, Any]) -> bool:
    estimate = sim.get("estimated_savings") or sim.get("estimated_html_reduction") or {}
    if not isinstance(estimate, dict):
        return False
    values = [estimate.get("low_bytes"), estimate.get("high_bytes"), estimate.get("low"), estimate.get("high")]
    values.extend([sim.get("estimated_reduction_low"), sim.get("estimated_reduction_high")])
    return any(isinstance(value, (int, float)) and value >= 0 for value in values)


def requirement_map(gate: str, inputs: Dict[str, Any]) -> Dict[str, bool]:
    dec = decisions(inputs).get(gate, {})
    sim = simulation_results(inputs).get(gate, {})
    base = {
        "owner_decision_present": dec.get("decision") != "pending_review",
        "owner_decision_is_dryrun_only": dec.get("decision") == "approved_for_dry_run_only",
        "simulation_present": bool(sim),
        "simulation_ready": sim.get("simulation_status") == SIM_READY,
        "healthcheck_plan_present": text_plan_present(inputs, ("simulation_healthcheck_plan", "medium_healthcheck_plan")),
        "rollback_plan_present": text_plan_present(inputs, ("simulation_rollback_plan", "medium_rollback_plan")),
        "trend_stable_or_ok": trend_is_stable_or_ok(inputs),
        "backup_requirement_defined": True,
        "post_apply_validation_defined": True,
        "fallback_abort_rules_defined": True,
    }
    if gate == "images":
        base.update({
            "image_candidates_present": bool(sim.get("image_candidates")),
            "estimated_savings_present": estimate_present(sim),
        })
    elif gate == "html-size":
        base.update({
            "estimated_savings_present": estimate_present(sim),
            "fse_post_page_risk_recognized": True,
            "manual_review_requirement_present": True,
        })
    return base


def missing_requirements(requirements: Dict[str, bool]) -> List[str]:
    return [name for name, ok in requirements.items() if not ok]


def apply_preflight_common(gate: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
    dec = decisions(inputs).get(gate, {})
    sim = simulation_results(inputs).get(gate, {})
    reqs = requirement_map(gate, inputs)
    misses = missing_requirements(reqs)
    breach_reasons = upstream_breach_reasons(inputs)

    if breach_reasons:
        status = PREFLIGHT_BLOCKED_SAFETY
    elif dec.get("decision") != "approved_for_dry_run_only":
        status = PREFLIGHT_BLOCKED_DECISION
    elif misses:
        status = PREFLIGHT_NOT_READY
    else:
        status = PREFLIGHT_READY

    return {
        "gate_id": gate,
        "risk_level": RISK,
        "owner_decision": dec,
        "simulation_status": sim.get("simulation_status") or "missing",
        "preflight_status": status,
        "requirements": reqs,
        "missing_requirements": misses,
        "upstream_breach_reasons": breach_reasons,
        "live_apply": False,
        "apply_status": APPLY_STATUS,
        "future_owner_decision_required": "approved_for_apply_preparation",
        "preflight_does_not_authorize_apply": True,
    }


def healthcheck_sequence(gate: str) -> List[str]:
    base = [
        "Pre: latest read-only monitor report shows HTTP 200.",
        "Pre: title, meta description, canonical and H1 are recorded.",
        "Pre: JSON-LD count and SOC known-issue status are recorded.",
        "Pre: current image count, HTML bytes, transfer bytes and TTFB are recorded.",
        "Post: HTTP remains 200 and no new 5xx growth is observed.",
        "Post: SEO essentials remain present unless Owner intentionally changes them.",
        "Post: player, radio, shop and ads receive manual visual review.",
        "Post: breach remains false and live_apply remains false.",
    ]
    if gate == "images":
        return base + [
            "Post: image count is not unexpectedly zero.",
            "Post: above-the-fold visual content is manually compared against the previous page.",
        ]
    return base + [
        "Post: HTML bytes do not increase versus pre-check.",
        "Post: FSE/page structure is manually compared against the previous page.",
    ]


def rollback_conditions(gate: str) -> List[str]:
    if gate == "images":
        return [
            "Rollback required if hero/above-the-fold media disappears or layout breaks.",
            "Rollback required if HTTP status changes away from 200.",
            "Rollback required if image count unexpectedly drops to zero.",
            "Rollback uses the original media asset or previous media setting kept by the Owner.",
        ]
    return [
        "Rollback required if page layout, player, shop, ads or navigation breaks.",
        "Rollback required if SEO essentials disappear unexpectedly.",
        "Rollback required if HTTP status changes away from 200 or 5xx grows.",
        "Rollback uses the previous WordPress/FSE/Page content kept by the Owner.",
    ]


def abort_conditions(gate: str) -> List[str]:
    shared = [
        "Abort if a required backup is missing.",
        "Abort if healthcheck baseline cannot be captured.",
        "Abort if any upstream breach is true.",
        "Abort if a planned change requires DB, remote write, Cloudflare, Nginx, htaccess, theme or plugin modification outside the later approved scope.",
        "Abort if Owner approval is anything other than the future approved_for_apply_preparation decision.",
    ]
    if gate == "images":
        return shared + ["Abort if image candidates are not specific enough to isolate one minimal manual change."]
    return shared + ["Abort if the exact FSE/Page block cannot be identified for a minimal manual change."]


def manual_strategy(gate: str) -> List[str]:
    if gate == "images":
        return [
            "Owner selects one image candidate from the simulation pack.",
            "Owner confirms original media backup or reversible media library state.",
            "Owner performs only one minimal manual image optimization in a later separately approved phase.",
            "Owner runs pre/post healthchecks and compares image count, HTML bytes and visible layout.",
        ]
    return [
        "Owner identifies one concrete oversized FSE/Page block from the simulation evidence.",
        "Owner saves a manual backup of the original content before any future edit.",
        "Owner performs only one minimal manual reduction in a later separately approved phase.",
        "Owner runs pre/post healthchecks and compares SEO essentials, player/shop/ads and HTML bytes.",
    ]


def backup_requirement(gate: str) -> Dict[str, Any]:
    if gate == "images":
        return {
            "required": True,
            "scope": "original media asset, media metadata and page reference before any future manual change",
            "minimum_evidence": ["original filename/path or media ID", "current rendered image URL", "pre-change screenshot or visual note"],
        }
    return {
        "required": True,
        "scope": "original WordPress/FSE/Page content for the exact block planned for future change",
        "minimum_evidence": ["page/template identifier", "original block content export or manual copy", "pre-change screenshot or visual note"],
    }


def preflight_gate(gate: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
    common = apply_preflight_common(gate, inputs)
    if gate not in ELIGIBLE_GATES:
        common.update({
            "possible_manual_apply_strategy": [],
            "backup_requirement": {"required": False, "reason": "Gate is not eligible for apply preflight."},
            "healthcheck_sequence": [],
            "rollback_conditions": [],
            "abort_conditions": ["Owner decision blocks this gate before simulation/apply-preflight."],
        })
        return common
    common.update({
        "possible_manual_apply_strategy": manual_strategy(gate),
        "backup_requirement": backup_requirement(gate),
        "healthcheck_sequence": healthcheck_sequence(gate),
        "rollback_conditions": rollback_conditions(gate),
        "abort_conditions": abort_conditions(gate),
    })
    if gate == "images":
        sim = simulation_results(inputs).get(gate, {})
        common.update({
            "image_candidates_count": len(sim.get("image_candidates") or []),
            "estimated_savings": sim.get("estimated_savings") or {},
            "manual_apply_scope": "one image candidate only in a future separately approved phase",
        })
    elif gate == "html-size":
        sim = simulation_results(inputs).get(gate, {})
        estimated = sim.get("estimated_html_reduction") or sim.get("estimated_savings") or {}
        if not estimated and (sim.get("estimated_reduction_low") is not None or sim.get("estimated_reduction_high") is not None):
            estimated = {
                "low_bytes": sim.get("estimated_reduction_low"),
                "high_bytes": sim.get("estimated_reduction_high"),
            }
        common.update({
            "estimated_savings": estimated,
            "recognized_risk": "FSE/Post/Page content risk; manual review is mandatory before any later preparation gate.",
            "manual_apply_scope": "one exact FSE/Page block only in a future separately approved phase",
        })
    return common


def selected_preflights(action: str, selected_gate: Optional[str], inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
    if selected_gate:
        return [preflight_gate(selected_gate, inputs)]
    if action == "preflight-all":
        return [preflight_gate(gate, inputs) for gate in GATES]
    if action == "owner-apply-review-pack":
        return [preflight_gate(gate, inputs) for gate in GATES]
    if action == "list-eligible":
        return [preflight_gate(gate, inputs) for gate in GATES]
    return []


def missing_inputs(inputs: Dict[str, Any]) -> List[str]:
    return [name for name, status in inputs["status"].items() if status != "ok"]


def build_report(action: str, selected_gate: Optional[str] = None, owner_pack: bool = False) -> Dict[str, Any]:
    inputs = load_inputs()
    results = selected_preflights(action, selected_gate, inputs)
    breach_reasons = upstream_breach_reasons(inputs)
    gate_statuses = {item["gate_id"]: item.get("preflight_status") for item in results}
    ready = [item["gate_id"] for item in results if item.get("preflight_status") == PREFLIGHT_READY]
    blocked = [item["gate_id"] for item in results if item.get("preflight_status") in {PREFLIGHT_BLOCKED_DECISION, PREFLIGHT_BLOCKED_SAFETY}]
    not_ready = [item["gate_id"] for item in results if item.get("preflight_status") == PREFLIGHT_NOT_READY]
    miss_count = sum(
        len(item.get("missing_requirements", []))
        for item in results
        if item.get("preflight_status") != PREFLIGHT_BLOCKED_DECISION
    )
    input_missing = missing_inputs(inputs)

    if breach_reasons or any(item.get("preflight_status") == PREFLIGHT_BLOCKED_SAFETY for item in results):
        status = STATUS_BLOCKED
        breach = True
    elif not_ready or input_missing:
        status = STATUS_WARNINGS
        breach = False
    else:
        status = STATUS_OK
        breach = False

    eligible = [gate for gate in ELIGIBLE_GATES if decisions(inputs).get(gate, {}).get("decision") == "approved_for_dry_run_only"]
    blocked_by_owner = [gate for gate in GATES if gate not in eligible]
    timestamp = timestamp_tag()
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp,
        "timestamp_utc": utc_now(),
        "action": action,
        "selected_gate": selected_gate,
        "status": status,
        "global_status": status,
        "breach": breach,
        "breach_reasons": breach_reasons,
        "live_apply": False,
        "emergency_stop_unchanged": True,
        "apply_status": APPLY_STATUS,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "eligible_gates": eligible,
        "eligible_gates_count": len(eligible),
        "blocked_gates": blocked_by_owner,
        "blocked_gates_count": len(blocked_by_owner),
        "not_eligible_gates": list(NOT_ELIGIBLE_GATES),
        "preflight_results": results,
        "preflight_gate_statuses": gate_statuses,
        "preflight_ready_count": len(ready),
        "preflight_not_ready_count": len(not_ready),
        "preflight_blocked_count": len(blocked),
        "missing_requirements_count": miss_count,
        "missing_inputs": input_missing,
        "input_status": inputs["status"],
        "trend_status": trend_status(inputs),
        "owner_apply_review_pack_written": bool(owner_pack),
        "healthcheck_sequence_written": bool(owner_pack),
        "rollback_requirements_written": bool(owner_pack),
        "recommended_owner_action": recommended_owner_action(status, ready, not_ready, blocked),
        "next_required_owner_decision": "approved_for_apply_preparation",
        "preflight_authorizes_apply": False,
    }
    return report


def recommended_owner_action(status: str, ready: List[str], not_ready: List[str], blocked: List[str]) -> str:
    if status == STATUS_BLOCKED:
        return "Do not proceed. Resolve safety blocker before any further MEDIUM apply planning."
    if not_ready:
        return "Review missing preflight requirements. No apply preparation is allowed yet."
    if ready:
        return "Review preflight pack only. A future real apply path needs a separate approved_for_apply_preparation Owner decision."
    if blocked:
        return "Gates are blocked by current Owner decisions. Continue manual review; do not apply."
    return "No eligible gate selected. Review current decisions before any further step."


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Approved MEDIUM Apply Preflight",
        "",
        f"- status: `{report.get('status')}`",
        f"- action: `{report.get('action')}`",
        f"- breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- emergency_stop_unchanged: `{report.get('emergency_stop_unchanged')}`",
        f"- eligible_gates_count: `{report.get('eligible_gates_count')}`",
        f"- blocked_gates_count: `{report.get('blocked_gates_count')}`",
        f"- missing_requirements_count: `{report.get('missing_requirements_count')}`",
        f"- trend_status: `{report.get('trend_status')}`",
        "",
        "This is only preflight. It does not authorize a production change.",
        "",
        "## Gate Results",
    ]
    for item in report.get("preflight_results", []):
        lines.extend([
            "",
            f"### {item.get('gate_id')}",
            f"- preflight_status: `{item.get('preflight_status')}`",
            f"- simulation_status: `{item.get('simulation_status')}`",
            f"- future_owner_decision_required: `{item.get('future_owner_decision_required')}`",
            f"- missing_requirements: `{', '.join(item.get('missing_requirements') or []) or '-'}`",
        ])
        if item.get("possible_manual_apply_strategy"):
            lines.append("- strategy preview:")
            for step in item["possible_manual_apply_strategy"]:
                lines.append(f"  - {step}")
    lines.extend([
        "",
        "## Owner Action",
        report.get("recommended_owner_action", "-"),
        "",
    ])
    return "\n".join(lines)


def render_owner_pack_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Approved MEDIUM Apply Owner Review Pack",
        "",
        "This document is a preflight review pack only.",
        "",
        "- No apply is performed.",
        "- No productive website output is changed.",
        "- Current dry-run approval is not enough for production action.",
        "- A later real path requires a separate Owner decision: `approved_for_apply_preparation`.",
        "- After that, a separate Apply-Preparation-Gate, backup evidence, healthcheck baseline, minimal action, validation and rollback decision are required.",
        "",
        "## Gate Preflight Summary",
    ]
    for item in report.get("preflight_results", []):
        lines.extend([
            "",
            f"### {item.get('gate_id')}",
            f"- preflight_status: `{item.get('preflight_status')}`",
            f"- risk_level: `{item.get('risk_level')}`",
            f"- future decision needed: `{item.get('future_owner_decision_required')}`",
            f"- missing requirements: `{', '.join(item.get('missing_requirements') or []) or '-'}`",
        ])
        if item.get("backup_requirement", {}).get("required"):
            lines.append(f"- backup requirement: {item['backup_requirement'].get('scope')}")
        if item.get("abort_conditions"):
            lines.append("- abort conditions:")
            for condition in item["abort_conditions"]:
                lines.append(f"  - {condition}")
    lines.extend([
        "",
        "## Required Future Sequence",
        "1. Owner grants separate `approved_for_apply_preparation` decision.",
        "2. Build a dedicated Apply-Preparation-Gate.",
        "3. Capture backup evidence.",
        "4. Capture pre-healthcheck baseline.",
        "5. Perform one minimal Owner-approved change in that later phase.",
        "6. Validate with post-healthchecks.",
        "7. Roll back if validation is worse.",
        "",
    ])
    return "\n".join(lines)


def render_healthcheck_md(report: Dict[str, Any]) -> str:
    lines = ["# Approved MEDIUM Apply Healthcheck Sequence", ""]
    for item in report.get("preflight_results", []):
        if item.get("preflight_status") == PREFLIGHT_READY:
            lines.extend([f"## {item.get('gate_id')}", ""])
            for step in item.get("healthcheck_sequence", []):
                lines.append(f"- {step}")
            lines.append("")
    return "\n".join(lines)


def render_rollback_md(report: Dict[str, Any]) -> str:
    lines = ["# Approved MEDIUM Apply Rollback Requirements", ""]
    for item in report.get("preflight_results", []):
        if item.get("preflight_status") == PREFLIGHT_READY:
            lines.extend([f"## {item.get('gate_id')}", ""])
            backup = item.get("backup_requirement") or {}
            lines.append(f"- backup required: `{backup.get('required')}`")
            lines.append(f"- backup scope: {backup.get('scope', '-')}")
            lines.append("- rollback conditions:")
            for condition in item.get("rollback_conditions", []):
                lines.append(f"  - {condition}")
            lines.append("")
    return "\n".join(lines)


def playbook_for(gate: str, report: Dict[str, Any]) -> Dict[str, Any]:
    result = next((item for item in report.get("preflight_results", []) if item.get("gate_id") == gate), {})
    return {
        "name": f"approved-{gate}-apply-preflight",
        "phase": "8.9",
        "purpose": "Check requirements for a future Owner-approved apply-preparation gate without changing production.",
        "gate_id": gate,
        "risk_level": RISK,
        "current_preflight_status": result.get("preflight_status"),
        "allowed_actions": [
            "read local simulation reports",
            "read healthcheck and rollback plans",
            "write local preflight reports",
            "write local audit and snapshot records",
            "update bot learning",
        ],
        "blocked_actions": [
            "production website changes",
            "remote writes",
            "database writes",
            "cache purge",
            "Cloudflare or Nginx or htaccess changes",
            "FSE or page or theme or plugin edits",
            "image or HTML file changes",
        ],
        "required_owner_decision_before_later_preparation": "approved_for_apply_preparation",
        "healthcheck_sequence": result.get("healthcheck_sequence", []),
        "rollback_requirements": result.get("rollback_conditions", []),
        "abort_conditions": result.get("abort_conditions", []),
        "live_apply": False,
        "apply_status": APPLY_STATUS,
    }


def update_json_file(path: Path, update: Dict[str, Any]) -> None:
    existing, status = read_json(path)
    data = existing if isinstance(existing, dict) and status == "ok" else {}
    data.update(update)
    write_json_atomic(path, data)


def update_learning(report: Dict[str, Any]) -> None:
    timestamp = report.get("timestamp_utc") or utc_now()
    learning = {
        "approved_medium_apply_preflight": {
            "last_status": report.get("status"),
            "eligible_gates": report.get("eligible_gates", []),
            "preflight_gate_statuses": report.get("preflight_gate_statuses", {}),
            "principles": [
                "Apply-preflight is separate from simulation and separate from any future production action.",
                "approved_for_dry_run_only is not an apply approval.",
                "Missing healthcheck, backup or rollback evidence blocks preflight readiness.",
                "A future production path requires approved_for_apply_preparation and a dedicated preparation gate.",
            ],
            "live_apply": False,
            "apply_status": APPLY_STATUS,
        }
    }
    update_json_file(KNOWLEDGE_BASE_JSON, learning)
    update_json_file(PATTERNS_JSON, {
        "approved_medium_apply_preflight_pattern": {
            "simulation_to_apply_preflight_boundary": True,
            "dry_run_approval_is_not_apply": True,
            "missing_inputs_block_preflight": True,
            "last_seen": timestamp,
        }
    })
    update_json_file(ACTION_RULES_JSON, {
        "approved_medium_apply_preflight_rules": {
            "allowed_now": ["preflight assessment", "owner review pack", "healthcheck sequence", "rollback requirements"],
            "requires_future_owner_decision": ["approved_for_apply_preparation"],
            "blocked_now": ["production change", "remote write", "database write", "image or HTML mutation"],
        }
    })
    update_json_file(ROLLBACK_RULES_JSON, {
        "approved_medium_apply_preflight_rollback_rules": {
            "images": rollback_conditions("images"),
            "html-size": rollback_conditions("html-size"),
            "automatic_restore_allowed_now": False,
        }
    })
    update_json_file(ADAPTIVE_LATEST_JSON, {
        "latest_approved_medium_apply_preflight_status": report.get("status"),
        "latest_approved_medium_apply_preflight_timestamp": timestamp,
        "latest_approved_medium_apply_preflight_breach": report.get("breach"),
    })
    append_jsonl(OBSERVATIONS_JSONL, [{
        "timestamp_utc": timestamp,
        "source": SCHEMA_VERSION,
        "observation": "Approved MEDIUM gates reached apply-preflight assessment only; no production action is authorized.",
        "eligible_gates": report.get("eligible_gates", []),
        "status": report.get("status"),
        "breach": report.get("breach"),
    }])
    section = (
        "\n\n## Phase 8.9 Approved MEDIUM Apply Preflight\n"
        f"- status: `{report.get('status')}`\n"
        f"- eligible_gates: `{', '.join(report.get('eligible_gates', [])) or '-'}`\n"
        f"- missing_requirements_count: `{report.get('missing_requirements_count')}`\n"
        "- Dry-run approval remains separate from any future production action.\n"
        "- A later real path requires `approved_for_apply_preparation` plus backup, healthcheck, validation and rollback evidence.\n"
    )
    append_text(ADAPTIVE_REPORT_MD, section)
    append_text(ADAPTIVE_RECOMMEND_MD, section)
    append_text(ADAPTIVE_CAPABILITY_MD, section)


def write_outputs(report: Dict[str, Any], owner_pack: bool = False) -> None:
    timestamp = report.get("timestamp") or timestamp_tag()
    snapshot = SNAPSHOT_DIR / f"approved-medium-apply-preflight-{timestamp}.json"
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(STATE_JSON, report)
    write_json_atomic(LATEST_JSON, report)
    write_json_atomic(snapshot, report)
    append_jsonl(AUDIT_JSONL, [report])
    if owner_pack:
        write_text_atomic(OWNER_PACK_MD, render_owner_pack_md(report))
        write_text_atomic(HEALTHCHECK_MD, render_healthcheck_md(report))
        write_text_atomic(ROLLBACK_MD, render_rollback_md(report))
    for gate in ELIGIBLE_GATES:
        write_json_atomic(PLAYBOOKS[gate], playbook_for(gate, report))
    update_learning(report)


def list_eligible() -> Dict[str, Any]:
    report = build_report("list-eligible")
    write_outputs(report)
    return report


def preflight_one(gate: str) -> Dict[str, Any]:
    report = build_report("preflight", selected_gate=gate)
    write_outputs(report)
    return report


def preflight_all() -> Dict[str, Any]:
    report = build_report("preflight-all")
    write_outputs(report)
    return report


def owner_apply_review_pack() -> Dict[str, Any]:
    report = build_report("owner-apply-review-pack", owner_pack=True)
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
    print(f"eligible_gates_count={report.get('eligible_gates_count')}")
    print(f"blocked_gates_count={report.get('blocked_gates_count')}")
    print(f"missing_requirements_count={report.get('missing_requirements_count')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop_unchanged={report.get('emergency_stop_unchanged')}")
    for item in report.get("preflight_results", []):
        print(f"gate={item.get('gate_id')} preflight_status={item.get('preflight_status')}")


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
            "latest_simulation": {
                "simulation_results": [
                    {"gate_id": "images", "simulation_status": SIM_READY, "image_candidates": [{"url": "https://example.test/a.jpg"}], "estimated_savings": {"low_bytes": 10, "high_bytes": 25}},
                    {"gate_id": "html-size", "simulation_status": SIM_READY, "estimated_html_reduction": {"low_bytes": 5, "high_bytes": 15}},
                ]
            },
            "trend_decision": {"trend_status": "STABLE", "breach": False, "live_apply": False, "apply_status": APPLY_STATUS},
            "simulation_healthcheck_plan": "healthcheck plan",
            "simulation_rollback_plan": "rollback plan",
            "medium_healthcheck_plan": "",
            "medium_rollback_plan": "",
            "performance_accumulator": {},
        },
        "status": {name: "ok" for name in INPUTS},
    }
    dec = decisions(fake_inputs)
    if [gate for gate in ELIGIBLE_GATES if dec[gate]["decision"] == "approved_for_dry_run_only"] != ["images", "html-size"]:
        raise AssertionError("eligible decisions failed")
    if preflight_gate("inline-css", fake_inputs)["preflight_status"] != PREFLIGHT_BLOCKED_DECISION:
        raise AssertionError("non-approved gate not blocked")
    if preflight_gate("scripts", fake_inputs)["preflight_status"] != PREFLIGHT_BLOCKED_DECISION:
        raise AssertionError("scripts gate not blocked")
    if preflight_gate("cache-expires", fake_inputs)["preflight_status"] != PREFLIGHT_BLOCKED_DECISION:
        raise AssertionError("cache-expires gate not blocked")
    if preflight_gate("images", fake_inputs)["preflight_status"] != PREFLIGHT_READY:
        raise AssertionError("images should be ready")
    if preflight_gate("html-size", fake_inputs)["preflight_status"] != PREFLIGHT_READY:
        raise AssertionError("html-size should be ready")
    if preflight_gate("images", fake_inputs).get("future_owner_decision_required") != "approved_for_apply_preparation":
        raise AssertionError("dry-run approval incorrectly treated as apply")
    no_rollback = json.loads(json.dumps(fake_inputs))
    no_rollback["data"]["simulation_rollback_plan"] = ""
    no_rollback["data"]["medium_rollback_plan"] = ""
    no_rollback["status"]["simulation_rollback_plan"] = "missing"
    no_rollback["status"]["medium_rollback_plan"] = "missing"
    if preflight_gate("images", no_rollback)["preflight_status"] != PREFLIGHT_NOT_READY:
        raise AssertionError("missing rollback did not block readiness")
    no_health = json.loads(json.dumps(fake_inputs))
    no_health["data"]["simulation_healthcheck_plan"] = ""
    no_health["data"]["medium_healthcheck_plan"] = ""
    no_health["status"]["simulation_healthcheck_plan"] = "missing"
    no_health["status"]["medium_healthcheck_plan"] = "missing"
    if preflight_gate("html-size", no_health)["preflight_status"] != PREFLIGHT_NOT_READY:
        raise AssertionError("missing healthcheck did not block readiness")
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
        PLAYBOOKS["html-size"],
    ):
        assert_allowed_write(path)
    json.dumps({"images": preflight_gate("images", fake_inputs), "html": preflight_gate("html-size", fake_inputs)})
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Approved MEDIUM apply-preflight gate.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--list-eligible", action="store_true")
    group.add_argument("--preflight", choices=GATES)
    group.add_argument("--preflight-all", action="store_true")
    group.add_argument("--owner-apply-review-pack", action="store_true")
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
        if args.list_eligible:
            report = list_eligible()
        elif args.preflight:
            report = preflight_one(args.preflight)
        elif args.preflight_all:
            report = preflight_all()
        elif args.owner_apply_review_pack:
            report = owner_apply_review_pack()
        else:
            parser.error("unreachable")
    except Exception as exc:  # noqa: BLE001
        failed = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": timestamp_tag(),
            "timestamp_utc": utc_now(),
            "action": "failed",
            "status": STATUS_FAILED,
            "global_status": STATUS_FAILED,
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
    raise SystemExit(main())
