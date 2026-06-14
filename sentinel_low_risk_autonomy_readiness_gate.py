#!/usr/bin/env python3
"""Low-Risk Autonomy Readiness Gate (Phase 5.5).

Read-only decision aid that judges whether the system is even ready to *prepare*
LOW-RISK SEO-&-performance autonomy (draft/policy only). It applies nothing,
enables no apply, frees no timer installation, and never changes the Master
status. It only reads upstream safety/readiness gates and emits a safe owner
decision template.

This is NOT an apply mechanism, NOT a WAF rule, NOT a WordPress change, NOT a
Cloudflare change, NOT an installation, and NOT an active timer.
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

MANUAL_RECHECK_GATE_JSON = PROJECT_DIR / "reports/latest/manual-website-recheck-gate.json"
LOW_GROWTH_TIMELINE_JSON = PROJECT_DIR / "reports/latest/low-growth-readiness-timeline.json"
ROLLING_OBSERVER_JSON = PROJECT_DIR / "reports/latest/rolling-window-decay-observer.json"
MASTER_CRITICAL_CAUSE_JSON = PROJECT_DIR / "reports/latest/master-critical-cause-snapshot.json"
FINAL_OWNER_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json"
FINAL_SAFETY_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
RUNTIME_LOCK_JSON = PROJECT_DIR / "config/autonomy-runtime-lock.json"
MANUAL_RECHECK_AUDIT_JSONL = PROJECT_DIR / "audit/manual-website-recheck-gate.jsonl"
LOW_GROWTH_AUDIT_JSONL = PROJECT_DIR / "audit/low-growth-readiness-timeline.jsonl"

REPORT_JSON = PROJECT_DIR / "reports/latest/low-risk-autonomy-readiness-gate.json"
REPORT_MD = PROJECT_DIR / "reports/latest/low-risk-autonomy-readiness-gate.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "drafts/owner/low-risk-autonomy-readiness-summary.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/low-risk-autonomy-readiness-gate.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/low-risk-autonomy-readiness-gate.md"
AUDIT_JSONL = PROJECT_DIR / "audit/low-risk-autonomy-readiness-gate.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, OWNER_SUMMARY_MD, SNAPSHOT_JSON, SNAPSHOT_MD, AUDIT_JSONL)
FORBIDDEN_OUTPUT_SUFFIXES = (".sh", ".bash", ".zsh", ".service", ".timer", ".run", ".bin", ".py")
FORBIDDEN_INSTALL_PATH_TOKENS = (
    "/etc/systemd",
    "systemd/system",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/etc/cron",
    "cron.d",
    "crontab",
)

SCHEMA_VERSION = "low-risk-autonomy-readiness-gate-5.5"
APPLY_NOT_APPLIED = "not_applied"

STATUS_NOT_READY = "LOW_RISK_AUTONOMY_NOT_READY_WAITING_FOR_WEBSITE_RECHECK"
STATUS_POLICY_DRAFT_ONLY = "LOW_RISK_AUTONOMY_READY_FOR_POLICY_DRAFT_ONLY"
STATUS_OWNER_POLICY_REVIEW = "LOW_RISK_AUTONOMY_READY_FOR_OWNER_POLICY_REVIEW"
STATUS_BLOCKED_BY_EMERGENCY_STOP = "LOW_RISK_AUTONOMY_BLOCKED_BY_EMERGENCY_STOP"
STATUS_BLOCKED_BY_BREACH = "LOW_RISK_AUTONOMY_BLOCKED_BY_BREACH"
STATUS_PARTIAL_INPUTS = "LOW_RISK_AUTONOMY_PARTIAL_INPUTS"
STATUS_BREACH = "LOW_RISK_AUTONOMY_BREACH"

ACTION_BY_STATUS = {
    STATUS_BLOCKED_BY_EMERGENCY_STOP: "Keep Emergency Stop active. Prepare policy drafts only; do not enable autonomy.",
    STATUS_NOT_READY: "Continue observation until manual website recheck is recommended. Do not enable LOW-RISK apply.",
    STATUS_POLICY_DRAFT_ONLY: "Create LOW-RISK policy draft and owner review checklist. Do not apply changes.",
    STATUS_OWNER_POLICY_REVIEW: "Owner may review LOW-RISK policy boundaries. No automatic apply.",
    STATUS_BLOCKED_BY_BREACH: "Do not proceed. Resolve the upstream safety breach first; keep autonomy disabled.",
    STATUS_BREACH: "Do not proceed. A safety breach was detected in this gate; keep autonomy disabled.",
    STATUS_PARTIAL_INPUTS: "Collect missing read-only safety/readiness inputs before deciding. Do not enable autonomy.",
}

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
FORBIDDEN_APPLY_COMMAND_RE = re.compile(
    r"(?i)\b(cloudflare\s+api|cfcli|wp\s+|wp-cli|nginx\s+reload|nginx\s+-s|"
    r"htaccess|\\.htaccess|apply-safe|consolidate-apply-safe|systemctl|crontab|"
    r"curl\s+.*(api|cloudflare|wp-json)|wget\s+.*(api|cloudflare|wp-json))\b"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def redact_text(value: Any, default: str = "-", max_len: int = 800) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def detect_secret_like(value: Any) -> bool:
    text = "" if value is None else str(value)
    return bool(SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if path not in ALLOWED_OUTPUT_PATHS and not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed low-risk-readiness roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install artifact: {path}")
    path_text = str(path)
    if any(token in path_text for token in FORBIDDEN_INSTALL_PATH_TOKENS):
        raise ValueError(f"Refusing to write systemd/crontab path: {path}")


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


def read_jsonl_count(path: Path) -> Tuple[int, str]:
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return 0, "refused_secret_like_path"
    if not path.exists():
        return 0, "not_available"
    try:
        count = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(item, dict):
                count += 1
        return count, "ok"
    except OSError:
        return 0, "read_error"


def parse_count(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def bool_from(data: Optional[Any], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def text_from(data: Optional[Any], key: str, default: str = "") -> str:
    if not isinstance(data, dict):
        return default
    return redact_text(data.get(key), default=default, max_len=500)


def detect_breach(
    *,
    low_risk_autonomy_allowed_now: bool,
    live_apply: bool,
    install_allowed_now: bool,
    can_install_timer_now: bool,
    apply_status: str,
    forbidden_apply_command_detected: bool,
    systemd_file_written: bool,
    crontab_file_written: bool,
    executable_install_script_generated: bool,
    secret_like_output: bool,
    output_path_breach: bool,
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if low_risk_autonomy_allowed_now:
        reasons.append("low_risk_autonomy_allowed_now=true")
    if live_apply:
        reasons.append("live_apply=true")
    if install_allowed_now:
        reasons.append("install_allowed_now=true")
    if can_install_timer_now:
        reasons.append("can_install_timer_now=true")
    if apply_status != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
    if forbidden_apply_command_detected:
        reasons.append("Cloudflare/WordPress/Nginx/.htaccess apply command detected")
    if systemd_file_written:
        reasons.append("systemd_file_written=true")
    if crontab_file_written:
        reasons.append("crontab_file_written=true")
    if executable_install_script_generated:
        reasons.append("executable install script generated")
    if secret_like_output:
        reasons.append("secret-like output")
    if output_path_breach:
        reasons.append("writing outside allowed roots")
    return bool(reasons), sorted(set(reasons))


def determine_status(
    *,
    direct_breach: bool,
    upstream_breach: bool,
    emergency_stop_active: bool,
    partial_inputs: bool,
    manual_recheck_recommended: bool,
    owner_policy_review_ready: bool,
) -> Tuple[str, bool]:
    """Decide the readiness status and whether it counts as a breach.

    Priority: real breaches first (true safety violations), then Emergency Stop
    (blocks but is NOT a breach), then missing inputs, then the website-recheck
    readiness signal. The live path tops out at POLICY_DRAFT_ONLY.
    """
    if direct_breach:
        return STATUS_BREACH, True
    if upstream_breach:
        return STATUS_BLOCKED_BY_BREACH, True
    if emergency_stop_active:
        return STATUS_BLOCKED_BY_EMERGENCY_STOP, False
    if partial_inputs:
        return STATUS_PARTIAL_INPUTS, False
    if not manual_recheck_recommended:
        return STATUS_NOT_READY, False
    if owner_policy_review_ready:
        return STATUS_OWNER_POLICY_REVIEW, False
    return STATUS_POLICY_DRAFT_ONLY, False


def build_report(
    manual_recheck_gate: Optional[Any],
    manual_recheck_status_read: str,
    timeline: Optional[Any],
    timeline_status_read: str,
    observer: Optional[Any],
    observer_status_read: str,
    critical_cause: Optional[Any],
    critical_cause_status_read: str,
    final_owner_snapshot: Optional[Any],
    final_owner_status_read: str,
    final_safety: Optional[Any],
    final_safety_status_read: str,
    master: Optional[Any],
    master_status_read: str,
    runtime_lock: Optional[Any],
    runtime_lock_status_read: str,
    manual_recheck_audit_count: int,
    manual_recheck_audit_status: str,
    low_growth_audit_count: int,
    low_growth_audit_status: str,
    *,
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    flags = forced_flags or {}

    # Hard-coded safe constants for this read-only gate.
    low_risk_autonomy_allowed_now = bool(flags.get("low_risk_autonomy_allowed_now", False))
    live_apply = bool(flags.get("live_apply", False))
    install_allowed_now = bool(flags.get("install_allowed_now", False))
    can_install_timer_now = bool(flags.get("can_install_timer_now", False))
    apply_status = str(flags.get("apply_status", APPLY_NOT_APPLIED))
    forbidden_apply_command_detected = bool(flags.get("forbidden_apply_command_detected", False))
    systemd_file_written = bool(flags.get("systemd_file_written", False))
    crontab_file_written = bool(flags.get("crontab_file_written", False))
    executable_install_script_generated = bool(flags.get("executable_install_script_generated", False))
    secret_like_output = bool(flags.get("secret_like_output", False))
    output_path_breach = bool(flags.get("output_path_breach", False))
    owner_policy_review_ready = bool(flags.get("owner_policy_review_ready", False))

    direct_breach, direct_breach_reasons = detect_breach(
        low_risk_autonomy_allowed_now=low_risk_autonomy_allowed_now,
        live_apply=live_apply,
        install_allowed_now=install_allowed_now,
        can_install_timer_now=can_install_timer_now,
        apply_status=apply_status,
        forbidden_apply_command_detected=forbidden_apply_command_detected,
        systemd_file_written=systemd_file_written,
        crontab_file_written=crontab_file_written,
        executable_install_script_generated=executable_install_script_generated,
        secret_like_output=secret_like_output,
        output_path_breach=output_path_breach,
    )

    # Upstream breaches from the safety/readiness chain.
    upstream_breach_reasons: List[str] = []
    if bool_from(manual_recheck_gate, "gate_breach"):
        upstream_breach_reasons.append("manual_website_recheck_gate:gate_breach=true")
    if bool_from(timeline, "snapshot_breach"):
        upstream_breach_reasons.append("low_growth_timeline:snapshot_breach=true")
    if bool_from(observer, "snapshot_breach"):
        upstream_breach_reasons.append("rolling_window_observer:snapshot_breach=true")
    if bool_from(critical_cause, "snapshot_breach"):
        upstream_breach_reasons.append("master_critical_cause:snapshot_breach=true")
    final_owner_snapshot_breach = (
        bool_from(final_owner_snapshot, "snapshot_breach")
        or bool_from(critical_cause, "final_owner_snapshot_breach")
    )
    if final_owner_snapshot_breach:
        upstream_breach_reasons.append("final_owner_snapshot:snapshot_breach=true")
    if bool_from(final_safety, "final_safety_breach"):
        upstream_breach_reasons.append("final_safety:final_safety_breach=true")

    autonomy_total_breaches = max(
        parse_count(critical_cause.get("autonomy_total_breaches")) if isinstance(critical_cause, dict) else 0,
        parse_count(final_owner_snapshot.get("total_breaches")) if isinstance(final_owner_snapshot, dict) else 0,
        parse_count(final_safety.get("total_breach_count")) if isinstance(final_safety, dict) else 0,
    )
    if autonomy_total_breaches > 0:
        upstream_breach_reasons.append(f"autonomy_total_breaches={autonomy_total_breaches}")
    upstream_breach = bool(upstream_breach_reasons)

    # Emergency stop: prefer the runtime lock, fall back to upstream snapshots.
    emergency_stop_active = (
        bool_from(runtime_lock, "emergency_stop")
        or bool_from(final_owner_snapshot, "emergency_stop_active")
        or bool_from(critical_cause, "emergency_stop_active")
        or bool_from(manual_recheck_gate, "emergency_stop_active")
    )

    manual_recheck_recommended = bool_from(manual_recheck_gate, "manual_recheck_recommended")
    manual_recheck_gate_status = text_from(manual_recheck_gate, "gate_status", "NOT_AVAILABLE")
    timeline_status = text_from(
        timeline, "timeline_status", text_from(manual_recheck_gate, "timeline_status", "NOT_AVAILABLE")
    )
    decay_status = text_from(
        observer, "decay_status", text_from(manual_recheck_gate, "decay_status", "NOT_AVAILABLE")
    )
    consecutive_points = parse_count(
        text_from(
            timeline,
            "consecutive_stable_or_decreasing_points",
            text_from(manual_recheck_gate, "consecutive_stable_or_decreasing_points", 0),
        )
    )

    # Required read-only inputs: the manual-recheck gate is the primary signal.
    partial_inputs = any(
        status != "ok"
        for status in (
            manual_recheck_status_read,
            timeline_status_read,
            observer_status_read,
            critical_cause_status_read,
            final_owner_status_read,
            final_safety_status_read,
            runtime_lock_status_read,
        )
    )

    readiness_status, readiness_breach = determine_status(
        direct_breach=direct_breach,
        upstream_breach=upstream_breach,
        emergency_stop_active=emergency_stop_active,
        partial_inputs=partial_inputs,
        manual_recheck_recommended=manual_recheck_recommended,
        owner_policy_review_ready=owner_policy_review_ready,
    )
    breach_reasons = sorted(set(direct_breach_reasons + upstream_breach_reasons))

    low_risk_policy_draft_allowed = (
        readiness_status in {STATUS_POLICY_DRAFT_ONLY, STATUS_OWNER_POLICY_REVIEW}
        and not readiness_breach
    )
    recommended_owner_action = ACTION_BY_STATUS.get(readiness_status, ACTION_BY_STATUS[STATUS_NOT_READY])

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "readiness_status": readiness_status,
        "low_risk_autonomy_allowed_now": False,
        "low_risk_policy_draft_allowed": low_risk_policy_draft_allowed,
        "owner_policy_review_required": True,
        "manual_recheck_recommended": manual_recheck_recommended,
        "manual_recheck_gate_status": manual_recheck_gate_status,
        "timeline_status": timeline_status,
        "decay_status": decay_status,
        "consecutive_stable_or_decreasing_points": consecutive_points,
        "emergency_stop_active": emergency_stop_active,
        "autonomy_total_breaches": autonomy_total_breaches,
        "final_owner_snapshot_breach": final_owner_snapshot_breach,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "readiness_breach": readiness_breach,
        "recommended_owner_action": recommended_owner_action,
        "readiness_breach_reasons": breach_reasons,
        "autonomy_safety": {
            "autonomy_total_breaches": autonomy_total_breaches,
            "final_owner_snapshot_breach": final_owner_snapshot_breach,
            "final_safety_breach": bool_from(final_safety, "final_safety_breach"),
            "final_safety_status": text_from(final_safety, "final_safety_status", "NOT_AVAILABLE"),
            "critical_caused_by_autonomy": bool_from(critical_cause, "critical_caused_by_autonomy"),
        },
        "website_recheck_readiness": {
            "manual_recheck_recommended": manual_recheck_recommended,
            "manual_recheck_gate_status": manual_recheck_gate_status,
            "timeline_status": timeline_status,
        },
        "rolling_window_stability": {
            "decay_status": decay_status,
            "consecutive_stable_or_decreasing_points": consecutive_points,
            "master_status": text_from(master, "overall_master_status", "UNKNOWN"),
        },
        "emergency_stop": {
            "emergency_stop_active": emergency_stop_active,
            "runtime_lock_status": runtime_lock_status_read,
        },
        "install_apply_locks": {
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "live_apply": False,
            "apply_status": APPLY_NOT_APPLIED,
        },
        "read_only": True,
        "network_access": False,
        "api_access": False,
        "cloudflare_mutations": False,
        "wordpress_mutations": False,
        "nginx_mutations": False,
        "htaccess_mutations": False,
        "systemd_file_written": systemd_file_written,
        "crontab_file_written": crontab_file_written,
        "executable_install_script_generated": executable_install_script_generated,
        "secrets_output": False,
        "master_status_not_auto_changed": True,
        "manual_recheck_audit_points": manual_recheck_audit_count,
        "low_growth_audit_points": low_growth_audit_count,
        "input_statuses": {
            "manual_website_recheck_gate": manual_recheck_status_read,
            "low_growth_timeline": timeline_status_read,
            "rolling_window_observer": observer_status_read,
            "master_critical_cause_snapshot": critical_cause_status_read,
            "final_owner_snapshot": final_owner_status_read,
            "final_safety_report": final_safety_status_read,
            "sentinel_master_json": master_status_read,
            "runtime_lock": runtime_lock_status_read,
            "manual_recheck_audit": manual_recheck_audit_status,
            "low_growth_audit": low_growth_audit_status,
        },
        "decision_template": {
            "blocked_by_breach": readiness_status in {STATUS_BLOCKED_BY_BREACH, STATUS_BREACH},
            "blocked_by_emergency_stop": readiness_status == STATUS_BLOCKED_BY_EMERGENCY_STOP,
            "waiting_for_website_recheck": readiness_status == STATUS_NOT_READY,
            "policy_draft_allowed": low_risk_policy_draft_allowed,
            "owner_policy_review_possible": readiness_status == STATUS_OWNER_POLICY_REVIEW,
        },
        "safe_owner_next_actions": [
            recommended_owner_action,
            "This gate is read-only and prepares decision drafts only; it never enables autonomy.",
            "Do not use this gate to change Master status automatically.",
        ],
        "do_not_apply_conditions": [
            "Do not enable LOW-RISK autonomy apply from this gate.",
            "Do not create WAF/Cloudflare rules from this gate.",
            "Do not install timers from this gate.",
            "Do not change WordPress, Nginx, .htaccess, systemd, or crontab from this gate.",
        ],
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_summary_md": str(OWNER_SUMMARY_MD),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Low-Risk Autonomy Readiness Gate",
        "",
        "> Read-only owner decision aid. Prepares LOW-RISK policy drafts only.",
        "> It enables no autonomy, no apply, and no timer installation.",
        "",
        "## Executive Summary",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Readiness status: `{report.get('readiness_status')}`",
        f"- LOW-RISK autonomy allowed now: `{report.get('low_risk_autonomy_allowed_now')}`",
        f"- LOW-RISK policy draft allowed: `{report.get('low_risk_policy_draft_allowed')}`",
        f"- Owner policy review required: `{report.get('owner_policy_review_required')}`",
        f"- Manual recheck recommended: `{report.get('manual_recheck_recommended')}`",
        f"- Manual recheck gate status: `{report.get('manual_recheck_gate_status')}`",
        f"- Timeline status: `{report.get('timeline_status')}`",
        f"- Decay status: `{report.get('decay_status')}`",
        f"- Consecutive stable/decreasing points: `{report.get('consecutive_stable_or_decreasing_points')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Autonomy total breaches: `{report.get('autonomy_total_breaches')}`",
        f"- Final owner snapshot breach: `{report.get('final_owner_snapshot_breach')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Readiness breach: `{report.get('readiness_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
        "## Separated Readiness Dimensions",
        "",
    ]
    sections = (
        ("Autonomy Safety", report.get("autonomy_safety")),
        ("Website Recheck Readiness", report.get("website_recheck_readiness")),
        ("Rolling Window Stability", report.get("rolling_window_stability")),
        ("Emergency Stop", report.get("emergency_stop")),
        ("Install / Apply Locks", report.get("install_apply_locks")),
    )
    for title, block in sections:
        lines.append(f"### {title}")
        if isinstance(block, dict):
            for key, value in block.items():
                lines.append(f"- {key}: `{redact_text(value, max_len=300)}`")
        lines.append("")
    breach_reasons = report.get("readiness_breach_reasons") or []
    lines.append("## Breach Reasons")
    lines.append("")
    if breach_reasons:
        for reason in breach_reasons:
            lines.append(f"- {redact_text(reason, max_len=400)}")
    else:
        lines.append("- none")
    lines.extend(["", "## Owner Decision Template", ""])
    decision = report.get("decision_template") if isinstance(report.get("decision_template"), dict) else {}
    for key in (
        "blocked_by_breach",
        "blocked_by_emergency_stop",
        "waiting_for_website_recheck",
        "policy_draft_allowed",
        "owner_policy_review_possible",
    ):
        lines.append(f"- {key}: `{decision.get(key)}`")
    lines.extend(["", "## Safe Owner Next Actions", ""])
    for item in report.get("safe_owner_next_actions", []):
        lines.append(f"- {redact_text(item, max_len=800)}")
    lines.extend(["", "## Do Not Apply Conditions", ""])
    for item in report.get("do_not_apply_conditions", []):
        lines.append(f"- {redact_text(item, max_len=700)}")
    lines.append("")
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "readiness_status": report.get("readiness_status"),
        "low_risk_autonomy_allowed_now": False,
        "low_risk_policy_draft_allowed": report.get("low_risk_policy_draft_allowed"),
        "manual_recheck_recommended": report.get("manual_recheck_recommended"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "autonomy_total_breaches": report.get("autonomy_total_breaches"),
        "readiness_breach": report.get("readiness_breach"),
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "network_access": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    markdown = render_markdown(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, markdown)
    write_text_atomic(OWNER_SUMMARY_MD, markdown)
    write_json_atomic(SNAPSHOT_JSON, report)
    write_text_atomic(SNAPSHOT_MD, markdown)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def build_current_report() -> Dict[str, Any]:
    manual_recheck_gate, manual_recheck_status = read_optional_json(MANUAL_RECHECK_GATE_JSON)
    timeline, timeline_status = read_optional_json(LOW_GROWTH_TIMELINE_JSON)
    observer, observer_status = read_optional_json(ROLLING_OBSERVER_JSON)
    critical, critical_status = read_optional_json(MASTER_CRITICAL_CAUSE_JSON)
    final_owner, final_owner_status = read_optional_json(FINAL_OWNER_SNAPSHOT_JSON)
    final_safety, final_safety_status = read_optional_json(FINAL_SAFETY_JSON)
    master, master_status = read_optional_json(MASTER_JSON)
    runtime_lock, runtime_lock_status = read_optional_json(RUNTIME_LOCK_JSON)
    manual_recheck_audit_count, manual_recheck_audit_status = read_jsonl_count(MANUAL_RECHECK_AUDIT_JSONL)
    low_growth_audit_count, low_growth_audit_status = read_jsonl_count(LOW_GROWTH_AUDIT_JSONL)
    return build_report(
        manual_recheck_gate,
        manual_recheck_status,
        timeline,
        timeline_status,
        observer,
        observer_status,
        critical,
        critical_status,
        final_owner,
        final_owner_status,
        final_safety,
        final_safety_status,
        master,
        master_status,
        runtime_lock,
        runtime_lock_status,
        manual_recheck_audit_count,
        manual_recheck_audit_status,
        low_growth_audit_count,
        low_growth_audit_status,
    )


def _base_inputs(**overrides: Any) -> Dict[str, Any]:
    base = {
        "manual_recheck_gate": {
            "manual_recheck_recommended": False,
            "gate_status": "MANUAL_RECHECK_GATE_EARLY_STABLE_WAIT",
            "gate_breach": False,
            "timeline_status": "LOW_GROWTH_TIMELINE_EARLY_STABLE",
            "decay_status": "ROLLING_WINDOW_DECAY_STABLE",
            "consecutive_stable_or_decreasing_points": 2,
            "emergency_stop_active": True,
        },
        "timeline": {
            "timeline_status": "LOW_GROWTH_TIMELINE_EARLY_STABLE",
            "consecutive_stable_or_decreasing_points": 2,
            "snapshot_breach": False,
        },
        "observer": {"decay_status": "ROLLING_WINDOW_DECAY_STABLE", "snapshot_breach": False},
        "critical": {
            "snapshot_breach": False,
            "autonomy_total_breaches": 0,
            "critical_caused_by_autonomy": False,
            "final_owner_snapshot_breach": False,
            "emergency_stop_active": True,
        },
        "final_owner": {"snapshot_breach": False, "total_breaches": 0, "emergency_stop_active": True},
        "final_safety": {"final_safety_breach": False, "total_breach_count": 0, "final_safety_status": "SAFE_BUT_LOCKED_BY_EMERGENCY_STOP"},
        "master": {"overall_master_status": "CRITICAL"},
        "runtime_lock": {"emergency_stop": True},
    }
    base.update(overrides)
    return base


def _report_from(inputs: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
    return build_report(
        inputs["manual_recheck_gate"], "ok",
        inputs["timeline"], "ok",
        inputs["observer"], "ok",
        inputs["critical"], "ok",
        inputs["final_owner"], "ok",
        inputs["final_safety"], "ok",
        inputs["master"], "ok",
        inputs["runtime_lock"], "ok",
        3, "ok",
        3, "ok",
        **kwargs,
    )


def run_self_test() -> int:
    # Resting state: emergency stop active -> BLOCKED_BY_EMERGENCY_STOP, no breach.
    rest = _report_from(_base_inputs())
    if rest["readiness_status"] != STATUS_BLOCKED_BY_EMERGENCY_STOP or rest["readiness_breach"]:
        raise AssertionError("emergency stop should block but not breach")
    if rest["low_risk_autonomy_allowed_now"] or rest["low_risk_policy_draft_allowed"]:
        raise AssertionError("autonomy/policy must not be allowed under emergency stop")

    # Emergency stop cleared, manual recheck NOT recommended -> NOT_READY, no breach.
    not_ready_inputs = _base_inputs(
        runtime_lock={"emergency_stop": False},
        critical={"snapshot_breach": False, "autonomy_total_breaches": 0, "emergency_stop_active": False},
        final_owner={"snapshot_breach": False, "total_breaches": 0, "emergency_stop_active": False},
        manual_recheck_gate=dict(_base_inputs()["manual_recheck_gate"], emergency_stop_active=False, manual_recheck_recommended=False),
    )
    not_ready = _report_from(not_ready_inputs)
    if not_ready["readiness_status"] != STATUS_NOT_READY or not_ready["readiness_breach"]:
        raise AssertionError("manual_recheck_recommended=false should be NOT_READY, no breach")

    # Emergency stop cleared, manual recheck recommended -> POLICY_DRAFT_ONLY (max), no breach.
    ready_inputs = _base_inputs(
        runtime_lock={"emergency_stop": False},
        critical={"snapshot_breach": False, "autonomy_total_breaches": 0, "emergency_stop_active": False},
        final_owner={"snapshot_breach": False, "total_breaches": 0, "emergency_stop_active": False},
        manual_recheck_gate=dict(_base_inputs()["manual_recheck_gate"], emergency_stop_active=False, manual_recheck_recommended=True),
    )
    ready = _report_from(ready_inputs)
    if ready["readiness_status"] != STATUS_POLICY_DRAFT_ONLY or ready["readiness_breach"]:
        raise AssertionError("manual_recheck_recommended=true should top out at POLICY_DRAFT_ONLY")
    if not ready["low_risk_policy_draft_allowed"] or ready["low_risk_autonomy_allowed_now"]:
        raise AssertionError("policy draft allowed but autonomy must stay disallowed")

    # Owner policy review explicitly ready -> OWNER_POLICY_REVIEW, still no apply.
    review = _report_from(ready_inputs, forced_flags={"owner_policy_review_ready": True})
    if review["readiness_status"] != STATUS_OWNER_POLICY_REVIEW or review["low_risk_autonomy_allowed_now"]:
        raise AssertionError("owner policy review path failed")

    # Upstream breach -> BLOCKED_BY_BREACH, breach=true.
    for key in (
        ("manual_recheck_gate", "gate_breach"),
        ("timeline", "snapshot_breach"),
        ("observer", "snapshot_breach"),
        ("critical", "snapshot_breach"),
        ("final_owner", "snapshot_breach"),
        ("final_safety", "final_safety_breach"),
    ):
        block, field = key
        inputs = _base_inputs()
        inputs[block] = dict(inputs[block], **{field: True})
        bad = _report_from(inputs)
        if bad["readiness_status"] != STATUS_BLOCKED_BY_BREACH or not bad["readiness_breach"]:
            raise AssertionError(f"upstream breach {block}.{field} did not block-by-breach")

    # autonomy_total_breaches > 0 -> BLOCKED_BY_BREACH.
    inputs = _base_inputs()
    inputs["critical"] = dict(inputs["critical"], autonomy_total_breaches=2)
    breaches = _report_from(inputs)
    if breaches["readiness_status"] != STATUS_BLOCKED_BY_BREACH or breaches["autonomy_total_breaches"] != 2:
        raise AssertionError("autonomy_total_breaches>0 did not block-by-breach")

    # Direct breach flags -> LOW_RISK_AUTONOMY_BREACH, breach=true (win over emergency stop).
    for flag in (
        "low_risk_autonomy_allowed_now",
        "live_apply",
        "install_allowed_now",
        "can_install_timer_now",
        "forbidden_apply_command_detected",
        "systemd_file_written",
        "crontab_file_written",
        "executable_install_script_generated",
        "secret_like_output",
        "output_path_breach",
    ):
        bad = _report_from(_base_inputs(), forced_flags={flag: True})
        if not bad["readiness_breach"] or bad["readiness_status"] != STATUS_BREACH:
            raise AssertionError(f"direct breach flag {flag} did not produce BREACH")

    bad_apply = _report_from(_base_inputs(), forced_flags={"apply_status": "applied"})
    if not bad_apply["readiness_breach"] or bad_apply["readiness_status"] != STATUS_BREACH:
        raise AssertionError("apply_status != not_applied did not breach")

    # Even on breach the hard-coded safe constants must remain safe.
    bad = _report_from(_base_inputs(), forced_flags={"live_apply": True})
    for must_be_false in ("low_risk_autonomy_allowed_now", "install_allowed_now", "can_install_timer_now", "live_apply"):
        if bad[must_be_false]:
            raise AssertionError(f"{must_be_false} must always be False in report")
    if bad["apply_status"] != APPLY_NOT_APPLIED:
        raise AssertionError("apply_status must always be not_applied in report")

    # Partial inputs (missing manual recheck gate), emergency stop cleared
    # everywhere -> PARTIAL_INPUTS, no breach.
    no_estop = _base_inputs(
        critical={"snapshot_breach": False, "autonomy_total_breaches": 0, "emergency_stop_active": False},
        final_owner={"snapshot_breach": False, "total_breaches": 0, "emergency_stop_active": False},
    )
    partial = build_report(
        None, "not_available",
        no_estop["timeline"], "ok",
        no_estop["observer"], "ok",
        no_estop["critical"], "ok",
        no_estop["final_owner"], "ok",
        no_estop["final_safety"], "ok",
        no_estop["master"], "ok",
        {"emergency_stop": False}, "ok",
        0, "not_available",
        0, "not_available",
    )
    if partial["readiness_status"] != STATUS_PARTIAL_INPUTS or partial["readiness_breach"]:
        raise AssertionError("partial inputs failed")

    # Missing inputs must not crash.
    crashless = build_report(
        None, "not_available", None, "not_available", None, "not_available",
        None, "not_available", None, "not_available", None, "not_available",
        None, "not_available", None, "not_available", 0, "not_available", 0, "not_available",
    )
    if not crashless["read_only"]:
        raise AssertionError("crashless run lost read_only")

    # Detector sanity.
    if not FORBIDDEN_APPLY_COMMAND_RE.search("cloudflare api update"):
        raise AssertionError("forbidden command detector failed")
    if not detect_secret_like("token=abc12345"):
        raise AssertionError("secret detector failed")
    for forbidden in (
        PROJECT_DIR / "reports/latest/bad.sh",
        PROJECT_DIR / "drafts/owner/bad.service",
        PROJECT_DIR / "snapshots/bad.timer",
        PROJECT_DIR / "audit/bad.py",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden artifact was not rejected: {forbidden}")
    try:
        assert_allowed_write(PROJECT_DIR / "config/low-risk-autonomy-readiness-gate.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write root was not rejected")

    # Markdown must render the five separated dimensions without raising.
    md = render_markdown(rest)
    for needed in ("Autonomy Safety", "Website Recheck Readiness", "Rolling Window Stability", "Emergency Stop", "Install / Apply Locks"):
        if needed not in md:
            raise AssertionError(f"markdown missing section: {needed}")
    print("low-risk-autonomy-readiness-gate self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Low-Risk Autonomy Readiness Gate; read-only, no apply.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "Low-Risk Autonomy Readiness Gate: "
        f"status={report.get('readiness_status')}, "
        f"allowed_now={report.get('low_risk_autonomy_allowed_now')}, "
        f"policy_draft_allowed={report.get('low_risk_policy_draft_allowed')}, "
        f"breach={report.get('readiness_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
