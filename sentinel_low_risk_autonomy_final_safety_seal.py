#!/usr/bin/env python3
"""LOW-RISK Autonomy Final Safety Seal (Phase 5.9).

Read-only final safety closure of the LOW-RISK preparation chain. The seal only
documents that the preparation artifacts exist, Emergency Stop is active, no
activation is allowed, no live apply, no installation, and no breaches. It
applies nothing and never changes the Master status.
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

POLICY_BOUNDARY_JSON = PROJECT_DIR / "reports/latest/low-risk-policy-boundary-draft.json"
TRACKER_JSON = PROJECT_DIR / "reports/latest/low-risk-policy-owner-review-tracker.json"
COMPLETION_GATE_JSON = PROJECT_DIR / "reports/latest/low-risk-policy-review-completion-gate.json"
READINESS_GATE_JSON = PROJECT_DIR / "reports/latest/low-risk-autonomy-readiness-gate.json"
FINAL_OWNER_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json"
FINAL_SAFETY_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
RUNTIME_LOCK_JSON = PROJECT_DIR / "config/autonomy-runtime-lock.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/low-risk-autonomy-final-safety-seal.json"
REPORT_MD = PROJECT_DIR / "reports/latest/low-risk-autonomy-final-safety-seal.md"
OWNER_MD = PROJECT_DIR / "drafts/owner/low-risk-autonomy-final-safety-seal.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/low-risk-autonomy-final-safety-seal.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/low-risk-autonomy-final-safety-seal.md"
AUDIT_JSONL = PROJECT_DIR / "audit/low-risk-autonomy-final-safety-seal.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, OWNER_MD, SNAPSHOT_JSON, SNAPSHOT_MD, AUDIT_JSONL)
FORBIDDEN_OUTPUT_SUFFIXES = (".sh", ".bash", ".zsh", ".service", ".timer", ".run", ".bin", ".py")
FORBIDDEN_INSTALL_PATH_TOKENS = ("/etc/systemd", "systemd/system", "/lib/systemd", "/usr/lib/systemd", "/etc/cron", "cron.d", "crontab")

SCHEMA_VERSION = "low-risk-autonomy-final-safety-seal-5.9"
APPLY_NOT_APPLIED = "not_applied"

STATUS_COMPLETE_LOCKED = "LOW_RISK_AUTONOMY_FINAL_SEAL_COMPLETE_LOCKED"
STATUS_INCOMPLETE = "LOW_RISK_AUTONOMY_FINAL_SEAL_INCOMPLETE"
STATUS_BLOCKED_BY_BREACH = "LOW_RISK_AUTONOMY_FINAL_SEAL_BLOCKED_BY_BREACH"
STATUS_BREACH = "LOW_RISK_AUTONOMY_FINAL_SEAL_BREACH"

ACTION_BY_STATUS = {
    STATUS_COMPLETE_LOCKED: "LOW-RISK preparation complete and locked. Keep Emergency Stop active. Do not enable autonomy.",
    STATUS_INCOMPLETE: "Finish policy owner review before considering any further step.",
    STATUS_BLOCKED_BY_BREACH: "Do not proceed. Resolve breach first.",
    STATUS_BREACH: "Do not proceed. Resolve breach first.",
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
        raise ValueError(f"Refusing to write outside allowed final-seal roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install artifact: {path}")
    if any(token in str(path) for token in FORBIDDEN_INSTALL_PATH_TOKENS):
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


def bool_from(data: Optional[Any], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def parse_count(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def count_breach_flags(data: Optional[Any]) -> int:
    if not isinstance(data, dict):
        return 0
    return sum(1 for key, value in data.items() if key.lower().endswith("breach") and bool(value))


def detect_direct_breach(flags: Dict[str, Any]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if bool(flags.get("low_risk_autonomy_allowed_now", False)):
        reasons.append("low_risk_autonomy_allowed_now=true")
    if bool(flags.get("policy_activation_allowed", False)):
        reasons.append("policy_activation_allowed=true")
    if bool(flags.get("live_apply", False)):
        reasons.append("live_apply=true")
    if bool(flags.get("install_allowed_now", False)):
        reasons.append("install_allowed_now=true")
    if bool(flags.get("can_install_timer_now", False)):
        reasons.append("can_install_timer_now=true")
    if str(flags.get("apply_status", APPLY_NOT_APPLIED)) != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
    if bool(flags.get("forbidden_apply_command_detected", False)):
        reasons.append("Cloudflare/WordPress/Nginx/.htaccess apply command detected")
    if bool(flags.get("systemd_file_written", False)):
        reasons.append("systemd_file_written=true")
    if bool(flags.get("crontab_file_written", False)):
        reasons.append("crontab_file_written=true")
    if bool(flags.get("executable_install_script_generated", False)):
        reasons.append("executable install script generated")
    if bool(flags.get("secret_like_output", False)):
        reasons.append("secret-like output")
    if bool(flags.get("output_path_breach", False)):
        reasons.append("writing outside allowed roots")
    return bool(reasons), sorted(set(reasons))


def build_report(
    policy: Optional[Any],
    policy_status_read: str,
    tracker: Optional[Any],
    tracker_status_read: str,
    completion_gate: Optional[Any],
    completion_gate_status_read: str,
    readiness: Optional[Any],
    readiness_status_read: str,
    final_owner: Optional[Any],
    final_owner_status_read: str,
    final_safety: Optional[Any],
    final_safety_status_read: str,
    master: Optional[Any],
    master_status_read: str,
    runtime_lock: Optional[Any],
    runtime_lock_status_read: str,
    *,
    generated_at: Optional[str] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    flags = forced_flags or {}

    direct_breach, direct_reasons = detect_direct_breach(flags)

    upstream_reasons: List[str] = []
    total_breaches = 0
    for label, data in (
        ("policy_boundary_draft", policy),
        ("tracker", tracker),
        ("completion_gate", completion_gate),
        ("readiness_gate", readiness),
        ("final_owner_snapshot", final_owner),
        ("final_safety_report", final_safety),
    ):
        c = count_breach_flags(data)
        if c:
            upstream_reasons.append(f"{label}:breach=true")
            total_breaches += c
    upstream_breach = bool(upstream_reasons)

    reviewed_count = parse_count(completion_gate.get("reviewed_count")) if isinstance(completion_gate, dict) else 0
    total_required = parse_count(completion_gate.get("total_required")) if isinstance(completion_gate, dict) else 0
    if total_required <= 0:
        total_required = 8
    gate_complete_locked = bool_from(completion_gate, "all_required_reviewed") and (
        redact_text(completion_gate.get("gate_status") if isinstance(completion_gate, dict) else "", default="", max_len=120)
        == "LOW_RISK_POLICY_REVIEW_GATE_COMPLETE_LOCKED"
    )
    review_completed = gate_complete_locked and reviewed_count >= total_required

    emergency_stop_active = (
        bool_from(runtime_lock, "emergency_stop")
        or bool_from(completion_gate, "emergency_stop_active")
        or bool_from(policy, "emergency_stop_active")
        or bool_from(final_owner, "emergency_stop_active")
    )

    if direct_breach:
        seal_status, seal_breach = STATUS_BREACH, True
    elif upstream_breach:
        seal_status, seal_breach = STATUS_BLOCKED_BY_BREACH, True
    elif review_completed and emergency_stop_active:
        seal_status, seal_breach = STATUS_COMPLETE_LOCKED, False
    else:
        seal_status, seal_breach = STATUS_INCOMPLETE, False

    breach_reasons = sorted(set(direct_reasons + upstream_reasons))
    recommended_owner_action = ACTION_BY_STATUS.get(seal_status, ACTION_BY_STATUS[STATUS_INCOMPLETE])

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "seal_status": seal_status,
        "review_completed": review_completed,
        "reviewed_count": reviewed_count,
        "total_required": total_required,
        "emergency_stop_active": emergency_stop_active,
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "total_breaches": total_breaches,
        "seal_breach": seal_breach,
        "recommended_owner_action": recommended_owner_action,
        "seal_breach_reasons": breach_reasons,
        "documented_preparation": {
            "policy_boundary_draft_present": policy_status_read == "ok",
            "owner_review_tracker_present": tracker_status_read == "ok",
            "completion_gate_present": completion_gate_status_read == "ok",
            "readiness_gate_present": readiness_status_read == "ok",
            "final_owner_snapshot_present": final_owner_status_read == "ok",
            "final_safety_report_present": final_safety_status_read == "ok",
            "emergency_stop_active": emergency_stop_active,
            "no_activation_allowed": True,
            "no_live_apply": True,
            "no_installation": True,
            "no_breaches": not (direct_breach or upstream_breach),
        },
        "read_only": True,
        "network_access": False,
        "api_access": False,
        "cloudflare_mutations": False,
        "wordpress_mutations": False,
        "nginx_mutations": False,
        "htaccess_mutations": False,
        "systemd_file_written": bool(flags.get("systemd_file_written", False)),
        "crontab_file_written": bool(flags.get("crontab_file_written", False)),
        "executable_install_script_generated": bool(flags.get("executable_install_script_generated", False)),
        "secrets_output": False,
        "master_status_not_auto_changed": True,
        "input_statuses": {
            "low_risk_policy_boundary_draft": policy_status_read,
            "low_risk_policy_owner_review_tracker": tracker_status_read,
            "low_risk_policy_review_completion_gate": completion_gate_status_read,
            "low_risk_autonomy_readiness_gate": readiness_status_read,
            "final_owner_snapshot": final_owner_status_read,
            "safe_draft_autonomy_final_safety_report": final_safety_status_read,
            "sentinel_master_json": master_status_read,
            "runtime_lock": runtime_lock_status_read,
        },
        "safe_owner_next_actions": [
            recommended_owner_action,
            "This seal is read-only documentation; it enables no activation and applies nothing.",
            "Do not use this seal to change Master status automatically.",
        ],
        "do_not_apply_conditions": [
            "Do not activate LOW-RISK autonomy from this seal.",
            "Do not install timers or write systemd/crontab from this seal.",
            "Do not change WordPress, Nginx, .htaccess or Cloudflare from this seal.",
        ],
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_md": str(OWNER_MD),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# LOW-RISK Autonomy Final Safety Seal",
        "",
        "> Read-only documentation seal. It enables no activation and applies nothing.",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Seal status: `{report.get('seal_status')}`",
        f"- Review completed: `{report.get('review_completed')}`",
        f"- Reviewed: `{report.get('reviewed_count')}` / `{report.get('total_required')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- LOW-RISK autonomy allowed now: `{report.get('low_risk_autonomy_allowed_now')}`",
        f"- Policy activation allowed: `{report.get('policy_activation_allowed')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Total breaches: `{report.get('total_breaches')}`",
        f"- Seal breach: `{report.get('seal_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
        "## Documented Preparation",
        "",
    ]
    block = report.get("documented_preparation") if isinstance(report.get("documented_preparation"), dict) else {}
    for key, value in block.items():
        lines.append(f"- {key}: `{value}`")
    if report.get("seal_breach_reasons"):
        lines.extend(["", "## Breach Reasons", ""])
        for reason in report.get("seal_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=400)}")
    lines.extend(["", "## Safe Owner Next Actions", ""])
    for item in report.get("safe_owner_next_actions", []):
        lines.append(f"- {redact_text(item, max_len=700)}")
    lines.extend(["", "## Do Not Apply Conditions", ""])
    for item in report.get("do_not_apply_conditions", []):
        lines.append(f"- {redact_text(item, max_len=700)}")
    lines.append("")
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "seal_status": report.get("seal_status"),
        "review_completed": report.get("review_completed"),
        "reviewed_count": report.get("reviewed_count"),
        "total_required": report.get("total_required"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "total_breaches": report.get("total_breaches"),
        "seal_breach": report.get("seal_breach"),
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
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
    write_text_atomic(OWNER_MD, markdown)
    write_json_atomic(SNAPSHOT_JSON, report)
    write_text_atomic(SNAPSHOT_MD, markdown)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def build_current_report() -> Dict[str, Any]:
    policy, policy_status = read_optional_json(POLICY_BOUNDARY_JSON)
    tracker, tracker_status = read_optional_json(TRACKER_JSON)
    gate, gate_status = read_optional_json(COMPLETION_GATE_JSON)
    readiness, readiness_status = read_optional_json(READINESS_GATE_JSON)
    final_owner, final_owner_status = read_optional_json(FINAL_OWNER_SNAPSHOT_JSON)
    final_safety, final_safety_status = read_optional_json(FINAL_SAFETY_JSON)
    master, master_status = read_optional_json(MASTER_JSON)
    runtime_lock, runtime_lock_status = read_optional_json(RUNTIME_LOCK_JSON)
    return build_report(
        policy, policy_status, tracker, tracker_status, gate, gate_status, readiness, readiness_status,
        final_owner, final_owner_status, final_safety, final_safety_status, master, master_status,
        runtime_lock, runtime_lock_status,
    )


def _inputs(**overrides: Any) -> Dict[str, Any]:
    base = {
        "policy": {"emergency_stop_active": True, "policy_breach": False},
        "tracker": {"tracker_breach": False, "emergency_stop_active": True},
        "gate": {"reviewed_count": 0, "total_required": 8, "all_required_reviewed": False, "gate_status": "LOW_RISK_POLICY_REVIEW_GATE_IN_PROGRESS", "gate_breach": False, "emergency_stop_active": True},
        "readiness": {"readiness_breach": False, "emergency_stop_active": True},
        "final_owner": {"snapshot_breach": False, "emergency_stop_active": True},
        "final_safety": {"final_safety_breach": False},
        "master": {"overall_master_status": "CRITICAL"},
        "runtime_lock": {"emergency_stop": True},
    }
    base.update(overrides)
    return base


def _report(inputs: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
    return build_report(
        inputs["policy"], "ok", inputs["tracker"], "ok", inputs["gate"], "ok", inputs["readiness"], "ok",
        inputs["final_owner"], "ok", inputs["final_safety"], "ok", inputs["master"], "ok", inputs["runtime_lock"], "ok",
        **kwargs,
    )


def run_self_test() -> int:
    # Review not complete -> INCOMPLETE, no breach.
    incomplete = _report(_inputs())
    if incomplete["seal_status"] != STATUS_INCOMPLETE or incomplete["seal_breach"]:
        raise AssertionError("incomplete failed")

    # All reviewed + gate complete locked + emergency stop -> COMPLETE_LOCKED.
    done_gate = {"reviewed_count": 8, "total_required": 8, "all_required_reviewed": True, "gate_status": "LOW_RISK_POLICY_REVIEW_GATE_COMPLETE_LOCKED", "gate_breach": False, "emergency_stop_active": True}
    done = _report(_inputs(gate=done_gate))
    if done["seal_status"] != STATUS_COMPLETE_LOCKED or done["seal_breach"]:
        raise AssertionError("complete-locked failed")
    if not done["review_completed"] or done["low_risk_autonomy_allowed_now"] or done["policy_activation_allowed"]:
        raise AssertionError("complete-locked invariants failed")

    # Upstream breach -> BLOCKED_BY_BREACH.
    for block, field in (("policy", "policy_breach"), ("tracker", "tracker_breach"), ("gate", "gate_breach"), ("readiness", "readiness_breach"), ("final_owner", "snapshot_breach"), ("final_safety", "final_safety_breach")):
        inputs = _inputs()
        inputs[block] = dict(inputs[block], **{field: True})
        bad = _report(inputs)
        if bad["seal_status"] != STATUS_BLOCKED_BY_BREACH or not bad["seal_breach"] or bad["total_breaches"] < 1:
            raise AssertionError(f"upstream breach {block}.{field} failed")

    # Direct breach flags -> BREACH.
    for flag in ("low_risk_autonomy_allowed_now", "policy_activation_allowed", "live_apply", "install_allowed_now", "can_install_timer_now", "forbidden_apply_command_detected", "systemd_file_written", "crontab_file_written", "executable_install_script_generated", "secret_like_output", "output_path_breach"):
        bad = _report(_inputs(), forced_flags={flag: True})
        if not bad["seal_breach"] or bad["seal_status"] != STATUS_BREACH:
            raise AssertionError(f"flag {flag} did not breach")
    if not _report(_inputs(), forced_flags={"apply_status": "applied"})["seal_breach"]:
        raise AssertionError("apply_status breach failed")

    # Safe constants on breach.
    bad = _report(_inputs(), forced_flags={"live_apply": True})
    for k in ("low_risk_autonomy_allowed_now", "policy_activation_allowed", "install_allowed_now", "can_install_timer_now", "live_apply"):
        if bad[k]:
            raise AssertionError(f"{k} must be False")
    if bad["apply_status"] != APPLY_NOT_APPLIED:
        raise AssertionError("apply_status must be not_applied")

    # Missing inputs must not crash.
    crashless = build_report(None, "not_available", None, "not_available", None, "not_available", None, "not_available", None, "not_available", None, "not_available", None, "not_available", None, "not_available")
    if not crashless["read_only"] or crashless["seal_status"] != STATUS_INCOMPLETE:
        raise AssertionError("crashless run failed")

    for forbidden in (PROJECT_DIR / "reports/latest/bad.sh", PROJECT_DIR / "drafts/owner/bad.service", PROJECT_DIR / "config/x.json"):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden path not rejected: {forbidden}")
    if not detect_secret_like("token=abc12345"):
        raise AssertionError("secret detector failed")
    print("low-risk-autonomy-final-safety-seal self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build LOW-RISK Autonomy Final Safety Seal; read-only, no activation.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_current_report()
    write_outputs(report)
    print(
        "LOW-RISK Autonomy Final Safety Seal: "
        f"status={report.get('seal_status')}, "
        f"review_completed={report.get('review_completed')}, "
        f"breach={report.get('seal_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
