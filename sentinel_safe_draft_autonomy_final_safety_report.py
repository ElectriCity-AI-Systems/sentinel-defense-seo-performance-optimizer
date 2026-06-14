#!/usr/bin/env python3
"""Sentinel Safe Draft Autonomy Final Safety Report (Phase 4.5).

Consolidates all Safe-Draft-Autonomy phases from the Safe Apply Registry to
the Owner Timer Install Evidence Pack into one final safety/readiness report.

This is not an installation, not an active timer, and not an apply mechanism.
It never executes systemctl, never writes systemd or crontab files, never
generates shell scripts, and never performs live changes.

Hard safety guarantees:
- No live changes and no live-apply function.
- No WordPress, .htaccess, Cloudflare, Nginx, DNS, API, login, or network work.
- apply_status stays not_applied; can_execute_live, can_install_timer_now, and
  install_allowed_now stay false.
- Writes are confined to drafts/owner, reports/latest, and audit.
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

INPUT_PHASES = [
    ("safe_apply_registry", "Safe Apply Candidate Registry", PROJECT_DIR / "reports/latest/safe-apply-candidate-registry-report.json", ("registry_breach",)),
    ("safe_apply_guard", "Safe Apply Guard Check", PROJECT_DIR / "reports/latest/safe-apply-guard-check-report.json", ("guard_breach",)),
    ("safe_apply_scope", "Safe Apply Scope Allowlist", PROJECT_DIR / "reports/latest/safe-apply-scope-allowlist-report.json", ("scope_breach",)),
    ("safe_apply_dry_run", "Safe Apply Dry Run Plan", PROJECT_DIR / "reports/latest/safe-apply-dry-run-plan-report.json", ("dry_run_breach",)),
    ("safe_apply_preflight", "Safe Apply Preflight Validation", PROJECT_DIR / "reports/latest/safe-apply-preflight-validation-report.json", ("preflight_breach",)),
    ("autonomy_runtime_lock", "Autonomy Runtime Lock", PROJECT_DIR / "reports/latest/autonomy-runtime-lock-report.json", ("runtime_lock_breach",)),
    ("safe_draft_runner", "Safe Draft Autonomy Runner", PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.json", ("runner_breach",)),
    ("safe_draft_verifier", "Safe Draft Autonomy Verifier", PROJECT_DIR / "reports/latest/safe-draft-autonomy-verifier-report.json", ("verifier_breach",)),
    ("safe_draft_scheduler", "Safe Draft Autonomy Scheduler Plan", PROJECT_DIR / "reports/latest/safe-draft-autonomy-scheduler-plan.json", ("scheduler_breach",)),
    ("safe_draft_timer_draft", "Safe Draft Autonomy Timer Draft", PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-draft-report.json", ("timer_draft_breach",)),
    ("safe_draft_timer_install_review", "Safe Draft Autonomy Timer Install Review", PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-install-review-report.json", ("install_reviewer_breach",)),
    ("owner_manual_timer_packet", "Owner Manual Timer Install Packet", PROJECT_DIR / "reports/latest/owner-manual-timer-install-packet-report.json", ("packet_breach",)),
    ("owner_timer_decision_gate", "Owner Timer Install Decision Gate", PROJECT_DIR / "reports/latest/owner-timer-install-decision-gate-report.json", ("decision_breach",)),
    ("manual_timer_command_preview", "Manual Timer Install Command Preview", PROJECT_DIR / "reports/latest/manual-timer-install-command-preview-report.json", ("preview_breach",)),
    ("owner_timer_evidence_pack", "Owner Timer Install Evidence Pack", PROJECT_DIR / "reports/latest/owner-timer-install-evidence-pack-report.json", ("evidence_pack_breach",)),
]

INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
INPUT_RUNTIME_LOCK_CONFIG = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_OWNER_DECISION_CONFIG = PROJECT_DIR / "config/owner-timer-install-decision.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.md"
OWNER_SUMMARY_MD = PROJECT_DIR / "drafts/owner/safe-draft-autonomy-final-owner-summary.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-draft-autonomy-final-safety-report.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, OWNER_SUMMARY_MD, AUDIT_JSONL)
FORBIDDEN_OUTPUT_SUFFIXES = (".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".bin", ".run")
FORBIDDEN_INSTALL_PATH_TOKENS = (
    "/etc/systemd",
    "systemd/system",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/etc/cron",
    "cron.d",
    "crontab",
)

SCHEMA_VERSION = "safe-draft-autonomy-final-safety-report-4.5"
APPLY_NOT_APPLIED = "not_applied"

STATUS_SAFETY_REVIEW_REQUIRED = "SAFETY_REVIEW_REQUIRED"
STATUS_LOCKED_EMERGENCY = "SAFE_BUT_LOCKED_BY_EMERGENCY_STOP"
STATUS_DRAFT_READY = "SAFE_DRAFT_ONLY_AUTONOMY_READY"
STATUS_DRAFT_NOT_READY = "SAFE_DRAFT_ONLY_AUTONOMY_NOT_READY"

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
ENV_SECRET_RE = re.compile(
    r"(?im)^\s*Environment=\s*[\"']?[A-Za-z0-9_]*"
    r"(api[_-]?key|secret|token|password|passwd|bearer|credential|session|cookie|authorization)"
    r"[A-Za-z0-9_]*\s*=\s*"
    r"(?!false\b|true\b|null\b|none\b|<redacted)\S{4,}"
)


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
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def detect_secret_in_text(text: str) -> bool:
    if not text:
        return False
    return bool(ENV_SECRET_RE.search(text) or SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def within_allowed_roots(path: Path) -> bool:
    return any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS)


def assert_allowed_write(path: Path) -> None:
    if not within_allowed_roots(path):
        raise ValueError(f"Refusing to write outside allowed final-safety roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write an executable/automation artifact: {path}")


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


def read_optional_json(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    try:
        if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
            return None, "refused_secret_like_path"
        if path.suffix.lower() not in {".json"}:
            return None, "unsupported_suffix"
        if not path.exists():
            return None, "not_available"
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None, "read_error"
    return data if isinstance(data, dict) else None, "ok" if isinstance(data, dict) else "invalid_root"


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(value)


def _count(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _nested_summary(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(data, dict) and isinstance(data.get("summary"), dict):
        return data["summary"]
    return {}


def _first_value(data: Optional[Dict[str, Any]], keys: List[str], default: Any = None) -> Any:
    if not isinstance(data, dict):
        return default
    summary = _nested_summary(data)
    for key in keys:
        if key in data:
            return data.get(key)
        if key in summary:
            return summary.get(key)
    return default


def _any_key_bool(data: Optional[Dict[str, Any]], keys: List[str]) -> bool:
    return any(_as_bool(_first_value(data, [key])) for key in keys)


def _apply_status(data: Optional[Dict[str, Any]]) -> str:
    return str(_first_value(data, ["apply_status"], APPLY_NOT_APPLIED) or APPLY_NOT_APPLIED)


def phase_breach(data: Optional[Dict[str, Any]], explicit_breach_keys: Tuple[str, ...]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    for key in explicit_breach_keys:
        if _as_bool(_first_value(data, [key])):
            reasons.append(f"{key}=true")
    if isinstance(data, dict):
        summary = _nested_summary(data)
        for source in (data, summary):
            for key, value in source.items():
                if key.endswith("_breach") and _as_bool(value) and f"{key}=true" not in reasons:
                    reasons.append(f"{key}=true")
    forbidden_flags = [
        "install_allowed_now",
        "can_install_timer_now",
        "live_apply",
        "can_execute_live",
        "systemd_file_written",
        "crontab_file_written",
        "shell_script_generated",
        "network_access",
        "api_access",
        "wordpress_login",
        "productive_change",
    ]
    for key in forbidden_flags:
        if _as_bool(_first_value(data, [key])):
            reasons.append(f"{key}=true")
    if _apply_status(data) != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
    return bool(reasons), reasons


def phase_status_text(data: Optional[Dict[str, Any]]) -> str:
    for key in ("final_safety_status", "evidence_pack_status", "preview_status", "gate_status", "packet_status", "install_review_status", "timer_draft_status", "scheduler_status", "verifier_status", "runner_status", "status"):
        value = _first_value(data, [key])
        if value is not None:
            return redact_text(value, max_len=120)
    return "NOT_AVAILABLE"


def summarize_phase(phase_id: str, title: str, data: Optional[Dict[str, Any]], status: str, breach_keys: Tuple[str, ...], path: Path) -> Dict[str, Any]:
    if status != "ok" or not isinstance(data, dict):
        return {
            "phase_id": phase_id,
            "title": title,
            "present": False,
            "path": str(path),
            "status": "NOT_AVAILABLE",
            "input_status": status,
            "breach": False,
            "live_apply": False,
            "productive_change": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "can_execute_live": False,
            "apply_status": APPLY_NOT_APPLIED,
            "blocked": False,
            "safety_interpretation": "not_available; missing input does not create a breach",
            "breach_reasons": [],
        }
    breach, reasons = phase_breach(data, breach_keys)
    status_text = phase_status_text(data)
    blocked = "BLOCKED" in status_text.upper()
    interpretation = (
        "breach detected; manual safety review required"
        if breach
        else "blocked/review-only; no breach"
        if blocked
        else "safe/read-only or draft-only phase; no breach"
    )
    return {
        "phase_id": phase_id,
        "title": title,
        "present": True,
        "path": str(path),
        "status": status_text,
        "input_status": status,
        "breach": breach,
        "live_apply": _as_bool(_first_value(data, ["live_apply", "live_apply_enabled"])),
        "productive_change": _as_bool(_first_value(data, ["productive_change"])),
        "install_allowed_now": _as_bool(_first_value(data, ["install_allowed_now"])),
        "can_install_timer_now": _as_bool(_first_value(data, ["can_install_timer_now"])),
        "can_execute_live": _as_bool(_first_value(data, ["can_execute_live"])),
        "systemd_file_written": _as_bool(_first_value(data, ["systemd_file_written"])),
        "crontab_file_written": _as_bool(_first_value(data, ["crontab_file_written"])),
        "shell_script_generated": _as_bool(_first_value(data, ["shell_script_generated"])),
        "network_access": _as_bool(_first_value(data, ["network_access"])),
        "api_access": _as_bool(_first_value(data, ["api_access"])),
        "wordpress_login": _as_bool(_first_value(data, ["wordpress_login"])),
        "apply_status": _apply_status(data),
        "blocked": blocked,
        "safety_interpretation": interpretation,
        "breach_reasons": reasons,
    }


def compute_final_breach(
    phases: List[Dict[str, Any]],
    output_paths: List[str],
    output_texts: Optional[List[str]] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, List[str]]:
    flags = forced_flags or {}
    reasons: List[str] = []
    for phase in phases:
        if phase.get("breach"):
            reasons.append(f"{phase.get('phase_id')}: phase breach")
        for key in (
            "install_allowed_now",
            "can_install_timer_now",
            "live_apply",
            "can_execute_live",
            "systemd_file_written",
            "crontab_file_written",
            "shell_script_generated",
            "network_access",
            "api_access",
            "wordpress_login",
        ):
            if phase.get(key):
                reasons.append(f"{phase.get('phase_id')}: {key}=true")
        if phase.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append(f"{phase.get('phase_id')}: apply_status != not_applied")
    for key in (
        "install_allowed_now",
        "can_install_timer_now",
        "live_apply",
        "can_execute_live",
        "systemd_file_written",
        "crontab_file_written",
        "shell_script_generated",
        "network_access",
        "api_access",
        "wordpress_login",
    ):
        if flags.get(key):
            reasons.append(f"{key}=true")
    if flags.get("apply_status") and flags.get("apply_status") != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
    for raw in output_paths:
        path = Path(str(raw))
        lower = str(raw).lower()
        if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
            reasons.append(f"executable install artifact generated: {redact_text(raw, max_len=120)}")
        if any(token in lower for token in FORBIDDEN_INSTALL_PATH_TOKENS):
            reasons.append(f"output path looks like a systemd/cron install path: {redact_text(raw, max_len=120)}")
        if not within_allowed_roots(path):
            reasons.append(f"output path outside allowed roots: {redact_text(raw, max_len=120)}")
    for text in output_texts or []:
        if detect_secret_in_text(text):
            reasons.append("secret-like values detected in generated output")
            break
    return bool(reasons), reasons


def load_inputs() -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, str]]:
    statuses: Dict[str, str] = {}
    phases: List[Dict[str, Any]] = []
    raw_by_id: Dict[str, Dict[str, Any]] = {}
    for phase_id, title, path, breach_keys in INPUT_PHASES:
        data, status = read_optional_json(path)
        statuses[phase_id] = status
        if isinstance(data, dict):
            raw_by_id[phase_id] = data
        phases.append(summarize_phase(phase_id, title, data, status, breach_keys, path))
    master, master_status = read_optional_json(INPUT_MASTER)
    runtime_cfg, runtime_cfg_status = read_optional_json(INPUT_RUNTIME_LOCK_CONFIG)
    decision_cfg, decision_cfg_status = read_optional_json(INPUT_OWNER_DECISION_CONFIG)
    statuses["sentinel_master"] = master_status
    statuses["autonomy_runtime_lock_config"] = runtime_cfg_status
    statuses["owner_timer_install_decision_config"] = decision_cfg_status
    context = {
        "master": master if isinstance(master, dict) else {},
        "runtime_config": runtime_cfg if isinstance(runtime_cfg, dict) else {},
        "decision_config": decision_cfg if isinstance(decision_cfg, dict) else {},
        "raw_by_id": raw_by_id,
    }
    return phases, context, statuses


def context_bool(context: Dict[str, Any], phase_id: str, keys: List[str], default: bool = False) -> bool:
    raw = context.get("raw_by_id", {}).get(phase_id)
    if isinstance(raw, dict):
        value = _first_value(raw, keys)
        if value is not None:
            return _as_bool(value)
    for source_key in ("runtime_config", "decision_config"):
        source = context.get(source_key)
        if isinstance(source, dict):
            value = _first_value(source, keys)
            if value is not None:
                return _as_bool(value)
    return default


def context_text(context: Dict[str, Any], phase_id: str, keys: List[str], default: str = "-") -> str:
    raw = context.get("raw_by_id", {}).get(phase_id)
    if isinstance(raw, dict):
        value = _first_value(raw, keys)
        if value is not None:
            return redact_text(value, default=default, max_len=160)
    for source_key in ("runtime_config", "decision_config"):
        source = context.get(source_key)
        if isinstance(source, dict):
            value = _first_value(source, keys)
            if value is not None:
                return redact_text(value, default=default, max_len=160)
    return default


def build_report(
    phases: List[Dict[str, Any]],
    context: Dict[str, Any],
    input_statuses: Dict[str, str],
    timestamp: Optional[str] = None,
    output_texts: Optional[List[str]] = None,
    output_paths: Optional[List[str]] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = timestamp or utc_now()
    paths = output_paths or [str(path) for path in ALLOWED_OUTPUT_PATHS]
    final_breach, breach_reasons = compute_final_breach(phases, paths, output_texts=output_texts, forced_flags=forced_flags)
    emergency_stop = context_bool(context, "autonomy_runtime_lock", ["emergency_stop"], True)
    draft_only_enabled = context_bool(context, "autonomy_runtime_lock", ["draft_only_enabled"], False)
    verifier_status = context_text(context, "safe_draft_verifier", ["verifier_status", "status"], "NOT_AVAILABLE")
    runner_status = context_text(context, "safe_draft_runner", ["runner_status", "status"], "NOT_AVAILABLE")
    draft_only_runner_verified = (
        not final_breach
        and ("VERIFIED_SAFE" in verifier_status.upper() or "SAFE" in verifier_status.upper())
        and runner_status != "NOT_AVAILABLE"
    )
    draft_only_autonomy_ready = bool(draft_only_enabled and not final_breach)
    decision_status = context_text(context, "owner_timer_decision_gate", ["decision_status"], "not_reviewed")
    manual_install_allowed = context_bool(context, "owner_timer_decision_gate", ["manual_install_allowed"], False)
    timer_installation_ready_for_owner_review = bool(
        decision_status == "reviewed_ready_for_manual_install"
        and manual_install_allowed
        and not final_breach
    )
    if final_breach:
        final_status = STATUS_SAFETY_REVIEW_REQUIRED
    elif emergency_stop:
        final_status = STATUS_LOCKED_EMERGENCY
    elif draft_only_enabled:
        final_status = STATUS_DRAFT_READY
    else:
        final_status = STATUS_DRAFT_NOT_READY

    if final_breach:
        recommended = "stop and review breach."
    elif emergency_stop:
        if timer_installation_ready_for_owner_review:
            recommended = "keep stopped; do not install; keep review documents only. Next phase: Manual Evidence Review Dashboard."
        else:
            recommended = "keep stopped or consciously enable draft-only for test."
    elif draft_only_enabled and draft_only_runner_verified:
        recommended = "optionally run draft-only safe cycle."
    elif timer_installation_ready_for_owner_review:
        recommended = "do not install automatically; continue with Manual Evidence Review Dashboard."
    else:
        recommended = "review missing safe-draft readiness inputs before any next step."

    total_phase_count = len(phases)
    total_breach_count = sum(1 for phase in phases if phase.get("breach"))
    blocked_phase_count = sum(1 for phase in phases if phase.get("blocked"))
    safe_phase_count = sum(1 for phase in phases if phase.get("present") and not phase.get("breach") and not phase.get("blocked"))
    summary = {
        "final_safety_status": final_status,
        "draft_only_autonomy_ready": draft_only_autonomy_ready,
        "draft_only_runner_verified": draft_only_runner_verified,
        "timer_installation_ready_for_owner_review": timer_installation_ready_for_owner_review,
        "timer_installation_allowed_now": False,
        "live_apply_allowed": False,
        "can_execute_live": False,
        "can_install_timer_now": False,
        "emergency_stop_active": emergency_stop,
        "total_breach_count": total_breach_count,
        "total_phase_count": total_phase_count,
        "safe_phase_count": safe_phase_count,
        "blocked_phase_count": blocked_phase_count,
        "final_safety_breach": final_breach,
        "final_safety_breach_reasons": breach_reasons,
        "final_recommended_owner_action": recommended,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": final_status,
        "final_safety_status": final_status,
        "draft_only_autonomy_ready": draft_only_autonomy_ready,
        "draft_only_runner_verified": draft_only_runner_verified,
        "timer_installation_ready_for_owner_review": timer_installation_ready_for_owner_review,
        "timer_installation_allowed_now": False,
        "live_apply_allowed": False,
        "can_execute_live": False,
        "can_install_timer_now": False,
        "install_allowed_now": False,
        "emergency_stop_active": emergency_stop,
        "total_breach_count": total_breach_count,
        "total_phase_count": total_phase_count,
        "safe_phase_count": safe_phase_count,
        "blocked_phase_count": blocked_phase_count,
        "final_safety_breach": final_breach,
        "final_safety_breach_reasons": breach_reasons,
        "final_recommended_owner_action": recommended,
        "draft_only_enabled": draft_only_enabled,
        "decision_status": decision_status,
        "manual_install_allowed": manual_install_allowed,
        "apply_status": APPLY_NOT_APPLIED,
        "live_apply": False,
        "productive_change": False,
        "network_access": False,
        "api_access": False,
        "wordpress_login": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "shell_script_generated": False,
        "phases": phases,
        "input_statuses": input_statuses,
        "summary": summary,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_summary_md": str(OWNER_SUMMARY_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
        "safety": {
            "no_live_changes": True,
            "systemctl_executed": False,
            "systemd_file_written": False,
            "crontab_file_written": False,
            "shell_script_generated": False,
            "cloudflare_mutation": False,
            "nginx_change": False,
            "htaccess_change": False,
            "secrets_output": False,
        },
    }


def render_markdown(report: Dict[str, Any], owner_summary: bool = False) -> str:
    title = "Safe Draft Autonomy Final Owner Summary" if owner_summary else "Safe Draft Autonomy Final Safety Report"
    lines = [
        f"# {title}",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Final safety status: `{report.get('final_safety_status')}`",
        f"- Draft-only autonomy ready: `{report.get('draft_only_autonomy_ready')}`",
        f"- Draft-only runner verified: `{report.get('draft_only_runner_verified')}`",
        f"- Timer installation ready for owner review: `{report.get('timer_installation_ready_for_owner_review')}`",
        f"- Timer installation allowed now: `{report.get('timer_installation_allowed_now')}`",
        f"- Live apply allowed: `{report.get('live_apply_allowed')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Total breaches: `{report.get('total_breach_count')}` / `{report.get('total_phase_count')}` phases",
        f"- Final safety breach: `{report.get('final_safety_breach')}`",
        f"- Final recommended owner action: `{redact_text(report.get('final_recommended_owner_action'), max_len=260)}`",
        "",
        "## Phase Summary",
        "",
        "| Phase | Status | Breach | Install Now | Can Install | Live Apply | Apply Status | Interpretation |",
        "|---|---|---:|---:|---:|---:|---|---|",
    ]
    for phase in report.get("phases", []):
        if not isinstance(phase, dict):
            continue
        lines.append(
            f"| {redact_text(phase.get('title'), max_len=80)} | "
            f"`{redact_text(phase.get('status'), max_len=80)}` | "
            f"`{phase.get('breach')}` | "
            f"`{phase.get('install_allowed_now')}` | "
            f"`{phase.get('can_install_timer_now')}` | "
            f"`{phase.get('live_apply')}` | "
            f"`{redact_text(phase.get('apply_status'), max_len=40)}` | "
            f"{redact_text(phase.get('safety_interpretation'), max_len=120)} |"
        )
    lines.extend(
        [
            "",
            "## Safety Boundaries",
            "",
            "- Keine Installation, kein aktiver Timer, kein Apply-Mechanismus.",
            "- `timer_installation_allowed_now=false`, `live_apply_allowed=false`, `can_execute_live=false`, `can_install_timer_now=false`.",
            "- Keine systemd-/crontab-/Shell-Dateien werden erzeugt.",
            "- Schreibzugriff nur unter drafts/owner, reports/latest, audit.",
            "",
        ]
    )
    return "\n".join(lines)


def rendered_output_texts(report: Dict[str, Any]) -> List[str]:
    return [
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        render_markdown(report),
        render_markdown(report, owner_summary=True),
    ]


def mark_secret_output_breach(report: Dict[str, Any]) -> Dict[str, Any]:
    if not any(detect_secret_in_text(text) for text in rendered_output_texts(report)):
        return report
    updated = dict(report)
    reasons = list(updated.get("final_safety_breach_reasons") if isinstance(updated.get("final_safety_breach_reasons"), list) else [])
    reason = "secret-like values detected in generated output"
    if reason not in reasons:
        reasons.append(reason)
    updated["final_safety_breach"] = True
    updated["final_safety_breach_reasons"] = reasons
    updated["final_safety_status"] = STATUS_SAFETY_REVIEW_REQUIRED
    updated["status"] = STATUS_SAFETY_REVIEW_REQUIRED
    summary = dict(updated.get("summary") if isinstance(updated.get("summary"), dict) else {})
    summary["final_safety_breach"] = True
    summary["final_safety_breach_reasons"] = reasons
    summary["final_safety_status"] = STATUS_SAFETY_REVIEW_REQUIRED
    updated["summary"] = summary
    safety = dict(updated.get("safety") if isinstance(updated.get("safety"), dict) else {})
    safety["secrets_output"] = True
    updated["safety"] = safety
    return updated


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "record_type": "safe_draft_autonomy_final_safety_report",
        "final_safety_status": report.get("final_safety_status"),
        "draft_only_autonomy_ready": report.get("draft_only_autonomy_ready"),
        "timer_installation_allowed_now": report.get("timer_installation_allowed_now"),
        "live_apply_allowed": report.get("live_apply_allowed"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "total_breach_count": report.get("total_breach_count"),
        "final_safety_breach": report.get("final_safety_breach"),
        "live_apply": False,
        "productive_change": False,
        "network_access": False,
    }


def write_outputs(report: Dict[str, Any]) -> Dict[str, Any]:
    report = mark_secret_output_breach(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report))
    write_text_atomic(OWNER_SUMMARY_MD, render_markdown(report, owner_summary=True))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])
    return report


def _phase(**overrides: Any) -> Dict[str, Any]:
    phase = {
        "phase_id": "test_phase",
        "title": "Test Phase",
        "present": True,
        "status": "OK",
        "breach": False,
        "live_apply": False,
        "productive_change": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "can_execute_live": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "shell_script_generated": False,
        "network_access": False,
        "api_access": False,
        "wordpress_login": False,
        "apply_status": APPLY_NOT_APPLIED,
        "blocked": False,
        "safety_interpretation": "safe",
        "breach_reasons": [],
    }
    phase.update(overrides)
    return phase


def _context(**overrides: Any) -> Dict[str, Any]:
    context = {
        "runtime_config": {"emergency_stop": False, "draft_only_enabled": True},
        "decision_config": {"decision_status": "reviewed_ready_for_manual_install", "manual_install_allowed": True},
        "raw_by_id": {
            "autonomy_runtime_lock": {"emergency_stop": False, "draft_only_enabled": True},
            "safe_draft_verifier": {"verifier_status": "VERIFIED_SAFE"},
            "safe_draft_runner": {"runner_status": "EXECUTED"},
            "owner_timer_decision_gate": {"decision_status": "reviewed_ready_for_manual_install", "manual_install_allowed": True},
        },
    }
    context.update(overrides)
    return context


def _report(phases: Optional[List[Dict[str, Any]]] = None, context: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return build_report(
        phases or [_phase()],
        context or _context(),
        {"test": "ok"},
        timestamp="2026-06-11T00:00:00Z",
        **kwargs,
    )


def run_self_test() -> int:
    ready = _report()
    if ready["final_safety_status"] != STATUS_DRAFT_READY:
        raise AssertionError("safe draft-only status not detected")
    if ready["timer_installation_allowed_now"] or ready["live_apply_allowed"]:
        raise AssertionError("final report must never allow timer install/live apply")
    locked = _report(context=_context(raw_by_id={"autonomy_runtime_lock": {"emergency_stop": True, "draft_only_enabled": True}}))
    if locked["final_safety_status"] != STATUS_LOCKED_EMERGENCY or locked["final_safety_breach"]:
        raise AssertionError("emergency stop must lock without breach")

    for key in (
        "install_allowed_now",
        "can_install_timer_now",
        "live_apply",
        "can_execute_live",
        "systemd_file_written",
        "crontab_file_written",
        "shell_script_generated",
        "network_access",
        "api_access",
        "wordpress_login",
    ):
        if not _report([_phase(**{key: True})])["final_safety_breach"]:
            raise AssertionError(f"phase {key}=true did not breach")
        if not _report(forced_flags={key: True})["final_safety_breach"]:
            raise AssertionError(f"forced {key}=true did not breach")
    if not _report([_phase(apply_status="applied")])["final_safety_breach"]:
        raise AssertionError("phase apply_status != not_applied did not breach")
    if not _report([_phase(breach=True)])["final_safety_breach"]:
        raise AssertionError("any phase breach did not breach")
    if not _report(output_paths=["drafts/owner/install.sh"])["final_safety_breach"]:
        raise AssertionError("executable install artifact did not breach")
    if not _report(output_paths=["/etc/systemd/system/x.service"])["final_safety_breach"]:
        raise AssertionError("systemd output path did not breach")
    if not _report(output_paths=["/tmp/final.json"])["final_safety_breach"]:
        raise AssertionError("outside output path did not breach")
    if not _report(output_texts=["token=0123456789abcdef"])["final_safety_breach"]:
        raise AssertionError("secret-like output did not breach")
    missing_phase = summarize_phase("missing", "Missing", None, "not_available", ("missing_breach",), PROJECT_DIR / "reports/latest/missing.json")
    missing = _report([missing_phase])
    if missing["final_safety_breach"]:
        raise AssertionError("missing inputs must not breach")
    for path in ALLOWED_OUTPUT_PATHS:
        assert_allowed_write(path)
    for bad in (Path("/etc/systemd/system/x.timer"), PROJECT_DIR / "drafts/owner/install.sh"):
        try:
            assert_allowed_write(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {bad}")
    print("safe-draft-autonomy-final-safety-report self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build final Safe-Draft-Autonomy safety consolidation report; no install, no live apply."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    phases, context, statuses = load_inputs()
    report = build_report(phases, context, statuses)
    report = write_outputs(report)
    print(
        "Safe Draft Autonomy Final Safety Report: "
        f"status={report.get('final_safety_status')}, "
        f"draft_ready={report.get('draft_only_autonomy_ready')}, "
        f"timer_allowed={report.get('timer_installation_allowed_now')}, "
        f"live_apply={report.get('live_apply_allowed')}, "
        f"emergency_stop={report.get('emergency_stop_active')}, "
        f"breaches={report.get('total_breach_count')}, "
        f"breach={report.get('final_safety_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
