#!/usr/bin/env python3
"""Sentinel Manual Evidence Review Dashboard (Phase 4.6).

Builds a local owner dashboard from Safe-Draft-Autonomy, timer review, command
preview, evidence pack, runtime lock, master, and website reports.

This is not an installation, not an active timer, and not an apply mechanism.
It never executes commands, never writes systemd/crontab/shell artifacts, and
never performs live changes.

Hard safety guarantees:
- No live changes and no live-apply function.
- No WordPress, .htaccess, Cloudflare, Nginx, DNS, API, login, or network work.
- apply_status stays not_applied; can_execute_live, install_allowed_now, and
  can_install_timer_now stay false.
- Writes are confined to drafts/owner, drafts/apply, reports/latest, and audit.
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

REPORT_INPUTS = [
    ("sentinel_master", "Sentinel Master", [PROJECT_DIR / "reports/latest/sentinel-master-report.json"], ("",)),
    ("safe_draft_runner", "Safe Draft Autonomy Runner", [PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.json"], ("runner_breach",)),
    ("safe_draft_verifier", "Safe Draft Autonomy Verifier", [PROJECT_DIR / "reports/latest/safe-draft-autonomy-verifier-report.json"], ("verifier_breach",)),
    ("safe_draft_scheduler", "Safe Draft Autonomy Scheduler Plan", [PROJECT_DIR / "reports/latest/safe-draft-autonomy-scheduler-plan.json"], ("scheduler_breach",)),
    ("safe_draft_timer_draft", "Safe Draft Autonomy Timer Draft", [PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-draft-report.json"], ("timer_draft_breach",)),
    ("safe_draft_timer_install_review", "Safe Draft Timer Install Review", [PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-install-review-report.json"], ("install_reviewer_breach",)),
    ("owner_manual_timer_packet", "Owner Manual Timer Install Packet", [PROJECT_DIR / "reports/latest/owner-manual-timer-install-packet-report.json"], ("packet_breach",)),
    (
        "owner_timer_decision",
        "Owner Timer Install Decision Gate",
        [
            PROJECT_DIR / "reports/latest/owner-timer-install-decision-gate-report.json",
            PROJECT_DIR / "reports/latest/owner-timer-install-decision-report.json",
        ],
        ("decision_breach",),
    ),
    (
        "manual_timer_preview",
        "Manual Timer Command Preview",
        [
            PROJECT_DIR / "reports/latest/manual-timer-install-command-preview-report.json",
            PROJECT_DIR / "reports/latest/manual-timer-command-preview-report.json",
        ],
        ("preview_breach",),
    ),
    ("owner_timer_evidence", "Owner Timer Install Evidence Pack", [PROJECT_DIR / "reports/latest/owner-timer-install-evidence-pack-report.json"], ("evidence_pack_breach",)),
    ("final_safety", "Safe Draft Autonomy Final Safety", [PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"], ("final_safety_breach",)),
    ("runtime_lock", "Autonomy Runtime Lock", [PROJECT_DIR / "reports/latest/autonomy-runtime-lock-report.json"], ("runtime_lock_breach",)),
    ("owner_daily", "Owner Daily Action Summary", [PROJECT_DIR / "reports/latest/owner-daily-action-summary.json"], ("summary_breach",)),
    ("website_sentinel", "Website Sentinel", [PROJECT_DIR / "reports/latest/sentinel-defense-report.json"], ("",)),
]

CONFIG_INPUTS = [
    ("runtime_lock_config", "Autonomy Runtime Lock Config", PROJECT_DIR / "config/autonomy-runtime-lock.json"),
    ("owner_timer_decision_config", "Owner Timer Install Decision Config", PROJECT_DIR / "config/owner-timer-install-decision.json"),
]

REVIEW_DOCS = [
    ("owner_manual_timer_packet", "Owner Manual Timer Install Packet", PROJECT_DIR / "drafts/owner/owner-manual-timer-install-packet.md"),
    ("owner_manual_timer_final_checklist", "Owner Manual Timer Final Checklist", PROJECT_DIR / "drafts/owner/owner-manual-timer-install-final-checklist.md"),
    ("owner_manual_timer_review_only", "Owner Manual Timer Review Only", PROJECT_DIR / "drafts/apply/owner-manual-timer-install-review-only.md"),
    ("manual_timer_command_preview", "Manual Timer Command Preview", PROJECT_DIR / "drafts/owner/manual-timer-install-command-preview.md"),
    ("manual_timer_command_preview_review_only", "Manual Timer Command Preview Review Only", PROJECT_DIR / "drafts/apply/manual-timer-install-command-preview-review-only.md"),
    ("owner_timer_evidence_pack", "Owner Timer Evidence Pack", PROJECT_DIR / "drafts/owner/owner-timer-install-evidence-pack.md"),
    ("owner_timer_evidence_template", "Owner Timer Evidence Template", PROJECT_DIR / "drafts/owner/owner-timer-install-evidence-template.md"),
    ("safe_draft_final_owner_summary", "Safe Draft Final Owner Summary", PROJECT_DIR / "drafts/owner/safe-draft-autonomy-final-owner-summary.md"),
]

REPORT_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-dashboard.json"
REPORT_MD = PROJECT_DIR / "reports/latest/manual-evidence-review-dashboard.md"
DASHBOARD_MD = PROJECT_DIR / "drafts/owner/manual-evidence-review-dashboard.md"
NEXT_ACTIONS_MD = PROJECT_DIR / "drafts/owner/manual-evidence-review-next-owner-actions.md"
AUDIT_JSONL = PROJECT_DIR / "audit/manual-evidence-review-dashboard.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, DASHBOARD_MD, NEXT_ACTIONS_MD, AUDIT_JSONL)
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

SCHEMA_VERSION = "manual-evidence-review-dashboard-4.6"
APPLY_NOT_APPLIED = "not_applied"
TIMER_NOT_INSTALLED = "not_installed"

DASHBOARD_READY_LOCKED = "READY_FOR_MANUAL_EVIDENCE_REVIEW_LOCKED"
DASHBOARD_READY_UNLOCKED = "READY_FOR_MANUAL_EVIDENCE_REVIEW_UNLOCKED"
DASHBOARD_BLOCKED_BREACH = "DASHBOARD_BLOCKED_BY_BREACH"
DASHBOARD_PARTIAL = "DASHBOARD_PARTIAL_INPUTS"
DASHBOARD_BREACH = "DASHBOARD_BREACH"

NEVER_ALLOWED_ACTIONS = [
    "live apply",
    "systemctl ausfuehren durch Bot",
    "systemd-Datei schreiben durch Bot",
    "crontab schreiben durch Bot",
    "wp-cli live write",
    "Cloudflare API Aenderung",
    "Nginx reload",
    ".htaccess Aenderung",
    "DNS Aenderung",
    "Browser-Automation/Login",
    "Netzwerk-Apply",
]

OPEN_OWNER_EVIDENCE_ITEMS = [
    "Runtime Lock manuell pruefen",
    "Final Safety Report pruefen",
    "Evidence Pack pruefen",
    "Command Preview pruefen",
    "Timer Drafts pruefen",
    "Keine Installation durchfuehren, solange Emergency Stop aktiv ist",
    "Kein Live-Apply aktivieren",
    "Keine Cloudflare-/Nginx-/WordPress-Live-Schritte ausfuehren",
]

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
        raise ValueError(f"Refusing to write outside allowed dashboard roots: {path}")
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


def read_optional_json(paths: List[Path]) -> Tuple[Optional[Dict[str, Any]], str, Optional[Path]]:
    last_status = "not_available"
    for path in paths:
        try:
            if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
                last_status = "refused_secret_like_path"
                continue
            if path.suffix.lower() != ".json":
                last_status = "unsupported_suffix"
                continue
            if not path.exists():
                last_status = "not_available"
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            last_status = "read_error"
            continue
        if isinstance(data, dict):
            return data, "ok", path
        last_status = "invalid_root"
    return None, last_status, paths[0] if paths else None


def text_doc_status(path: Path) -> str:
    try:
        if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
            return "refused_secret_like_path"
        if path.suffix.lower() != ".md":
            return "unsupported_suffix"
        if not path.exists():
            return "not_available"
        path.read_text(encoding="utf-8")
        return "ok"
    except OSError:
        return "read_error"


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


def summary(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(data, dict) and isinstance(data.get("summary"), dict):
        return data["summary"]
    return {}


def first_value(data: Optional[Dict[str, Any]], keys: List[str], default: Any = None) -> Any:
    if not isinstance(data, dict):
        return default
    nested = summary(data)
    for key in keys:
        if key in data:
            return data.get(key)
        if key in nested:
            return nested.get(key)
    return default


def any_breach(data: Optional[Dict[str, Any]], explicit_keys: Tuple[str, ...]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if not isinstance(data, dict):
        return False, reasons
    for source in (data, summary(data)):
        for key, value in source.items():
            if (key.endswith("_breach") or key in explicit_keys) and _as_bool(value):
                reason = f"{key}=true"
                if reason not in reasons:
                    reasons.append(reason)
    return bool(reasons), reasons


def apply_status(data: Optional[Dict[str, Any]]) -> str:
    return str(first_value(data, ["apply_status"], APPLY_NOT_APPLIED) or APPLY_NOT_APPLIED)


def phase_status(data: Optional[Dict[str, Any]]) -> str:
    for key in (
        "dashboard_status",
        "final_safety_status",
        "evidence_pack_status",
        "preview_status",
        "gate_status",
        "packet_status",
        "install_review_status",
        "timer_draft_status",
        "scheduler_status",
        "verifier_status",
        "runner_status",
        "status",
    ):
        value = first_value(data, [key])
        if value is not None:
            return redact_text(value, max_len=120)
    return "NOT_AVAILABLE"


def phase_summary(phase_id: str, title: str, data: Optional[Dict[str, Any]], status: str, path: Optional[Path], breach_keys: Tuple[str, ...]) -> Dict[str, Any]:
    if status != "ok" or not isinstance(data, dict):
        return {
            "phase_id": phase_id,
            "title": title,
            "present": False,
            "path": str(path) if path else "-",
            "status": "NOT_AVAILABLE",
            "input_status": status,
            "breach": False,
            "blocked": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "live_apply": False,
            "can_execute_live": False,
            "systemd_file_written": False,
            "crontab_file_written": False,
            "apply_status": APPLY_NOT_APPLIED,
            "interpretation": "not_available; missing input does not create a breach",
            "breach_reasons": [],
        }
    breach, reasons = any_breach(data, breach_keys)
    status_text = phase_status(data)
    blocked = "BLOCKED" in status_text.upper() or "LOCKED" in status_text.upper()
    return {
        "phase_id": phase_id,
        "title": title,
        "present": True,
        "path": str(path) if path else "-",
        "status": status_text,
        "input_status": status,
        "breach": breach,
        "blocked": blocked,
        "install_allowed_now": _as_bool(first_value(data, ["install_allowed_now"])),
        "can_install_timer_now": _as_bool(first_value(data, ["can_install_timer_now"])),
        "live_apply": _as_bool(first_value(data, ["live_apply", "live_apply_allowed", "live_apply_enabled"])),
        "can_execute_live": _as_bool(first_value(data, ["can_execute_live"])),
        "systemd_file_written": _as_bool(first_value(data, ["systemd_file_written"])),
        "crontab_file_written": _as_bool(first_value(data, ["crontab_file_written"])),
        "shell_script_generated": _as_bool(first_value(data, ["shell_script_generated"])),
        "network_access": _as_bool(first_value(data, ["network_access"])),
        "api_access": _as_bool(first_value(data, ["api_access"])),
        "wordpress_login": _as_bool(first_value(data, ["wordpress_login"])),
        "apply_status": apply_status(data),
        "interpretation": "breach detected" if breach else "blocked/review-only" if blocked else "safe/read-only",
        "breach_reasons": reasons,
    }


def collect_inputs() -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str], List[Dict[str, Any]], List[Dict[str, Any]]]:
    raw: Dict[str, Dict[str, Any]] = {}
    statuses: Dict[str, str] = {}
    phases: List[Dict[str, Any]] = []
    for phase_id, title, paths, breach_keys in REPORT_INPUTS:
        data, status, used_path = read_optional_json(paths)
        statuses[phase_id] = status
        if isinstance(data, dict):
            raw[phase_id] = data
        phases.append(phase_summary(phase_id, title, data, status, used_path, breach_keys))
    for config_id, title, path in CONFIG_INPUTS:
        data, status, used_path = read_optional_json([path])
        statuses[config_id] = status
        if isinstance(data, dict):
            raw[config_id] = data
        phases.append(phase_summary(config_id, title, data, status, used_path, ("runtime_lock_breach", "decision_breach")))

    docs: List[Dict[str, Any]] = []
    for doc_id, title, path in REVIEW_DOCS:
        status = text_doc_status(path)
        statuses[doc_id] = status
        docs.append({"doc_id": doc_id, "title": title, "path": str(path), "available": status == "ok", "status": status})
    return raw, statuses, phases, docs


def bool_from(raw: Dict[str, Dict[str, Any]], source_id: str, keys: List[str], default: bool = False) -> bool:
    source = raw.get(source_id)
    value = first_value(source, keys)
    if value is not None:
        return _as_bool(value)
    return default


def text_from(raw: Dict[str, Dict[str, Any]], source_id: str, keys: List[str], default: str = "-") -> str:
    source = raw.get(source_id)
    value = first_value(source, keys)
    if value is not None:
        return redact_text(value, default=default, max_len=240)
    return default


def compute_dashboard_breach(
    phases: List[Dict[str, Any]],
    emergency_stop: bool,
    output_paths: List[str],
    output_texts: Optional[List[str]] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, List[str]]:
    flags = forced_flags or {}
    reasons: List[str] = []
    for phase in phases:
        if phase.get("breach"):
            reasons.append(f"{phase.get('phase_id')}: upstream breach")
        if phase.get("live_apply"):
            reasons.append(f"{phase.get('phase_id')}: live_apply=true")
        if phase.get("can_execute_live"):
            reasons.append(f"{phase.get('phase_id')}: can_execute_live=true")
        if emergency_stop and phase.get("install_allowed_now"):
            reasons.append(f"{phase.get('phase_id')}: install_allowed_now=true while emergency_stop=true")
        if emergency_stop and phase.get("can_install_timer_now"):
            reasons.append(f"{phase.get('phase_id')}: can_install_timer_now=true while emergency_stop=true")
        if phase.get("systemd_file_written"):
            reasons.append(f"{phase.get('phase_id')}: systemd_file_written=true")
        if phase.get("crontab_file_written"):
            reasons.append(f"{phase.get('phase_id')}: crontab_file_written=true")
        if phase.get("shell_script_generated"):
            reasons.append(f"{phase.get('phase_id')}: shell_script_generated=true")
        if phase.get("network_access") or phase.get("api_access") or phase.get("wordpress_login"):
            reasons.append(f"{phase.get('phase_id')}: network/API/login detected")
        if phase.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append(f"{phase.get('phase_id')}: apply_status != not_applied")
    for key in (
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
    if flags.get("live_apply_allowed"):
        reasons.append("live_apply_allowed=true")
    if emergency_stop and flags.get("install_allowed_now"):
        reasons.append("install_allowed_now=true while emergency_stop=true")
    if emergency_stop and flags.get("can_install_timer_now"):
        reasons.append("can_install_timer_now=true while emergency_stop=true")
    if flags.get("timer_installation_status") and flags.get("timer_installation_status") != TIMER_NOT_INSTALLED:
        reasons.append("timer_installation_status != not_installed")
    if flags.get("apply_status") and flags.get("apply_status") != APPLY_NOT_APPLIED:
        reasons.append("apply_status != not_applied")
    for raw_path in output_paths:
        path = Path(str(raw_path))
        lower = str(raw_path).lower()
        if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
            reasons.append(f"executable install artifact generated: {redact_text(raw_path, max_len=120)}")
        if any(token in lower for token in FORBIDDEN_INSTALL_PATH_TOKENS):
            reasons.append(f"output path looks like a systemd/cron install path: {redact_text(raw_path, max_len=120)}")
        if not within_allowed_roots(path):
            reasons.append(f"output path outside allowed roots: {redact_text(raw_path, max_len=120)}")
    for text in output_texts or []:
        if detect_secret_in_text(text):
            reasons.append("secret-like values detected in generated output")
            break
    return bool(reasons), reasons


def website_context(raw: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    master = raw.get("sentinel_master", {})
    website = raw.get("website_sentinel", {})
    challenge = master.get("cloudflare_challenge_diagnosis") if isinstance(master.get("cloudflare_challenge_diagnosis"), dict) else {}
    ai_radio = master.get("ai_radio_timeout_diagnosis") if isinstance(master.get("ai_radio_timeout_diagnosis"), dict) else {}
    sourcemap = master.get("sourcemap_prevention") if isinstance(master.get("sourcemap_prevention"), dict) else {}
    return {
        "website_status": redact_text(master.get("website_status") or website.get("overall_status"), default="UNKNOWN", max_len=80),
        "website_correlation_status": redact_text(master.get("website_correlation_status") or website.get("correlation_status"), default="UNKNOWN", max_len=80),
        "action_status": redact_text(master.get("action_status"), default="UNKNOWN", max_len=80),
        "cloudflare_botfight_note": bool(challenge.get("present")),
        "ai_radio_microcache_deployed": bool(
            (ai_radio.get("microcache_remediation") if isinstance(ai_radio.get("microcache_remediation"), dict) else {}).get("microcache_deployed")
        ),
        "ai_radio_latest_5xx_delta": (
            (ai_radio.get("rolling_window_status") if isinstance(ai_radio.get("rolling_window_status"), dict) else {}).get("latest_5xx_delta")
        ),
        "sourcemap_status": redact_text(sourcemap.get("status"), default="NOT_AVAILABLE", max_len=80),
        "no_waf_action_recommended": True,
    }


def build_report(
    raw: Dict[str, Dict[str, Any]],
    statuses: Dict[str, str],
    phases: List[Dict[str, Any]],
    docs: List[Dict[str, Any]],
    timestamp: Optional[str] = None,
    output_texts: Optional[List[str]] = None,
    output_paths: Optional[List[str]] = None,
    forced_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    generated = timestamp or utc_now()
    final_status = text_from(raw, "final_safety", ["final_safety_status"], "NOT_AVAILABLE")
    emergency_stop = bool_from(raw, "final_safety", ["emergency_stop_active"], bool_from(raw, "runtime_lock", ["emergency_stop"], True))
    draft_ready = bool_from(raw, "final_safety", ["draft_only_autonomy_ready"], False)
    runner_verified = bool_from(raw, "final_safety", ["draft_only_runner_verified"], False)
    timer_review_ready = bool_from(raw, "final_safety", ["timer_installation_ready_for_owner_review"], False)
    evidence_template_written = bool_from(raw, "owner_timer_evidence", ["evidence_template_written"], False)
    command_preview_written = bool_from(raw, "manual_timer_preview", ["command_preview_written"], False)
    timer_installation_status = text_from(raw, "safe_draft_timer_draft", ["timer_installation_status"], TIMER_NOT_INSTALLED)
    total_upstream_breaches = sum(1 for phase in phases if phase.get("breach"))
    paths = output_paths or [str(path) for path in ALLOWED_OUTPUT_PATHS]
    breach, breach_reasons = compute_dashboard_breach(phases, emergency_stop, paths, output_texts=output_texts, forced_flags=forced_flags)

    important_missing = [
        key for key in (
            "final_safety",
            "owner_timer_evidence",
            "manual_timer_preview",
            "owner_timer_decision",
            "owner_manual_timer_packet",
            "runtime_lock",
            "sentinel_master",
        )
        if statuses.get(key) != "ok"
    ]
    if breach:
        dashboard_status = DASHBOARD_BLOCKED_BREACH
    elif important_missing:
        dashboard_status = DASHBOARD_PARTIAL
    elif final_status == "SAFE_BUT_LOCKED_BY_EMERGENCY_STOP" or emergency_stop:
        dashboard_status = DASHBOARD_READY_LOCKED
    else:
        dashboard_status = DASHBOARD_READY_UNLOCKED

    if breach:
        recommended = "stop and review dashboard breach."
    elif emergency_stop:
        recommended = "review evidence documents only; do not install while Emergency Stop is active."
    elif dashboard_status == DASHBOARD_PARTIAL:
        recommended = "generate missing review reports before owner evidence review."
    else:
        recommended = "continue manual evidence review; no install is performed by Sentinel."
    final_recommended = text_from(raw, "final_safety", ["final_recommended_owner_action"], recommended)
    next_safe_step = "Manual evidence review only; no install, no live apply."
    available_docs = sum(1 for doc in docs if doc.get("available"))
    missing_docs = sum(1 for doc in docs if not doc.get("available"))
    blocked_items = [item for item in OPEN_OWNER_EVIDENCE_ITEMS if "Keine" in item or "Kein" in item]
    safe_chain_count = sum(1 for phase in phases if phase.get("present") and not phase.get("breach") and not phase.get("blocked"))
    blocked_chain_count = sum(1 for phase in phases if phase.get("blocked"))

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": dashboard_status,
        "dashboard_status": dashboard_status,
        "dashboard_breach": breach,
        "dashboard_breach_reasons": breach_reasons,
        "final_safety_status": final_status,
        "emergency_stop_active": emergency_stop,
        "draft_only_autonomy_ready": draft_ready,
        "draft_only_runner_verified": runner_verified,
        "timer_installation_ready_for_owner_review": timer_review_ready,
        "timer_installation_allowed_now": False,
        "timer_installation_status": timer_installation_status,
        "live_apply_allowed": False,
        "live_apply": False,
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
        "evidence_template_written": evidence_template_written,
        "command_preview_written": command_preview_written,
        "owner_review_required": True,
        "open_owner_evidence_items_count": len(OPEN_OWNER_EVIDENCE_ITEMS),
        "blocked_items_count": len(blocked_items),
        "total_breaches": total_upstream_breaches,
        "safe_chain_count": safe_chain_count,
        "blocked_chain_count": blocked_chain_count,
        "evidence_docs_available_count": available_docs,
        "evidence_docs_missing_count": missing_docs,
        "final_recommended_owner_action": final_recommended,
        "recommended_next_owner_action": recommended,
        "next_safe_step": next_safe_step,
        "important_missing_inputs": important_missing,
        "phases": phases,
        "evidence_documents": docs,
        "open_owner_evidence_items": OPEN_OWNER_EVIDENCE_ITEMS,
        "blocked_items": blocked_items,
        "never_allowed_actions": NEVER_ALLOWED_ACTIONS,
        "website_context": website_context(raw),
        "input_statuses": statuses,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "dashboard_md": str(DASHBOARD_MD),
            "next_actions_md": str(NEXT_ACTIONS_MD),
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


def render_dashboard_markdown(report: Dict[str, Any]) -> str:
    wc = report.get("website_context") if isinstance(report.get("website_context"), dict) else {}
    lines = [
        "# Manual Evidence Review Dashboard",
        "",
        "## 1. Executive Summary",
        "",
        f"- Dashboard status: `{report.get('dashboard_status')}`",
        f"- Dashboard breach: `{report.get('dashboard_breach')}`",
        f"- Final safety status: `{report.get('final_safety_status')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Timer installation allowed now: `{report.get('timer_installation_allowed_now')}`",
        f"- Live apply allowed: `{report.get('live_apply_allowed')}`",
        f"- Final recommended owner action: `{redact_text(report.get('final_recommended_owner_action'), max_len=300)}`",
        "",
        "## 2. Current Lock State",
        "",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- can_execute_live: `{report.get('can_execute_live')}`",
        f"- install_allowed_now: `{report.get('install_allowed_now')}`",
        f"- can_install_timer_now: `{report.get('can_install_timer_now')}`",
        f"- timer_installation_status: `{report.get('timer_installation_status')}`",
        f"- systemd_file_written: `{report.get('systemd_file_written')}`",
        f"- crontab_file_written: `{report.get('crontab_file_written')}`",
        "",
        "## 3. Safe Draft Autonomy Chain",
        "",
        "| Phase | Status | Breach | Blocked | Interpretation |",
        "|---|---|---:|---:|---|",
    ]
    for phase in report.get("phases", []):
        if isinstance(phase, dict):
            lines.append(
                f"| {redact_text(phase.get('title'), max_len=80)} | "
                f"`{redact_text(phase.get('status'), max_len=100)}` | "
                f"`{phase.get('breach')}` | `{phase.get('blocked')}` | "
                f"{redact_text(phase.get('interpretation'), max_len=120)} |"
            )
    lines.extend(
        [
            "",
            "## 4. Timer Review Chain",
            "",
            f"- Timer installation status: `{report.get('timer_installation_status')}`",
            f"- Timer installation ready for owner review: `{report.get('timer_installation_ready_for_owner_review')}`",
            f"- Timer installation allowed now: `{report.get('timer_installation_allowed_now')}`",
            "",
            "## 5. Evidence/Decision Chain",
            "",
            f"- Evidence template written: `{report.get('evidence_template_written')}`",
            f"- Command preview written: `{report.get('command_preview_written')}`",
            f"- Evidence docs available/missing: `{report.get('evidence_docs_available_count')}` / `{report.get('evidence_docs_missing_count')}`",
            "",
            "## 6. Website Warning Context",
            "",
            f"- Website status: `{wc.get('website_status')}`",
            f"- Website correlation status: `{wc.get('website_correlation_status')}`",
            f"- Action status: `{wc.get('action_status')}`",
            f"- Cloudflare Bot Fight Mode note available: `{wc.get('cloudflare_botfight_note')}`",
            f"- NowPlaying microcache deployed/HIT-confirmed: `{wc.get('ai_radio_microcache_deployed')}`",
            f"- AI-Radio latest 5xx delta: `{wc.get('ai_radio_latest_5xx_delta')}`",
            f"- SourceMap status: `{wc.get('sourcemap_status')}`",
            "- No automatic WAF rule is derived from this dashboard.",
            "",
            "## 7. Manual Owner Checklist",
            "",
        ]
    )
    for item in report.get("open_owner_evidence_items", []):
        lines.append(f"- [ ] {redact_text(item, max_len=180)}")
    lines.extend(["", "## 8. Files to Review", ""])
    for doc in report.get("evidence_documents", []):
        if isinstance(doc, dict):
            lines.append(f"- `{doc.get('status')}` - {redact_text(doc.get('title'), max_len=100)}: `{redact_text(doc.get('path'), max_len=180)}`")
    lines.extend(["", "## 9. Do Not Proceed Conditions", ""])
    for item in report.get("blocked_items", []):
        lines.append(f"- {redact_text(item, max_len=180)}")
    lines.extend(["", "## Never Allowed Actions", ""])
    for item in report.get("never_allowed_actions", []):
        lines.append(f"- {redact_text(item, max_len=180)}")
    lines.extend(
        [
            "",
            "## 10. Final Recommendation",
            "",
            f"- Recommended next owner action: `{redact_text(report.get('recommended_next_owner_action'), max_len=300)}`",
            f"- Next safe step: `{redact_text(report.get('next_safe_step'), max_len=240)}`",
            "",
        ]
    )
    return "\n".join(lines)


def render_next_actions_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Manual Evidence Review - Next Owner Actions",
        "",
        f"- Dashboard status: `{report.get('dashboard_status')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        "",
        "## Next Safe Step",
        "",
        f"- {redact_text(report.get('next_safe_step'), max_len=240)}",
        "",
        "## Open Items",
        "",
    ]
    for item in report.get("open_owner_evidence_items", []):
        lines.append(f"- [ ] {redact_text(item, max_len=180)}")
    lines.append("")
    return "\n".join(lines)


def rendered_output_texts(report: Dict[str, Any]) -> List[str]:
    return [
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        render_dashboard_markdown(report),
        render_next_actions_markdown(report),
    ]


def mark_secret_output_breach(report: Dict[str, Any]) -> Dict[str, Any]:
    if not any(detect_secret_in_text(text) for text in rendered_output_texts(report)):
        return report
    updated = dict(report)
    reasons = list(updated.get("dashboard_breach_reasons") if isinstance(updated.get("dashboard_breach_reasons"), list) else [])
    reason = "secret-like values detected in generated output"
    if reason not in reasons:
        reasons.append(reason)
    updated["dashboard_breach"] = True
    updated["dashboard_breach_reasons"] = reasons
    updated["dashboard_status"] = DASHBOARD_BREACH
    updated["status"] = DASHBOARD_BREACH
    safety = dict(updated.get("safety") if isinstance(updated.get("safety"), dict) else {})
    safety["secrets_output"] = True
    updated["safety"] = safety
    return updated


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "record_type": "manual_evidence_review_dashboard",
        "dashboard_status": report.get("dashboard_status"),
        "dashboard_breach": report.get("dashboard_breach"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "total_breaches": report.get("total_breaches"),
        "install_allowed_now": report.get("install_allowed_now"),
        "can_install_timer_now": report.get("can_install_timer_now"),
        "live_apply": False,
        "productive_change": False,
        "network_access": False,
    }


def write_outputs(report: Dict[str, Any]) -> Dict[str, Any]:
    report = mark_secret_output_breach(report)
    write_json_atomic(REPORT_JSON, report)
    dashboard = render_dashboard_markdown(report)
    write_text_atomic(REPORT_MD, dashboard)
    write_text_atomic(DASHBOARD_MD, dashboard)
    write_text_atomic(NEXT_ACTIONS_MD, render_next_actions_markdown(report))
    append_jsonl(AUDIT_JSONL, [audit_record(report)])
    return report


def _phase(**overrides: Any) -> Dict[str, Any]:
    phase = {
        "phase_id": "test_phase",
        "title": "Test Phase",
        "present": True,
        "status": "OK",
        "input_status": "ok",
        "breach": False,
        "blocked": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "can_execute_live": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "shell_script_generated": False,
        "network_access": False,
        "api_access": False,
        "wordpress_login": False,
        "apply_status": APPLY_NOT_APPLIED,
        "interpretation": "safe",
        "breach_reasons": [],
    }
    phase.update(overrides)
    return phase


def _raw(**overrides: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    raw = {
        "final_safety": {
            "final_safety_status": "SAFE_BUT_LOCKED_BY_EMERGENCY_STOP",
            "emergency_stop_active": True,
            "draft_only_autonomy_ready": False,
            "draft_only_runner_verified": True,
            "timer_installation_ready_for_owner_review": True,
            "final_recommended_owner_action": "keep stopped; do not install; keep review documents only.",
        },
        "runtime_lock": {"emergency_stop": True},
        "owner_timer_evidence": {"evidence_template_written": True},
        "manual_timer_preview": {"command_preview_written": True},
        "safe_draft_timer_draft": {"timer_installation_status": TIMER_NOT_INSTALLED},
        "sentinel_master": {"website_status": "WARNING", "website_correlation_status": "NORMAL", "action_status": "WARNING_REVIEW"},
    }
    raw.update(overrides)
    return raw


def _docs() -> List[Dict[str, Any]]:
    return [{"doc_id": "doc", "title": "Doc", "path": "drafts/owner/doc.md", "available": True, "status": "ok"}]


def _report(raw: Optional[Dict[str, Dict[str, Any]]] = None, phases: Optional[List[Dict[str, Any]]] = None, **kwargs: Any) -> Dict[str, Any]:
    statuses = {
        "final_safety": "ok",
        "owner_timer_evidence": "ok",
        "manual_timer_preview": "ok",
        "owner_timer_decision": "ok",
        "owner_manual_timer_packet": "ok",
        "runtime_lock": "ok",
        "sentinel_master": "ok",
    }
    return build_report(
        raw or _raw(),
        statuses,
        phases or [_phase()],
        _docs(),
        timestamp="2026-06-11T00:00:00Z",
        **kwargs,
    )


def run_self_test() -> int:
    locked = _report()
    if locked["dashboard_status"] != DASHBOARD_READY_LOCKED:
        raise AssertionError("locked safe report did not produce READY_FOR_MANUAL_EVIDENCE_REVIEW_LOCKED")
    if locked["dashboard_breach"]:
        raise AssertionError("locked safe dashboard must not breach")
    unlocked = _report(_raw(final_safety={"final_safety_status": "SAFE_DRAFT_ONLY_AUTONOMY_READY", "emergency_stop_active": False}, runtime_lock={"emergency_stop": False}))
    if unlocked["dashboard_status"] != DASHBOARD_READY_UNLOCKED:
        raise AssertionError("unlocked safe report did not produce READY_FOR_MANUAL_EVIDENCE_REVIEW_UNLOCKED")
    partial = _report(_raw(), phases=[_phase(present=False, input_status="not_available", status="NOT_AVAILABLE")])
    if partial["dashboard_breach"]:
        raise AssertionError("missing inputs must not breach")
    for key in ("live_apply", "can_execute_live", "systemd_file_written", "crontab_file_written", "shell_script_generated", "network_access", "api_access", "wordpress_login"):
        if not _report(phases=[_phase(**{key: True})])["dashboard_breach"]:
            raise AssertionError(f"{key}=true did not breach")
        if not _report(forced_flags={key: True})["dashboard_breach"]:
            raise AssertionError(f"forced {key}=true did not breach")
    if not _report(phases=[_phase(apply_status="applied")])["dashboard_breach"]:
        raise AssertionError("apply_status != not_applied did not breach")
    if not _report(phases=[_phase(breach=True)])["dashboard_breach"]:
        raise AssertionError("upstream breach did not breach")
    if not _report(forced_flags={"install_allowed_now": True})["dashboard_breach"]:
        raise AssertionError("install_allowed_now=true with emergency_stop did not breach")
    if not _report(forced_flags={"can_install_timer_now": True})["dashboard_breach"]:
        raise AssertionError("can_install_timer_now=true with emergency_stop did not breach")
    if not _report(forced_flags={"timer_installation_status": "installed"})["dashboard_breach"]:
        raise AssertionError("timer_installation_status != not_installed did not breach")
    if not _report(output_paths=["drafts/owner/install.sh"])["dashboard_breach"]:
        raise AssertionError("shell script output path did not breach")
    if not _report(output_paths=["/etc/systemd/system/x.service"])["dashboard_breach"]:
        raise AssertionError("systemd output path did not breach")
    if not _report(output_paths=["/tmp/dashboard.json"])["dashboard_breach"]:
        raise AssertionError("outside output path did not breach")
    if not _report(output_texts=["token=0123456789abcdef"])["dashboard_breach"]:
        raise AssertionError("secret-like output did not breach")
    for path in ALLOWED_OUTPUT_PATHS:
        assert_allowed_write(path)
    for bad in (Path("/etc/systemd/system/x.timer"), PROJECT_DIR / "drafts/owner/install.sh"):
        try:
            assert_allowed_write(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {bad}")
    print("manual-evidence-review-dashboard self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build Manual Evidence Review Dashboard; no install, no live apply."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    raw, statuses, phases, docs = collect_inputs()
    report = build_report(raw, statuses, phases, docs)
    report = write_outputs(report)
    print(
        "Manual Evidence Review Dashboard: "
        f"status={report.get('dashboard_status')}, "
        f"emergency_stop={report.get('emergency_stop_active')}, "
        f"breaches={report.get('total_breaches')}, "
        f"install_allowed={report.get('install_allowed_now')}, "
        f"can_install={report.get('can_install_timer_now')}, "
        f"breach={report.get('dashboard_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
