#!/usr/bin/env python3
"""Sentinel Self-Governing Safe Autonomy Kernel (Phase 10.0).

The transition from a collection of standalone helper scripts to a single,
self-governing *safe* autonomy core. The kernel observes the project state,
decides the next sensible task, classifies its risk, executes ONLY tasks that
are safe and explicitly allowed, validates the result, repairs safe failures,
learns from the outcome and proposes the next safe step.

Doctrine (hard defaults, never relaxed by this module):

    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    HIGH stays blocked, never automatic
    breach            = false

emergency_stop=true blocks live apply, external systems, timers, Cloudflare,
WordPress, SFTP, database, Nginx, .htaccess and customer systems. It does NOT
block safe *local* autonomy (read-only / draft / low-risk local file work),
which is explicitly allowed in this phase.

The kernel never performs a live apply. It never touches the network, never
sends e-mail, never uploads, never installs timers/cron/systemd and never runs
a free shell. Sub-processes are restricted to a hard allowlist of local
Sentinel Python modules with a hard argument allowlist (shell=False, timeout,
cwd=/srv/sentinel-defense).

Cycle: observe -> decide -> classify -> execute -> validate -> repair -> learn
       -> owner summary -> next cycle.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

SCHEMA_VERSION = "self-governing-safe-autonomy-kernel-10.0"
PHASE = "10.0"

# ---------------------------------------------------------------------------
# Autonomy levels
# ---------------------------------------------------------------------------
READ_ONLY = "READ_ONLY"
DRAFT = "DRAFT"
LOW_LOCAL = "LOW_LOCAL"
LOW_EXPORT = "LOW_EXPORT"
LOW_STATE = "LOW_STATE"
LOW_LIVE = "LOW_LIVE"
MEDIUM = "MEDIUM"
HIGH = "HIGH"

AUTO_ALLOWED_RISK = {READ_ONLY, DRAFT, LOW_LOCAL, LOW_EXPORT, LOW_STATE}
NEVER_AUTO_RISK = {LOW_LIVE, MEDIUM, HIGH}

# Safety LEVEL model (mirror of the rest of the pipeline).
LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
LEVEL_2 = "LEVEL_2_LOW_RISK_PREP_PREVIEW"
ALLOWED_CURRENT_LEVELS = {LEVEL_1, LEVEL_2}
DEFAULT_CURRENT_LEVEL = LEVEL_2

MAX_AGE_HOURS = 24.0  # an output older than this counts as "stale"
HISTORY_LIMIT = 50

# ---------------------------------------------------------------------------
# Allowed autonomous tasks (Phase 10.0)
# ---------------------------------------------------------------------------
ALLOWED_AUTONOMOUS_TASKS = [
    "observe_project_state",
    "update_owner_summary",
    "update_service_proof",
    "rebuild_payhip_upload_pack",
    "rerun_payhip_launch_qa",
    "update_fulfillment_board",
    "run_first_order_dryrun",
    "check_public_asset_safety",
    "check_missing_inputs",
    "generate_next_safe_actions",
    "repair_missing_public_asset",
    "repair_invalid_json_output",
    "rebuild_manifest_and_checksums",
    "repair_capability_health_warning",
    "update_learning_state",
    "write_audit_event",
    "generate_git_checkpoint_suggestion",
]

FORBIDDEN_TASKS = [
    "change Cloudflare live", "change WordPress live", "change database live",
    "change Nginx live", "change .htaccess live", "SFTP upload", "FTP upload",
    "store real customer data", "store passwords/API keys/tokens", "send e-mail",
    "use Payhip API", "external network access", "install timers", "install cronjobs",
    "enable systemd", "purge cache", "set redirects", "set WAF rules",
    "change theme/plugin code live", "mass changes", "execute HIGH-risk",
]

# Risk class per allowed task.
TASK_RISK_CLASS: Dict[str, str] = {
    "observe_project_state": READ_ONLY,
    "check_public_asset_safety": READ_ONLY,
    "check_missing_inputs": READ_ONLY,
    "generate_next_safe_actions": DRAFT,
    "generate_git_checkpoint_suggestion": DRAFT,
    "update_owner_summary": LOW_STATE,
    "update_service_proof": LOW_STATE,
    "rerun_payhip_launch_qa": LOW_STATE,
    "update_fulfillment_board": LOW_STATE,
    "run_first_order_dryrun": LOW_STATE,
    "update_learning_state": LOW_STATE,
    "write_audit_event": LOW_STATE,
    "repair_invalid_json_output": LOW_STATE,
    "repair_missing_public_asset": LOW_STATE,
    "repair_capability_health_warning": LOW_STATE,
    "rebuild_payhip_upload_pack": LOW_EXPORT,
    "rebuild_manifest_and_checksums": LOW_EXPORT,
}

SCOPE_BY_RISK: Dict[str, List[str]] = {
    READ_ONLY: ["reports/latest"],
    DRAFT: ["reports/latest"],
    LOW_LOCAL: ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
    LOW_STATE: ["reports/latest", "state/adaptive-learning", "audit", "playbooks"],
    LOW_EXPORT: ["exports/payhip-upload-pack"],
}

# ---------------------------------------------------------------------------
# Hard subprocess allowlist (shell=False, exact files, exact args, timeout, cwd)
# ---------------------------------------------------------------------------
ALLOWED_MODULE_FILES = {
    "sentinel_payhip_upload_pack_export_helper.py",
    "sentinel_payhip_launch_qa_finalizer.py",
    "sentinel_payhip_fulfillment_board.py",
    "sentinel_payhip_first_order_dryrun.py",
    "sentinel_service_proof_trend.py",
    "sentinel_payhip_public_client_assets.py",
    "sentinel_payhip_customer_intake_delivery.py",
    "sentinel_owner_dashboard_service_packaging.py",
    "sentinel_autonomous_capability_health_governor.py",
}
ALLOWED_MODULE_ARGS = {
    "--self-test", "--build-export", "--build-copy-fields", "--build-upload-checklist",
    "--build-zip", "--scan-upload-pack", "--validate-fields", "--build-launch-console",
    "--build-final-checklist", "--build-board", "--build-case-template",
    "--build-delivery-checklists", "--build-risk-review", "--build-completion-pack",
    "--build-dummy-case", "--simulate-intake", "--simulate-package-workflows",
    "--build-sample-report", "--build-delivery-pack", "--collect-proof",
    "--analyze-decay", "--build-client-summary", "--build-payhip-proof",
    "--build-product-file", "--build-public-assets", "--build-descriptions",
    "--build-faq", "--build-pdf-source", "--status", "--cycle",
    "--scan-health", "--classify-warnings", "--plan-repairs",
    "--execute-safe-repairs", "--validate-repairs", "--learn",
}

# Task -> (module file, [args]) for module-backed tasks. All others are internal.
TASK_EXEC: Dict[str, Tuple[str, List[str]]] = {
    "update_service_proof": ("sentinel_service_proof_trend.py", ["--status"]),
    "rebuild_payhip_upload_pack": ("sentinel_payhip_upload_pack_export_helper.py", ["--build-zip"]),
    "rebuild_manifest_and_checksums": ("sentinel_payhip_upload_pack_export_helper.py", ["--build-export"]),
    "rerun_payhip_launch_qa": ("sentinel_payhip_launch_qa_finalizer.py", ["--scan-upload-pack"]),
    "update_fulfillment_board": ("sentinel_payhip_fulfillment_board.py", ["--build-board"]),
    "run_first_order_dryrun": ("sentinel_payhip_first_order_dryrun.py", ["--status"]),
    "repair_missing_public_asset": ("sentinel_payhip_public_client_assets.py", ["--build-public-assets"]),
    "repair_capability_health_warning": ("sentinel_autonomous_capability_health_governor.py", ["--cycle"]),
}

# ---------------------------------------------------------------------------
# Inputs observed (read-only)
# ---------------------------------------------------------------------------
EXPORT_LATEST_DIR = PROJECT_DIR / "exports/payhip-upload-pack/latest"
EXPORT_BASE_DIR = PROJECT_DIR / "exports/payhip-upload-pack"

OBSERVED_FILES = {
    "export_pack": PROJECT_DIR / "reports/latest/sentinel-payhip-upload-pack-export.json",
    "launch_qa": PROJECT_DIR / "reports/latest/sentinel-payhip-launch-qa.json",
    "fulfillment_board": PROJECT_DIR / "reports/latest/sentinel-payhip-fulfillment-board.json",
    "first_order_dryrun": PROJECT_DIR / "reports/latest/sentinel-payhip-first-order-dryrun.json",
    "service_proof": PROJECT_DIR / "reports/latest/sentinel-service-proof.json",
    "owner_dashboard": PROJECT_DIR / "reports/latest/sentinel-owner-dashboard.json",
}
DAILY_REPORT_FILES = [
    PROJECT_DIR / "reports/latest/sentinel-master-report.json",
    PROJECT_DIR / "reports/latest/sentinel-defense-report.json",
    PROJECT_DIR / "cloudflare-monitor/latest/cloudflare-daily-monitor.md",
]
PUBLIC_ASSET_FILES = [
    PROJECT_DIR / "reports/latest/sentinel-payhip-product-file-final.txt",
    PROJECT_DIR / "reports/latest/sentinel-payhip-short-description.md",
    PROJECT_DIR / "reports/latest/sentinel-payhip-long-description.md",
    PROJECT_DIR / "reports/latest/sentinel-payhip-faq.md",
    PROJECT_DIR / "reports/latest/sentinel-payhip-public-intake-form.md",
    PROJECT_DIR / "reports/latest/sentinel-payhip-public-safety-agreement.md",
    PROJECT_DIR / "reports/latest/sentinel-payhip-public-service-overview.md",
    PROJECT_DIR / "reports/latest/sentinel-payhip-package-deliverables.md",
]
JSON_SCAN_DIRS = [
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "state/adaptive-learning",
]

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
R = PROJECT_DIR / "reports/latest"
KERNEL_JSON = R / "sentinel-self-governing-autonomy-kernel.json"
KERNEL_MD = R / "sentinel-self-governing-autonomy-kernel.md"
OBSERVATION_MD = R / "sentinel-autonomy-observation.md"
DECISION_MD = R / "sentinel-autonomy-task-decision.md"
CLASSIFICATION_MD = R / "sentinel-autonomy-classification.md"
EXECUTION_MD = R / "sentinel-autonomy-execution-result.md"
VALIDATION_MD = R / "sentinel-autonomy-validation.md"
REPAIR_MD = R / "sentinel-autonomy-repair.md"
LEARNING_MD = R / "sentinel-autonomy-learning.md"
OWNER_SUMMARY_MD = R / "sentinel-autonomy-owner-summary.md"
NEXT_CYCLE_MD = R / "sentinel-autonomy-next-cycle.md"
GIT_CHECKPOINT_MD = R / "sentinel-autonomy-git-checkpoint-suggestion.md"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_JSON = STATE_DIR / "sentinel_self_governing_autonomy_kernel.json"
STATE_LATEST_JSON = STATE_DIR / "latest_self_governing_autonomy_kernel.json"
TASK_MEMORY_JSON = STATE_DIR / "autonomy_task_memory.json"
PRIORITY_MODEL_JSON = STATE_DIR / "autonomy_task_priority_model.json"
CAPABILITY_REGISTRY_JSON = STATE_DIR / "autonomous_capability_registry.json"
HEALTH_GOVERNOR_JSON = STATE_DIR / "latest_autonomous_capability_health_governor.json"
GOAL_MANAGER_JSON = STATE_DIR / "latest_autonomous_goal_manager.json"
MISSION_RUNNER_JSON = STATE_DIR / "latest_autonomous_mission_queue_runner.json"
SUPERVISOR_JSON = STATE_DIR / "latest_autonomous_operations_supervisor.json"
OPERATION_GOVERNOR_JSON = STATE_DIR / "latest_autonomous_operation_governor.json"
SUCCESS_PATTERNS_JSON = STATE_DIR / "autonomy_success_patterns.json"
BLOCKED_PATTERNS_JSON = STATE_DIR / "autonomy_blocked_patterns.json"
REPAIR_PATTERNS_JSON = STATE_DIR / "autonomy_repair_patterns.json"
CYCLE_HISTORY_JSON = STATE_DIR / "autonomy_cycle_history.json"

PRIORITY_COMPANION_ONLY_TASKS = {"write_audit_event", "update_learning_state"}
PRIORITY_RECOVERY_REPEAT_ALLOWED = {
    "repair_invalid_json_output",
    "repair_missing_public_asset",
    "rebuild_manifest_and_checksums",
}
PRIORITY_TASK_COOLDOWNS = {
    "generate_next_safe_actions": 2,
    "repair_capability_health_warning": 2,
    "update_owner_summary": 2,
    "rebuild_payhip_upload_pack": 3,
    "rerun_payhip_launch_qa": 3,
    "update_fulfillment_board": 3,
    "run_first_order_dryrun": 5,
}
PRIORITY_MAX_IN_WINDOW = {
    "check_public_asset_safety": (2, 5),
    "check_missing_inputs": (2, 5),
}

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-self-governing-autonomy-kernel.jsonl"

PLAYBOOK_KERNEL = PROJECT_DIR / "playbooks/sentinel-self-governing-autonomy-kernel.playbook.json"
PLAYBOOK_CYCLE = PROJECT_DIR / "playbooks/sentinel-autonomy-cycle.playbook.json"
PLAYBOOK_CLASSIFICATION = PROJECT_DIR / "playbooks/sentinel-autonomy-task-classification.playbook.json"
PLAYBOOK_VALIDATION_REPAIR = PROJECT_DIR / "playbooks/sentinel-autonomy-validation-repair.playbook.json"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "exports/payhip-upload-pack",
    PROJECT_DIR / "playbooks",
)
FORBIDDEN_OUTPUT_SUFFIXES = (
    ".sh", ".bash", ".zsh", ".service", ".timer", ".run", ".bin", ".py", ".php", ".env",
)
FORBIDDEN_INSTALL_PATH_TOKENS = (
    "/etc/systemd", "systemd/system", "/lib/systemd", "/usr/lib/systemd",
    "/etc/cron", "cron.d", "crontab",
)
RECOMMENDED_GIT_CHECKPOINT = [
    "sentinel_self_governing_safe_autonomy_kernel.py",
    "sentinel_autonomous_operations_supervisor.py",
    "sentinel_autonomy.py",
    "sentinel_autonomous_operation_governor.py",
    "sentinel_autonomous_mission_queue_runner.py",
    "sentinel_autonomous_capability_health_governor.py",
    "playbooks/sentinel-self-governing-autonomy-kernel.playbook.json",
    "playbooks/sentinel-autonomy-cycle.playbook.json",
    "playbooks/sentinel-autonomy-task-classification.playbook.json",
    "playbooks/sentinel-autonomy-validation-repair.playbook.json",
    "playbooks/sentinel-autonomous-capability-health-governor.playbook.json",
    "playbooks/sentinel-autonomous-capability-self-repair.playbook.json",
    "playbooks/sentinel-autonomous-capability-warning-classification.playbook.json",
    "playbooks/sentinel-autonomous-capability-repair-validation.playbook.json",
    "playbooks/sentinel-autonomous-mission-queue-runner.playbook.json",
    "playbooks/sentinel-autonomous-mission-runner-stop-rules.playbook.json",
    "playbooks/sentinel-autonomous-mission-completion-ledger.playbook.json",
    "playbooks/sentinel-autonomous-mission-runner-owner-summary.playbook.json",
    "playbooks/sentinel-autonomous-operations-supervisor.playbook.json",
    "playbooks/sentinel-autonomous-operation-decision.playbook.json",
    "playbooks/sentinel-autonomous-system-validation.playbook.json",
    "playbooks/sentinel-autonomous-owner-briefing.playbook.json",
    "playbooks/sentinel-autonomous-operation-governor.playbook.json",
    "playbooks/sentinel-autonomous-operation-impact-scoring.playbook.json",
    "playbooks/sentinel-autonomous-operation-noop-detection.playbook.json",
    "playbooks/sentinel-autonomous-operation-diversity.playbook.json",
]

# ---------------------------------------------------------------------------
# Secret / safety regexes (value-bearing detection)
# ---------------------------------------------------------------------------
SENSITIVE_NAME_RE = re.compile(
    r"(?i)(\.env\b|sftp.*env|\.pem$|\.key$|id_rsa|id_ed25519|\.p12$|\.pfx$|"
    r"secret|token|credential|password|passwd|\.htpasswd|api[_-]?key|private[_-]?key)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|"
    r"authorization|set-cookie|x-api-key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b|required\b|"
    r"requested\b|warning\b|field\b|of any kind\b|reminder\b|received\b|blocked\b|"
    r"not requested\b|stored\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{40,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}
URL_RE = re.compile(r"(?i)\bhttps?://([A-Za-z0-9.\-]+)")
ALLOWED_URL_SUFFIXES = ("example.com", "example.org", "example.net")
INTERNAL_PATH_RE = re.compile(r"/(srv|etc|home|root|var|usr|opt|boot|proc)/")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HARD_SECRET_FORMAT_RE = re.compile(
    r"(?i)(begin private key|github_pat_[A-Za-z0-9_]{8,}|ghp_[A-Za-z0-9]{8,}|"
    r"\bsk-[A-Za-z0-9]{16,}|AIza[A-Za-z0-9_\-]{16,})"
)
DISALLOWED_CLAIMS_RE = re.compile(
    r"(?i)(guarantee(?:d|s)?\s+100%|guarantee(?:d|s)?\s+rank|automatic full repair|"
    r"fully autonomous live repair|no review required|change cloudflare automatically|"
    r"edit database automatically|bypass security)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def detect_secret_like(value: Any) -> bool:
    text = "" if value is None else str(value)
    return bool(SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


def redact_text(value: Any, default: str = "-", max_len: int = 300) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install/secret artifact: {path}")
    if any(token in str(path) for token in FORBIDDEN_INSTALL_PATH_TOKENS):
        raise ValueError(f"Refusing to write systemd/crontab path: {path}")


def _host_allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in ALLOWED_URL_SUFFIXES)


def _assert_no_secret_blob(path: Path, blob: str) -> None:
    if SECRET_ASSIGNMENT_RE.search(blob) or LONG_HEX_RE.search(blob):
        raise ValueError(f"Refusing to write secret-like content to {path}")
    if HARD_SECRET_FORMAT_RE.search(blob):
        raise ValueError(f"Refusing to write concrete secret key to {path}")
    for m in EMAIL_RE.findall(blob):
        if m.rsplit("@", 1)[-1].lower() not in ALLOWED_EMAIL_DOMAINS:
            raise ValueError(f"Refusing to write real-looking e-mail address to {path}: {m}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    _assert_no_secret_blob(path, content)
    if INTERNAL_PATH_RE.search(content):
        raise ValueError(f"Refusing to write internal server path to {path}")
    if IPV4_RE.search(content):
        raise ValueError(f"Refusing to write IP address to {path}")
    for host in URL_RE.findall(content):
        if not _host_allowed(host):
            raise ValueError(f"Refusing to write non-example domain to {path}: {host}")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Any) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            blob = json.dumps(record, ensure_ascii=False, sort_keys=True)
            _assert_no_secret_blob(path, blob)
            handle.write(blob + "\n")


def read_optional_json(path: Path) -> Tuple[Optional[Any], str]:
    if SENSITIVE_NAME_RE.search(path.name):
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


def run_readonly(cmd: List[str], timeout: int = 10) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=str(PROJECT_DIR), capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode == 0, redact_text(proc.stdout, max_len=6000)
    except (OSError, subprocess.SubprocessError):
        return False, ""


def run_module(filename: str, args: List[str], timeout: int = 90) -> Dict[str, Any]:
    """Run an allowlisted Sentinel module with an allowlisted argument set.

    shell=False, exact file allowlist, exact argument allowlist, fixed cwd,
    timeout. Never a free shell, never a free command.
    """
    if filename not in ALLOWED_MODULE_FILES:
        raise ValueError(f"module not on allowlist: {filename}")
    for a in args:
        if a not in ALLOWED_MODULE_ARGS:
            raise ValueError(f"argument not on allowlist: {a}")
    module_path = PROJECT_DIR / filename
    if not module_path.exists():
        return {"status": "blocked_missing_module", "returncode": None,
                "module": filename, "args": args, "stdout_lines": 0}
    try:
        proc = subprocess.run(
            [sys.executable, str(module_path), *args],
            cwd=str(PROJECT_DIR), capture_output=True, text=True,
            timeout=timeout, check=False, shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "returncode": None, "module": filename,
                "args": args, "stdout_lines": 0}
    except (OSError, subprocess.SubprocessError):
        return {"status": "error", "returncode": None, "module": filename,
                "args": args, "stdout_lines": 0}
    status = "executed" if proc.returncode == 0 else "failed"
    return {
        "status": status,
        "returncode": proc.returncode,
        "module": filename,
        "args": args,
        "stdout_lines": len([ln for ln in (proc.stdout or "").splitlines() if ln.strip()]),
    }


# ---------------------------------------------------------------------------
# Foreign-asset scans (real-secret only; do NOT flag the business own
# domain/e-mail in legitimate public marketing assets).
# ---------------------------------------------------------------------------
def forbidden_real_findings(blob: str) -> List[str]:
    reasons: List[str] = []
    if INTERNAL_PATH_RE.search(blob):
        reasons.append("internal_server_path")
    if IPV4_RE.search(blob):
        reasons.append("ip_address")
    if HARD_SECRET_FORMAT_RE.search(blob):
        reasons.append("secret_key_format")
    if SECRET_ASSIGNMENT_RE.search(blob):
        reasons.append("secret_assignment")
    if LONG_HEX_RE.search(blob):
        reasons.append("long_hex_blob")
    return reasons


def _file_info(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {"exists": path.exists(), "stale": False, "age_hours": None}
    if path.exists():
        try:
            mtime = path.stat().st_mtime
            age = (datetime.now(timezone.utc).timestamp() - mtime) / 3600.0
            info["age_hours"] = round(age, 2)
            info["stale"] = age > MAX_AGE_HOURS
        except OSError:
            pass
    return info


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------
def _load_state(path: Path, default: Any) -> Any:
    obj, status = read_optional_json(path)
    return obj if status == "ok" and obj is not None else default


def _git_status() -> Dict[str, Any]:
    log_ok, _ = run_readonly(["git", "log", "--oneline", "-15"])
    st_ok, st_out = run_readonly(["git", "status", "--short"])
    lines = [ln for ln in st_out.splitlines() if ln.strip()]
    untracked = sum(1 for ln in lines if ln.startswith("??"))
    modified = len(lines) - untracked
    return {
        "log_available": log_ok,
        "status_available": st_ok,
        "untracked_count": untracked,
        "modified_count": modified,
        "recommended": (untracked + modified) > 0,
    }


def resolve_safety() -> Dict[str, Any]:
    src = _load_state(OBSERVED_FILES["owner_dashboard"], None)

    def pick(key: str, default: Any) -> Any:
        if isinstance(src, dict) and key in src:
            return src[key]
        return default

    return {
        "live_apply": bool(pick("live_apply", False)),
        "emergency_stop": bool(pick("emergency_stop", True)),
        "allowed_apply_now": bool(pick("allowed_apply_now", False)),
        "current_level": pick("autonomy_level", DEFAULT_CURRENT_LEVEL),
        "high_blocked": bool(pick("high_blocked", True)),
        "upstream_breach": bool(src.get("breach")) if isinstance(src, dict) else False,
        "source_available": isinstance(src, dict),
    }


def compute_breach(safety: Dict[str, Any]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if safety["live_apply"] is not False:
        reasons.append("live_apply must be false")
    if safety["emergency_stop"] is not True:
        reasons.append("emergency_stop must be true")
    if safety["allowed_apply_now"] is not False:
        reasons.append("allowed_apply_now must be false")
    if safety["current_level"] not in ALLOWED_CURRENT_LEVELS:
        reasons.append(f"current_level {safety['current_level']} not allowed")
    if safety["high_blocked"] is not True:
        reasons.append("HIGH must stay blocked")
    if safety.get("upstream_breach"):
        reasons.append("upstream report breach")
    return (len(reasons) > 0), reasons


# ---------------------------------------------------------------------------
# OBSERVE
# ---------------------------------------------------------------------------
def observe() -> Dict[str, Any]:
    phase9_modules = {name: (PROJECT_DIR / name).exists() for name in sorted(ALLOWED_MODULE_FILES)}

    export_files = []
    if EXPORT_LATEST_DIR.exists():
        for child in sorted(EXPORT_LATEST_DIR.iterdir()):
            if child.is_file():
                export_files.append(child.name)
    # The export helper writes the ZIP to the base dir, not inside latest/.
    zip_present = EXPORT_BASE_DIR.exists() and any(
        c.is_file() and c.suffix.lower() == ".zip" for c in EXPORT_BASE_DIR.iterdir()
    )

    old_export_packs = 0
    if EXPORT_BASE_DIR.exists():
        old_export_packs = sum(
            1 for c in EXPORT_BASE_DIR.iterdir() if c.is_dir() and c.name != "latest"
        )

    file_status = {key: _file_info(path) for key, path in OBSERVED_FILES.items()}

    daily_reports_present = any(p.exists() for p in DAILY_REPORT_FILES)

    # Missing public assets (absence).
    missing_public_assets = [
        str(p.relative_to(PROJECT_DIR)) for p in PUBLIC_ASSET_FILES if not p.exists()
    ]

    # Forbidden real-secret patterns in existing public assets (presence of leaks).
    forbidden_in_public: Dict[str, List[str]] = {}
    for p in PUBLIC_ASSET_FILES:
        if not p.exists() or SENSITIVE_NAME_RE.search(p.name):
            continue
        try:
            blob = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings = forbidden_real_findings(blob)
        if findings:
            forbidden_in_public[str(p.relative_to(PROJECT_DIR))] = findings

    # Broken JSON outputs.
    broken_json: List[str] = []
    missing_inputs: List[str] = []
    for d in JSON_SCAN_DIRS:
        if not d.exists():
            continue
        for child in sorted(d.glob("*.json")):
            if SENSITIVE_NAME_RE.search(child.name):
                continue
            _, status = read_optional_json(child)
            if status == "invalid_json":
                broken_json.append(str(child.relative_to(PROJECT_DIR)))
    for key, path in OBSERVED_FILES.items():
        if not path.exists():
            missing_inputs.append(str(path.relative_to(PROJECT_DIR)))

    task_memory = _load_state(TASK_MEMORY_JSON, {})
    last_successful_task = task_memory.get("last_successful_task") if isinstance(task_memory, dict) else None
    last_blockers = task_memory.get("last_blockers", []) if isinstance(task_memory, dict) else []

    return {
        "phase9_modules": phase9_modules,
        "all_phase9_modules_present": all(phase9_modules.values()),
        "export_pack": file_status["export_pack"],
        "export_files_count": len(export_files),
        "zip_present": zip_present,
        "launch_qa": file_status["launch_qa"],
        "fulfillment_board": file_status["fulfillment_board"],
        "first_order_dryrun": file_status["first_order_dryrun"],
        "service_proof": file_status["service_proof"],
        "owner_dashboard": file_status["owner_dashboard"],
        "daily_reports_present": daily_reports_present,
        "missing_inputs": missing_inputs,
        "missing_public_assets": missing_public_assets,
        "broken_json": broken_json,
        "forbidden_in_public": forbidden_in_public,
        "old_export_packs": old_export_packs,
        "last_successful_task": last_successful_task,
        "last_blockers": last_blockers,
    }


# ---------------------------------------------------------------------------
# DECIDE
# ---------------------------------------------------------------------------
def _missing_or_stale(info: Dict[str, Any]) -> bool:
    return (not info.get("exists")) or bool(info.get("stale"))


def build_pending(observation: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Ordered list of (task, reason) by priority. First is the decision."""
    pending: List[Tuple[str, str]] = []
    registry, registry_status = read_optional_json(CAPABILITY_REGISTRY_JSON)
    registry_health = (registry.get("health") or {}).get("status") if registry_status == "ok" and isinstance(registry, dict) else None
    governor, governor_status = read_optional_json(HEALTH_GOVERNOR_JSON)
    governor_warnings = int(governor.get("warning_count") or 0) if governor_status == "ok" and isinstance(governor, dict) else 0
    if observation["broken_json"]:
        pending.append(("repair_invalid_json_output",
                        f"{len(observation['broken_json'])} broken JSON output(s) detected"))
    if registry_health == "CAPABILITY_HEALTH_WARNINGS" or governor_warnings:
        pending.append(("repair_capability_health_warning",
                        "Capability health warnings are repairable by safe local governor"))
    if observation["missing_public_assets"]:
        pending.append(("repair_missing_public_asset",
                        f"{len(observation['missing_public_assets'])} public asset(s) missing"))
    if _missing_or_stale(observation["export_pack"]) or not observation["zip_present"]:
        pending.append(("rebuild_payhip_upload_pack",
                        "Payhip export pack missing/stale or ZIP absent"))
    if _missing_or_stale(observation["launch_qa"]):
        pending.append(("rerun_payhip_launch_qa", "Launch QA missing/stale"))
    if _missing_or_stale(observation["fulfillment_board"]):
        pending.append(("update_fulfillment_board", "Fulfillment board missing/stale"))
    if not observation["first_order_dryrun"]["exists"]:
        pending.append(("run_first_order_dryrun", "First order dry-run missing"))
    if _missing_or_stale(observation["service_proof"]):
        pending.append(("update_service_proof", "Service proof missing/stale"))
    if _missing_or_stale(_file_info(OWNER_SUMMARY_MD)):
        pending.append(("update_owner_summary", "Owner summary missing/stale"))
    return pending


def priority_model_decision(observation: Dict[str, Any],
                            pending: List[Tuple[str, str]]) -> Tuple[Optional[Dict[str, Any]], str]:
    model, status = read_optional_json(PRIORITY_MODEL_JSON)
    if status != "ok" or not isinstance(model, dict):
        return None, status
    if model.get("integration_enabled") is not True:
        return None, "model_integration_disabled"
    if model.get("breach") is True:
        return None, "model_breach_true"

    # Current recovery signals always override any stored priority model.
    if pending:
        recovery_tasks = {"repair_invalid_json_output", "repair_missing_public_asset",
                          "rebuild_manifest_and_checksums"}
        first_task = pending[0][0]
        if first_task in recovery_tasks and model.get("selected_task") != first_task:
            return None, "current_recovery_priority_overrides_model"

    task, candidate, selection_status = choose_priority_candidate(model)
    if not task:
        return None, selection_status
    if task not in ALLOWED_AUTONOMOUS_TASKS:
        return None, "model_task_not_allowlisted"
    if task in PRIORITY_COMPANION_ONLY_TASKS:
        return None, "model_task_is_companion_only"
    risk = TASK_RISK_CLASS.get(task, HIGH)
    if risk not in AUTO_ALLOWED_RISK:
        return None, "model_task_risk_not_auto_allowed"
    if model.get("can_execute_now") is not True and model.get("selected_task_executable") is not True:
        return None, "model_task_not_executable"
    module = TASK_EXEC.get(task)
    if module and not (PROJECT_DIR / module[0]).exists():
        return None, f"model_task_module_missing:{module[0]}"

    return {
        "selected_task": task,
        "reason": f"priority engine selected {task}: "
                  f"{redact_text(candidate.get('reason') or model.get('selected_task_reason'), max_len=180)}",
        "priority_rank": 1.5,
        "halt": False,
        "pending": pending,
        "priority_engine": {
            "used": True,
            "model_status": model.get("status"),
            "selected_task_score": candidate.get("score", model.get("selected_task_score")),
            "selected_capability": candidate.get("capability_id") or model.get("selected_capability"),
            "capability_status": candidate.get("capability_status") or model.get("selected_capability_status"),
            "selected_mission": candidate.get("mission_type") or model.get("selected_mission"),
            "mission_status": candidate.get("mission_status") or model.get("selected_mission_status"),
            "anti_loop_status": (model.get("anti_loop") or {}).get("status"),
            "diversity_status": (model.get("diversity") or {}).get("status"),
            "cooldown_respected": (model.get("anti_loop") or {}).get("cooldown_respected"),
            "dynamic_selection_status": selection_status,
        },
        "priority_model_status": "used",
    }, "used"


def recent_kernel_tasks() -> List[str]:
    history = _load_state(CYCLE_HISTORY_JSON, [])
    tasks: List[str] = []
    if isinstance(history, list):
        for item in history:
            if isinstance(item, dict) and item.get("selected_task"):
                tasks.append(str(item["selected_task"]))
    return tasks[-20:]


def priority_cooldown_remaining(task: str, recent: List[str]) -> int:
    cooldown = PRIORITY_TASK_COOLDOWNS.get(task, 0)
    if cooldown <= 0:
        return 0
    for index, item in enumerate(reversed(recent), start=1):
        if item == task:
            return max(0, cooldown - (index - 1))
    return 0


def priority_window_blocked(task: str, recent: List[str]) -> bool:
    rule = PRIORITY_MAX_IN_WINDOW.get(task)
    if not rule:
        return False
    max_count, window = rule
    return recent[-window:].count(task) >= max_count


def choose_priority_candidate(model: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any], str]:
    recent = recent_kernel_tasks()
    candidates = model.get("task_scores")
    if not isinstance(candidates, list):
        candidates = [{
            "task": model.get("selected_task"),
            "score": model.get("selected_task_score"),
            "risk_class": model.get("selected_task_risk_class"),
            "can_execute_now": model.get("can_execute_now"),
            "reason": model.get("selected_task_reason"),
        }]
    sorted_candidates = sorted(
        [c for c in candidates if isinstance(c, dict)],
        key=lambda c: int(c.get("score") or -99999),
        reverse=True,
    )
    last = recent[-1] if recent else None
    blocked_by_rotation = 0
    for candidate in sorted_candidates:
        task = str(candidate.get("task") or "")
        if task not in ALLOWED_AUTONOMOUS_TASKS:
            continue
        if task in PRIORITY_COMPANION_ONLY_TASKS:
            continue
        if TASK_RISK_CLASS.get(task, HIGH) not in AUTO_ALLOWED_RISK:
            continue
        if candidate.get("can_execute_now") is False:
            continue
        if priority_window_blocked(task, recent):
            blocked_by_rotation += 1
            continue
        if last == task and task not in PRIORITY_RECOVERY_REPEAT_ALLOWED:
            blocked_by_rotation += 1
            continue
        if priority_cooldown_remaining(task, recent) > 0:
            blocked_by_rotation += 1
            continue
        return task, candidate, "dynamic_candidate_selected"
    if blocked_by_rotation:
        return None, {}, "no_diverse_priority_candidate"
    return None, {}, "no_priority_candidate"


def capability_context_for(task: str, decision: Dict[str, Any]) -> Dict[str, Any]:
    registry, status = read_optional_json(CAPABILITY_REGISTRY_JSON)
    selected_capability = (decision.get("priority_engine") or {}).get("selected_capability")
    if not selected_capability:
        model, model_status = read_optional_json(PRIORITY_MODEL_JSON)
        if model_status == "ok" and isinstance(model, dict):
            selected_capability = model.get("selected_capability")
    if status != "ok" or not isinstance(registry, dict):
        return {
            "registry_status": status,
            "selected_capability": selected_capability,
            "capability_health": "registry_unavailable",
            "capability_reason": "capability registry missing or unavailable; task safety falls back to kernel classification",
            "capability_risk": TASK_RISK_CLASS.get(task, HIGH),
            "capability_freshness": None,
        }
    capabilities = registry.get("capabilities") if isinstance(registry.get("capabilities"), list) else []
    selected = None
    for cap in capabilities:
        if not isinstance(cap, dict):
            continue
        if selected_capability and cap.get("capability_id") == selected_capability:
            selected = cap
            break
        if task in (cap.get("task_ids") or []) and selected is None:
            selected = cap
    if not selected:
        return {
            "registry_status": "ok",
            "selected_capability": selected_capability,
            "capability_health": "capability_not_mapped",
            "capability_reason": "no registered capability mapped to selected task",
            "capability_risk": TASK_RISK_CLASS.get(task, HIGH),
            "capability_freshness": None,
        }
    return {
        "registry_status": "ok",
        "selected_capability": selected.get("capability_id"),
        "capability_health": selected.get("health_status"),
        "capability_reason": selected.get("reason_if_blocked") or "capability available under local safe guards",
        "capability_risk": selected.get("risk_class"),
        "capability_freshness": selected.get("freshness_score"),
        "capability_usefulness": selected.get("usefulness_score"),
        "capability_priority": selected.get("priority_score"),
        "capability_can_run_autonomously": selected.get("can_run_autonomously"),
    }


def mission_context_for(task: str, decision: Dict[str, Any]) -> Dict[str, Any]:
    goal, status = read_optional_json(GOAL_MANAGER_JSON)
    selected_mission = (decision.get("priority_engine") or {}).get("selected_mission")
    if not selected_mission:
        model, model_status = read_optional_json(PRIORITY_MODEL_JSON)
        if model_status == "ok" and isinstance(model, dict):
            selected_mission = model.get("selected_mission")
    if status != "ok" or not isinstance(goal, dict):
        return {
            "state_path": "state/adaptive-learning/latest_autonomous_goal_manager.json",
            "goal_manager_status": status,
            "selected_mission": selected_mission,
            "mission_reason": "goal manager state missing; kernel falls back to task-level decision",
            "mission_risk": TASK_RISK_CLASS.get(task, HIGH),
            "mission_status": "goal_state_unavailable",
            "mission_completion_status": None,
            "next_mission": None,
        }
    missions = goal.get("mission_queue") or goal.get("classified_missions") or goal.get("routed_missions") or []
    if not isinstance(missions, list):
        missions = []
    selected = None
    for mission in missions:
        if not isinstance(mission, dict):
            continue
        if selected_mission and mission.get("mission_type") == selected_mission:
            selected = mission
            break
        if task in (mission.get("linked_tasks") or []) and selected is None:
            selected = mission
    if not selected and isinstance(goal.get("selected_mission"), dict):
        selected = goal["selected_mission"]
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_goal_manager.json",
        "goal_manager_status": goal.get("status"),
        "selected_mission": selected.get("mission_type") if selected else selected_mission,
        "mission_reason": selected.get("trigger_source") if selected else "no mission mapped to selected task",
        "mission_risk": selected.get("risk_class") if selected else TASK_RISK_CLASS.get(task, HIGH),
        "mission_status": selected.get("status") if selected else "mission_not_mapped",
        "mission_completion_status": selected.get("completion_status") if selected else None,
        "next_mission": goal.get("next_mission") or goal.get("next_recommended_mission"),
        "linked_capability": selected.get("linked_capability") if selected else None,
        "mission_priority_score": selected.get("priority_score") if selected else None,
    }


def mission_runner_context() -> Dict[str, Any]:
    runner, status = read_optional_json(MISSION_RUNNER_JSON)
    runner = runner if status == "ok" and isinstance(runner, dict) else {}
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_mission_queue_runner.json",
        "available": bool(runner),
        "mission_runner_status": runner.get("status") if runner else "not_available",
        "completed_mission_count": int(runner.get("missions_completed") or 0) if runner else 0,
        "selected_missions": runner.get("selected_missions") if isinstance(runner.get("selected_missions"), list) else [],
        "next_mission": runner.get("next_recommended_mission") if runner else None,
        "stop_reason": runner.get("stop_reason") if runner else None,
        "mission_diversity": (runner.get("mission_diversity") or {}).get("status") if isinstance(runner.get("mission_diversity"), dict) else None,
    }


def operations_supervisor_context() -> Dict[str, Any]:
    supervisor, status = read_optional_json(SUPERVISOR_JSON)
    supervisor = supervisor if status == "ok" and isinstance(supervisor, dict) else {}
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_operations_supervisor.json",
        "available": bool(supervisor),
        "supervisor_status": supervisor.get("status") if supervisor else "not_available",
        "selected_operation": supervisor.get("selected_operation") if supervisor else None,
        "next_operation": supervisor.get("next_operation") if supervisor else None,
        "operations_completed": int(supervisor.get("operations_completed") or 0) if supervisor else 0,
    }


def operation_governor_context() -> Dict[str, Any]:
    governor, status = read_optional_json(OPERATION_GOVERNOR_JSON)
    governor = governor if status == "ok" and isinstance(governor, dict) else {}
    return {
        "state_path": "state/adaptive-learning/latest_autonomous_operation_governor.json",
        "available": bool(governor),
        "status": governor.get("status") if governor else status,
        "selected_operation": governor.get("selected_operation_name") if governor else None,
        "diversity_status": (governor.get("diversity") or {}).get("status") if governor else None,
    }


def decide(observation: Dict[str, Any], breach: bool) -> Dict[str, Any]:
    if breach:
        return {"selected_task": "halt_and_report", "reason": "breach detected",
                "priority_rank": 1, "halt": True, "pending": [],
                "priority_model_status": "skipped_breach"}
    if observation["forbidden_in_public"]:
        return {"selected_task": "halt_and_report",
                "reason": "forbidden pattern detected in public assets",
                "priority_rank": 1, "halt": True,
                "pending": [], "priority_model_status": "skipped_forbidden_public"}
    pending = build_pending(observation)
    model_decision, model_status = priority_model_decision(observation, pending)
    if model_decision:
        return model_decision
    if pending:
        task, reason = pending[0]
        return {"selected_task": task, "reason": reason, "priority_rank": 2,
                "halt": False, "pending": pending,
                "priority_model_status": model_status}
    return {"selected_task": "generate_next_safe_actions",
            "reason": "all tracked outputs present and fresh; generate next safe actions",
            "priority_rank": 10, "halt": False, "pending": [],
            "priority_model_status": model_status}


# ---------------------------------------------------------------------------
# CLASSIFY
# ---------------------------------------------------------------------------
def classify(task: str, observation: Dict[str, Any], breach: bool) -> Dict[str, Any]:
    if task == "halt_and_report":
        return {
            "task_id": "T-HALT",
            "task_name": task,
            "risk_class": "STOP",
            "allowed_scope": [],
            "input_paths": [],
            "output_paths": ["reports/latest/sentinel-autonomy-owner-summary.md"],
            "expected_outputs": [],
            "forbidden_actions": FORBIDDEN_TASKS,
            "guard_requirements": ["emergency_stop=true", "no live apply", "owner review"],
            "can_execute_now": False,
            "reason_if_blocked": "breach or forbidden pattern detected; only owner summary is produced",
        }

    risk = TASK_RISK_CLASS.get(task, HIGH)
    in_allowlist = task in ALLOWED_AUTONOMOUS_TASKS
    risk_ok = risk in AUTO_ALLOWED_RISK
    module = TASK_EXEC.get(task)
    module_missing = bool(module) and not (PROJECT_DIR / module[0]).exists()

    can_execute = in_allowlist and risk_ok and not breach and not module_missing
    reason_blocked = None
    if not in_allowlist:
        reason_blocked = "task not in ALLOWED_AUTONOMOUS_TASKS"
    elif not risk_ok:
        reason_blocked = f"risk_class {risk} is never auto-executed in Phase 10.0"
    elif breach:
        reason_blocked = "breach state blocks all execution"
    elif module_missing:
        reason_blocked = f"required module missing: {module[0]}"

    expected = TASK_EXPECTED_OUTPUTS.get(task, [])
    return {
        "task_id": f"T-{abs(hash(task)) % 100000:05d}",
        "task_name": task,
        "risk_class": risk,
        "allowed_scope": SCOPE_BY_RISK.get(risk, []),
        "input_paths": [str(p.relative_to(PROJECT_DIR)) for p in OBSERVED_FILES.values()],
        "output_paths": SCOPE_BY_RISK.get(risk, []),
        "expected_outputs": expected,
        "forbidden_actions": FORBIDDEN_TASKS,
        "guard_requirements": [
            "no network", "no live apply", "no customer credentials",
            "no HIGH", "no MEDIUM", "no free shell", "shell=False subprocess only",
        ],
        "can_execute_now": can_execute,
        "reason_if_blocked": reason_blocked,
        "module_backed": bool(module),
    }


TASK_EXPECTED_OUTPUTS: Dict[str, List[str]] = {
    "rebuild_payhip_upload_pack": ["reports/latest/sentinel-payhip-upload-pack-export.json"],
    "rebuild_manifest_and_checksums": ["reports/latest/sentinel-payhip-upload-pack-export.json"],
    "rerun_payhip_launch_qa": ["reports/latest/sentinel-payhip-launch-qa.json"],
    "update_fulfillment_board": ["reports/latest/sentinel-payhip-fulfillment-board.json"],
    "run_first_order_dryrun": ["reports/latest/sentinel-payhip-first-order-dryrun.json"],
    "update_service_proof": ["reports/latest/sentinel-service-proof.json"],
    "repair_missing_public_asset": ["reports/latest/sentinel-payhip-public-service-overview.md"],
    "repair_capability_health_warning": [
        "reports/latest/sentinel-autonomous-capability-health-governor.json",
        "reports/latest/sentinel-autonomous-capability-repair-validation.md",
    ],
    "update_owner_summary": ["reports/latest/sentinel-autonomy-owner-summary.md"],
    "generate_next_safe_actions": ["reports/latest/sentinel-autonomy-next-cycle.md"],
}


# ---------------------------------------------------------------------------
# EXECUTE
# ---------------------------------------------------------------------------
def execute(classification: Dict[str, Any], execute_flag: bool) -> Dict[str, Any]:
    task = classification["task_name"]

    if task == "halt_and_report":
        return {"task": task, "status": "halted", "executed": False,
                "detail": "no execution; breach/forbidden pattern -> owner summary only"}

    if not classification["can_execute_now"]:
        return {"task": task, "status": "blocked", "executed": False,
                "detail": classification["reason_if_blocked"] or "not executable"}

    module = TASK_EXEC.get(task)
    if module is None:
        # Internal task: the kernel handles it by writing its own report files.
        return {"task": task, "status": "internal_handled", "executed": True,
                "detail": "handled internally by the kernel (report generation)"}

    if not execute_flag:
        return {"task": task, "status": "would_execute", "executed": False,
                "detail": f"dry classification only; would run {module[0]} {' '.join(module[1])}"}

    result = run_module(module[0], module[1])
    executed = result["status"] == "executed"
    return {"task": task, "status": result["status"], "executed": executed,
            "module": result["module"], "module_args": result["args"],
            "returncode": result["returncode"], "stdout_lines": result["stdout_lines"],
            "detail": f"ran {module[0]} {' '.join(module[1])} via hard allowlist (shell=False)"}


# ---------------------------------------------------------------------------
# VALIDATE
# ---------------------------------------------------------------------------
def validate(classification: Dict[str, Any], execution: Dict[str, Any],
             safety: Dict[str, Any], breach: bool) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    def chk(cid: str, passed: bool, detail: str) -> None:
        checks.append({"check": cid, "passed": bool(passed), "detail": detail})

    # Expected outputs exist + JSON valid + non-empty.
    for rel in classification.get("expected_outputs", []):
        path = PROJECT_DIR / rel
        exists = path.exists()
        chk(f"exists:{rel}", exists, "present" if exists else "missing")
        if exists and path.suffix == ".json":
            _, st = read_optional_json(path)
            chk(f"json_valid:{rel}", st == "ok", st)
        if exists and path.suffix in (".md", ".txt", ".html"):
            try:
                nonempty = path.stat().st_size > 0
            except OSError:
                nonempty = False
            chk(f"non_empty:{rel}", nonempty, "non-empty" if nonempty else "empty")
            try:
                blob = path.read_text(encoding="utf-8", errors="replace")
                clean = not forbidden_real_findings(blob)
                chk(f"no_secret:{rel}", clean, "clean" if clean else "leak detected")
            except OSError:
                chk(f"no_secret:{rel}", False, "read error")

    # Invariants stay safe.
    chk("breach_false", not breach, "breach=false" if not breach else "breach")
    chk("live_apply_false", safety["live_apply"] is False, str(safety["live_apply"]))
    chk("allowed_apply_now_false", safety["allowed_apply_now"] is False,
        str(safety["allowed_apply_now"]))
    chk("high_blocked", safety["high_blocked"] is True, str(safety["high_blocked"]))
    chk("execution_not_failed", execution["status"] not in ("failed", "error", "timeout"),
        execution["status"])

    all_passed = all(c["passed"] for c in checks)
    has_failures = not all_passed
    status = "PASS" if all_passed else "ATTENTION"
    return {"status": status, "all_passed": all_passed, "has_failures": has_failures,
            "checks": checks,
            "failed": [c["check"] for c in checks if not c["passed"]]}


# ---------------------------------------------------------------------------
# REPAIR
# ---------------------------------------------------------------------------
def repair(classification: Dict[str, Any], execution: Dict[str, Any],
           validation: Dict[str, Any], observation: Dict[str, Any],
           breach: bool, execute_flag: bool) -> Dict[str, Any]:
    will_not_repair_by = [
        "website change", "Cloudflare change", "database change", "SFTP", "network",
        "customer data", "secrets", "live apply", "HIGH/MEDIUM execution",
    ]
    if breach:
        return {"status": "skipped_breach", "repaired": False, "actions": [],
                "will_not_repair_by": will_not_repair_by,
                "detail": "breach state: repair limited to owner summary, no auto-fix"}
    if validation["all_passed"]:
        return {"status": "not_needed", "repaired": False, "actions": [],
                "will_not_repair_by": will_not_repair_by,
                "detail": "validation passed; nothing to repair"}

    actions: List[str] = []
    repaired = False

    # Safe repair: regenerate missing public asset via allowlisted module.
    if observation["missing_public_assets"] and execute_flag:
        result = run_module("sentinel_payhip_public_client_assets.py", ["--build-public-assets"])
        actions.append(f"rebuild public assets -> {result['status']}")
        repaired = repaired or result["status"] == "executed"

    # Safe repair: rebuild manifest/checksums by re-running the export helper.
    needs_export = (_missing_or_stale(observation["export_pack"])
                    or not observation["zip_present"])
    if needs_export and execute_flag:
        result = run_module("sentinel_payhip_upload_pack_export_helper.py", ["--build-export"])
        actions.append(f"rebuild export pack + manifest/checksums -> {result['status']}")
        repaired = repaired or result["status"] == "executed"

    # Broken JSON owned by the kernel is always rewritten freshly each run, so
    # foreign broken JSON is only documented as an owner recommendation.
    if observation["broken_json"]:
        actions.append("documented broken foreign JSON for owner re-run "
                       f"({len(observation['broken_json'])} file(s)); not auto-overwritten")

    if not actions:
        actions.append("no safe automatic repair available; documented for owner review")

    return {"status": "repaired" if repaired else "documented", "repaired": repaired,
            "actions": actions, "will_not_repair_by": will_not_repair_by}


# ---------------------------------------------------------------------------
# LEARN
# ---------------------------------------------------------------------------
def learn(decision: Dict[str, Any], classification: Dict[str, Any],
          execution: Dict[str, Any], validation: Dict[str, Any],
          repair_res: Dict[str, Any], observation: Dict[str, Any],
          next_suggested: str, timestamp: str) -> Dict[str, Any]:
    task = decision["selected_task"]

    task_memory = _load_state(TASK_MEMORY_JSON, {})
    if not isinstance(task_memory, dict):
        task_memory = {}
    counts = task_memory.get("task_counts", {})
    counts[task] = int(counts.get(task, 0)) + 1
    task_memory["task_counts"] = counts
    task_memory["last_task"] = task
    task_memory["last_status"] = execution["status"]
    task_memory["last_validation"] = validation["status"]
    task_memory["last_updated"] = timestamp
    if execution["executed"] and validation["all_passed"]:
        task_memory["last_successful_task"] = task
    task_memory["last_blockers"] = (
        [classification["reason_if_blocked"]] if classification.get("reason_if_blocked") else []
    )

    success_patterns = _load_state(SUCCESS_PATTERNS_JSON, [])
    blocked_patterns = _load_state(BLOCKED_PATTERNS_JSON, [])
    repair_patterns = _load_state(REPAIR_PATTERNS_JSON, [])
    if not isinstance(success_patterns, list):
        success_patterns = []
    if not isinstance(blocked_patterns, list):
        blocked_patterns = []
    if not isinstance(repair_patterns, list):
        repair_patterns = []

    if execution["executed"] and validation["all_passed"]:
        success_patterns.append({"ts": timestamp, "task": task,
                                 "risk_class": classification["risk_class"]})
    if execution["status"] in ("blocked", "halted"):
        blocked_patterns.append({"ts": timestamp, "task": task,
                                 "reason": classification.get("reason_if_blocked")
                                 or decision["reason"]})
    if repair_res.get("repaired"):
        repair_patterns.append({"ts": timestamp, "task": task,
                                "actions": repair_res["actions"]})

    success_patterns = success_patterns[-HISTORY_LIMIT:]
    blocked_patterns = blocked_patterns[-HISTORY_LIMIT:]
    repair_patterns = repair_patterns[-HISTORY_LIMIT:]

    learning = {
        "selected_task": task,
        "execution_status": execution["status"],
        "validation_status": validation["status"],
        "repaired": repair_res.get("repaired", False),
        "blocked_reason": classification.get("reason_if_blocked"),
        "missing_inputs": observation["missing_inputs"],
        "useful_outputs": classification.get("expected_outputs", []),
        "next_suggested_task": next_suggested,
        "not_stored": ["passwords", "tokens", "API keys", "real customer data",
                       "private keys", "customer access data", "payment data"],
    }
    return {
        "learning": learning,
        "task_memory": task_memory,
        "success_patterns": success_patterns,
        "blocked_patterns": blocked_patterns,
        "repair_patterns": repair_patterns,
    }


# ---------------------------------------------------------------------------
# Pipeline assembly
# ---------------------------------------------------------------------------
def next_suggestion(observation: Dict[str, Any], decision: Dict[str, Any]) -> str:
    pending = decision.get("pending", [])
    if len(pending) > 1:
        return pending[1][0]
    if decision["selected_task"] == "halt_and_report":
        return "owner review then re-run --cycle"
    return "generate_next_safe_actions"


def build_full_state(execute_flag: bool = False) -> Dict[str, Any]:
    timestamp = utc_now()
    safety = resolve_safety()
    breach, breach_reasons = compute_breach(safety)
    git = _git_status()

    observation = observe()
    decision = decide(observation, breach)
    task = decision["selected_task"]
    classification = classify(task, observation, breach)
    capability_context = capability_context_for(task, decision)
    mission_context = mission_context_for(task, decision)
    mission_runner = mission_runner_context()
    operations_supervisor = operations_supervisor_context()
    operation_governor = operation_governor_context()
    health_governor, health_governor_status = read_optional_json(HEALTH_GOVERNOR_JSON)
    health_governor_context = {
        "state_path": "state/adaptive-learning/latest_autonomous_capability_health_governor.json",
        "status": health_governor.get("status") if health_governor_status == "ok" and isinstance(health_governor, dict) else health_governor_status,
        "before_health": health_governor.get("before_health") if isinstance(health_governor, dict) else None,
        "after_health": health_governor.get("after_health") if isinstance(health_governor, dict) else None,
        "warning_count": health_governor.get("warning_count") if isinstance(health_governor, dict) else 0,
        "repairs_attempted": health_governor.get("planned_repair_count") if isinstance(health_governor, dict) else 0,
        "repairs_successful": health_governor.get("executed_repair_count") if isinstance(health_governor, dict) else 0,
        "repairs_blocked": health_governor.get("blocked_repair_count") if isinstance(health_governor, dict) else 0,
    }
    execution = execute(classification, execute_flag)
    validation = validate(classification, execution, safety, breach)
    repair_res = repair(classification, execution, validation, observation, breach, execute_flag)
    nxt = next_suggestion(observation, decision)
    learned = learn(decision, classification, execution, validation, repair_res,
                    observation, nxt, timestamp)

    autonomous_capabilities = [
        t for t in ALLOWED_AUTONOMOUS_TASKS
        if TASK_RISK_CLASS.get(t, HIGH) in AUTO_ALLOWED_RISK
    ]

    owner_summary = {
        "what_sentinel_did": (f"Selected and handled '{task}' "
                              f"({execution['status']})."),
        "why_this_task": decision["reason"],
        "priority_engine_status": decision.get("priority_model_status", "not_checked"),
        "selected_mission": mission_context.get("selected_mission"),
        "mission_reason": mission_context.get("mission_reason"),
        "mission_risk": mission_context.get("mission_risk"),
        "mission_status": mission_context.get("mission_status"),
        "next_mission": mission_context.get("next_mission"),
        "mission_runner_status": mission_runner.get("mission_runner_status"),
        "mission_runner_completed_count": mission_runner.get("completed_mission_count"),
        "mission_runner_stop_reason": mission_runner.get("stop_reason"),
        "supervisor_status": operations_supervisor.get("supervisor_status"),
        "selected_operation": operations_supervisor.get("selected_operation"),
        "next_operation": operations_supervisor.get("next_operation"),
        "operation_governor_status": operation_governor.get("status"),
        "operation_governor_selected": operation_governor.get("selected_operation"),
        "selected_capability": capability_context.get("selected_capability"),
        "capability_health": capability_context.get("capability_health"),
        "capability_reason": capability_context.get("capability_reason"),
        "capability_risk": capability_context.get("capability_risk"),
        "capability_freshness": capability_context.get("capability_freshness"),
        "capability_health_before": health_governor_context.get("before_health"),
        "capability_health_after": health_governor_context.get("after_health"),
        "repairs_attempted": health_governor_context.get("repairs_attempted"),
        "repairs_successful": health_governor_context.get("repairs_successful"),
        "repairs_blocked": health_governor_context.get("repairs_blocked"),
        "what_was_created": classification.get("expected_outputs", []),
        "what_was_validated": validation["status"],
        "what_was_blocked": (classification.get("reason_if_blocked")
                             if not classification["can_execute_now"] else "nothing"),
        "what_was_learned": learned["learning"]["next_suggested_task"],
        "next_safe_step": nxt,
        "what_stays_forbidden": FORBIDDEN_TASKS,
        "live_apply": safety["live_apply"],
        "emergency_stop": safety["emergency_stop"],
        "allowed_apply_now": safety["allowed_apply_now"],
        "breach": breach,
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "generated_at": timestamp,
        "status": "AUTONOMY_HALTED" if decision.get("halt") else "AUTONOMY_CYCLE_OK",
        "doctrine": "automatic autonomous, safely controlled, self-validating, "
                    "self-correcting, self-learning - within the safety doctrine",
        "execute_mode": execute_flag,
        "observation": observation,
        "decision": decision,
        "priority_engine_integration": {
            "model_path": "state/adaptive-learning/autonomy_task_priority_model.json",
            "status": decision.get("priority_model_status", "not_checked"),
            "used": bool((decision.get("priority_engine") or {}).get("used")),
            "anti_loop_status": (decision.get("priority_engine") or {}).get("anti_loop_status"),
            "diversity_status": (decision.get("priority_engine") or {}).get("diversity_status"),
            "cooldown_respected": (decision.get("priority_engine") or {}).get("cooldown_respected"),
        },
        "goal_manager_integration": mission_context,
        "mission_runner_integration": mission_runner,
        "operations_supervisor_integration": operations_supervisor,
        "operation_governor_integration": operation_governor,
        "capability_registry_integration": capability_context,
        "capability_health_governor_integration": health_governor_context,
        "classification": classification,
        "execution": execution,
        "validation": validation,
        "repair": repair_res,
        "learning": learned["learning"],
        "owner_summary": owner_summary,
        "next_suggested_task": nxt,
        "autonomous_capabilities_now_enabled": autonomous_capabilities,
        "blocked_capabilities": FORBIDDEN_TASKS,
        "never_auto_risk_classes": sorted(NEVER_AUTO_RISK),
        "low_live_executable": False,
        "autonomy_level": safety["current_level"],
        "live_apply": safety["live_apply"],
        "emergency_stop": safety["emergency_stop"],
        "allowed_apply_now": safety["allowed_apply_now"],
        "high_blocked": safety["high_blocked"],
        "high_risk_blocked": True,
        "breach": breach,
        "breach_reasons": breach_reasons,
        "network_access": False,
        "sends_email": False,
        "uploads_anything": False,
        "installs_packages": False,
        "installs_timers": False,
        "applies_changes": False,
        "stores_credentials": False,
        "processes_real_customer_data": False,
        "free_shell_used": False,
        "secrets_in_report": False,
        "recommended_git_checkpoint": RECOMMENDED_GIT_CHECKPOINT,
        "git_checkpoint": git,
    }
    return {"report": report, "safety": safety, "breach": breach,
            "state": learned}


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def _kv_lines(d: Dict[str, Any], keys: List[str]) -> List[str]:
    return [f"- **{k}**: {redact_text(d.get(k), max_len=200)}" for k in keys]


def render_observation_md(o: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Observation", "",
             f"- all Phase-9 modules present: {o['all_phase9_modules_present']}",
             f"- export files (latest): {o['export_files_count']} | ZIP present: {o['zip_present']}",
             f"- old export packs: {o['old_export_packs']}",
             f"- daily reports present: {o['daily_reports_present']}",
             f"- launch QA: exists={o['launch_qa']['exists']} stale={o['launch_qa']['stale']}",
             f"- fulfillment board: exists={o['fulfillment_board']['exists']} "
             f"stale={o['fulfillment_board']['stale']}",
             f"- first order dry-run: exists={o['first_order_dryrun']['exists']}",
             f"- service proof: exists={o['service_proof']['exists']} "
             f"stale={o['service_proof']['stale']}",
             f"- missing inputs: {len(o['missing_inputs'])}",
             f"- missing public assets: {len(o['missing_public_assets'])}",
             f"- broken JSON outputs: {len(o['broken_json'])}",
             f"- forbidden patterns in public assets: {len(o['forbidden_in_public'])}",
             f"- last successful task: {redact_text(o['last_successful_task'])}",
             ""]
    return "\n".join(lines) + "\n"


def render_decision_md(d: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Task Decision", "",
             f"- selected task: **{d['selected_task']}**",
             f"- reason: {d['reason']}",
             f"- priority rank: {d['priority_rank']}",
             f"- halt: {d.get('halt', False)}",
             f"- priority model status: {d.get('priority_model_status', '-')}",
             f"- priority engine used: {bool((d.get('priority_engine') or {}).get('used'))}", "",
             "## Pending (priority order)"]
    if d.get("pending"):
        for t, r in d["pending"]:
            lines.append(f"- {t}: {r}")
    else:
        lines.append("- (none)")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_classification_md(c: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Classification", "",
             f"- task_id: {c['task_id']}",
             f"- task_name: {c['task_name']}",
             f"- risk_class: {c['risk_class']}",
             f"- allowed_scope: {', '.join(c['allowed_scope']) or '-'}",
             f"- can_execute_now: {c['can_execute_now']}",
             f"- reason_if_blocked: {redact_text(c['reason_if_blocked'])}",
             "", "## Expected outputs"]
    for e in c["expected_outputs"] or ["-"]:
        lines.append(f"- {e}")
    lines += ["", "## Guard requirements"]
    for g in c["guard_requirements"]:
        lines.append(f"- {g}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_execution_md(e: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Execution Result", "",
             f"- task: {e['task']}",
             f"- status: **{e['status']}**",
             f"- executed: {e['executed']}",
             f"- detail: {redact_text(e.get('detail'))}"]
    if "module" in e:
        lines += [f"- module: {e['module']}",
                  f"- module args: {' '.join(e.get('module_args', []))}",
                  f"- returncode: {e.get('returncode')}",
                  f"- stdout lines: {e.get('stdout_lines')}"]
    lines.append("")
    return "\n".join(lines) + "\n"


def render_validation_md(v: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Validation", "",
             f"- status: **{v['status']}**",
             f"- all passed: {v['all_passed']}", "", "## Checks"]
    for c in v["checks"]:
        mark = "x" if c["passed"] else " "
        lines.append(f"- [{mark}] {c['check']} - {redact_text(c['detail'], max_len=120)}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_repair_md(rp: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Repair", "",
             f"- status: **{rp['status']}**",
             f"- repaired: {rp['repaired']}", "", "## Actions"]
    for a in rp["actions"] or ["-"]:
        lines.append(f"- {redact_text(a, max_len=160)}")
    lines += ["", "## Never repaired by"]
    for w in rp["will_not_repair_by"]:
        lines.append(f"- {w}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_learning_md(l: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Learning", "",
             f"- selected task: {l['selected_task']}",
             f"- execution status: {l['execution_status']}",
             f"- validation status: {l['validation_status']}",
             f"- repaired: {l['repaired']}",
             f"- next suggested task: {l['next_suggested_task']}",
             "", "## Never stored"]
    for n in l["not_stored"]:
        lines.append(f"- {n}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_owner_summary_md(s: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Owner Summary", "",
             f"- What Sentinel did: {redact_text(s['what_sentinel_did'])}",
             f"- Why this task: {redact_text(s['why_this_task'])}",
             f"- Priority engine: {redact_text(s.get('priority_engine_status'))}",
             f"- Selected mission: {redact_text(s.get('selected_mission'))}",
             f"- Mission reason: {redact_text(s.get('mission_reason'))}",
             f"- Mission risk: {redact_text(s.get('mission_risk'))}",
             f"- Mission status: {redact_text(s.get('mission_status'))}",
             f"- Next mission: {redact_text(s.get('next_mission'))}",
             f"- Mission runner status: {redact_text(s.get('mission_runner_status'))}",
             f"- Mission runner completed count: {redact_text(s.get('mission_runner_completed_count'))}",
             f"- Mission runner stop reason: {redact_text(s.get('mission_runner_stop_reason'))}",
             f"- Supervisor status: {redact_text(s.get('supervisor_status'))}",
             f"- Selected operation: {redact_text(s.get('selected_operation'))}",
             f"- Next operation: {redact_text(s.get('next_operation'))}",
             f"- Operation governor status: {redact_text(s.get('operation_governor_status'))}",
             f"- Operation governor selected: {redact_text(s.get('operation_governor_selected'))}",
             f"- Selected capability: {redact_text(s.get('selected_capability'))}",
             f"- Capability health: {redact_text(s.get('capability_health'))}",
             f"- Capability risk: {redact_text(s.get('capability_risk'))}",
             f"- Capability freshness: {redact_text(s.get('capability_freshness'))}",
             f"- Capability health before: {redact_text(s.get('capability_health_before'))}",
             f"- Capability health after: {redact_text(s.get('capability_health_after'))}",
             f"- Repairs attempted: {redact_text(s.get('repairs_attempted'))}",
             f"- Repairs successful: {redact_text(s.get('repairs_successful'))}",
             f"- Repairs blocked: {redact_text(s.get('repairs_blocked'))}",
             f"- What was validated: {s['what_was_validated']}",
             f"- What was blocked: {redact_text(s['what_was_blocked'])}",
             f"- What was learned -> next: {redact_text(s['what_was_learned'])}",
             f"- Next safe step: {redact_text(s['next_safe_step'])}",
             "", "## What was created"]
    for c in s["what_was_created"] or ["-"]:
        lines.append(f"- {c}")
    lines += ["", "## What stays forbidden"]
    for f in s["what_stays_forbidden"]:
        lines.append(f"- {f}")
    lines += ["", "## Safety",
              f"- live_apply: {s['live_apply']}",
              f"- emergency_stop: {s['emergency_stop']}",
              f"- allowed_apply_now: {s['allowed_apply_now']}",
              f"- breach: {s['breach']}", ""]
    return "\n".join(lines) + "\n"


def render_next_cycle_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Next Cycle", "",
             f"- next suggested task: **{report['next_suggested_task']}**",
             "", "## Autonomous capabilities now enabled (safe, local)"]
    for c in report["autonomous_capabilities_now_enabled"]:
        lines.append(f"- {c}")
    lines += ["", "## Blocked capabilities (never automatic)"]
    for c in report["blocked_capabilities"]:
        lines.append(f"- {c}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_git_checkpoint_md(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy - Git Checkpoint Suggestion", "",
             "> Suggestion only. Nothing is committed automatically.",
             "> Do NOT commit reports/state/audit/exports.", "",
             "## Recommended files (script + playbooks only)"]
    for f in report["recommended_git_checkpoint"]:
        lines.append(f"- {f}")
    g = report["git_checkpoint"]
    lines += ["", f"- untracked: {g['untracked_count']} | modified: {g['modified_count']} | "
              f"checkpoint recommended: {g['recommended']}", ""]
    return "\n".join(lines) + "\n"


def render_kernel_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Self-Governing Safe Autonomy Kernel (Phase 10.0)", "",
        f"- status: **{report['status']}**",
        f"- generated: {report['generated_at']}",
        f"- selected task: {report['decision']['selected_task']}",
        f"- priority engine: {report.get('priority_engine_integration', {}).get('status', '-')}",
        f"- selected capability: {report.get('capability_registry_integration', {}).get('selected_capability', '-')}",
        f"- capability health: {report.get('capability_registry_integration', {}).get('capability_health', '-')}",
        f"- execution: {report['execution']['status']}",
        f"- validation: {report['validation']['status']}",
        f"- repair: {report['repair']['status']}",
        f"- next suggested task: {report['next_suggested_task']}",
        "",
        "## Doctrine",
        f"_{report['doctrine']}_",
        "",
        "Within its boundaries it executes itself. Outside its boundaries it blocks "
        "itself. After every execution it validates itself. On safe failures it repairs "
        "itself. Then it learns by itself.",
        "",
        "## Safety",
        f"- live_apply: {report['live_apply']}",
        f"- emergency_stop: {report['emergency_stop']}",
        f"- allowed_apply_now: {report['allowed_apply_now']}",
        f"- HIGH blocked: {report['high_blocked']}",
        f"- breach: {report['breach']}",
        "- emergency_stop=true blocks live/external systems, but NOT safe local autonomy.",
        "",
        "## Autonomous capabilities now enabled (safe, local)",
    ]
    for c in report["autonomous_capabilities_now_enabled"]:
        lines.append(f"- {c}")
    lines += ["", "## Blocked capabilities (never automatic)"]
    for c in report["blocked_capabilities"]:
        lines.append(f"- {c}")
    lines += ["", "## Recommended Git checkpoint (script + playbooks only)"]
    for f in report["recommended_git_checkpoint"]:
        lines.append(f"- {f}")
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------
def build_playbooks(report: Dict[str, Any]) -> Dict[Path, Dict[str, Any]]:
    base = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": report["generated_at"],
        "read_only_core": True,
        "applies_changes": False,
        "uploads_anything": False,
        "network_access": False,
    }
    return {
        PLAYBOOK_KERNEL: dict(base, playbook="sentinel-self-governing-autonomy-kernel",
                              cycle=["observe", "decide", "classify", "execute", "validate",
                                     "repair", "learn", "owner_summary", "next_cycle"],
                              allowed_autonomous_tasks=ALLOWED_AUTONOMOUS_TASKS,
                              blocked_capabilities=FORBIDDEN_TASKS,
                              live_apply=False, emergency_stop=True, allowed_apply_now=False,
                              high_blocked=True),
        PLAYBOOK_CYCLE: dict(base, playbook="sentinel-autonomy-cycle",
                             steps=[
                                 "Observe project state and inputs.",
                                 "Decide the next sensible task by priority.",
                                 "Classify risk and check if auto-allowed.",
                                 "Execute only READ_ONLY/DRAFT/LOW_LOCAL/LOW_EXPORT/LOW_STATE.",
                                 "Validate outputs and invariants.",
                                 "Repair safe failures only.",
                                 "Learn and emit owner summary + next suggestion.",
                             ]),
        PLAYBOOK_CLASSIFICATION: dict(base, playbook="sentinel-autonomy-task-classification",
                                      auto_allowed_risk=sorted(AUTO_ALLOWED_RISK),
                                      never_auto_risk=sorted(NEVER_AUTO_RISK),
                                      task_risk_class=TASK_RISK_CLASS,
                                      low_live_executable=False),
        PLAYBOOK_VALIDATION_REPAIR: dict(base, playbook="sentinel-autonomy-validation-repair",
                                         validates=["expected files", "json valid",
                                                    "non-empty md/txt/html", "no secrets",
                                                    "breach=false", "live_apply=false",
                                                    "allowed_apply_now=false", "HIGH blocked"],
                                         repairs_only=["missing public asset",
                                                       "missing manifest/checksums",
                                                       "kernel-owned reports"],
                                         never_repairs_by=["website", "cloudflare", "db",
                                                           "sftp", "network", "secrets",
                                                           "live apply", "HIGH/MEDIUM"]),
    }


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------
def write_all_outputs(state: Dict[str, Any]) -> List[str]:
    report = state["report"]
    learned = state["state"]
    written: List[str] = []

    def w(path: Path, text: str) -> None:
        write_text_atomic(path, text)
        written.append(str(path.relative_to(PROJECT_DIR)))

    def wj(path: Path, data: Any) -> None:
        write_json_atomic(path, data)
        written.append(str(path.relative_to(PROJECT_DIR)))

    wj(KERNEL_JSON, report)
    w(KERNEL_MD, render_kernel_md(report))
    w(OBSERVATION_MD, render_observation_md(report["observation"]))
    w(DECISION_MD, render_decision_md(report["decision"]))
    w(CLASSIFICATION_MD, render_classification_md(report["classification"]))
    w(EXECUTION_MD, render_execution_md(report["execution"]))
    w(VALIDATION_MD, render_validation_md(report["validation"]))
    w(REPAIR_MD, render_repair_md(report["repair"]))
    w(LEARNING_MD, render_learning_md(report["learning"]))
    w(OWNER_SUMMARY_MD, render_owner_summary_md(report["owner_summary"]))
    w(NEXT_CYCLE_MD, render_next_cycle_md(report))
    w(GIT_CHECKPOINT_MD, render_git_checkpoint_md(report))

    wj(STATE_JSON, report)
    wj(STATE_LATEST_JSON, report)
    wj(TASK_MEMORY_JSON, learned["task_memory"])
    wj(SUCCESS_PATTERNS_JSON, learned["success_patterns"])
    wj(BLOCKED_PATTERNS_JSON, learned["blocked_patterns"])
    wj(REPAIR_PATTERNS_JSON, learned["repair_patterns"])

    history = _load_state(CYCLE_HISTORY_JSON, [])
    if not isinstance(history, list):
        history = []
    history.append({
        "ts": report["generated_at"],
        "selected_task": report["decision"]["selected_task"],
        "execution_status": report["execution"]["status"],
        "validation_status": report["validation"]["status"],
        "repaired": report["repair"]["repaired"],
        "breach": report["breach"],
    })
    history = history[-HISTORY_LIMIT:]
    wj(CYCLE_HISTORY_JSON, history)

    for path, data in build_playbooks(report).items():
        wj(path, data)

    append_jsonl(AUDIT_JSONL, [{
        "ts": report["generated_at"],
        "phase": PHASE,
        "module": "sentinel_self_governing_safe_autonomy_kernel",
        "status": report["status"],
        "selected_task": report["decision"]["selected_task"],
        "execution_status": report["execution"]["status"],
        "validation_status": report["validation"]["status"],
        "repaired": report["repair"]["repaired"],
        "execute_mode": report["execute_mode"],
        "live_apply": report["live_apply"],
        "emergency_stop": report["emergency_stop"],
        "allowed_apply_now": report["allowed_apply_now"],
        "high_blocked": report["high_blocked"],
        "breach": report["breach"],
        "secrets_in_report": False,
    }])
    written.append(str(AUDIT_JSONL.relative_to(PROJECT_DIR)))

    return written


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def run_self_test() -> int:
    full_src = Path(__file__).read_text(encoding="utf-8")
    _st = full_src.find("\ndef run_self_test")
    _end = full_src.find("\ndef ", _st + 1) if _st != -1 else -1
    src = full_src[:_st] + (full_src[_end:] if _end != -1 else "") if _st != -1 else full_src

    if re.search(r"add_argument\([\"']--apply", src):
        raise AssertionError("module must not define a free --apply")

    net_import = re.compile(
        r"(?m)^\s*(?:import|from)\s+(requests|urllib|http\.client|smtplib|socket|paramiko|cloudflare)\b"
    )
    if net_import.search(src):
        raise AssertionError("module must not import network/email libraries")

    if re.search(r"shell\s*=\s*True", src):
        raise AssertionError("module must never use shell" + "=True")

    install_re = re.compile(r"(?i)\b(apt-get|apt|pip3?|npm|yarn|pipenv|poetry)\s+install\b")
    if install_re.search(src):
        raise AssertionError("module must not install packages")

    forbidden_capabilities = [
        ("sftp write", re.compile(r"paramiko|sftp\.put\(|\.put\(\s")),
        ("db write", re.compile(r"\$wpdb|wpdb->|cursor\.\w+\(|\.execute\(|pymysql|psycopg|MySQLdb|"
                                r"DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET")),
        ("cloudflare write", re.compile(r"api\.cloudflare\.com|requests\.(put|post|patch|delete)\(|"
                                        r"httpx\.(put|post|patch|delete)\(")),
        ("wordpress write", re.compile(r"wp_insert_post|wp_update_post|update_option\(|wp_mail\(|"
                                       r"add_post_meta\(")),
        ("service start/enable", re.compile(r"systemctl\s+(start|enable|restart|stop|disable)\b")),
        ("timer install", re.compile(r"systemctl\s+daemon-reload\b|crontab\s+-[uerl]\b|"
                                     r"WantedBy\s*=|\.timer\s+install")),
        ("rm " + "-rf", re.compile(r"rm\s+-rf|shutil\.rmtree")),
    ]
    for label, pattern in forbidden_capabilities:
        if pattern.search(src):
            raise AssertionError(f"forbidden capability present in source: {label}")

    allowed_names = {str(r.relative_to(PROJECT_DIR)) for r in ALLOWED_WRITE_ROOTS}
    if allowed_names != {"reports/latest", "state/adaptive-learning", "audit",
                         "exports/payhip-upload-pack", "playbooks"}:
        raise AssertionError(f"unexpected write roots: {allowed_names}")

    # Subprocess allowlist enforcement.
    try:
        run_module("rm.py", ["--status"])
    except ValueError:
        pass
    else:
        raise AssertionError("run_module accepted a non-allowlisted file")
    try:
        run_module("sentinel_payhip_fulfillment_board.py", ["--evil"])
    except ValueError:
        pass
    else:
        raise AssertionError("run_module accepted a non-allowlisted argument")

    # Risk gating: LOW_LIVE / MEDIUM / HIGH never auto-executable.
    for risk in NEVER_AUTO_RISK:
        if risk in AUTO_ALLOWED_RISK:
            raise AssertionError(f"{risk} must never be auto-allowed")
    fake_obs = {"missing_public_assets": [], "broken_json": [], "export_pack": {"exists": True,
                "stale": False}, "zip_present": True, "launch_qa": {"exists": True, "stale": False},
                "fulfillment_board": {"exists": True, "stale": False},
                "first_order_dryrun": {"exists": True}, "service_proof": {"exists": True,
                "stale": False}, "forbidden_in_public": {}, "missing_inputs": []}
    for high_task in ("execute HIGH-risk-change",):
        c = classify(high_task, fake_obs, breach=False)
        if c["can_execute_now"]:
            raise AssertionError("unknown/HIGH task must not be executable")

    # emergency_stop=true must NOT block safe local autonomy.
    safety_es = {"live_apply": False, "emergency_stop": True, "allowed_apply_now": False,
                 "current_level": LEVEL_2, "high_blocked": True, "upstream_breach": False}
    if compute_breach(safety_es)[0]:
        raise AssertionError("emergency_stop=true must not breach / block safe local autonomy")
    c_safe = classify("observe_project_state", fake_obs, breach=False)
    if not c_safe["can_execute_now"]:
        raise AssertionError("safe READ_ONLY task must be auto-executable under emergency_stop")

    # Breach detection on tampered safety.
    for tamper in ({"live_apply": True}, {"emergency_stop": False}, {"allowed_apply_now": True},
                   {"current_level": "LEVEL_4_MEDIUM_CANARY_ONLY"}, {"high_blocked": False},
                   {"upstream_breach": True}):
        if not compute_breach(dict(safety_es, **tamper))[0]:
            raise AssertionError(f"tamper did not breach: {tamper}")
    # Under breach, even safe tasks blocked; decision halts.
    c_breach = classify("observe_project_state", fake_obs, breach=True)
    if c_breach["can_execute_now"]:
        raise AssertionError("breach must block execution")
    if decide(fake_obs, breach=True)["selected_task"] != "halt_and_report":
        raise AssertionError("breach must halt")

    # Forbidden pattern in public assets must halt.
    if decide(dict(fake_obs, forbidden_in_public={"x.md": ["secret_assignment"]}),
              breach=False)["selected_task"] != "halt_and_report":
        raise AssertionError("forbidden pattern must halt")

    # Public scanner catches real leaks, not the business own domain/e-mail.
    for bad in ("see /etc/passwd", "origin 203.0.113.7", "ghp_" + "abcdefghijklmnop12345",
                "password" + "=" + "ABCDEFGH12345678"):
        if not forbidden_real_findings(bad):
            raise AssertionError(f"forbidden_real_findings missed: {bad}")
    for ok in ("Contact us at hello@some-business.com", "Visit https://some-business.com",
               "Never store passwords, API keys or tokens."):
        if forbidden_real_findings(ok):
            raise AssertionError(f"forbidden_real_findings false positive: {ok}")

    # Kernel-own writer stays strict (example-only domains, no secrets/paths/IPs).
    for bad in ("token" + "=" + "ABCDEFGH12345678", "path /srv/sentinel-defense", "ip 198.51.100.9",
                "visit https://real-customer-site.com"):
        try:
            write_text_atomic(KERNEL_MD, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"kernel writer failed to reject: {bad}")
    for forbidden in (PROJECT_DIR / "reports/latest/x.sh",
                      PROJECT_DIR / "config/x.json",
                      PROJECT_DIR / "state/adaptive-learning/x.service"):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")

    # Build a full state in-memory (no module subprocess) and verify invariants.
    state = build_full_state(execute_flag=False)
    report = state["report"]
    if report["live_apply"] is not False:
        raise AssertionError("live_apply must be false")
    if report["emergency_stop"] is not True:
        raise AssertionError("emergency_stop must be true")
    if report["allowed_apply_now"] is not False:
        raise AssertionError("allowed_apply_now must be false")
    if report["high_blocked"] is not True or report["high_risk_blocked"] is not True:
        raise AssertionError("HIGH must stay blocked")
    if report["low_live_executable"] is not False:
        raise AssertionError("LOW_LIVE must not be executable")
    if report["autonomy_level"] not in ALLOWED_CURRENT_LEVELS:
        raise AssertionError("autonomy_level must be LEVEL_1/LEVEL_2")
    if report["breach"]:
        raise AssertionError(f"clean state must not breach: {report['breach_reasons']}")
    for flag in ("network_access", "sends_email", "uploads_anything", "installs_packages",
                 "installs_timers", "applies_changes", "stores_credentials",
                 "processes_real_customer_data", "free_shell_used", "secrets_in_report"):
        if report[flag] is not False:
            raise AssertionError(f"{flag} must be false")

    # All rendered kernel outputs must be JSON-serialisable and public-safe.
    rendered = [
        render_kernel_md(report), render_observation_md(report["observation"]),
        render_decision_md(report["decision"]), render_classification_md(report["classification"]),
        render_execution_md(report["execution"]), render_validation_md(report["validation"]),
        render_repair_md(report["repair"]), render_learning_md(report["learning"]),
        render_owner_summary_md(report["owner_summary"]), render_next_cycle_md(report),
        render_git_checkpoint_md(report),
    ]
    for blob in rendered:
        findings = forbidden_real_findings(blob)
        if findings:
            raise AssertionError(f"kernel output not public-safe: {findings}")
    for obj in (report, *build_playbooks(report).values(),
                state["state"]["task_memory"], state["state"]["success_patterns"]):
        json.dumps(obj)

    if not detect_secret_like("password" + "=" + "supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("the autonomy core needs no login and stores no credentials"):
        raise AssertionError("secret detector false positive on prose")

    print("self-governing-safe-autonomy-kernel self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], written: List[str]) -> None:
    r = state["report"]
    print("=== Sentinel Self-Governing Safe Autonomy Kernel (Phase 10.0) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"observe status: all modules present={r['observation']['all_phase9_modules_present']} | "
          f"broken_json={len(r['observation']['broken_json'])} | "
          f"missing_public_assets={len(r['observation']['missing_public_assets'])}")
    print(f"selected task: {r['decision']['selected_task']} ({r['decision']['reason']})")
    print(f"classification: risk={r['classification']['risk_class']} "
          f"can_execute_now={r['classification']['can_execute_now']}")
    print(f"execution status: {r['execution']['status']}")
    print(f"validation status: {r['validation']['status']}")
    print(f"repair status: {r['repair']['status']}")
    print(f"learning status: next={r['learning']['next_suggested_task']}")
    print(f"next suggested task: {r['next_suggested_task']}")
    print(f"owner summary status: written ({len(r['owner_summary']['what_was_created'])} outputs)")
    print("autonomous capabilities now enabled:")
    for c in r["autonomous_capabilities_now_enabled"]:
        print(f"  - {c}")
    print("blocked capabilities:")
    for c in r["blocked_capabilities"]:
        print(f"  - {c}")
    print(f"live_apply: {r['live_apply']}")
    print(f"emergency_stop: {r['emergency_stop']}")
    print(f"allowed_apply_now: {r['allowed_apply_now']}")
    print(f"HIGH blocked: {r['high_blocked']}")
    print(f"breach: {r['breach']}")
    print("recommended Git checkpoint (script + playbooks only):")
    for f in r["recommended_git_checkpoint"]:
        print(f"  - {f}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Self-Governing Safe Autonomy Kernel (Phase 10.0). "
                    "Safe local autonomy only; no live apply, no network, no upload."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--observe", action="store_true", help="Observe the project state.")
    p.add_argument("--decide", action="store_true", help="Decide the next task.")
    p.add_argument("--classify", action="store_true", help="Classify the selected task.")
    p.add_argument("--execute", action="store_true", help="Execute the selected safe task.")
    p.add_argument("--validate", action="store_true", help="Validate outputs/invariants.")
    p.add_argument("--repair", action="store_true", help="Repair safe failures.")
    p.add_argument("--learn", action="store_true", help="Update learning state.")
    p.add_argument("--cycle", action="store_true", help="Run one full safe cycle.")
    p.add_argument("--status", action="store_true", help="Print status summary.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    execute_flag = bool(args.execute or args.cycle)
    state = build_full_state(execute_flag=execute_flag)
    written = write_all_outputs(state)
    r = state["report"]

    if args.observe:
        o = r["observation"]
        print(f"[observe] modules_present={o['all_phase9_modules_present']} "
              f"broken_json={len(o['broken_json'])} missing_assets={len(o['missing_public_assets'])} "
              f"forbidden_in_public={len(o['forbidden_in_public'])}")
    if args.decide:
        print(f"[decide] selected={r['decision']['selected_task']} | {r['decision']['reason']}")
    if args.classify:
        c = r["classification"]
        print(f"[classify] {c['task_name']} risk={c['risk_class']} "
              f"can_execute_now={c['can_execute_now']}")
    if args.execute:
        print(f"[execute] {r['execution']['task']} -> {r['execution']['status']}")
    if args.validate:
        print(f"[validate] {r['validation']['status']} (failed={r['validation']['failed']})")
    if args.repair:
        print(f"[repair] {r['repair']['status']} repaired={r['repair']['repaired']}")
    if args.learn:
        print(f"[learn] next={r['learning']['next_suggested_task']}")
    if args.cycle:
        print(f"[cycle] {r['status']} | task={r['decision']['selected_task']} "
              f"exec={r['execution']['status']} validate={r['validation']['status']} "
              f"repair={r['repair']['status']} breach={r['breach']}")

    if args.status or not any((args.observe, args.decide, args.classify, args.execute,
                               args.validate, args.repair, args.learn, args.cycle)):
        _print_status(state, written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
