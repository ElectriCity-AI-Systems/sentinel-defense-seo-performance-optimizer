#!/usr/bin/env python3
"""Sentinel Safe Draft Autonomy Output Verifier (Phase 3.7).

Verifies the results of the Safe Draft-Only Autonomous Runner (Phase 3.6). It
checks that every autonomous draft/report/validation output is correct, lives
inside an allowed path, and is strictly non-productive. It applies NOTHING and
makes no live change of any kind.

Hard safety guarantees (enforced structurally):
- No live changes; no live-apply function exists in this module.
- Never edits WordPress files, .htaccess, Cloudflare rules, or Nginx config.
- No external writes, no network access, no WordPress login, no API calls.
- No secrets/cookies/auth values are stored or printed.
- apply_status stays not_applied; can_execute_live stays false.
- Writes are confined to drafts/apply, drafts/validation, reports/latest, audit.
- It only reads runner outputs/reports/audit logs and verifies allowed paths.
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

INPUT_RUNNER_REPORT = PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.json"
INPUT_RUNNER_AUDIT = PROJECT_DIR / "audit/safe-draft-autonomy-runner.jsonl"
INPUT_RUNTIME_LOCK = PROJECT_DIR / "config/autonomy-runtime-lock.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
INPUT_SCOPE = PROJECT_DIR / "drafts/apply/safe-apply-scope-allowlist.json"
INPUT_PREFLIGHT = PROJECT_DIR / "drafts/apply/safe-apply-preflight-validation.json"

REPORT_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-verifier-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-draft-autonomy-verifier-report.md"
VERIFICATION_MD = PROJECT_DIR / "drafts/validation/safe-draft-autonomy-verification.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-draft-autonomy-verifier.jsonl"

# Where THIS verifier may write its own outputs.
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "drafts/validation",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

# Paths that a runner-generated output is permitted to live inside.
RUNNER_ALLOWED_OUTPUT_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/seo",
    PROJECT_DIR / "drafts/performance",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "drafts/validation",
    PROJECT_DIR / "audit",
)

# Always-forbidden path tokens / targets (any of these => forbidden path).
FORBIDDEN_PATH_TOKENS = [
    "/etc/nginx",
    "/etc",
    ".htaccess",
    "wp-config.php",
    "wp-content/plugins",
    "wp-content/themes",
    "cloudflare-api-targets",
    "cloudflare-api",
    "dns-provider-configs",
    "dns-provider",
    "systemd-units",
    "systemd/",
    "live-public-html",
    "/var/www",
    "public_html",
]

SCHEMA_VERSION = "safe-draft-autonomy-verifier-3.7"

APPLY_NOT_APPLIED = "not_applied"

# Runner statuses that legitimately produce no output (lock/emergency stop).
RUNNER_BLOCKED_STATUSES = {"BLOCKED_BY_EMERGENCY_STOP", "BLOCKED_BY_RUNTIME_LOCK"}
RUNNER_EXECUTED_ITEM_STATUSES = {"EXECUTED_DRAFT_ONLY", "EXECUTED_VALIDATION_ONLY"}

# Verification status vocabulary (Phase 3.7).
VERIFIED_SAFE_DRAFT_OUTPUT = "VERIFIED_SAFE_DRAFT_OUTPUT"
VERIFIED_SAFE_REPORT_OUTPUT = "VERIFIED_SAFE_REPORT_OUTPUT"
VERIFIED_NO_OUTPUT_DUE_TO_LOCK = "VERIFIED_NO_OUTPUT_DUE_TO_LOCK"
WARNING_MISSING_OUTPUT = "WARNING_MISSING_OUTPUT"
WARNING_INVALID_JSON = "WARNING_INVALID_JSON"
WARNING_SECRET_PATTERN = "WARNING_SECRET_PATTERN"
BREACH_FORBIDDEN_PATH = "BREACH_FORBIDDEN_PATH"
BREACH_LIVE_APPLY = "BREACH_LIVE_APPLY"
BREACH_PRODUCTIVE_CHANGE = "BREACH_PRODUCTIVE_CHANGE"
BREACH_APPLY_STATUS_CHANGED = "BREACH_APPLY_STATUS_CHANGED"

VERIFIED_SAFE_STATUSES = {VERIFIED_SAFE_DRAFT_OUTPUT, VERIFIED_SAFE_REPORT_OUTPUT}

# Top-level verifier status vocabulary.
VERIFIER_OK = "VERIFIED_SAFE"
VERIFIER_NO_OUTPUT = "VERIFIED_NO_OUTPUT_DUE_TO_LOCK"
VERIFIER_WARNING = "VERIFIER_WARNING"
VERIFIER_BREACH = "VERIFIER_BREACH"
VERIFIER_NOT_AVAILABLE = "NOT_AVAILABLE"

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)
# A real secret value assignment: a credential-ish key bound to a credential-ish
# value (>=8 chars, not a boolean/null/redacted/path marker).
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
# Opaque 40+ char token: alnum only (no underscores that would join dictionary
# words such as long check-key identifiers) and must mix letters and digits.
LONG_TOKEN_RE = re.compile(r"\b(?=[A-Za-z0-9]*[A-Za-z])(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{40,}\b")
# Authorization/Bearer/Set-Cookie headers carrying an opaque value.
HEADER_SECRET_RE = re.compile(r"(?i)\b(bearer|set-cookie|authorization)\b[\s:=]+[A-Za-z0-9._/+\-]{12,}")


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
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def detect_secret_in_text(text: str) -> bool:
    """Return True only for genuine credential VALUES, not field names.

    Deliberately ignores bare key names (e.g. ``"secrets_output": false``) so
    that the runner's own safety fields do not trigger a false positive.
    """
    if not text:
        return False
    if SECRET_ASSIGNMENT_RE.search(text):
        return True
    if HEADER_SECRET_RE.search(text):
        return True
    if LONG_HEX_RE.search(text):
        return True
    if LONG_TOKEN_RE.search(text):
        return True
    return False


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def within_allowed_roots(path: Path) -> bool:
    return any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS)


def within_runner_allowed_roots(path: Path) -> bool:
    return any(is_within(path, root) for root in RUNNER_ALLOWED_OUTPUT_ROOTS)


def path_is_forbidden(raw: str) -> bool:
    lower = str(raw).lower()
    return any(token.lower() in lower for token in FORBIDDEN_PATH_TOKENS)


def assert_allowed_write(path: Path) -> None:
    if not within_allowed_roots(path):
        raise ValueError(f"Refusing to write outside allowed verifier roots: {path}")


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


def read_json_status(path: Path) -> Tuple[Optional[Any], str]:
    try:
        if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
            return None, "refused_secret_like_path"
        if path.suffix.lower() != ".json":
            return None, "unsupported_suffix"
        if not path.exists():
            return None, "not_available"
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except (OSError, ValueError, json.JSONDecodeError):
        return None, "read_error"


def count_audit_lines(path: Path) -> int:
    try:
        if not path.exists():
            return 0
        count = 0
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    count += 1
        return count
    except OSError:
        return 0


def inspect_output_file(raw_path: str) -> Tuple[bool, Optional[bool], bool]:
    """Return (exists, json_valid_if_applicable, secret_detected) for a path.

    Read-only. ``json_valid_if_applicable`` is None for non-.json outputs.
    Secrets are detected from genuine credential values only.
    """
    path = Path(raw_path)
    exists = False
    json_valid: Optional[bool] = None
    secret = False
    try:
        exists = path.exists() and path.is_file()
    except OSError:
        exists = False
    if not exists:
        # Nothing to validate or scan for a non-existent file.
        return False, None, False
    try:
        if within_runner_allowed_roots(path) and not path_is_forbidden(raw_path):
            content = path.read_text(encoding="utf-8", errors="replace")
        else:
            content = ""
    except OSError:
        content = ""
    if path.suffix.lower() == ".json":
        try:
            json.loads(content if content else path.read_text(encoding="utf-8"))
            json_valid = True
        except (OSError, ValueError, json.JSONDecodeError):
            json_valid = False
    if content:
        secret = detect_secret_in_text(content)
    return exists, json_valid, secret


def normalize_apply_status(value: Any) -> str:
    if value == APPLY_NOT_APPLIED:
        return APPLY_NOT_APPLIED
    return redact_text(value, default=APPLY_NOT_APPLIED, max_len=80)


def classify_output(
    raw_path: str,
    item: Dict[str, Any],
) -> Tuple[str, str, Dict[str, Any]]:
    """Classify one generated output. Returns (status, reason, facts)."""
    live_apply = bool(item.get("live_apply"))
    productive_change = bool(item.get("productive_change"))
    apply_status = normalize_apply_status(item.get("apply_status"))

    exists, json_valid, secret = inspect_output_file(raw_path)
    path = Path(raw_path)
    forbidden = path_is_forbidden(raw_path) or not within_runner_allowed_roots(path)
    is_json = path.suffix.lower() == ".json"
    is_report = is_within(path, PROJECT_DIR / "reports/latest")

    facts = {
        "output_exists": bool(exists),
        "path_allowed": (not forbidden),
        "json_valid_if_applicable": (json_valid if is_json else None),
        "secret_scan_status": ("SECRET_DETECTED" if secret else "CLEAN"),
        "live_apply": live_apply,
        "productive_change": productive_change,
        "apply_status": apply_status,
    }

    # Breach-first precedence.
    if live_apply:
        return BREACH_LIVE_APPLY, "Runner item reports live_apply=true.", facts
    if productive_change:
        return BREACH_PRODUCTIVE_CHANGE, "Runner item reports productive_change=true.", facts
    if apply_status != APPLY_NOT_APPLIED:
        return BREACH_APPLY_STATUS_CHANGED, "Runner item apply_status != not_applied.", facts
    if forbidden:
        return BREACH_FORBIDDEN_PATH, "Output path is forbidden or outside allowed runner roots.", facts
    if is_json and json_valid is False:
        return WARNING_INVALID_JSON, "JSON output failed to parse.", facts
    if secret:
        return WARNING_SECRET_PATTERN, "A secret-like value was detected in the output.", facts
    if not exists:
        return WARNING_MISSING_OUTPUT, "Declared output file does not exist.", facts
    if is_report:
        return VERIFIED_SAFE_REPORT_OUTPUT, "Safe report output verified inside reports/latest.", facts
    return VERIFIED_SAFE_DRAFT_OUTPUT, "Safe draft output verified inside an allowed draft path.", facts


def build_verifier_item(
    raw_path: str,
    item: Dict[str, Any],
    index: int,
) -> Tuple[Dict[str, Any], bool]:
    status, reason, facts = classify_output(raw_path, item)
    requires_io = bool(
        item.get("requires_network_access")
        or item.get("requires_api_access")
        or item.get("requires_login")
    )
    breach = status in {
        BREACH_FORBIDDEN_PATH,
        BREACH_LIVE_APPLY,
        BREACH_PRODUCTIVE_CHANGE,
        BREACH_APPLY_STATUS_CHANGED,
    } or status in {WARNING_INVALID_JSON, WARNING_SECRET_PATTERN} or requires_io
    record = {
        "verifier_item_id": f"safe_draft_verifier:{index:03d}",
        "source_runner_item_id": redact_text(item.get("runner_item_id"), max_len=80),
        "candidate_id": redact_text(item.get("candidate_id"), max_len=160),
        "generated_output": redact_text(raw_path, max_len=320),
        "output_exists": facts["output_exists"],
        "path_allowed": facts["path_allowed"],
        "json_valid_if_applicable": facts["json_valid_if_applicable"],
        "secret_scan_status": facts["secret_scan_status"],
        "live_apply": facts["live_apply"],
        "productive_change": facts["productive_change"],
        "apply_status": facts["apply_status"],
        "verification_status": status,
        "requires_network_api_login": requires_io,
        "reason": reason if not requires_io else reason + " network/API/login requirement detected.",
    }
    return record, breach


def build_lock_item(item: Dict[str, Any], index: int) -> Dict[str, Any]:
    return {
        "verifier_item_id": f"safe_draft_verifier:{index:03d}",
        "source_runner_item_id": redact_text(item.get("runner_item_id"), max_len=80),
        "candidate_id": redact_text(item.get("candidate_id"), max_len=160),
        "generated_output": "-",
        "output_exists": False,
        "path_allowed": True,
        "json_valid_if_applicable": None,
        "secret_scan_status": "CLEAN",
        "live_apply": False,
        "productive_change": False,
        "apply_status": APPLY_NOT_APPLIED,
        "verification_status": VERIFIED_NO_OUTPUT_DUE_TO_LOCK,
        "requires_network_api_login": False,
        "reason": "Runner produced no output for this item due to runtime lock / emergency stop.",
    }


def lock_state_from(lock: Optional[Dict[str, Any]], runner_report: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    keys = (
        "autonomy_enabled",
        "draft_only_enabled",
        "validation_only_enabled",
        "live_apply_enabled",
        "owner_disable_switch",
        "emergency_stop",
    )
    # Consistency checks must judge the runner against the lock it actually
    # observed, which the runner records in its own report. The live lock file
    # may have changed AFTER the run (e.g. owner armed emergency-stop later), so
    # it is only a fallback for fields the runner did not record.
    source: Dict[str, Any] = {}
    if isinstance(lock, dict):
        source.update(lock)
    if isinstance(runner_report, dict) and isinstance(runner_report.get("runtime_lock_state"), dict):
        source.update(runner_report["runtime_lock_state"])
    state = {key: bool(source.get(key)) for key in keys}
    # live_apply is never honored as enabled.
    state["live_apply_enabled"] = bool(source.get("live_apply_enabled"))
    return state


def build_verifier_report(
    runner_report: Optional[Dict[str, Any]],
    lock: Optional[Dict[str, Any]],
    input_statuses: Dict[str, str],
    audit_line_count: int,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    runner_available = isinstance(runner_report, dict)
    audit_available = audit_line_count > 0
    lock_state = lock_state_from(lock, runner_report)

    runner_items = []
    if runner_available:
        raw_items = runner_report.get("runner_items")
        if isinstance(raw_items, list):
            runner_items = [it for it in raw_items if isinstance(it, dict)]

    runner_summary = runner_report.get("summary") if runner_available and isinstance(runner_report.get("summary"), dict) else {}
    last_runner_status = redact_text(runner_report.get("runner_status"), max_len=80) if runner_available else VERIFIER_NOT_AVAILABLE
    executed_count = 0
    for value in (
        runner_summary.get("executed_draft_only_count"),
        runner_summary.get("executed_validation_only_count"),
    ):
        try:
            executed_count += int(value)
        except (TypeError, ValueError):
            pass

    items: List[Dict[str, Any]] = []
    breach_reasons: List[str] = []
    index = 1
    for item in runner_items:
        status = str(item.get("runner_status") or "")
        outputs = item.get("generated_outputs") if isinstance(item.get("generated_outputs"), list) else []
        if status in RUNNER_BLOCKED_STATUSES and not outputs:
            items.append(build_lock_item(item, index))
            index += 1
            continue
        if not outputs:
            # Skipped/no-output, non-blocked items: nothing to verify.
            continue
        for raw_path in outputs:
            record, item_breach = build_verifier_item(str(raw_path), item, index)
            items.append(record)
            if item_breach:
                breach_reasons.append(f"{record['verifier_item_id']}: {record['verification_status']}")
            index += 1

    # Aggregate counts.
    def count_status(target: str) -> int:
        return sum(1 for it in items if it.get("verification_status") == target)

    verified_safe = sum(1 for it in items if it.get("verification_status") in VERIFIED_SAFE_STATUSES)
    missing = count_status(WARNING_MISSING_OUTPUT)
    invalid_json = count_status(WARNING_INVALID_JSON)
    forbidden = count_status(BREACH_FORBIDDEN_PATH)
    secret = count_status(WARNING_SECRET_PATTERN)
    live_apply = count_status(BREACH_LIVE_APPLY)
    productive = count_status(BREACH_PRODUCTIVE_CHANGE)
    apply_changed = count_status(BREACH_APPLY_STATUS_CHANGED)
    no_output_lock = count_status(VERIFIED_NO_OUTPUT_DUE_TO_LOCK)
    network_io = sum(1 for it in items if it.get("requires_network_api_login"))

    # Cross checks.
    all_outputs_exist = all(
        it.get("output_exists") for it in items
        if it.get("verification_status") != VERIFIED_NO_OUTPUT_DUE_TO_LOCK
    )
    all_inside_allowed = forbidden == 0
    all_json_valid = invalid_json == 0
    no_forbidden = forbidden == 0
    no_secret = secret == 0
    no_live_apply = live_apply == 0
    no_productive = productive == 0
    all_apply_not_applied = apply_changed == 0
    all_can_execute_live_false = all(
        not bool(it.get("can_execute_live", False)) for it in runner_items
    )
    emergency_stop = bool(lock_state.get("emergency_stop"))
    draft_only_enabled = bool(lock_state.get("draft_only_enabled"))
    emergency_stop_blocks_execution = (not emergency_stop) or executed_count == 0
    executed_only_when_draft_only_enabled = executed_count == 0 or draft_only_enabled
    runtime_lock_respected = emergency_stop_blocks_execution and executed_only_when_draft_only_enabled
    runner_breach_false = not bool(runner_summary.get("runner_breach", False)) and not bool(
        runner_report.get("runner_breach", False) if runner_available else False
    )

    # runner-level safety violations are also verifier breaches.
    if not emergency_stop_blocks_execution:
        breach_reasons.append("runner executed while emergency_stop is set")
    if not executed_only_when_draft_only_enabled:
        breach_reasons.append("runner executed while draft_only is disabled")

    verifier_breach = bool(breach_reasons)

    if not runner_available:
        verifier_status = VERIFIER_NOT_AVAILABLE
    elif verifier_breach:
        verifier_status = VERIFIER_BREACH
    elif invalid_json or secret or missing:
        verifier_status = VERIFIER_WARNING
    elif items and all(it.get("verification_status") == VERIFIED_NO_OUTPUT_DUE_TO_LOCK for it in items):
        verifier_status = VERIFIER_NO_OUTPUT
    elif not items:
        verifier_status = VERIFIER_NO_OUTPUT
    else:
        verifier_status = VERIFIER_OK

    status = VERIFIER_WARNING if verifier_breach else verifier_status

    checks = {
        "runner_report_available": runner_available,
        "audit_log_available": audit_available,
        "all_generated_outputs_exist": bool(all_outputs_exist),
        "all_generated_outputs_inside_allowed_paths": bool(all_inside_allowed),
        "all_json_outputs_valid": bool(all_json_valid),
        "no_forbidden_paths_touched": bool(no_forbidden),
        "no_secret_patterns_detected": bool(no_secret),
        "no_live_apply": bool(no_live_apply),
        "no_productive_change": bool(no_productive),
        "all_apply_status_not_applied": bool(all_apply_not_applied),
        "all_can_execute_live_false": bool(all_can_execute_live_false),
        "runtime_lock_respected": bool(runtime_lock_respected),
        "emergency_stop_blocks_execution": bool(emergency_stop_blocks_execution),
        "executed_only_when_draft_only_enabled": bool(executed_only_when_draft_only_enabled),
        "runner_breach_false": bool(runner_breach_false),
    }

    summary = {
        "verifier_status": verifier_status,
        "verified_safe_outputs_count": verified_safe,
        "missing_outputs_count": missing,
        "invalid_json_count": invalid_json,
        "forbidden_path_count": forbidden,
        "secret_pattern_count": secret,
        "live_apply_count": live_apply,
        "productive_change_count": productive,
        "apply_status_changed_count": apply_changed,
        "no_output_due_to_lock_count": no_output_lock,
        "network_api_login_count": network_io,
        "verifier_breach": verifier_breach,
        "verifier_breach_reasons": breach_reasons,
        "last_runner_status": last_runner_status,
        "last_runner_executed_count": executed_count,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "verifier_status": verifier_status,
        "read_only": True,
        "live_apply": False,
        "live_apply_function": False,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "productive_change": False,
        "secrets_output": False,
        "apply_status": APPLY_NOT_APPLIED,
        "can_execute_live": False,
        "verified_safe_outputs_count": verified_safe,
        "missing_outputs_count": missing,
        "invalid_json_count": invalid_json,
        "forbidden_path_count": forbidden,
        "secret_pattern_count": secret,
        "live_apply_count": live_apply,
        "productive_change_count": productive,
        "apply_status_changed_count": apply_changed,
        "verifier_breach": verifier_breach,
        "last_runner_status": last_runner_status,
        "last_runner_executed_count": executed_count,
        "runtime_lock_state": lock_state,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "runner_allowed_output_roots": [str(path) for path in RUNNER_ALLOWED_OUTPUT_ROOTS],
        "input_statuses": input_statuses,
        "checks": checks,
        "summary": summary,
        "verifier_items": items,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "verification_md": str(VERIFICATION_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(report: Dict[str, Any], *, title: str) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    lock_state = report.get("runtime_lock_state") if isinstance(report.get("runtime_lock_state"), dict) else {}
    lines = [
        f"# {title}",
        "",
        f"- Generated (UTC): `{report.get('generated_at_utc')}`",
        f"- Status: `{report.get('status')}`",
        f"- Verifier status: `{report.get('verifier_status')}`",
        f"- Last runner status: `{summary.get('last_runner_status')}`",
        f"- Last runner executed: `{summary.get('last_runner_executed_count')}`",
        f"- Verified safe outputs: `{summary.get('verified_safe_outputs_count')}`",
        f"- Missing outputs: `{summary.get('missing_outputs_count')}`",
        f"- Invalid JSON: `{summary.get('invalid_json_count')}`",
        f"- Forbidden path: `{summary.get('forbidden_path_count')}`",
        f"- Secret pattern: `{summary.get('secret_pattern_count')}`",
        f"- Live apply: `{summary.get('live_apply_count')}`",
        f"- Productive change: `{summary.get('productive_change_count')}`",
        f"- Apply status changed: `{summary.get('apply_status_changed_count')}`",
        f"- Verifier breach: `{summary.get('verifier_breach')}`",
        "",
        "## Runtime Lock State",
        "",
        f"- autonomy_enabled: `{lock_state.get('autonomy_enabled')}`",
        f"- draft_only_enabled: `{lock_state.get('draft_only_enabled')}`",
        f"- live_apply_enabled: `{lock_state.get('live_apply_enabled')}`",
        f"- emergency_stop: `{lock_state.get('emergency_stop')}`",
        "",
        "## Checks",
        "",
    ]
    for key in sorted(checks):
        lines.append(f"- {key}: `{checks.get(key)}`")
    lines.extend(
        [
            "",
            "## Verifier Items",
            "",
            "| Item | Source | Candidate | Output | Exists | Allowed | JSON | Secret | Status |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for item in report.get("verifier_items", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(item.get('verifier_item_id'), max_len=80)}` | "
            f"`{redact_text(item.get('source_runner_item_id'), max_len=60)}` | "
            f"`{redact_text(item.get('candidate_id'), max_len=60)}` | "
            f"`{redact_text(item.get('generated_output'), max_len=80)}` | "
            f"`{redact_text(item.get('output_exists'), max_len=8)}` | "
            f"`{redact_text(item.get('path_allowed'), max_len=8)}` | "
            f"`{redact_text(item.get('json_valid_if_applicable'), max_len=8)}` | "
            f"`{redact_text(item.get('secret_scan_status'), max_len=20)}` | "
            f"`{redact_text(item.get('verification_status'), max_len=40)}` |"
        )
    lines.extend(
        [
            "",
            "## Sicherheitsgrenzen",
            "",
            "- Nur Verifikation von Runner-Ausgaben; keine Live-Aenderungen, keine Live-Apply-Funktion.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff, keine externen Schreibzugriffe.",
            "- Keine Secrets/Cookies/Auth speichern oder ausgeben.",
            "- `apply_status=not_applied`, `live_apply=false`, `can_execute_live=false`, `productive_change=false`.",
            "- Schreibzugriff nur unter drafts/apply, drafts/validation, reports/latest, audit.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    run_record = {
        "timestamp_utc": report.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "record_type": "verify_run",
        "verifier_status": report.get("verifier_status"),
        "status": report.get("status"),
        "verified_safe_outputs_count": summary.get("verified_safe_outputs_count"),
        "missing_outputs_count": summary.get("missing_outputs_count"),
        "invalid_json_count": summary.get("invalid_json_count"),
        "forbidden_path_count": summary.get("forbidden_path_count"),
        "secret_pattern_count": summary.get("secret_pattern_count"),
        "live_apply_count": summary.get("live_apply_count"),
        "productive_change_count": summary.get("productive_change_count"),
        "apply_status_changed_count": summary.get("apply_status_changed_count"),
        "verifier_breach": summary.get("verifier_breach"),
        "last_runner_status": summary.get("last_runner_status"),
        "live_apply": False,
        "productive_change": False,
        "network_access": False,
    }
    records = [run_record]
    for item in report.get("verifier_items", []):
        if not isinstance(item, dict):
            continue
        if item.get("verification_status") in VERIFIED_SAFE_STATUSES:
            continue
        records.append(
            {
                "timestamp_utc": report.get("generated_at_utc"),
                "schema_version": SCHEMA_VERSION,
                "record_type": "verifier_item",
                "verifier_item_id": item.get("verifier_item_id"),
                "source_runner_item_id": item.get("source_runner_item_id"),
                "candidate_id": item.get("candidate_id"),
                "generated_output": item.get("generated_output"),
                "verification_status": item.get("verification_status"),
                "apply_status": APPLY_NOT_APPLIED,
                "live_apply": False,
                "productive_change": False,
            }
        )
    return records


def write_outputs(report: Dict[str, Any]) -> None:
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report, title="Safe Draft Autonomy Verifier Report"))
    write_text_atomic(VERIFICATION_MD, render_markdown(report, title="Safe Draft Autonomy Verification"))
    append_jsonl(AUDIT_JSONL, audit_records(report))


def load_inputs() -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], int, Dict[str, str]]:
    runner, runner_status = read_json_status(INPUT_RUNNER_REPORT)
    lock, lock_status = read_json_status(INPUT_RUNTIME_LOCK)
    audit_lines = count_audit_lines(INPUT_RUNNER_AUDIT)
    statuses = {
        "safe_draft_autonomy_runner_report": runner_status,
        "autonomy_runtime_lock": lock_status,
        "safe_draft_autonomy_runner_audit": "ok" if audit_lines > 0 else "not_available",
        "sentinel_master": read_json_status(INPUT_MASTER)[1],
        "safe_apply_scope_allowlist": read_json_status(INPUT_SCOPE)[1],
        "safe_apply_preflight_validation": read_json_status(INPUT_PREFLIGHT)[1],
    }
    return (
        runner if isinstance(runner, dict) else None,
        lock if isinstance(lock, dict) else None,
        audit_lines,
        statuses,
    )


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def _runner_item(**overrides: Any) -> Dict[str, Any]:
    base = {
        "runner_item_id": "safe_draft_runner:001",
        "candidate_id": "safe_apply_candidate:001",
        "action_type": "report_update_only",
        "runner_status": "EXECUTED_DRAFT_ONLY",
        "generated_outputs": [str(REPORT_JSON)],
        "apply_status": "not_applied",
        "live_apply": False,
        "productive_change": False,
        "can_execute_live": False,
        "requires_network_access": False,
        "requires_api_access": False,
        "requires_login": False,
    }
    base.update(overrides)
    return base


def _runner_report(items: List[Dict[str, Any]], lock_state: Dict[str, Any], summary: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "runner_status": summary.get("runner_status", "EXECUTED"),
        "runtime_lock_state": lock_state,
        "summary": summary,
        "runner_items": items,
    }


def run_self_test() -> int:
    enabled_lock = {
        "autonomy_enabled": True,
        "draft_only_enabled": True,
        "validation_only_enabled": True,
        "live_apply_enabled": False,
        "owner_disable_switch": True,
        "emergency_stop": False,
    }
    stop_lock = {**enabled_lock, "emergency_stop": True, "autonomy_enabled": False, "draft_only_enabled": False}
    clean_summary = {
        "runner_status": "EXECUTED",
        "executed_draft_only_count": 1,
        "executed_validation_only_count": 0,
        "skipped_count": 0,
        "runner_breach": False,
    }

    # 1) Clean executed run -> verified safe report output, no breach.
    #    Use a real temp file inside an allowed report root so existence and
    #    JSON validity are deterministic.
    tmp_out = PROJECT_DIR / "reports/latest/.safe-draft-autonomy-verifier-selftest.json"
    tmp_out.parent.mkdir(parents=True, exist_ok=True)
    tmp_out.write_text(json.dumps({"ok": True}) + "\n", encoding="utf-8")
    try:
        clean = build_verifier_report(
            _runner_report([_runner_item(generated_outputs=[str(tmp_out)])], enabled_lock, clean_summary),
            enabled_lock,
            {"safe_draft_autonomy_runner_report": "ok"},
            audit_line_count=3,
            generated_at="2026-06-11T00:00:00Z",
        )
    finally:
        try:
            tmp_out.unlink()
        except OSError:
            pass
    if clean["verifier_breach"]:
        raise AssertionError("clean run must not breach")
    if clean["summary"]["verified_safe_outputs_count"] != 1:
        raise AssertionError("clean run did not verify one safe output")
    if clean["verifier_items"][0]["verification_status"] != VERIFIED_SAFE_REPORT_OUTPUT:
        raise AssertionError("report output not classified as safe report output")

    # 2) Missing runner report -> NOT_AVAILABLE, no crash, no breach.
    na = build_verifier_report(None, None, {"safe_draft_autonomy_runner_report": "not_available"}, 0,
                               generated_at="2026-06-11T00:01:00Z")
    if na["verifier_status"] != VERIFIER_NOT_AVAILABLE or na["verifier_breach"]:
        raise AssertionError("missing runner report must be NOT_AVAILABLE and not breach")

    # 3) Missing audit must not crash and is reflected as a check only.
    no_audit = build_verifier_report(
        _runner_report([_runner_item()], enabled_lock, clean_summary), enabled_lock,
        {"safe_draft_autonomy_runner_report": "ok"}, audit_line_count=0,
        generated_at="2026-06-11T00:02:00Z",
    )
    if no_audit["checks"]["audit_log_available"]:
        raise AssertionError("audit_log_available should be False when no audit lines")
    if no_audit["verifier_breach"]:
        raise AssertionError("missing audit alone must not breach")

    # 4) Forbidden path output -> breach.
    forb = build_verifier_report(
        _runner_report([_runner_item(generated_outputs=["/etc/nginx/site.conf"])], enabled_lock, clean_summary),
        enabled_lock, {"safe_draft_autonomy_runner_report": "ok"}, 3, generated_at="2026-06-11T00:03:00Z",
    )
    if not forb["verifier_breach"] or forb["summary"]["forbidden_path_count"] != 1:
        raise AssertionError("forbidden path did not breach")
    if forb["verifier_items"][0]["verification_status"] != BREACH_FORBIDDEN_PATH:
        raise AssertionError("forbidden path not classified correctly")

    # 5) live_apply=true -> breach.
    la = build_verifier_report(
        _runner_report([_runner_item(live_apply=True)], enabled_lock, clean_summary),
        enabled_lock, {"safe_draft_autonomy_runner_report": "ok"}, 3, generated_at="2026-06-11T00:04:00Z",
    )
    if not la["verifier_breach"] or la["summary"]["live_apply_count"] != 1:
        raise AssertionError("live_apply did not breach")

    # 6) productive_change=true -> breach.
    pc = build_verifier_report(
        _runner_report([_runner_item(productive_change=True)], enabled_lock, clean_summary),
        enabled_lock, {"safe_draft_autonomy_runner_report": "ok"}, 3, generated_at="2026-06-11T00:05:00Z",
    )
    if not pc["verifier_breach"] or pc["summary"]["productive_change_count"] != 1:
        raise AssertionError("productive_change did not breach")

    # 7) apply_status != not_applied -> breach.
    asx = build_verifier_report(
        _runner_report([_runner_item(apply_status="applied")], enabled_lock, clean_summary),
        enabled_lock, {"safe_draft_autonomy_runner_report": "ok"}, 3, generated_at="2026-06-11T00:06:00Z",
    )
    if not asx["verifier_breach"] or asx["summary"]["apply_status_changed_count"] != 1:
        raise AssertionError("apply_status change did not breach")

    # 8) Secret pattern detection (genuine value) -> breach; field name must not.
    if detect_secret_in_text('"secrets_output": false'):
        raise AssertionError("field name 'secrets_output' must not be flagged as a secret")
    if detect_secret_in_text('"api_access": false'):
        raise AssertionError("'api_access: false' must not be flagged as a secret")
    if not detect_secret_in_text("authorization: Bearer abcDEF1234567890ghij"):
        raise AssertionError("genuine bearer token was not detected")
    if not detect_secret_in_text("api_key = sk-0123456789abcdef0123"):
        raise AssertionError("genuine api_key value was not detected")
    if not detect_secret_in_text("deadbeefdeadbeefdeadbeefdeadbeef00"):
        raise AssertionError("long hex secret not detected")

    # 9) network/API/login requirement on an output -> breach.
    nio = build_verifier_report(
        _runner_report([_runner_item(requires_login=True)], enabled_lock, clean_summary),
        enabled_lock, {"safe_draft_autonomy_runner_report": "ok"}, 3, generated_at="2026-06-11T00:07:00Z",
    )
    if not nio["verifier_breach"]:
        raise AssertionError("network/API/login requirement did not breach")

    # 10) Emergency stop -> blocked items, no output, no breach.
    blocked = build_verifier_report(
        _runner_report(
            [_runner_item(runner_status="BLOCKED_BY_EMERGENCY_STOP", generated_outputs=[])],
            stop_lock,
            {"runner_status": "BLOCKED_BY_EMERGENCY_STOP", "executed_draft_only_count": 0,
             "executed_validation_only_count": 0, "runner_breach": False},
        ),
        stop_lock, {"safe_draft_autonomy_runner_report": "ok"}, 1, generated_at="2026-06-11T00:08:00Z",
    )
    if blocked["verifier_breach"]:
        raise AssertionError("blocked-by-lock run must not breach")
    if blocked["verifier_items"][0]["verification_status"] != VERIFIED_NO_OUTPUT_DUE_TO_LOCK:
        raise AssertionError("blocked item not classified as no-output-due-to-lock")
    if not blocked["checks"]["emergency_stop_blocks_execution"]:
        raise AssertionError("emergency_stop_blocks_execution should hold when nothing executed")

    # 11) Runner executed under emergency_stop -> breach (runtime lock not respected).
    bad_lock_exec = build_verifier_report(
        _runner_report(
            [_runner_item()],
            stop_lock,
            {"runner_status": "EXECUTED", "executed_draft_only_count": 1,
             "executed_validation_only_count": 0, "runner_breach": False},
        ),
        stop_lock, {"safe_draft_autonomy_runner_report": "ok"}, 3, generated_at="2026-06-11T00:09:00Z",
    )
    if not bad_lock_exec["verifier_breach"]:
        raise AssertionError("execution under emergency_stop must breach")
    if bad_lock_exec["checks"]["emergency_stop_blocks_execution"]:
        raise AssertionError("emergency_stop_blocks_execution should be False when executed under stop")

    # Forbidden write path for the verifier itself is rejected.
    try:
        assert_allowed_write(PROJECT_DIR / "config/should-not-write.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden verifier write path (config) was not rejected")

    print("safe-draft-autonomy-verifier self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify Safe Draft-Only Autonomous Runner outputs (read-only; no live apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    runner_report, lock, audit_lines, statuses = load_inputs()
    report = build_verifier_report(runner_report, lock, statuses, audit_lines)
    write_outputs(report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(
        "Safe Draft Autonomy Verifier: "
        f"status={report.get('verifier_status')}, "
        f"safe_outputs={summary.get('verified_safe_outputs_count')}, "
        f"missing={summary.get('missing_outputs_count')}, "
        f"invalid_json={summary.get('invalid_json_count')}, "
        f"forbidden={summary.get('forbidden_path_count')}, "
        f"breach={summary.get('verifier_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
