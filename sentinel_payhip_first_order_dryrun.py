#!/usr/bin/env python3
"""Sentinel Payhip First Order Dry-Run Simulator & Sample Client Delivery Pack (Phase 9.8).

A safe, *local* dry-run of the first Payhip order for the service
"Sentinel Security, SEO & Performance Safe Optimization".

It walks the whole post-purchase flow with placeholder data only:

    dummy purchase -> dummy intake -> scope review -> risk review ->
    package workflows -> sample client report -> delivery pack ->
    completion checklist.

Everything uses safe placeholders (example.com, customer@example.com). It
processes NO real buyer data, performs NO real audit, stores NO secrets and
sends nothing. It is read-only with respect to production: no apply, no upload,
no website change, no autopilot, no timer install, no SFTP/DB/Cloudflare/Nginx/
WordPress write, no network access, no Payhip API access and no e-mail send.

Invariants surfaced and enforced:
    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    HIGH stays blocked / review-only, never automatic
    only example.com placeholders; no real customer data, secrets, paths or IPs.
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

# ---------------------------------------------------------------------------
# Inputs (read-only; optional; for availability/provenance only — never echoed)
# ---------------------------------------------------------------------------
INPUT_JSON: List[Tuple[str, Path]] = [
    ("fulfillment_board", PROJECT_DIR / "reports/latest/sentinel-payhip-fulfillment-board.json"),
    ("fulfillment_state",
     PROJECT_DIR / "state/adaptive-learning/latest_payhip_fulfillment_board.json"),
]
INPUT_FILES: List[Tuple[str, Path]] = [
    ("case_template", PROJECT_DIR / "reports/latest/sentinel-payhip-case-template.md"),
    ("order_status_flow", PROJECT_DIR / "reports/latest/sentinel-payhip-order-status-flow.md"),
    ("scope_risk_review", PROJECT_DIR / "reports/latest/sentinel-payhip-scope-risk-review.md"),
    ("package_delivery_checklists",
     PROJECT_DIR / "reports/latest/sentinel-payhip-package-delivery-checklists.md"),
    ("client_report_template",
     PROJECT_DIR / "reports/latest/sentinel-payhip-client-report-delivery-template.md"),
    ("completion_checklist",
     PROJECT_DIR / "reports/latest/sentinel-payhip-completion-checklist.md"),
    ("do_not_store_policy", PROJECT_DIR / "reports/latest/sentinel-payhip-do-not-store-policy.md"),
]

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
DRYRUN_JSON = PROJECT_DIR / "reports/latest/sentinel-payhip-first-order-dryrun.json"
DRYRUN_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-first-order-dryrun.md"
DUMMY_CASE_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-dummy-case.md"
DUMMY_INTAKE_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-dummy-intake.md"
DUMMY_SCOPE_RISK_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-dummy-scope-risk-review.md"
DUMMY_WORKFLOWS_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-dummy-package-workflows.md"
SAMPLE_REPORT_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-sample-client-report.md"
SAMPLE_DELIVERY_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-sample-delivery-pack.md"
COMPLETION_CHECKLIST_MD = \
    PROJECT_DIR / "reports/latest/sentinel-payhip-first-order-completion-checklist.md"
REAL_ORDER_STEPS_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-real-order-manual-steps.md"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_JSON = STATE_DIR / "sentinel_payhip_first_order_dryrun.json"
STATE_LATEST_JSON = STATE_DIR / "latest_payhip_first_order_dryrun.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-payhip-first-order-dryrun.jsonl"

PLAYBOOK_DRYRUN = PROJECT_DIR / "playbooks/sentinel-payhip-first-order-dryrun.playbook.json"
PLAYBOOK_SAMPLE_REPORT = PROJECT_DIR / "playbooks/sentinel-payhip-sample-client-report.playbook.json"
PLAYBOOK_DELIVERY = PROJECT_DIR / "playbooks/sentinel-payhip-delivery-pack.playbook.json"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "playbooks",
)
FORBIDDEN_OUTPUT_SUFFIXES = (
    ".sh", ".bash", ".zsh", ".service", ".timer", ".run", ".bin", ".py", ".php", ".env",
)
FORBIDDEN_INSTALL_PATH_TOKENS = (
    "/etc/systemd", "systemd/system", "/lib/systemd", "/usr/lib/systemd",
    "/etc/cron", "cron.d", "crontab",
)

SCHEMA_VERSION = "payhip-first-order-dryrun-9.8"

LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
LEVEL_2 = "LEVEL_2_LOW_RISK_PREP_PREVIEW"
ALLOWED_CURRENT_LEVELS = {LEVEL_1, LEVEL_2}
DEFAULT_CURRENT_LEVEL = LEVEL_2

DECISION_READY = "READY"
DECISION_NEEDS_REVIEW = "NEEDS_REVIEW"
DECISION_BLOCKED = "BLOCKED"

# ---------------------------------------------------------------------------
# Secret / safety regexes
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
    r"not requested\b)"
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
    r"unlimited emergency support|instant fix|fully autonomous live repair|"
    r"no review required|change cloudflare automatically|edit database automatically|"
    r"edit your database automatically|bypass security)"
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


def public_safety_findings(blob: str) -> List[str]:
    """Reasons a blob is NOT safe to publish (empty == safe). Value-bearing detection."""
    reasons: List[str] = []
    if INTERNAL_PATH_RE.search(blob):
        reasons.append("internal_server_path")
    if IPV4_RE.search(blob):
        reasons.append("ip_address")
    if HARD_SECRET_FORMAT_RE.search(blob):
        reasons.append("secret_key_format")
    if SECRET_ASSIGNMENT_RE.search(blob):
        reasons.append("secret_assignment")
    if DISALLOWED_CLAIMS_RE.search(blob):
        reasons.append("disallowed_marketing_claim")
    for m in EMAIL_RE.findall(blob):
        if m.rsplit("@", 1)[-1].lower() not in ALLOWED_EMAIL_DOMAINS:
            reasons.append("real_email")
            break
    for host in URL_RE.findall(blob):
        if not _host_allowed(host):
            reasons.append("non_example_domain")
            break
    return reasons


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


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
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


# ---------------------------------------------------------------------------
# Dry-run content constants (placeholders only)
# ---------------------------------------------------------------------------
SERVICE_TITLE = "Sentinel Security, SEO & Performance Safe Optimization"
CONTACT_PLACEHOLDER = "[provider contact email to be filled in by the owner]"
SAMPLE_DISCLAIMER_LINE = ("This is a sample report using placeholder data only. "
                          "It is not a real audit.")
NO_GUARANTEE_DISCLAIMER = (
    "This service provides safety-first diagnosis, review and recommendations. Results depend "
    "on your website, hosting and content. We do not promise a specific search ranking or a "
    "fixed performance score, and high-risk changes always stay review-only until you "
    "explicitly approve a safe, controlled step."
)

PACKAGES = ["Sentinel Audit Report", "Sentinel Safe Optimization",
            "Sentinel Monitoring & Improvement"]
PACKAGE_PRICES = {
    "Sentinel Audit Report": "59 EUR",
    "Sentinel Safe Optimization": "149 EUR",
    "Sentinel Monitoring & Improvement": "99 EUR",
}

DUMMY_CASE: List[Tuple[str, str]] = [
    ("case_id", "CASE-EXAMPLE-0001"),
    ("customer_alias", "Example Customer"),
    ("contact_placeholder", "customer@example.com"),
    ("website_url_placeholder", "https://example.com"),
    ("selected_package", "Sentinel Audit Report"),
    ("main_goal", "SEO / Speed / Security / Stability"),
    ("no_password_received", "true"),
    ("secrets_received", "false"),
    ("live_apply", "false"),
    ("high_risk_blocked", "true"),
    ("delivery_status", "DRYRUN_ONLY"),
]

DUMMY_INTAKE: List[Tuple[str, str]] = [
    ("Website URL", "https://example.com"),
    ("Selected Package", "Sentinel Audit Report"),
    ("Platform", "WordPress / unknown"),
    ("Cloudflare", "unknown"),
    ("Known Problems", "placeholder only"),
    ("Passwords", "not requested"),
    ("Credentials", "not requested"),
    ("Consent", "read-only audit only"),
]

RISK_REVIEW_DRYRUN: List[Tuple[str, str]] = [
    ("READ_ONLY", "allowed for public audit simulation"),
    ("DRAFT", "allowed for sample recommendations"),
    ("LOW", "allowed as documented recommendation only"),
    ("MEDIUM", "review-only, no execution"),
    ("HIGH", "blocked / review-only"),
]

PACKAGE_WORKFLOWS: Dict[str, List[str]] = {
    "Sentinel Audit Report": [
        "Review the intake for completeness and safety.",
        "Evaluate the website publicly / read-only.",
        "Structure the findings.",
        "Classify risk for each finding.",
        "Create the report.",
        "Run the delivery checklist.",
        "Prepare the completion message.",
    ],
    "Sentinel Safe Optimization": [
        "Everything from the Audit package.",
        "Select safe candidates.",
        "Mark owner-review items.",
        "Prepare a backup / healthcheck / rollback plan.",
        "Document LOW/MEDIUM items as review-gated only.",
        "Never execute a HIGH change.",
        "Create the final report.",
    ],
    "Sentinel Monitoring & Improvement": [
        "Document the monitoring period.",
        "Collect trend points.",
        "Interpret 5xx / origin / Cloudflare signals (read-only).",
        "Maintain the SEO / performance backlog.",
        "Prepare the monthly summary.",
        "Document owner review and next safe steps.",
    ],
}

SAMPLE_REPORT_SECTIONS: List[Tuple[str, str]] = [
    ("Executive Summary",
     "Placeholder summary of a safety-first, read-only review. No real findings - sample only."),
    ("Website Context Placeholder",
     "Website: https://example.com (placeholder). Platform: WordPress / unknown (placeholder)."),
    ("SEO Findings Placeholder",
     "[Sample SEO findings would be listed here, e.g. meta titles, headings, internal links.]"),
    ("Performance Findings Placeholder",
     "[Sample performance findings would be listed here, e.g. image sizes, caching hints.]"),
    ("Security / Cloudflare Findings Placeholder",
     "[Sample security / Cloudflare signal interpretation would be listed here - read-only.]"),
    ("Risk Classification",
     "READ_ONLY and DRAFT items are safe; MEDIUM items are review-only; HIGH items are blocked."),
    ("Safe Recommendations",
     "[Sample safe, review-first recommendations would be listed here.]"),
    ("Owner Review Items",
     "[Sample items that need the owner's explicit approval would be listed here.]"),
    ("Blocked High-Risk Items",
     "[Any HIGH-risk request stays blocked / review-only and is never auto-applied.]"),
    ("Next Safe Steps",
     "[Sample next safe steps the owner can take at their own pace would be listed here.]"),
    ("Disclaimer", NO_GUARANTEE_DISCLAIMER),
]

DELIVERY_PACK_SECTIONS: List[Tuple[str, str]] = [
    ("Client report placeholder",
     "Attach the sample client report (sentinel-payhip-sample-client-report.md) as the example."),
    ("Delivery message placeholder",
     "Hi [first name], your sample review is ready. This dry-run uses placeholder data only."),
    ("Safety note",
     "The service ran read-only; no high-risk change was applied and no password was needed."),
    ("What was reviewed",
     "Public SEO, performance and security signals (sample placeholders only)."),
    ("What was not changed",
     "No website, theme, plugin, database, Cloudflare or server change was applied."),
    ("Next safe steps",
     "Apply safe, review-first recommendations at your own pace, with backups and rollback."),
    ("Completion checklist",
     "See sentinel-payhip-first-order-completion-checklist.md."),
]

COMPLETION_CHECKLIST = [
    "Dummy case opened with placeholder data only.",
    "Intake simulated; no password or credential requested or stored.",
    "Scope and risk review simulated; HIGH stays blocked / review-only.",
    "All three package workflows simulated.",
    "Sample client report generated with the placeholder-only disclaimer.",
    "Sample delivery pack generated.",
    "No website, server, Cloudflare or database change applied.",
    "No real customer data, secrets, server paths or IPs in any output.",
]

REAL_ORDER_MANUAL_STEPS = [
    "Record a new real order manually (do not automate).",
    "Do not accept passwords; the first audit is read-only.",
    "Review the intake for completeness and safety.",
    "Confirm the scope with the buyer.",
    "Start the public, read-only audit.",
    "Transfer the findings into the client report.",
    "Run the risk review (READ_ONLY / DRAFT / LOW / MEDIUM / HIGH).",
    "Do the final owner review of the report.",
    "Send the delivery message through the agreed channel.",
    "Mark the case delivered / completed.",
]

DO_NOT_STORE = [
    "No passwords", "No API keys", "No secret tokens", "No SSH keys",
    "No FTP / SFTP access data", "No database access data",
    "No hosting or Cloudflare account passwords", "No 2FA backup codes",
    "No payment data", "No private customer documents without explicit release",
]
RECOMMENDED_GIT_CHECKPOINT = [
    "sentinel_payhip_first_order_dryrun.py",
    "playbooks/sentinel-payhip-first-order-dryrun.playbook.json",
    "playbooks/sentinel-payhip-sample-client-report.playbook.json",
    "playbooks/sentinel-payhip-delivery-pack.playbook.json",
]


# ---------------------------------------------------------------------------
# Inputs / git / safety
# ---------------------------------------------------------------------------
def read_inputs() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    status: Dict[str, str] = {}
    missing: List[str] = []
    for key, path in INPUT_JSON:
        obj, st = read_optional_json(path)
        data[key] = obj
        status[key] = st
        if st != "ok":
            missing.append(str(path.relative_to(PROJECT_DIR)))
    for key, path in INPUT_FILES:
        ok = path.exists() and not SENSITIVE_NAME_RE.search(path.name)
        status[key] = "ok" if ok else "not_available"
        if not ok:
            missing.append(str(path.relative_to(PROJECT_DIR)))
    return {"data": data, "input_status": status, "missing_inputs": missing}


def _git_status() -> Dict[str, Any]:
    log_ok, _ = run_readonly(["git", "log", "--oneline", "-15"])
    st_ok, st_out = run_readonly(["git", "status", "--short"])
    lines = [ln for ln in st_out.splitlines() if ln.strip()]
    untracked = sum(1 for ln in lines if ln.startswith("??"))
    modified = len(lines) - untracked
    files_sample: List[str] = []
    for ln in lines[:15]:
        name = ln[3:].strip() if len(ln) > 3 else ln.strip()
        files_sample.append(redact_text(name, max_len=120))
    return {
        "log_available": log_ok,
        "status_available": st_ok,
        "untracked_count": untracked,
        "modified_count": modified,
        "recommended": (untracked + modified) > 0,
        "files_sample": files_sample,
    }


def resolve_safety(inputs: Dict[str, Any]) -> Dict[str, Any]:
    src = inputs["data"].get("fulfillment_state") or inputs["data"].get("fulfillment_board")

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
        reasons.append("upstream fulfillment reports breach")
    return (len(reasons) > 0), reasons


# ---------------------------------------------------------------------------
# Renderers (all placeholder-only, public-safe)
# ---------------------------------------------------------------------------
def render_dummy_case_md() -> str:
    lines = ["# Sentinel Payhip - Dummy Case (dry-run, placeholders only)", "",
             "> Placeholder data only. Not a real customer.", "", "```yaml"]
    for k, v in DUMMY_CASE:
        lines.append(f"{k}: {v}")
    lines += ["```", ""]
    return "\n".join(lines) + "\n"


def render_dummy_intake_md() -> str:
    lines = ["# Sentinel Payhip - Dummy Intake (dry-run, placeholders only)", "",
             "> Simulated intake with placeholder data. No password or credential requested.", ""]
    for k, v in DUMMY_INTAKE:
        lines.append(f"- **{k}**: {v}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_dummy_scope_risk_md() -> str:
    lines = ["# Sentinel Payhip - Dummy Scope & Risk Review (dry-run)", "",
             "Simulated mapping of the dummy request to risk classes:", ""]
    for cls, note in RISK_REVIEW_DRYRUN:
        lines.append(f"- **{cls}**: {note}")
    lines += ["", "HIGH-risk actions are never auto-applied; they stay blocked / review-only.", ""]
    return "\n".join(lines) + "\n"


def render_dummy_workflows_md() -> str:
    lines = ["# Sentinel Payhip - Dummy Package Workflows (dry-run, simulated)", ""]
    for p in PACKAGES:
        lines.append(f"## {p} ({PACKAGE_PRICES[p]})")
        for step in PACKAGE_WORKFLOWS[p]:
            lines.append(f"- [SIMULATED OK] {step}")
        lines.append("")
    lines += ["_All steps are simulated with placeholder data; nothing was executed._", ""]
    return "\n".join(lines) + "\n"


def render_sample_report_md() -> str:
    lines = ["# Sentinel Payhip - Sample Client Report (placeholder data only)", "",
             f"> {SAMPLE_DISCLAIMER_LINE}", ""]
    for i, (title, body) in enumerate(SAMPLE_REPORT_SECTIONS, 1):
        lines.append(f"## {i}. {title}")
        lines.append(body)
        lines.append("")
    lines += [f"Contact: {CONTACT_PLACEHOLDER}", ""]
    return "\n".join(lines) + "\n"


def render_sample_delivery_md() -> str:
    lines = ["# Sentinel Payhip - Sample Delivery Pack (placeholder data only)", "",
             f"> {SAMPLE_DISCLAIMER_LINE}", ""]
    for title, body in DELIVERY_PACK_SECTIONS:
        lines.append(f"## {title}")
        lines.append(body)
        lines.append("")
    return "\n".join(lines) + "\n"


def render_completion_checklist_md() -> str:
    lines = ["# Sentinel Payhip - First Order Completion Checklist (dry-run)", ""]
    for x in COMPLETION_CHECKLIST:
        lines.append(f"- [x] {x}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_real_order_steps_md() -> str:
    lines = ["# Sentinel Payhip - Real Order Manual Steps", "",
             "When a real order arrives, do this manually (this dry-run does none of it for real):",
             ""]
    for i, s in enumerate(REAL_ORDER_MANUAL_STEPS, 1):
        lines.append(f"{i}. {s}")
    lines += ["", "## Never store", *[f"- {x}" for x in DO_NOT_STORE], ""]
    return "\n".join(lines) + "\n"


def render_dryrun_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Payhip First Order Dry-Run (Phase 9.8)",
        "",
        f"- QA decision: **{report['decision']}**",
        f"- Generated: {report['generated_at']}",
        f"- {SAMPLE_DISCLAIMER_LINE}",
        "",
        "## Simulated stages",
        f"- Dummy case: {report['dummy_case_status']}",
        f"- Intake simulation: {report['intake_simulation_status']}",
        f"- Scope & risk review: {report['scope_risk_status']}",
        f"- Package workflows: {report['package_workflow_status']} "
        f"({len(report['packages'])} packages)",
        f"- Sample client report: {report['sample_report_status']} "
        f"({report['sample_report_sections']} sections)",
        f"- Sample delivery pack: {report['delivery_pack_status']}",
        f"- Completion checklist: {report['completion_checklist_status']}",
        "",
        "## When a real order arrives (do manually)",
    ]
    for i, s in enumerate(REAL_ORDER_MANUAL_STEPS, 1):
        lines.append(f"{i}. {s}")
    lines += ["", "## Never store"]
    for x in DO_NOT_STORE:
        lines.append(f"- {x}")
    lines += [
        "", "## Safety",
        f"- live_apply: {report['live_apply']}",
        f"- emergency_stop: {report['emergency_stop']}",
        f"- allowed_apply_now: {report['allowed_apply_now']}",
        f"- breach: {report['breach']}",
        "- This is a dry-run only: no real customer data, no audit, no upload, no send.",
        "",
        "## Recommended Git checkpoint (script + playbooks only)",
    ]
    for x in RECOMMENDED_GIT_CHECKPOINT:
        lines.append(f"- {x}")
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Build / write
# ---------------------------------------------------------------------------
def build_full_state() -> Dict[str, Any]:
    timestamp = utc_now()
    inputs = read_inputs()
    safety = resolve_safety(inputs)
    breach, reasons = compute_breach(safety)
    git = _git_status()

    # Validate that all generated dry-run docs are public-safe and disclaimer is present.
    rendered = {
        "dummy_case": render_dummy_case_md(),
        "dummy_intake": render_dummy_intake_md(),
        "dummy_scope_risk": render_dummy_scope_risk_md(),
        "dummy_workflows": render_dummy_workflows_md(),
        "sample_report": render_sample_report_md(),
        "sample_delivery": render_sample_delivery_md(),
        "completion": render_completion_checklist_md(),
        "real_order": render_real_order_steps_md(),
    }
    unsafe: Dict[str, List[str]] = {}
    for name, blob in rendered.items():
        findings = public_safety_findings(blob)
        if findings:
            unsafe[name] = findings
    disclaimer_ok = SAMPLE_DISCLAIMER_LINE in rendered["sample_report"]

    if breach or unsafe:
        decision = DECISION_BLOCKED
    elif not disclaimer_ok:
        decision = DECISION_NEEDS_REVIEW
    else:
        decision = DECISION_READY

    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.8",
        "generated_at": timestamp,
        "status": f"FIRST_ORDER_DRYRUN_{decision}",
        "read_only": True,
        "dry_run_only": True,
        "service_title": SERVICE_TITLE,
        "packages": PACKAGES,
        "package_prices": PACKAGE_PRICES,
        "decision": decision,
        "sample_disclaimer_present": disclaimer_ok,
        "sample_disclaimer_line": SAMPLE_DISCLAIMER_LINE,
        "unsafe_outputs": unsafe,
        "dummy_case_status": "READY",
        "intake_simulation_status": "SIMULATED",
        "scope_risk_status": "SIMULATED",
        "package_workflow_status": "SIMULATED",
        "sample_report_status": "READY",
        "sample_report_sections": len(SAMPLE_REPORT_SECTIONS),
        "delivery_pack_status": "READY",
        "completion_checklist_status": "READY",
        "dummy_case_fields": [k for k, _ in DUMMY_CASE],
        "real_order_manual_steps": REAL_ORDER_MANUAL_STEPS,
        "do_not_store": DO_NOT_STORE,
        "recommended_git_checkpoint": RECOMMENDED_GIT_CHECKPOINT,
        "customer_files_committed": False,
        # safety mirror / explicit non-actions
        "autonomy_level": safety["current_level"],
        "live_apply": safety["live_apply"],
        "emergency_stop": safety["emergency_stop"],
        "allowed_apply_now": safety["allowed_apply_now"],
        "high_blocked": safety["high_blocked"],
        "high_risk_blocked": True,
        "breach": breach,
        "breach_reasons": reasons,
        "processes_real_customer_data": False,
        "is_real_audit": False,
        "requests_passwords": False,
        "stores_credentials": False,
        "sends_email": False,
        "network_access": False,
        "payhip_api_access": False,
        "uploads_anything": False,
        "installs_packages": False,
        "applies_changes": False,
        "secrets_in_report": False,
        "git_checkpoint": git,
        "input_status": inputs["input_status"],
        "missing_inputs": inputs["missing_inputs"],
    }
    return {"report": report, "safety": safety, "breach": breach}


def build_playbooks(report: Dict[str, Any]) -> Dict[Path, Dict[str, Any]]:
    return {
        PLAYBOOK_DRYRUN: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-first-order-dryrun",
            "generated_at": report["generated_at"],
            "status": report["status"],
            "read_only": True,
            "dry_run_only": True,
            "applies_changes": False,
            "uploads_anything": False,
            "decision": report["decision"],
            "steps": [
                "Build a dummy case with placeholders (example.com only).",
                "Simulate intake, scope and risk review.",
                "Simulate all three package workflows.",
                "Generate a sample client report and delivery pack.",
                "Emit the QA decision and real-order manual steps.",
            ],
        },
        PLAYBOOK_SAMPLE_REPORT: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-sample-client-report",
            "generated_at": report["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "sections": [t for t, _ in SAMPLE_REPORT_SECTIONS],
            "disclaimer": SAMPLE_DISCLAIMER_LINE,
        },
        PLAYBOOK_DELIVERY: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-delivery-pack",
            "generated_at": report["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "sections": [t for t, _ in DELIVERY_PACK_SECTIONS],
        },
    }


def write_all_outputs(state: Dict[str, Any]) -> List[str]:
    report = state["report"]
    written: List[str] = []

    def w(path: Path, text: str) -> None:
        write_text_atomic(path, text)
        written.append(str(path.relative_to(PROJECT_DIR)))

    def wj(path: Path, data: Dict[str, Any]) -> None:
        write_json_atomic(path, data)
        written.append(str(path.relative_to(PROJECT_DIR)))

    wj(DRYRUN_JSON, report)
    w(DRYRUN_MD, render_dryrun_md(report))
    w(DUMMY_CASE_MD, render_dummy_case_md())
    w(DUMMY_INTAKE_MD, render_dummy_intake_md())
    w(DUMMY_SCOPE_RISK_MD, render_dummy_scope_risk_md())
    w(DUMMY_WORKFLOWS_MD, render_dummy_workflows_md())
    w(SAMPLE_REPORT_MD, render_sample_report_md())
    w(SAMPLE_DELIVERY_MD, render_sample_delivery_md())
    w(COMPLETION_CHECKLIST_MD, render_completion_checklist_md())
    w(REAL_ORDER_STEPS_MD, render_real_order_steps_md())

    wj(STATE_JSON, report)
    wj(STATE_LATEST_JSON, report)

    for path, data in build_playbooks(report).items():
        wj(path, data)

    append_jsonl(AUDIT_JSONL, [{
        "ts": report["generated_at"],
        "phase": "9.8",
        "module": "sentinel_payhip_first_order_dryrun",
        "status": report["status"],
        "decision": report["decision"],
        "dry_run_only": True,
        "sample_disclaimer_present": report["sample_disclaimer_present"],
        "package_count": len(report["packages"]),
        "live_apply": report["live_apply"],
        "emergency_stop": report["emergency_stop"],
        "allowed_apply_now": report["allowed_apply_now"],
        "high_blocked": report["high_blocked"],
        "processes_real_customer_data": False,
        "is_real_audit": False,
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
        raise AssertionError("module must not define --apply")

    net_import = re.compile(
        r"(?m)^\s*(?:import|from)\s+(requests|urllib|http\.client|smtplib|socket|paramiko|cloudflare)\b"
    )
    if net_import.search(src):
        raise AssertionError("module must not import network/email libraries")

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
        ("rm -rf", re.compile(r"rm\s+-rf|shutil\.rmtree")),
    ]
    for label, pattern in forbidden_capabilities:
        if pattern.search(src):
            raise AssertionError(f"forbidden capability present in source: {label}")

    allowed_names = {str(r.relative_to(PROJECT_DIR)) for r in ALLOWED_WRITE_ROOTS}
    if allowed_names != {"reports/latest", "state/adaptive-learning", "audit", "playbooks"}:
        raise AssertionError(f"unexpected write roots: {allowed_names}")

    for bad in ("/etc/sentinel-defense.env", "deploy.key", "id_rsa", "api-token.json"):
        obj, status = read_optional_json(Path(bad))
        if obj is not None or status not in ("refused_secret_like_path", "not_available"):
            raise AssertionError(f"sensitive path not refused: {bad} -> {status}")

    # Public-safety scanner: catches real leaks + non-example domains.
    for bad in ("see /etc/passwd here", "origin at 203.0.113.7", "we guarantee 100% pagespeed",
                "we will bypass security", "ghp_abcdefghijklmnop12345",
                "password=ABCDEFGH12345678", "contact real.person@gmail.com",
                "visit https://real-customer-site.com now"):
        if not public_safety_findings(bad):
            raise AssertionError(f"public-safety scanner missed: {bad}")
    for good in ("Website: https://example.com (placeholder).",
                 "Contact: customer@example.com.",
                 "no_password_received: true and secrets_received: false",
                 "Never store passwords, API keys or tokens.",
                 "We do not promise a specific search ranking; review-first only."):
        if public_safety_findings(good):
            raise AssertionError(f"public-safety scanner false positive: {good}")

    # Writer must reject secrets, paths, IPs and non-example domains.
    for bad in ("token=ABCDEFGH12345678", "path /srv/sentinel-defense", "ip 198.51.100.9",
                "https://not-example.org"):
        try:
            write_text_atomic(DRYRUN_MD, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"writer failed to reject: {bad}")

    # Dummy case must use only safe placeholders.
    case = dict(DUMMY_CASE)
    if case["website_url_placeholder"] != "https://example.com":
        raise AssertionError("dummy website must be https://example.com")
    if case["contact_placeholder"] != "customer@example.com":
        raise AssertionError("dummy contact must be customer@example.com")
    for key, expected in (("no_password_received", "true"), ("secrets_received", "false"),
                          ("live_apply", "false"), ("high_risk_blocked", "true"),
                          ("delivery_status", "DRYRUN_ONLY")):
        if case[key] != expected:
            raise AssertionError(f"dummy case {key} must be {expected}")

    # Dummy intake must not request passwords/credentials.
    intake = dict(DUMMY_INTAKE)
    if intake["Passwords"] != "not requested" or intake["Credentials"] != "not requested":
        raise AssertionError("dummy intake must not request passwords/credentials")

    # Sample report must carry the placeholder disclaimer and the 11 sections.
    sample = render_sample_report_md()
    if SAMPLE_DISCLAIMER_LINE not in sample:
        raise AssertionError("sample report must state it is placeholder-only")
    if len(SAMPLE_REPORT_SECTIONS) != 11:
        raise AssertionError("sample report must have 11 sections")

    # Build state and validate invariants.
    state = build_full_state()
    report = state["report"]
    if report["live_apply"] is not False:
        raise AssertionError("live_apply must be false")
    if report["emergency_stop"] is not True:
        raise AssertionError("emergency_stop must be true")
    if report["allowed_apply_now"] is not False:
        raise AssertionError("allowed_apply_now must be false")
    if report["high_blocked"] is not True or report["high_risk_blocked"] is not True:
        raise AssertionError("HIGH must stay blocked")
    if report["autonomy_level"] not in ALLOWED_CURRENT_LEVELS:
        raise AssertionError("autonomy_level must be LEVEL_1/LEVEL_2")
    if report["breach"]:
        raise AssertionError(f"clean state must not breach: {report['breach_reasons']}")
    if report["decision"] not in (DECISION_READY, DECISION_NEEDS_REVIEW, DECISION_BLOCKED):
        raise AssertionError("decision invalid")
    if report["unsafe_outputs"]:
        raise AssertionError(f"dry-run outputs not public-safe: {report['unsafe_outputs']}")
    for flag in ("processes_real_customer_data", "is_real_audit", "requests_passwords",
                 "stores_credentials", "sends_email", "network_access", "payhip_api_access",
                 "uploads_anything", "installs_packages", "applies_changes"):
        if report[flag] is not False:
            raise AssertionError(f"{flag} must be false")

    # All rendered outputs must be public-safe.
    rendered = [
        render_dryrun_md(report), render_dummy_case_md(), render_dummy_intake_md(),
        render_dummy_scope_risk_md(), render_dummy_workflows_md(), render_sample_report_md(),
        render_sample_delivery_md(), render_completion_checklist_md(), render_real_order_steps_md(),
    ]
    for blob in rendered:
        findings = public_safety_findings(blob)
        if findings:
            raise AssertionError(f"generated output not public-safe: {findings}")

    for blob_obj in (report, *build_playbooks(report).values()):
        json.dumps(blob_obj)

    # Breach detection on tampered safety.
    base_safety = {"live_apply": False, "emergency_stop": True, "allowed_apply_now": False,
                   "current_level": LEVEL_2, "high_blocked": True, "upstream_breach": False}
    if compute_breach(base_safety)[0]:
        raise AssertionError("clean safety must not breach")
    for tamper in ({"live_apply": True}, {"emergency_stop": False}, {"allowed_apply_now": True},
                   {"current_level": "LEVEL_4_MEDIUM_CANARY_ONLY"}, {"high_blocked": False},
                   {"upstream_breach": True}):
        if not compute_breach(dict(base_safety, **tamper))[0]:
            raise AssertionError(f"tamper did not breach: {tamper}")

    # Write-path guards.
    for forbidden in (
        PROJECT_DIR / "reports/latest/x.sh",
        PROJECT_DIR / "exports/x.md",
        PROJECT_DIR / "state/adaptive-learning/x.service",
        PROJECT_DIR / "config/x.json",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")
    for ok_path in (DRYRUN_JSON, DRYRUN_MD, SAMPLE_REPORT_MD, STATE_JSON, AUDIT_JSONL,
                    PLAYBOOK_DRYRUN):
        assert_allowed_write(ok_path)

    if not detect_secret_like("password=supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("The first audit is read-only and needs no login"):
        raise AssertionError("secret detector false positive on prose")

    print("payhip-first-order-dryrun self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], written: List[str]) -> None:
    r = state["report"]
    print("=== Sentinel Payhip First Order Dry-Run Simulator (Phase 9.8) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"dummy case status: {r['dummy_case_status']} ({len(r['dummy_case_fields'])} fields)")
    print(f"intake simulation status: {r['intake_simulation_status']}")
    print(f"package workflow simulation status: {r['package_workflow_status']} "
          f"({len(r['packages'])} packages)")
    print(f"sample report status: {r['sample_report_status']} "
          f"({r['sample_report_sections']} sections, disclaimer={r['sample_disclaimer_present']})")
    print(f"delivery pack status: {r['delivery_pack_status']}")
    print(f"completion checklist status: {r['completion_checklist_status']}")
    print(f"QA decision: {r['decision']}")
    print(f"live_apply: {r['live_apply']}")
    print(f"emergency_stop: {r['emergency_stop']}")
    print(f"allowed_apply_now: {r['allowed_apply_now']}")
    print(f"breach: {r['breach']}")
    print("when a real first order arrives - do manually:")
    for x in r["real_order_manual_steps"]:
        print(f"  - {x}")
    print("never store:")
    for x in r["do_not_store"]:
        print(f"  - {x}")
    print("recommended Git checkpoint (script + playbooks only):")
    for x in r["recommended_git_checkpoint"]:
        print(f"  - {x}")
    print("note: dry-run only; no real customer data; customer/export files are NOT committed.")
    if r["missing_inputs"]:
        print(f"missing inputs (safe defaults used): {', '.join(r['missing_inputs'])}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Payhip First Order Dry-Run Simulator (Phase 9.8). "
                    "Placeholder data only; no real audit; no upload; no apply."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--build-dummy-case", action="store_true", help="Build the dummy case.")
    p.add_argument("--simulate-intake", action="store_true", help="Simulate the intake.")
    p.add_argument("--simulate-package-workflows", action="store_true",
                   help="Simulate all three package workflows.")
    p.add_argument("--build-sample-report", action="store_true", help="Build the sample report.")
    p.add_argument("--build-delivery-pack", action="store_true", help="Build the sample delivery pack.")
    p.add_argument("--status", action="store_true", help="Print status summary.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    state = build_full_state()
    written = write_all_outputs(state)
    r = state["report"]

    if args.build_dummy_case:
        print(f"[dummy-case] ready | {len(r['dummy_case_fields'])} fields | placeholders only")
    if args.simulate_intake:
        print(f"[intake] {r['intake_simulation_status']} | no password/credential requested")
    if args.simulate_package_workflows:
        print(f"[workflows] {r['package_workflow_status']} | {len(r['packages'])} packages")
    if args.build_sample_report:
        print(f"[sample-report] ready | {r['sample_report_sections']} sections | "
              f"disclaimer={r['sample_disclaimer_present']}")
    if args.build_delivery_pack:
        print(f"[delivery-pack] {r['delivery_pack_status']} | decision={r['decision']}")

    if args.status or not any(
        (args.build_dummy_case, args.simulate_intake, args.simulate_package_workflows,
         args.build_sample_report, args.build_delivery_pack)
    ):
        _print_status(state, written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
