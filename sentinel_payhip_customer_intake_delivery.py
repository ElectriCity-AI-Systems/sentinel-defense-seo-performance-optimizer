#!/usr/bin/env python3
"""Sentinel Payhip Customer Intake & Delivery Workflow (Phase 9.3).

A safe, read-only customer-onboarding layer for the Payhip service
"Sentinel Security, SEO & Performance Safe Optimization". It models the flow:

    Payhip purchase -> buyer instructions -> customer delivers URL + goal
    -> Sentinel intake structure -> audit/review/delivery workflow
    -> client-ready hand-over.

It produces local templates, workflows, reports and safe text building blocks
only. It changes nothing, applies nothing, never asks for passwords, never
stores real customer credentials, sends no email and performs no network access.

There is deliberately no apply mode, no SFTP write, no DB write, no Cloudflare
write, no WordPress write, no service activation through systemctl, no timer
installation and no Payhip API access. It reads optional local Phase 9.0-9.2
reports/state (plus git status read-only) and writes reports/state/audit/
playbook files under the allowed project roots.

Strict separation of concerns:
    public marketing text  | customer input | internal technical analysis
    owner review           | delivery

Invariants surfaced and enforced:
    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    every HIGH action  -> blocked / review-only
    no passwords requested, no real customer data stored, no secrets in output.
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
# Output paths
# ---------------------------------------------------------------------------
INTAKE_JSON = PROJECT_DIR / "reports/latest/sentinel-payhip-customer-intake.json"
INTAKE_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-customer-intake.md"
BUYER_INSTRUCTIONS_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-buyer-instructions.md"
INTAKE_FORM_MD = PROJECT_DIR / "reports/latest/sentinel-customer-intake-form.md"
DELIVERY_WORKFLOW_MD = PROJECT_DIR / "reports/latest/sentinel-service-delivery-workflow.md"
PACKAGE_DELIVERABLES_MD = PROJECT_DIR / "reports/latest/sentinel-package-deliverables.md"
ONBOARDING_MESSAGE_MD = PROJECT_DIR / "reports/latest/sentinel-client-onboarding-message.md"
DELIVERY_MESSAGE_MD = PROJECT_DIR / "reports/latest/sentinel-client-delivery-message.md"
SAFETY_AGREEMENT_MD = PROJECT_DIR / "reports/latest/sentinel-client-safety-agreement.md"
PROCESSING_CHECKLIST_MD = PROJECT_DIR / "reports/latest/sentinel-internal-processing-checklist.md"
CLIENT_REPORT_TEMPLATE_MD = PROJECT_DIR / "reports/latest/sentinel-client-report-template.md"
PRODUCT_FILE_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-product-file-text.md"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_INTAKE_JSON = STATE_DIR / "sentinel_payhip_customer_intake_delivery.json"
STATE_LATEST_INTAKE_JSON = STATE_DIR / "latest_payhip_customer_intake_delivery.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-payhip-customer-intake-delivery.jsonl"

PLAYBOOK_INTAKE = PROJECT_DIR / "playbooks/sentinel-payhip-customer-intake.playbook.json"
PLAYBOOK_DELIVERY = PROJECT_DIR / "playbooks/sentinel-service-delivery-workflow.playbook.json"
PLAYBOOK_REPORT = PROJECT_DIR / "playbooks/sentinel-client-report-template.playbook.json"

# Output is restricted to exactly these roots (same as 9.1/9.2).
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

SCHEMA_VERSION = "payhip-customer-intake-delivery-9.3"

# ---------------------------------------------------------------------------
# Autonomy levels (must mirror Phase 9.0)
# ---------------------------------------------------------------------------
LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
LEVEL_2 = "LEVEL_2_LOW_RISK_PREP_PREVIEW"
ALLOWED_CURRENT_LEVELS = {LEVEL_1, LEVEL_2}
DEFAULT_CURRENT_LEVEL = LEVEL_2

READ_ONLY = "READ_ONLY"
DRAFT = "DRAFT"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CLASS_ORDER = [READ_ONLY, DRAFT, LOW, MEDIUM, HIGH]

# ---------------------------------------------------------------------------
# Inputs (read-only; optional)
# ---------------------------------------------------------------------------
INPUT_JSON: List[Tuple[str, Path]] = [
    ("owner_dashboard", PROJECT_DIR / "reports/latest/sentinel-owner-dashboard.json"),
    ("service_proof", STATE_DIR / "latest_service_proof.json"),
]
INPUT_MD: List[Tuple[str, Path]] = [
    ("service_packages_md", PROJECT_DIR / "reports/latest/sentinel-service-packages.md"),
    ("sales_page_md", PROJECT_DIR / "reports/latest/sentinel-service-sales-page.md"),
    ("service_proof_md", PROJECT_DIR / "reports/latest/sentinel-service-proof.md"),
    ("service_proof_marketing_md", PROJECT_DIR / "reports/latest/sentinel-service-proof-marketing.md"),
    ("payhip_proof_snippet_md", PROJECT_DIR / "reports/latest/sentinel-payhip-proof-snippet.md"),
]

# ---------------------------------------------------------------------------
# Secret handling (verbatim from the proven 9.0-9.2 scaffolding)
# ---------------------------------------------------------------------------
SENSITIVE_NAME_RE = re.compile(
    r"(?i)(\.env\b|sftp.*env|\.pem$|\.key$|id_rsa|id_ed25519|\.p12$|\.pfx$|"
    r"secret|token|credential|password|passwd|\.htpasswd|api[_-]?key|private[_-]?key)"
)
SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"set-cookie|credential|x-api-key|access[_-]?key|private[_-]?key)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|"
    r"authorization|set-cookie|x-api-key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b|required\b|"
    r"requested\b|warning\b|field\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{40,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Reserved/placeholder e-mail domains permitted in templates (never real data).
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}


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
        raise ValueError(f"Refusing to write outside allowed customer roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install/secret artifact: {path}")
    if any(token in str(path) for token in FORBIDDEN_INSTALL_PATH_TOKENS):
        raise ValueError(f"Refusing to write systemd/crontab path: {path}")


def _assert_no_secret_blob(path: Path, blob: str) -> None:
    if SECRET_ASSIGNMENT_RE.search(blob) or LONG_HEX_RE.search(blob):
        raise ValueError(f"Refusing to write secret-like content to {path}")
    for m in EMAIL_RE.findall(blob):
        domain = m.rsplit("@", 1)[-1].lower()
        if domain not in ALLOWED_EMAIL_DOMAINS:
            raise ValueError(f"Refusing to write real-looking e-mail address to {path}: {m}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    _assert_no_secret_blob(path, content)
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
# Service packages
# ---------------------------------------------------------------------------
PACKAGES: List[Dict[str, Any]] = [
    {
        "id": "sentinel_audit",
        "name": "Sentinel Audit Report",
        "risk": "READ_ONLY",
        "delivery_time": "about 2-4 business days after a complete intake",
    },
    {
        "id": "sentinel_safe_optimization",
        "name": "Sentinel Safe Optimization",
        "risk": "MEDIUM (owner-gated, review-first)",
        "delivery_time": "about 1-2 weeks, depending on owner review turnaround",
    },
    {
        "id": "sentinel_monitoring_improvement",
        "name": "Sentinel Monitoring & Improvement",
        "risk": "MEDIUM (owner-gated, recurring)",
        "delivery_time": "recurring service with a monthly owner review",
    },
]
PACKAGE_BY_ID = {p["id"]: p for p in PACKAGES}

MAIN_GOALS = ["SEO", "Speed", "Security", "Stability", "All"]

# ---------------------------------------------------------------------------
# Customer intake form (field definitions only; no real data)
# ---------------------------------------------------------------------------
CONSENT_TEXT = (
    "I understand that this service starts with read-only analysis and does not "
    "require passwords for the first audit."
)
PERMISSION_LEVELS = [
    "public read-only audit only",
    "owner may provide screenshots",
    "owner may provide reports",
    "no login access at this stage",
]
INTAKE_FIELDS: List[Dict[str, Any]] = [
    {"key": "customer_name", "label": "Customer name or business name", "type": "text", "required": True},
    {"key": "contact_email", "label": "Contact email", "type": "email", "required": True,
     "placeholder": "you@example.com"},
    {"key": "website_url", "label": "Website URL", "type": "url", "required": True,
     "placeholder": "https://your-website.example.com"},
    {"key": "selected_package", "label": "Selected package", "type": "choice", "required": True,
     "options": [p["name"] for p in PACKAGES]},
    {"key": "main_goal", "label": "Main goal", "type": "choice", "required": True, "options": MAIN_GOALS},
    {"key": "website_platform", "label": "Website platform", "type": "text", "required": False,
     "placeholder": "e.g. WordPress, custom, Next.js, unknown"},
    {"key": "wordpress_usage", "label": "WordPress usage", "type": "choice", "required": True,
     "options": ["yes", "no", "unknown"]},
    {"key": "cloudflare_usage", "label": "Cloudflare usage", "type": "choice", "required": True,
     "options": ["yes", "no", "unknown"]},
    {"key": "hosting_provider", "label": "Hosting provider if known", "type": "text", "required": False},
    {"key": "known_problems", "label": "Known problems", "type": "long_text", "required": False},
    {"key": "recent_changes", "label": "Recent changes", "type": "long_text", "required": False},
    {"key": "plugins_tools", "label": "Plugins/tools known", "type": "long_text", "required": False},
    {"key": "external_embeds", "label": "External embeds/widgets", "type": "long_text", "required": False},
    {"key": "is_live_business", "label": "Is this a live business website?", "type": "choice",
     "required": True, "options": ["yes", "no", "unknown"]},
    {"key": "report_language", "label": "Preferred report language", "type": "choice", "required": True,
     "options": ["English", "German"]},
    {"key": "permission_level", "label": "Permission level", "type": "choice", "required": True,
     "options": PERMISSION_LEVELS},
    {"key": "consent", "label": "Consent checkbox", "type": "consent", "required": True,
     "consent_text": CONSENT_TEXT},
]

PASSWORD_WARNING = (
    "Never send passwords, API keys, private keys or other login credentials through "
    "normal Payhip messages or email. The first audit is read-only and does not need "
    "any login. If secure access is ever required for a later, controlled step, it is "
    "arranged only through a separately agreed secure channel."
)

# Customer data that is NEVER requested through normal messages/forms.
NEVER_REQUESTED_NORMALLY = [
    "passwords of any kind",
    "API keys or secret tokens",
    "private SSH or TLS keys",
    "FTP/SFTP credentials",
    "database credentials",
    "hosting or Cloudflare account passwords",
    "two-factor backup codes",
]

# ---------------------------------------------------------------------------
# Delivery workflow per package
# ---------------------------------------------------------------------------
DELIVERY_WORKFLOWS: Dict[str, List[str]] = {
    "sentinel_audit": [
        "Check intake for completeness (URL, package, goal).",
        "Plan a public, read-only scan (no login, no write).",
        "Run SEO / performance / security diagnosis (read-only).",
        "Risk classification (READ_ONLY / DRAFT / LOW / MEDIUM / HIGH).",
        "Produce the client report.",
        "Provide safe recommendations.",
        "No live changes are made.",
    ],
    "sentinel_safe_optimization": [
        "Everything from the Audit Report.",
        "Draft recommendations (no live apply).",
        "Build an owner review pack.",
        "Identify safe optimization candidates.",
        "Only controlled LOW/MEDIUM canary preparation.",
        "No HIGH actions without explicit review.",
        "Backup / healthcheck / rollback plan for any controlled change.",
        "Final completion report.",
    ],
    "sentinel_monitoring_improvement": [
        "Recurring monitoring plan.",
        "Trend observation over time.",
        "5xx / origin / Cloudflare interpretation (read-only).",
        "SEO / performance roadmap.",
        "Monthly owner review.",
        "Safe improvement backlog.",
        "No blind automation.",
    ],
}

PACKAGE_DELIVERABLES: Dict[str, List[str]] = {
    "sentinel_audit": [
        "Read-only SEO/performance/security audit report.",
        "Risk classification table.",
        "Prioritized safe recommendation list.",
        "No changes applied.",
    ],
    "sentinel_safe_optimization": [
        "Audit report + draft optimization recommendations.",
        "Owner review pack with safe candidates.",
        "Controlled LOW/MEDIUM canary preparation plan (review-first).",
        "Backup/healthcheck/rollback plan.",
        "Completion report after owner-approved steps.",
    ],
    "sentinel_monitoring_improvement": [
        "Recurring monitoring + trend reports.",
        "5xx/origin/Cloudflare interpretation.",
        "SEO/performance improvement roadmap.",
        "Monthly owner review summary.",
        "Safe improvement backlog.",
    ],
}

# ---------------------------------------------------------------------------
# Message templates (no sending; placeholders only)
# ---------------------------------------------------------------------------
MESSAGE_TEMPLATES: List[Dict[str, str]] = [
    {
        "id": "client_onboarding",
        "title": "Client onboarding message after purchase",
        "body": "Hi [first name],\n\nThank you for purchasing [package name]. To get started, "
                "please complete the short intake form and send your website URL and main goal. "
                "Reminder: the first audit is read-only, so please do not send any passwords.",
    },
    {
        "id": "missing_information",
        "title": "Missing information request",
        "body": "Hi [first name],\n\nTo begin your [package name], I still need: [missing items]. "
                "Once I have these, I can plan the read-only analysis. No passwords are required.",
    },
    {
        "id": "audit_started",
        "title": "Audit started message",
        "body": "Hi [first name],\n\nYour read-only audit for [website URL] has started. "
                "I am analyzing SEO, performance and security signals. I will share the report "
                "in [delivery time]. No changes are made to your site during this step.",
    },
    {
        "id": "audit_delivery",
        "title": "Audit delivery message",
        "body": "Hi [first name],\n\nYour Sentinel audit report is ready. It includes the website "
                "status, SEO/performance/security findings, a risk classification and safe "
                "recommendations. Nothing was changed on your site. Next steps are your decision.",
    },
    {
        "id": "safe_optimization_review_request",
        "title": "Safe Optimization review request",
        "body": "Hi [first name],\n\nI prepared a draft optimization pack for your review. These are "
                "proposals only. For any controlled change we use backup, healthcheck and rollback, "
                "and nothing is applied without your explicit approval.",
    },
    {
        "id": "monitoring_monthly_summary",
        "title": "Monitoring monthly summary message",
        "body": "Hi [first name],\n\nHere is your monthly monitoring summary: trend status, "
                "5xx/origin/Cloudflare interpretation and the current safe improvement backlog. "
                "No blind automation is used; you stay in control of approvals.",
    },
    {
        "id": "password_warning",
        "title": "Password warning message",
        "body": "Hi [first name],\n\n" + PASSWORD_WARNING,
    },
    {
        "id": "scope_clarification",
        "title": "Scope clarification message",
        "body": "Hi [first name],\n\nTo set expectations: this service starts with read-only "
                "analysis. Controlled changes are review-first and owner-approved. High-risk "
                "changes are never applied blindly.",
    },
    {
        "id": "high_risk_refusal",
        "title": "High-risk refusal / review-only explanation",
        "body": "Hi [first name],\n\nThe requested change is classified as high-risk. For your "
                "safety it stays review-only and is not auto-applied. I can document it, explain the "
                "risk and propose a safe, reviewed alternative path instead.",
    },
    {
        "id": "completion_next_steps",
        "title": "Completion and next steps message",
        "body": "Hi [first name],\n\nThis stage is complete. You have the report, the safe "
                "recommendations and a clear list of next steps. You remain the owner of all final "
                "approvals. Let me know if you would like ongoing monitoring.",
    },
]

# Claims these texts must never make.
NOT_PROMISED: List[str] = [
    "No guaranteed 100% PageSpeed score.",
    "No guaranteed Google ranking position.",
    "No automatic full repair.",
    "No unlimited emergency support.",
    "No blind Cloudflare or WordPress changes.",
    "No database, theme or plugin edits without review.",
]

# ---------------------------------------------------------------------------
# Client safety agreement
# ---------------------------------------------------------------------------
SAFETY_AGREEMENT: List[str] = [
    "The service starts read-only.",
    "No password is required for the first audit.",
    "No blind autopilot is used.",
    "No high-risk changes are made without explicit review.",
    "No guarantee of ranking or a fixed PageSpeed score.",
    "Backups, healthchecks and rollback are required for any controlled change.",
    "The client remains the owner of all final approvals.",
    "Sensitive access is used only through a secure, separately agreed channel if ever needed.",
    "The provider may refuse unsafe changes.",
]

# ---------------------------------------------------------------------------
# Internal processing checklist (owner side)
# ---------------------------------------------------------------------------
PROCESSING_CHECKLIST: List[str] = [
    "Verify purchase and selected package (Payhip side, manual).",
    "Confirm intake form is complete; request missing items if needed.",
    "Confirm NO passwords/credentials were sent; if so, advise rotation and do not store.",
    "Record website URL and main goal in internal analysis notes (not in customer-facing files).",
    "Plan read-only public scan scope.",
    "Run SEO/performance/security diagnosis (read-only).",
    "Classify findings by risk; mark HIGH as blocked/review-only.",
    "Draft owner review pack (Safe Optimization/Monitoring only).",
    "Prepare backup/healthcheck/rollback plan for any controlled candidate.",
    "Produce client report from the template.",
    "Owner review and sign-off before any controlled step.",
    "Deliver report + safe recommendations to the client.",
    "Log delivery in audit (no secrets, no customer credentials).",
]

# ---------------------------------------------------------------------------
# Client report template sections
# ---------------------------------------------------------------------------
REPORT_TEMPLATE_SECTIONS: List[Dict[str, str]] = [
    {"title": "Executive Summary", "hint": "Plain-language summary of the current state and key findings."},
    {"title": "Website Status", "hint": "Overall status (OK/WARNING/CRITICAL) and what it means."},
    {"title": "SEO Findings", "hint": "Titles, meta, structure, schema, indexing observations."},
    {"title": "Performance Findings", "hint": "Speed, caching, images, render-blocking observations."},
    {"title": "Security / Cloudflare Findings", "hint": "Scanner pressure, 5xx/origin, challenge rules (read-only)."},
    {"title": "Risk Classification", "hint": "READ_ONLY / DRAFT / LOW / MEDIUM / HIGH per finding."},
    {"title": "Safe Recommendations", "hint": "Low-risk, review-first improvement proposals."},
    {"title": "Owner Review Items", "hint": "Items that need explicit owner approval before any change."},
    {"title": "Blocked High-Risk Items", "hint": "High-risk items kept review-only and never auto-applied."},
    {"title": "Next Safe Steps", "hint": "Recommended next actions, all owner-controlled."},
    {"title": "Disclaimer", "hint": "No guaranteed ranking/PageSpeed; read-only first; no blind autopilot."},
]

# ---------------------------------------------------------------------------
# Payhip product file text sections
# ---------------------------------------------------------------------------
PRODUCT_FILE_SECTIONS: List[Dict[str, str]] = [
    {"title": "Thank you for your purchase",
     "body": "Thank you for choosing Sentinel Security, SEO & Performance Safe Optimization."},
    {"title": "Please complete the intake form",
     "body": "Open the intake form and fill in your website URL, selected package and main goal."},
    {"title": "Do not send passwords",
     "body": PASSWORD_WARNING},
    {"title": "Send website URL and selected package",
     "body": "Reply with your website URL and the package you purchased so analysis can be planned."},
    {"title": "What happens next",
     "body": "Sentinel runs a read-only analysis, classifies risk and delivers a clear report with "
             "safe recommendations. Controlled changes are review-first and owner-approved."},
    {"title": "Contact",
     "body": "Contact: [provider contact email to be filled in by the owner]."},
    {"title": "Safety first",
     "body": "This service starts read-only, uses no blind autopilot, and never applies high-risk "
             "changes without explicit review."},
]


# ---------------------------------------------------------------------------
# Inputs / git / safety
# ---------------------------------------------------------------------------
def read_inputs() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    input_status: Dict[str, str] = {}
    missing: List[str] = []
    for key, path in INPUT_JSON:
        obj, status = read_optional_json(path)
        data[key] = obj
        input_status[key] = status
        if status != "ok":
            missing.append(key)
    for key, path in INPUT_MD:
        available = path.exists() and not SENSITIVE_NAME_RE.search(path.name)
        input_status[key] = "ok" if available else "not_available"
        if not available:
            missing.append(key)
    return {"data": data, "input_status": input_status, "missing_inputs": missing}


def _git_status() -> Dict[str, Any]:
    log_ok, log_out = run_readonly(["git", "log", "--oneline", "-15"])
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
    dash = inputs["data"].get("owner_dashboard")
    proof = inputs["data"].get("service_proof")

    def pick(key: str, default: Any) -> Any:
        if isinstance(dash, dict) and key in dash:
            return dash[key]
        if isinstance(proof, dict) and key in proof:
            return proof[key]
        return default

    upstream_breach = False
    if isinstance(dash, dict):
        upstream_breach = bool(dash.get("breach"))
    elif isinstance(proof, dict):
        upstream_breach = bool(proof.get("breach"))

    return {
        "live_apply": bool(pick("live_apply", False)),
        "emergency_stop": bool(pick("emergency_stop", True)),
        "allowed_apply_now": bool(pick("allowed_apply_now", False)),
        "current_level": pick("autonomy_level", DEFAULT_CURRENT_LEVEL),
        "upstream_breach": upstream_breach,
        "dashboard_available": isinstance(dash, dict),
    }


def _high_blocked_groups(inputs: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Mirror HIGH/MEDIUM action discipline from the owner dashboard if present."""
    dash = inputs["data"].get("owner_dashboard")
    groups: Dict[str, List[Dict[str, Any]]] = {c: [] for c in CLASS_ORDER}
    if isinstance(dash, dict) and isinstance(dash.get("actions"), dict):
        actions = dash["actions"]
        for a in actions.get("high_blocked", []) or []:
            if isinstance(a, dict):
                groups[HIGH].append({"id": a.get("id"), "blocked": bool(a.get("blocked", True))})
        for a in actions.get("medium_owner_gated", []) or []:
            if isinstance(a, dict):
                groups[MEDIUM].append({"id": a.get("id"),
                                       "owner_gate_required": bool(a.get("owner_gate_required", True))})
    return groups


def compute_breach(safety: Dict[str, Any], groups: Dict[str, List[Dict[str, Any]]]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if safety["live_apply"] is not False:
        reasons.append("live_apply must be false")
    if safety["emergency_stop"] is not True:
        reasons.append("emergency_stop must be true")
    if safety["allowed_apply_now"] is not False:
        reasons.append("allowed_apply_now must be false")
    if safety["current_level"] not in ALLOWED_CURRENT_LEVELS:
        reasons.append(f"current_level {safety['current_level']} not allowed")
    if safety.get("upstream_breach"):
        reasons.append("upstream owner dashboard reports breach")
    for a in groups.get(HIGH, []):
        if not a.get("blocked"):
            reasons.append(f"HIGH action {a.get('id')} not blocked")
    for a in groups.get(MEDIUM, []):
        if not a.get("owner_gate_required"):
            reasons.append(f"MEDIUM action {a.get('id')} missing owner gate")
    return (len(reasons) > 0), reasons


# ---------------------------------------------------------------------------
# Full build
# ---------------------------------------------------------------------------
def build_full_state() -> Dict[str, Any]:
    inputs = read_inputs()
    safety = resolve_safety(inputs)
    groups = _high_blocked_groups(inputs)
    breach, reasons = compute_breach(safety, groups)
    git = _git_status()

    status = "PAYHIP_CUSTOMER_WORKFLOW_READY_LOCKED"
    if breach:
        status = "PAYHIP_CUSTOMER_WORKFLOW_BREACH"

    intake = {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.3",
        "generated_at": utc_now(),
        "status": status,
        "read_only": True,
        "service_focus": "Sentinel Security, SEO & Performance Safe Optimization",
        "packages": PACKAGES,
        "main_goals": MAIN_GOALS,
        "intake_fields": INTAKE_FIELDS,
        "consent_text": CONSENT_TEXT,
        "permission_levels": PERMISSION_LEVELS,
        "password_warning": PASSWORD_WARNING,
        "never_requested_normally": NEVER_REQUESTED_NORMALLY,
        "delivery_workflows": DELIVERY_WORKFLOWS,
        "package_deliverables": PACKAGE_DELIVERABLES,
        "message_templates": [{"id": m["id"], "title": m["title"]} for m in MESSAGE_TEMPLATES],
        "message_template_count": len(MESSAGE_TEMPLATES),
        "not_promised": NOT_PROMISED,
        "safety_agreement": SAFETY_AGREEMENT,
        "processing_checklist": PROCESSING_CHECKLIST,
        "report_template_sections": [s["title"] for s in REPORT_TEMPLATE_SECTIONS],
        "product_file_sections": [s["title"] for s in PRODUCT_FILE_SECTIONS],
        "separation_of_concerns": [
            "public marketing text", "customer input", "internal technical analysis",
            "owner review", "delivery",
        ],
        "buyer_receives_after_purchase": [
            "Thank-you + buyer instructions",
            "Intake form to complete",
            "Password-safety warning (read-only first audit)",
            "Clear next-steps and rough delivery time per package",
        ],
        # safety mirror / explicit non-actions
        "autonomy_level": safety["current_level"],
        "live_apply": safety["live_apply"],
        "emergency_stop": safety["emergency_stop"],
        "allowed_apply_now": safety["allowed_apply_now"],
        "high_blocked": True,
        "breach": breach,
        "breach_reasons": reasons,
        "stores_real_customer_data": False,
        "requests_passwords": False,
        "sends_email": False,
        "network_access": False,
        "payhip_api_access": False,
        "applies_changes": False,
        "secrets_in_report": False,
        "upstream": {
            "dashboard_available": safety["dashboard_available"],
            "dashboard_breach": safety["upstream_breach"],
        },
        "git_checkpoint": git,
        "missing_inputs": inputs["missing_inputs"],
        "input_status": inputs["input_status"],
    }
    return {"inputs": inputs, "safety": safety, "intake": intake}


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def _md_header(title: str, intake: Dict[str, Any]) -> List[str]:
    return [f"# {title}", "", f"- Generated: {intake['generated_at']}", ""]


def render_intake_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel Payhip Customer Intake & Delivery (Phase 9.3)", intake)
    lines += [
        f"- Status: **{intake['status']}**",
        f"- Service focus: {intake['service_focus']}",
        f"- live_apply: `{intake['live_apply']}` | emergency_stop: `{intake['emergency_stop']}` | "
        f"allowed_apply_now: `{intake['allowed_apply_now']}` | breach: `{intake['breach']}`",
        "",
        "## Packages",
    ]
    for p in intake["packages"]:
        lines.append(f"- **{p['name']}** ({p['risk']}) — {p['delivery_time']}")
    lines += ["", "## Separation of concerns"]
    for s in intake["separation_of_concerns"]:
        lines.append(f"- {s}")
    lines += ["", "## What the buyer receives after purchase"]
    for b in intake["buyer_receives_after_purchase"]:
        lines.append(f"- {b}")
    lines += ["", "## Customer data never requested through normal messages"]
    for n in intake["never_requested_normally"]:
        lines.append(f"- {n}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_buyer_instructions_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel — Payhip Buyer Instructions", intake)
    lines += [
        "## Thank you for your purchase",
        "Thank you for purchasing a Sentinel package. Here is how we start safely.",
        "",
        "## What happens next",
        "1. You complete the short intake form.",
        "2. You send your website URL, selected package and main goal.",
        "3. Sentinel runs a read-only analysis and classifies risk.",
        "4. You receive a clear report with safe recommendations.",
        "",
        "## Information to provide",
        "- Website URL",
        "- Selected package",
        "- Main goal: SEO / Speed / Security / Stability / All",
        "- Known problems",
        "- Cloudflare: yes / no / unknown",
        "- WordPress: yes / no / unknown",
        "- Preferred contact email",
        "- Optional notes",
        "",
        "## Important security warning",
        f"> {intake['password_warning']}",
        "",
        "## Rough delivery time per package",
    ]
    for p in intake["packages"]:
        lines.append(f"- **{p['name']}**: {p['delivery_time']}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_intake_form_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel — Customer Intake Form", intake)
    lines += [
        "Please fill in the fields below. **Do not enter any passwords or credentials.**",
        "",
    ]
    for f in INTAKE_FIELDS:
        req = "required" if f.get("required") else "optional"
        if f["type"] == "consent":
            lines.append(f"- [ ] **{f['label']}** ({req}): \"{f['consent_text']}\"")
        elif f.get("options"):
            opts = " / ".join(f["options"])
            lines.append(f"- **{f['label']}** ({req}): {opts}")
        else:
            ph = f" — e.g. {f['placeholder']}" if f.get("placeholder") else ""
            lines.append(f"- **{f['label']}** ({req}): ____{ph}")
    lines += ["", "## Security note", f"> {intake['password_warning']}", ""]
    return "\n".join(lines) + "\n"


def render_delivery_workflow_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel — Service Delivery Workflow", intake)
    for p in intake["packages"]:
        lines.append(f"## {p['name']} ({p['risk']})")
        for i, step in enumerate(DELIVERY_WORKFLOWS[p["id"]], 1):
            lines.append(f"{i}. {step}")
        lines.append("")
    lines += ["## Always", "- No live changes without explicit owner review and approval.",
              "- HIGH-risk actions stay blocked / review-only.", ""]
    return "\n".join(lines) + "\n"


def render_package_deliverables_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel — Package Deliverables", intake)
    for p in intake["packages"]:
        lines.append(f"## {p['name']}")
        for d in PACKAGE_DELIVERABLES[p["id"]]:
            lines.append(f"- {d}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_onboarding_message_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel — Client Onboarding Message", intake)
    for m in MESSAGE_TEMPLATES:
        lines.append(f"## {m['title']}")
        lines.append("```")
        lines.append(m["body"])
        lines.append("```")
        lines.append("")
    lines += ["## These messages must never claim"]
    for n in NOT_PROMISED:
        lines.append(f"- {n}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_delivery_message_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel — Client Delivery Message", intake)
    for mid in ("audit_delivery", "completion_next_steps", "monitoring_monthly_summary"):
        m = next(x for x in MESSAGE_TEMPLATES if x["id"] == mid)
        lines.append(f"## {m['title']}")
        lines.append("```")
        lines.append(m["body"])
        lines.append("```")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_safety_agreement_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel — Client Safety Agreement", intake)
    for a in SAFETY_AGREEMENT:
        lines.append(f"- {a}")
    lines += ["", "## This service does not promise"]
    for n in NOT_PROMISED:
        lines.append(f"- {n}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_processing_checklist_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel — Internal Processing Checklist (owner side)", intake)
    for i, step in enumerate(PROCESSING_CHECKLIST, 1):
        lines.append(f"{i}. [ ] {step}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_client_report_template_md(intake: Dict[str, Any]) -> str:
    lines = _md_header("Sentinel — Client Report Template", intake)
    lines.append("_Fill in each section for the client. Read-only findings; no changes applied._")
    lines.append("")
    for s in REPORT_TEMPLATE_SECTIONS:
        lines.append(f"## {s['title']}")
        lines.append(f"_{s['hint']}_")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_product_file_md(intake: Dict[str, Any]) -> str:
    lines = ["# Sentinel — Thank You & Getting Started", "",
             "_Upload-ready text for the Payhip product file (PDF/TXT)._", ""]
    for s in PRODUCT_FILE_SECTIONS:
        lines.append(f"## {s['title']}")
        lines.append(s["body"])
        lines.append("")
    return "\n".join(lines) + "\n"


def build_playbooks(intake: Dict[str, Any]) -> Dict[Path, Dict[str, Any]]:
    return {
        PLAYBOOK_INTAKE: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-customer-intake",
            "generated_at": intake["generated_at"],
            "status": intake["status"],
            "read_only": True,
            "applies_changes": False,
            "requests_passwords": False,
            "stores_real_customer_data": False,
            "steps": [
                "Buyer purchases on Payhip and receives buyer instructions.",
                "Buyer completes the intake form (URL, package, goal; no passwords).",
                "Owner verifies intake; requests missing info if needed.",
                "Owner records URL/goal in internal notes (not customer-facing files).",
            ],
        },
        PLAYBOOK_DELIVERY: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-service-delivery-workflow",
            "generated_at": intake["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "high_blocked": True,
            "workflows": DELIVERY_WORKFLOWS,
        },
        PLAYBOOK_REPORT: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-client-report-template",
            "generated_at": intake["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "sections": [s["title"] for s in REPORT_TEMPLATE_SECTIONS],
        },
    }


def write_all_outputs(state: Dict[str, Any]) -> List[str]:
    intake = state["intake"]
    written: List[str] = []

    def _wj(path: Path, data: Dict[str, Any]) -> None:
        write_json_atomic(path, data)
        written.append(str(path.relative_to(PROJECT_DIR)))

    def _wt(path: Path, text: str) -> None:
        write_text_atomic(path, text)
        written.append(str(path.relative_to(PROJECT_DIR)))

    _wj(INTAKE_JSON, intake)
    _wt(INTAKE_MD, render_intake_md(intake))
    _wt(BUYER_INSTRUCTIONS_MD, render_buyer_instructions_md(intake))
    _wt(INTAKE_FORM_MD, render_intake_form_md(intake))
    _wt(DELIVERY_WORKFLOW_MD, render_delivery_workflow_md(intake))
    _wt(PACKAGE_DELIVERABLES_MD, render_package_deliverables_md(intake))
    _wt(ONBOARDING_MESSAGE_MD, render_onboarding_message_md(intake))
    _wt(DELIVERY_MESSAGE_MD, render_delivery_message_md(intake))
    _wt(SAFETY_AGREEMENT_MD, render_safety_agreement_md(intake))
    _wt(PROCESSING_CHECKLIST_MD, render_processing_checklist_md(intake))
    _wt(CLIENT_REPORT_TEMPLATE_MD, render_client_report_template_md(intake))
    _wt(PRODUCT_FILE_MD, render_product_file_md(intake))

    _wj(STATE_INTAKE_JSON, intake)
    _wj(STATE_LATEST_INTAKE_JSON, intake)

    for path, data in build_playbooks(intake).items():
        _wj(path, data)

    append_jsonl(AUDIT_JSONL, [{
        "ts": intake["generated_at"],
        "phase": "9.3",
        "module": "sentinel_payhip_customer_intake_delivery",
        "status": intake["status"],
        "packages": [p["name"] for p in intake["packages"]],
        "message_template_count": intake["message_template_count"],
        "live_apply": intake["live_apply"],
        "emergency_stop": intake["emergency_stop"],
        "allowed_apply_now": intake["allowed_apply_now"],
        "high_blocked": intake["high_blocked"],
        "breach": intake["breach"],
        "requests_passwords": intake["requests_passwords"],
        "stores_real_customer_data": intake["stores_real_customer_data"],
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

    # No network imports (anchored to real import statements; prose-safe).
    net_import = re.compile(
        r"(?m)^\s*(?:import|from)\s+(requests|urllib|http\.client|smtplib|socket|paramiko|cloudflare)\b"
    )
    if net_import.search(src):
        raise AssertionError("module must not import network/email libraries")

    forbidden_capabilities = [
        ("sftp write", re.compile(r"paramiko|sftp\.put\(|\.put\(\s")),
        ("db write", re.compile(r"\$wpdb|wpdb->|cursor\.\w+\(|\.execute\(|pymysql|psycopg|MySQLdb|"
                                r"DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET")),
        ("cloudflare write", re.compile(r"api\.cloudflare\.com|requests\.(put|post|patch|delete)\(|"
                                        r"httpx\.(put|post|patch|delete)\(")),
        ("wordpress write", re.compile(r"wp_insert_post|wp_update_post|update_option\(|wp_mail\(|"
                                       r"add_post_meta\(")),
        ("service start/enable", re.compile(r"systemctl\s+(start|enable|restart|stop|disable)\b")),
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

    # No password field is ever requested; consent + warning present.
    field_keys = {f["key"] for f in INTAKE_FIELDS}
    if field_keys & {"password", "passwort", "api_key", "secret", "token", "credentials"}:
        raise AssertionError("intake form must not request passwords/credentials")
    if CONSENT_TEXT not in {f.get("consent_text") for f in INTAKE_FIELDS}:
        raise AssertionError("consent text missing")

    state = build_full_state()
    intake = state["intake"]
    if intake["live_apply"] is not False:
        raise AssertionError("live_apply must be false")
    if intake["emergency_stop"] is not True:
        raise AssertionError("emergency_stop must be true")
    if intake["allowed_apply_now"] is not False:
        raise AssertionError("allowed_apply_now must be false")
    if intake["high_blocked"] is not True:
        raise AssertionError("HIGH must stay blocked")
    if intake["autonomy_level"] not in ALLOWED_CURRENT_LEVELS:
        raise AssertionError("autonomy_level must be LEVEL_1/LEVEL_2")
    if intake["breach"]:
        raise AssertionError(f"clean intake must not breach: {intake['breach_reasons']}")
    for flag in ("requests_passwords", "stores_real_customer_data", "sends_email",
                 "network_access", "payhip_api_access", "applies_changes"):
        if intake[flag] is not False:
            raise AssertionError(f"{flag} must be false")
    if len(MESSAGE_TEMPLATES) != 10:
        raise AssertionError("expected 10 message templates")
    if len(REPORT_TEMPLATE_SECTIONS) != 11:
        raise AssertionError("expected 11 report template sections")

    # JSON validity of all structured outputs.
    for blob_obj in (intake, *build_playbooks(intake).values()):
        json.dumps(blob_obj)

    # Breach detection on tampered safety.
    base_safety = {"live_apply": False, "emergency_stop": True, "allowed_apply_now": False,
                   "current_level": LEVEL_2, "upstream_breach": False}
    empty_groups = {c: [] for c in CLASS_ORDER}
    if compute_breach(base_safety, empty_groups)[0]:
        raise AssertionError("clean safety must not breach")
    for tamper in ({"live_apply": True}, {"emergency_stop": False}, {"allowed_apply_now": True},
                   {"current_level": "LEVEL_4_MEDIUM_CANARY_ONLY"}, {"upstream_breach": True}):
        if not compute_breach(dict(base_safety, **tamper), empty_groups)[0]:
            raise AssertionError(f"tamper did not breach: {tamper}")
    unblocked_high = {**empty_groups, HIGH: [{"id": "x", "blocked": False}]}
    if not compute_breach(base_safety, unblocked_high)[0]:
        raise AssertionError("unblocked HIGH did not breach")

    # No secrets / no real e-mails / no claims in any rendered output.
    rendered = [
        render_intake_md(intake), render_buyer_instructions_md(intake),
        render_intake_form_md(intake), render_delivery_workflow_md(intake),
        render_package_deliverables_md(intake), render_onboarding_message_md(intake),
        render_delivery_message_md(intake), render_safety_agreement_md(intake),
        render_processing_checklist_md(intake), render_client_report_template_md(intake),
        render_product_file_md(intake), json.dumps(intake),
    ]
    # Positive forbidden claims only — disclaimers ("No guaranteed ...") are allowed.
    banned_claims = re.compile(r"(?i)(guaranteed\s+(100%|ranking|pagespeed)|automatic full repair|"
                               r"unlimited emergency support)")
    negation = re.compile(r"(?i)\b(no|not|never|without)\b")
    for blob in rendered:
        if SECRET_ASSIGNMENT_RE.search(blob) or LONG_HEX_RE.search(blob):
            raise AssertionError("secret-like content in output")
        for m in EMAIL_RE.findall(blob):
            if m.rsplit("@", 1)[-1].lower() not in ALLOWED_EMAIL_DOMAINS:
                raise AssertionError(f"real-looking e-mail in output: {m}")
        for line in blob.splitlines():
            if banned_claims.search(line) and not negation.search(line):
                raise AssertionError(f"forbidden marketing claim in output: {line.strip()[:80]}")
    if PASSWORD_WARNING not in render_buyer_instructions_md(intake):
        raise AssertionError("password warning missing from buyer instructions")

    # Write-path guards.
    for forbidden in (
        PROJECT_DIR / "reports/latest/x.sh",
        PROJECT_DIR / "reports/latest/x.php",
        PROJECT_DIR / "state/adaptive-learning/x.service",
        PROJECT_DIR / "snapshots/x.json",      # snapshots NOT allowed in 9.3
        PROJECT_DIR / "config/x.json",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")
    for ok_path in (INTAKE_JSON, STATE_INTAKE_JSON, AUDIT_JSONL, PLAYBOOK_INTAKE):
        assert_allowed_write(ok_path)

    # Secret-blob writer must reject a real-looking e-mail.
    try:
        _assert_no_secret_blob(INTAKE_MD, "contact real.person@gmail.com")
    except ValueError:
        pass
    else:
        raise AssertionError("writer did not reject real-looking e-mail")

    if not detect_secret_like("password=supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("No password required for first audit"):
        raise AssertionError("secret detector false positive on prose")

    print("payhip-customer-intake-delivery self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], written: List[str]) -> None:
    intake = state["intake"]
    print("=== Sentinel Payhip Customer Intake & Delivery (Phase 9.3) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"status: {intake['status']}")
    print(f"intake status: {len(INTAKE_FIELDS)} form fields ready")
    print(f"delivery workflow status: {len(DELIVERY_WORKFLOWS)} package workflows ready")
    print(f"message template status: {intake['message_template_count']} templates ready (no sending)")
    print("client pack status: buyer instructions + intake form + safety agreement + "
          "report template + product file ready")
    print(f"package names: {', '.join(p['name'] for p in PACKAGES)}")
    print(f"safety agreement status: {len(SAFETY_AGREEMENT)} clauses ready")
    print(f"report template status: {len(REPORT_TEMPLATE_SECTIONS)} sections ready")
    print(f"payhip product file text status: {len(PRODUCT_FILE_SECTIONS)} sections ready")
    print(f"live_apply: {intake['live_apply']}")
    print(f"emergency_stop: {intake['emergency_stop']}")
    print(f"allowed_apply_now: {intake['allowed_apply_now']}")
    print(f"breach: {intake['breach']}")
    print("what the buyer receives after purchase:")
    for b in intake["buyer_receives_after_purchase"]:
        print(f"  - {b}")
    print("customer data never requested normally:")
    for n in intake["never_requested_normally"]:
        print(f"  - {n}")
    print(f"recommended Git checkpoint: {intake['git_checkpoint']['recommended']} "
          f"({intake['git_checkpoint']['untracked_count']} untracked, "
          f"{intake['git_checkpoint']['modified_count']} modified)")
    if intake["git_checkpoint"]["files_sample"]:
        print("recommended Git checkpoint files (sample):")
        for f in intake["git_checkpoint"]["files_sample"]:
            print(f"  - {f}")
    if intake["missing_inputs"]:
        print(f"missing inputs: {', '.join(intake['missing_inputs'])}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Payhip Customer Intake & Delivery (Phase 9.3). Read-only; no apply."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--build-intake", action="store_true", help="Build buyer instructions + intake form.")
    p.add_argument("--build-delivery-workflow", action="store_true", help="Build per-package delivery workflow.")
    p.add_argument("--build-message-templates", action="store_true", help="Build client message templates (no sending).")
    p.add_argument("--build-client-pack", action="store_true", help="Build safety agreement + report template + product file.")
    p.add_argument("--status", action="store_true", help="Print status summary.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    state = build_full_state()
    written = write_all_outputs(state)
    intake = state["intake"]

    if args.build_intake:
        print(f"[intake] {len(INTAKE_FIELDS)} fields | buyer instructions + form ready | "
              f"no passwords requested ({not intake['requests_passwords']})")
    if args.build_delivery_workflow:
        print(f"[delivery] {len(DELIVERY_WORKFLOWS)} workflows: "
              f"{', '.join(p['name'] for p in PACKAGES)}")
    if args.build_message_templates:
        print(f"[messages] {intake['message_template_count']} templates (no sending): "
              f"{', '.join(m['id'] for m in MESSAGE_TEMPLATES)}")
    if args.build_client_pack:
        print(f"[client-pack] safety agreement ({len(SAFETY_AGREEMENT)}), "
              f"report template ({len(REPORT_TEMPLATE_SECTIONS)}), "
              f"product file ({len(PRODUCT_FILE_SECTIONS)})")

    if args.status or not any(
        (args.build_intake, args.build_delivery_workflow, args.build_message_templates,
         args.build_client_pack)
    ):
        _print_status(state, written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
