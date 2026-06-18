#!/usr/bin/env python3
"""Sentinel Payhip Product File PDF + Public Client Assets (Phase 9.4).

Turns the Phase 9.3 internal intake/delivery layer into clean, public,
upload-ready Payhip buyer files and client assets for the service
"Sentinel Security, SEO & Performance Safe Optimization".

It generates only safe, public marketing/onboarding text built from constants.
It never copies internal reports verbatim, never emits server paths, IPs,
Cloudflare rule details, secrets, real customer data or passwords.

There is deliberately no apply mode, no SFTP/DB/Cloudflare/Nginx/WordPress
write, no email send, no network access, no Payhip API access and no package
installation (no apt/pip/npm). A real PDF is produced with a tiny pure-Python
writer (no external library); if that ever fails it degrades to PDF source
(Markdown + HTML) and reports PDF_SOURCE_READY_NO_BINARY_PDF.

Invariants surfaced and enforced:
    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    HIGH stays blocked
    no secrets, no internal server paths or IPs in public assets.
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
PRODUCT_FILE_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-product-file-final.md"
PRODUCT_FILE_TXT = PROJECT_DIR / "reports/latest/sentinel-payhip-product-file-final.txt"
PRODUCT_FILE_HTML = PROJECT_DIR / "reports/latest/sentinel-payhip-product-file-final.html"
PUBLIC_INTAKE_FORM_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-public-intake-form.md"
PUBLIC_SAFETY_AGREEMENT_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-public-safety-agreement.md"
PUBLIC_SERVICE_OVERVIEW_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-public-service-overview.md"
SHORT_DESCRIPTION_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-short-description.md"
LONG_DESCRIPTION_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-long-description.md"
FAQ_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-faq.md"
PACKAGE_DELIVERABLES_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-package-deliverables.md"
AFTER_PURCHASE_MESSAGE_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-after-purchase-message.md"
PDF_SOURCE_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-pdf-source.md"
PDF_SOURCE_HTML = PROJECT_DIR / "reports/latest/sentinel-payhip-pdf-source.html"
PDF_BINARY = PROJECT_DIR / "reports/latest/sentinel-payhip-service-access-instructions.pdf"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_ASSETS_JSON = STATE_DIR / "sentinel_payhip_public_client_assets.json"
STATE_LATEST_ASSETS_JSON = STATE_DIR / "latest_payhip_public_client_assets.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-payhip-public-client-assets.jsonl"

PLAYBOOK_ASSETS = PROJECT_DIR / "playbooks/sentinel-payhip-public-client-assets.playbook.json"
PLAYBOOK_PRODUCT = PROJECT_DIR / "playbooks/sentinel-payhip-product-file.playbook.json"
PLAYBOOK_FAQ = PROJECT_DIR / "playbooks/sentinel-payhip-public-faq.playbook.json"

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

SCHEMA_VERSION = "payhip-public-client-assets-9.4"

LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
LEVEL_2 = "LEVEL_2_LOW_RISK_PREP_PREVIEW"
ALLOWED_CURRENT_LEVELS = {LEVEL_1, LEVEL_2}
DEFAULT_CURRENT_LEVEL = LEVEL_2

# ---------------------------------------------------------------------------
# Inputs (read-only; optional; for availability/provenance only — never copied)
# ---------------------------------------------------------------------------
INPUT_JSON: List[Tuple[str, Path]] = [
    ("intake_delivery", STATE_DIR / "latest_payhip_customer_intake_delivery.json"),
]
INPUT_MD: List[Tuple[str, Path]] = [
    ("buyer_instructions_md", PROJECT_DIR / "reports/latest/sentinel-payhip-buyer-instructions.md"),
    ("intake_form_md", PROJECT_DIR / "reports/latest/sentinel-customer-intake-form.md"),
    ("safety_agreement_md", PROJECT_DIR / "reports/latest/sentinel-client-safety-agreement.md"),
    ("delivery_workflow_md", PROJECT_DIR / "reports/latest/sentinel-service-delivery-workflow.md"),
    ("package_deliverables_md", PROJECT_DIR / "reports/latest/sentinel-package-deliverables.md"),
    ("client_report_template_md", PROJECT_DIR / "reports/latest/sentinel-client-report-template.md"),
    ("product_file_text_md", PROJECT_DIR / "reports/latest/sentinel-payhip-product-file-text.md"),
    ("service_proof_marketing_md", PROJECT_DIR / "reports/latest/sentinel-service-proof-marketing.md"),
    ("service_proof_md", PROJECT_DIR / "reports/latest/sentinel-service-proof.md"),
    ("payhip_proof_snippet_md", PROJECT_DIR / "reports/latest/sentinel-payhip-proof-snippet.md"),
]

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
    r"requested\b|warning\b|field\b|of any kind\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{40,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}
INTERNAL_PATH_RE = re.compile(r"/(srv|etc|home|root|var|usr|opt|boot|proc)/")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Positive promises that must never appear in public assets (hard-forbidden).
DISALLOWED_CLAIMS_RE = re.compile(
    r"(?i)(guarantee(?:d|s)?\s+100%|guarantee(?:d|s)?\s+rank|automatic full repair|"
    r"unlimited emergency support|instant fix|fully autonomous live repair|"
    r"no review required|change cloudflare automatically|"
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
        raise ValueError(f"Refusing to write outside allowed public-asset roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install/secret artifact: {path}")
    if any(token in str(path) for token in FORBIDDEN_INSTALL_PATH_TOKENS):
        raise ValueError(f"Refusing to write systemd/crontab path: {path}")


def _assert_no_secret_blob(path: Path, blob: str) -> None:
    if SECRET_ASSIGNMENT_RE.search(blob) or LONG_HEX_RE.search(blob):
        raise ValueError(f"Refusing to write secret-like content to {path}")
    for m in EMAIL_RE.findall(blob):
        if m.rsplit("@", 1)[-1].lower() not in ALLOWED_EMAIL_DOMAINS:
            raise ValueError(f"Refusing to write real-looking e-mail address to {path}: {m}")


def _assert_public_safe(path: Path, blob: str) -> None:
    """Extra guard for public-facing files: no server paths, IPs, claims."""
    if INTERNAL_PATH_RE.search(blob):
        raise ValueError(f"Refusing to write internal server path to public asset {path}")
    if IPV4_RE.search(blob):
        raise ValueError(f"Refusing to write IP address to public asset {path}")
    if DISALLOWED_CLAIMS_RE.search(blob):
        raise ValueError(f"Refusing to write a forbidden marketing claim to public asset {path}")


def write_text_atomic(path: Path, content: str, public: bool = False) -> None:
    assert_allowed_write(path)
    _assert_no_secret_blob(path, content)
    if public:
        _assert_public_safe(path, content)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_bytes_atomic(path: Path, data: bytes, source_text: str) -> None:
    assert_allowed_write(path)
    _assert_no_secret_blob(path, source_text)
    _assert_public_safe(path, source_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
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
# Public content constants
# ---------------------------------------------------------------------------
SERVICE_NAME = "Sentinel Security, SEO & Performance Safe Optimization"
PRODUCT_TITLE = f"{SERVICE_NAME} - Service Access Instructions"
CONTACT_PLACEHOLDER = "[provider contact email to be filled in by the owner]"

PACKAGES: List[Dict[str, str]] = [
    {"name": "Sentinel Audit Report", "risk": "read-only",
     "delivery_time": "about 2-4 business days after a complete intake"},
    {"name": "Sentinel Safe Optimization", "risk": "review-first, owner-approved",
     "delivery_time": "about 1-2 weeks, depending on owner review turnaround"},
    {"name": "Sentinel Monitoring & Improvement", "risk": "recurring, owner-approved",
     "delivery_time": "recurring service with a monthly owner review"},
]

WHAT_TO_SEND = [
    "Website URL",
    "Selected package",
    "Main goal: SEO / Speed / Security / Stability / All",
    "Known problems",
    "WordPress usage if known",
    "Cloudflare usage if known",
    "Hosting provider if known",
    "Preferred report language",
    "Contact email",
]
WHAT_NOT_TO_SEND = [
    "Passwords",
    "API keys",
    "Secret tokens",
    "SSH keys",
    "FTP/SFTP credentials",
    "Database credentials",
    "Hosting account passwords",
    "Cloudflare account passwords",
    "2FA backup codes",
]

PASSWORD_WARNING = (
    "Please never send passwords, API keys, private keys or other login credentials "
    "through Payhip messages or email. The first audit is read-only and does not need "
    "any login. If secure access is ever required for a later, controlled step, it is "
    "arranged only through a separately agreed secure channel."
)

SAFE_AUTONOMY_EXPLANATION = (
    "Safe Autonomy means Sentinel works in clear, controlled stages: it observes and "
    "diagnoses read-only first, classifies risk, and proposes changes for your review. "
    "Nothing high-risk is applied on its own. You stay the owner of every final "
    "approval, and any controlled change uses backup, healthcheck and rollback."
)

SAFETY_AGREEMENT = [
    "The service starts read-only.",
    "No password is required for the first audit.",
    "No blind autopilot is used.",
    "No high-risk changes are made without explicit review.",
    "We do not promise a specific search ranking or a fixed PageSpeed score.",
    "Backups, healthchecks and rollback are required for any controlled change.",
    "The client remains the owner of all final approvals.",
    "Sensitive access is used only through a secure, separately agreed channel if ever needed.",
    "The provider may refuse unsafe changes.",
]

DELIVERABLES: Dict[str, List[str]] = {
    "Sentinel Audit Report": [
        "Public read-only audit",
        "SEO / performance / security findings",
        "Risk classification",
        "Prioritized recommendations",
        "Client report",
    ],
    "Sentinel Safe Optimization": [
        "Audit",
        "Owner review checklist",
        "Draft recommendations",
        "Safe candidates",
        "Backup / healthcheck / rollback plan for controlled steps",
        "Final summary",
    ],
    "Sentinel Monitoring & Improvement": [
        "Recurring review structure",
        "Trend interpretation",
        "5xx / origin / Cloudflare observation",
        "Safe improvement backlog",
        "Monthly owner summary",
    ],
}

NOT_PROMISED = [
    "We do not promise a 100 percent PageSpeed score.",
    "We do not promise a specific Google ranking position.",
    "We do not perform a blind, fully automated repair.",
    "We do not offer always-on emergency support without limits.",
    "We do not change Cloudflare or WordPress on our own.",
    "We do not edit databases, themes or plugins without review.",
]

DISCLAIMER = (
    "This service provides safety-first diagnosis, review and recommendations. Results "
    "depend on your website, hosting and content. We do not promise a specific search "
    "ranking or a fixed performance score, and high-risk changes always stay "
    "review-only until you explicitly approve a safe, controlled step."
)

# FAQ: list of (question, answer) — answers phrased to avoid forbidden claims.
FAQ: List[Tuple[str, str]] = [
    ("Is this an automatic repair bot?",
     "No. Sentinel is not a blind autopilot. It starts with read-only diagnosis, "
     "classifies risk and proposes reviewed recommendations."),
    ("Do you guarantee a 100 percent PageSpeed score?",
     "No. We do not promise a specific performance score. We identify safe, "
     "prioritized improvements you can approve."),
    ("Do you guarantee search rankings?",
     "No. Rankings depend on many factors outside one service. We focus on safe SEO, "
     "performance and stability improvements."),
    ("Do you need my WordPress password?",
     "No. The first audit is read-only and needs no login. Please do not send passwords."),
    ("Do you change Cloudflare settings?",
     "No. We never change Cloudflare settings on our own. Any change is review-first and "
     "owner-approved."),
    ("Can this be used for live business websites?",
     "Yes. The read-only start is designed to be safe for live sites, and controlled "
     "changes use backup, healthcheck and rollback."),
    ("What happens after purchase?",
     "You receive buyer instructions, complete a short intake form, and send your "
     "website URL and main goal. Then the read-only analysis is planned."),
    ("What should I send?",
     "Your website URL, selected package, main goal, known problems, and optional "
     "WordPress/Cloudflare/hosting details. A contact email helps too."),
    ("What should I never send?",
     "Never send passwords, API keys, tokens, SSH keys, FTP/SFTP or database "
     "credentials, or account passwords."),
    ("What is Safe Autonomy?",
     SAFE_AUTONOMY_EXPLANATION),
    ("What if high-risk changes are needed?",
     "High-risk changes are never auto-applied. They stay review-only, and we explain "
     "the risk and a safe, reviewed alternative."),
    ("Can this become ongoing monitoring?",
     "Yes. The Monitoring & Improvement package adds recurring trend review, a safe "
     "improvement backlog and a monthly owner summary."),
]

SHORT_DESCRIPTION = (
    "Sentinel is a safety-first Security, SEO and Performance service for WordPress and "
    "other websites. We start with read-only diagnosis, classify risk, and deliver clear "
    "review and recommendations with an owner approval step. Controlled improvements are "
    "review-first and owner-approved - no blind autopilot, no promised rankings. Choose "
    "Audit, Safe Optimization, or Monitoring & Improvement."
)

# Long description as ordered (heading, paragraph) blocks.
LONG_DESCRIPTION_BLOCKS: List[Tuple[str, str]] = [
    ("Problem",
     "Most websites carry hidden SEO, performance and security issues. Many tools react "
     "blindly and risk breaking a live site."),
    ("Solution",
     "Sentinel is a safety-first service. It starts read-only, diagnoses the real signals, "
     "classifies risk, and proposes clear, reviewed improvements."),
    ("Safe Autonomy", SAFE_AUTONOMY_EXPLANATION),
    ("Packages",
     "Sentinel Audit Report (read-only audit), Sentinel Safe Optimization (reviewed, "
     "controlled improvement), and Sentinel Monitoring & Improvement (recurring review)."),
    ("How it works",
     "Purchase, complete the short intake form, send your URL and main goal, receive a "
     "read-only analysis and a clear report with safe next steps."),
    ("What is included",
     "SEO, performance and security findings, a risk classification, prioritized "
     "recommendations, an owner review step, and optional ongoing monitoring."),
    ("What is not promised",
     "We do not promise a fixed performance score or a specific ranking, and we never "
     "apply high-risk changes blindly."),
    ("Disclaimer", DISCLAIMER),
]

# Public intake questions (no sensitive fields, no password field).
PUBLIC_INTAKE_QUESTIONS: List[Dict[str, Any]] = [
    {"label": "Customer name or business name", "required": True},
    {"label": "Contact email", "required": True, "example": "you@example.com"},
    {"label": "Website URL", "required": True, "example": "https://your-website.example.com"},
    {"label": "Selected package", "required": True,
     "options": [p["name"] for p in PACKAGES]},
    {"label": "Main goal", "required": True,
     "options": ["SEO", "Speed", "Security", "Stability", "All"]},
    {"label": "WordPress usage", "required": False, "options": ["yes", "no", "unknown"]},
    {"label": "Cloudflare usage", "required": False, "options": ["yes", "no", "unknown"]},
    {"label": "Hosting provider if known", "required": False},
    {"label": "Known problems", "required": False},
    {"label": "Preferred report language", "required": False, "options": ["English", "German"]},
]
CONSENT_TEXT = (
    "I understand that this service starts with read-only analysis and does not require "
    "passwords for the first audit."
)

# 10 product-file sections (title, body paragraphs as list).
def product_sections() -> List[Tuple[str, List[str]]]:
    pkg_lines = [f"- {p['name']} ({p['risk']}) - {p['delivery_time']}" for p in PACKAGES]
    return [
        ("1. Thank You",
         ["Thank you for choosing " + SERVICE_NAME + "."]),
        ("2. What You Purchased",
         ["A safety-first service for Security, SEO and Performance that starts with a "
          "read-only analysis and delivers clear, reviewed recommendations."]),
        ("3. Available Packages", pkg_lines),
        ("4. What Happens Next",
         ["1. Complete the short intake form.",
          "2. Send your website URL, selected package and main goal.",
          "3. Sentinel runs a read-only analysis and classifies risk.",
          "4. You receive a clear report with safe recommendations."]),
        ("5. What To Send", [f"- {x}" for x in WHAT_TO_SEND]),
        ("6. What Not To Send", [f"- {x}" for x in WHAT_NOT_TO_SEND]),
        ("7. Safety-First Workflow",
         [SAFE_AUTONOMY_EXPLANATION]),
        ("8. Delivery Overview",
         [f"- {p['name']}: {p['delivery_time']}" for p in PACKAGES]),
        ("9. Important Disclaimer", [DISCLAIMER]),
        ("10. Contact", [f"Contact: {CONTACT_PLACEHOLDER}."]),
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
    src = inputs["data"].get("intake_delivery")

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
        reasons.append("upstream intake/delivery reports breach")
    return (len(reasons) > 0), reasons


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def product_plain_lines() -> List[str]:
    lines = [PRODUCT_TITLE, ""]
    for title, body in product_sections():
        lines.append(title)
        for b in body:
            lines.append(b)
        lines.append("")
    lines.append("Security note:")
    lines.append(PASSWORD_WARNING)
    lines.append("")
    return lines


def render_product_md() -> str:
    lines = [f"# {PRODUCT_TITLE}", ""]
    for title, body in product_sections():
        lines.append(f"## {title}")
        lines.extend(body)
        lines.append("")
    lines += ["## Security note", f"> {PASSWORD_WARNING}", ""]
    return "\n".join(lines) + "\n"


def render_product_txt() -> str:
    return "\n".join(product_plain_lines()) + "\n"


def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_product_html() -> str:
    parts = [
        "<!doctype html>",
        "<html lang=\"en\"><head><meta charset=\"utf-8\">",
        f"<title>{_html_escape(PRODUCT_TITLE)}</title>",
        "<style>body{font-family:Arial,Helvetica,sans-serif;max-width:760px;margin:2rem auto;"
        "padding:0 1rem;line-height:1.5;color:#1a1a1a}h1{font-size:1.5rem}h2{font-size:1.15rem;"
        "margin-top:1.6rem}blockquote{border-left:4px solid #ccc;padding-left:1rem;color:#444}"
        "</style></head><body>",
        f"<h1>{_html_escape(PRODUCT_TITLE)}</h1>",
    ]
    for title, body in product_sections():
        parts.append(f"<h2>{_html_escape(title)}</h2>")
        for b in body:
            parts.append(f"<p>{_html_escape(b)}</p>")
    parts.append("<h2>Security note</h2>")
    parts.append(f"<blockquote>{_html_escape(PASSWORD_WARNING)}</blockquote>")
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def render_public_intake_form_md() -> str:
    lines = ["# Sentinel - Public Intake Form", "",
             "Please fill in the fields below. **Do not enter any passwords or credentials.**", ""]
    for q in PUBLIC_INTAKE_QUESTIONS:
        req = "required" if q.get("required") else "optional"
        if q.get("options"):
            lines.append(f"- **{q['label']}** ({req}): {' / '.join(q['options'])}")
        else:
            ex = f" - e.g. {q['example']}" if q.get("example") else ""
            lines.append(f"- **{q['label']}** ({req}): ____{ex}")
    lines += ["", f"- [ ] Consent: \"{CONSENT_TEXT}\"", "",
              "## Security note", f"> {PASSWORD_WARNING}", ""]
    return "\n".join(lines) + "\n"


def render_public_safety_agreement_md() -> str:
    lines = ["# Sentinel - Client Safety Agreement", ""]
    for a in SAFETY_AGREEMENT:
        lines.append(f"- {a}")
    lines += ["", "## This service does not promise"]
    for n in NOT_PROMISED:
        lines.append(f"- {n}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_public_service_overview_md() -> str:
    lines = [f"# {SERVICE_NAME}", "", "## Packages"]
    for p in PACKAGES:
        lines.append(f"- **{p['name']}** ({p['risk']}) - {p['delivery_time']}")
        for d in DELIVERABLES[p["name"]]:
            lines.append(f"  - {d}")
    lines += ["", "## Safe Autonomy", SAFE_AUTONOMY_EXPLANATION,
              "", "## Disclaimer", DISCLAIMER, ""]
    return "\n".join(lines) + "\n"


def render_short_description_md() -> str:
    return "# Sentinel - Short Payhip Description\n\n" + SHORT_DESCRIPTION + "\n"


def render_long_description_md() -> str:
    lines = ["# Sentinel - Long Payhip Description", ""]
    for title, para in LONG_DESCRIPTION_BLOCKS:
        lines.append(f"## {title}")
        lines.append(para)
        lines.append("")
    return "\n".join(lines) + "\n"


def render_faq_md() -> str:
    lines = ["# Sentinel - Frequently Asked Questions", ""]
    for i, (q, a) in enumerate(FAQ, 1):
        lines.append(f"**{i}. {q}**")
        lines.append("")
        lines.append(a)
        lines.append("")
    return "\n".join(lines) + "\n"


def render_package_deliverables_md() -> str:
    lines = ["# Sentinel - Package Deliverables", ""]
    for p in PACKAGES:
        lines.append(f"## {p['name']}")
        for d in DELIVERABLES[p["name"]]:
            lines.append(f"- {d}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_after_purchase_message_md() -> str:
    lines = ["# Sentinel - After Purchase Message", "", "```",
             "Hi [first name],", "",
             "Thank you for your purchase of " + SERVICE_NAME + ".",
             "To get started, please complete the short intake form and send your website "
             "URL, selected package and main goal.",
             "",
             "Reminder: the first audit is read-only, so please do not send any passwords.",
             "",
             f"Questions? Contact: {CONTACT_PLACEHOLDER}.",
             "```", ""]
    return "\n".join(lines) + "\n"


def render_pdf_source_md() -> str:
    return ("# PDF source (Markdown) - " + PRODUCT_TITLE + "\n\n"
            "_Print or convert this file to PDF if a binary PDF is not attached._\n\n"
            + render_product_md())


def render_pdf_source_html() -> str:
    return render_product_html()


# ---------------------------------------------------------------------------
# Minimal pure-Python PDF writer (no external library)
# ---------------------------------------------------------------------------
def render_pdf_bytes(lines: List[str]) -> bytes:
    page_w, page_h = 595, 842  # A4 points
    margin_x, top_y, leading, font_size = 50, 800, 14, 10
    max_lines = int((top_y - 60) / leading)

    wrapped: List[str] = []
    for raw in lines:
        ln = raw.rstrip("\n").encode("ascii", "replace").decode("ascii")
        if ln == "":
            wrapped.append("")
            continue
        while len(ln) > 95:
            wrapped.append(ln[:95])
            ln = ln[95:]
        wrapped.append(ln)
    pages = [wrapped[i:i + max_lines] for i in range(0, len(wrapped), max_lines)] or [[""]]
    n_pages = len(pages)

    catalog_obj, pages_obj, font_obj = 1, 2, 3
    first_content = 4
    first_page = first_content + n_pages
    max_obj = first_page + n_pages - 1

    objs: Dict[int, bytes] = {}
    page_ids = list(range(first_page, first_page + n_pages))
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objs[catalog_obj] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objs[pages_obj] = f"<< /Type /Pages /Count {n_pages} /Kids [{kids}] >>".encode("latin-1")
    objs[font_obj] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    for idx, page_lines in enumerate(pages):
        content_id = first_content + idx
        page_id = first_page + idx
        parts = ["BT", f"/F1 {font_size} Tf", f"{leading} TL", f"{margin_x} {top_y} Td"]
        for j, ln in enumerate(page_lines):
            if j > 0:
                parts.append("T*")
            parts.append(f"({esc(ln)}) Tj")
        parts.append("ET")
        stream = "\n".join(parts).encode("latin-1")
        objs[content_id] = b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream)
        objs[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_w} {page_h}] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("latin-1")

    out = bytearray(b"%PDF-1.4\n")
    offsets: Dict[int, int] = {}
    for num in range(1, max_obj + 1):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode("latin-1")
        out += objs[num]
        out += b"\nendobj\n"
    xref_pos = len(out)
    count = max_obj + 1
    out += f"xref\n0 {count}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for num in range(1, max_obj + 1):
        out += f"{offsets[num]:010d} 00000 n \n".encode("latin-1")
    out += (f"trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n").encode("latin-1")
    return bytes(out)


# ---------------------------------------------------------------------------
# Full build
# ---------------------------------------------------------------------------
def build_full_state() -> Dict[str, Any]:
    inputs = read_inputs()
    safety = resolve_safety(inputs)
    breach, reasons = compute_breach(safety)
    git = _git_status()

    plain = product_plain_lines()
    pdf_generated = False
    pdf_status = "PDF_SOURCE_READY_NO_BINARY_PDF"
    pdf_bytes: Optional[bytes] = None
    try:
        candidate = render_pdf_bytes(plain)
        if candidate[:5] == b"%PDF-" and candidate.rstrip().endswith(b"%%EOF"):
            pdf_bytes = candidate
            pdf_generated = True
            pdf_status = "PDF_GENERATED_PURE_PYTHON"
    except Exception:  # pragma: no cover - degrade safely to source-only
        pdf_bytes = None
        pdf_generated = False
        pdf_status = "PDF_SOURCE_READY_NO_BINARY_PDF"

    upload_to_payhip = [
        "reports/latest/sentinel-payhip-product-file-final.md",
        "reports/latest/sentinel-payhip-product-file-final.txt",
        "reports/latest/sentinel-payhip-product-file-final.html",
        "reports/latest/sentinel-payhip-public-intake-form.md",
        "reports/latest/sentinel-payhip-public-safety-agreement.md",
        "reports/latest/sentinel-payhip-faq.md",
        "reports/latest/sentinel-payhip-package-deliverables.md",
        "reports/latest/sentinel-payhip-after-purchase-message.md",
    ]
    if pdf_generated:
        upload_to_payhip.append("reports/latest/sentinel-payhip-service-access-instructions.pdf")
    else:
        upload_to_payhip += [
            "reports/latest/sentinel-payhip-pdf-source.md",
            "reports/latest/sentinel-payhip-pdf-source.html",
        ]
    copy_into_description = [
        "reports/latest/sentinel-payhip-short-description.md (Payhip short description)",
        "reports/latest/sentinel-payhip-long-description.md (Payhip long description)",
    ]

    status = "PUBLIC_CLIENT_ASSETS_READY_LOCKED"
    if breach:
        status = "PUBLIC_CLIENT_ASSETS_BREACH"

    assets = {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.4",
        "generated_at": utc_now(),
        "status": status,
        "read_only": True,
        "service_name": SERVICE_NAME,
        "product_title": PRODUCT_TITLE,
        "packages": [p["name"] for p in PACKAGES],
        "what_to_send": WHAT_TO_SEND,
        "what_not_to_send": WHAT_NOT_TO_SEND,
        "short_description": SHORT_DESCRIPTION,
        "short_description_length": len(SHORT_DESCRIPTION),
        "long_description_sections": [t for t, _ in LONG_DESCRIPTION_BLOCKS],
        "faq_count": len(FAQ),
        "product_file_sections": [t for t, _ in product_sections()],
        "deliverables": DELIVERABLES,
        "safety_agreement": SAFETY_AGREEMENT,
        "not_promised": NOT_PROMISED,
        "contact_placeholder": CONTACT_PLACEHOLDER,
        "pdf_generated": pdf_generated,
        "pdf_status": pdf_status,
        "upload_to_payhip": upload_to_payhip,
        "copy_into_description": copy_into_description,
        # safety mirror / explicit non-actions
        "autonomy_level": safety["current_level"],
        "live_apply": safety["live_apply"],
        "emergency_stop": safety["emergency_stop"],
        "allowed_apply_now": safety["allowed_apply_now"],
        "high_blocked": safety["high_blocked"],
        "breach": breach,
        "breach_reasons": reasons,
        "stores_real_customer_data": False,
        "requests_passwords": False,
        "sends_email": False,
        "network_access": False,
        "payhip_api_access": False,
        "installs_packages": False,
        "applies_changes": False,
        "secrets_in_report": False,
        "git_checkpoint": git,
        "missing_inputs": inputs["missing_inputs"],
        "input_status": inputs["input_status"],
    }
    return {"inputs": inputs, "safety": safety, "assets": assets, "pdf_bytes": pdf_bytes,
            "plain_text": "\n".join(plain)}


def build_playbooks(assets: Dict[str, Any]) -> Dict[Path, Dict[str, Any]]:
    return {
        PLAYBOOK_ASSETS: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-public-client-assets",
            "generated_at": assets["generated_at"],
            "status": assets["status"],
            "read_only": True,
            "applies_changes": False,
            "installs_packages": False,
            "steps": [
                "Build public product file (md/txt/html) from safe constants.",
                "Build public intake form, safety agreement and service overview.",
                "Build short/long descriptions and FAQ.",
                "Generate a pure-Python PDF or PDF source (md/html) if not possible.",
                "Upload public files to Payhip; copy descriptions into the listing.",
            ],
        },
        PLAYBOOK_PRODUCT: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-product-file",
            "generated_at": assets["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "title": PRODUCT_TITLE,
            "sections": assets["product_file_sections"],
            "pdf_status": assets["pdf_status"],
        },
        PLAYBOOK_FAQ: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-public-faq",
            "generated_at": assets["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "faq_count": assets["faq_count"],
            "questions": [q for q, _ in FAQ],
        },
    }


def write_all_outputs(state: Dict[str, Any]) -> List[str]:
    assets = state["assets"]
    written: List[str] = []

    def _wj(path: Path, data: Dict[str, Any]) -> None:
        write_json_atomic(path, data)
        written.append(str(path.relative_to(PROJECT_DIR)))

    def _wp(path: Path, text: str) -> None:  # public file
        write_text_atomic(path, text, public=True)
        written.append(str(path.relative_to(PROJECT_DIR)))

    _wp(PRODUCT_FILE_MD, render_product_md())
    _wp(PRODUCT_FILE_TXT, render_product_txt())
    _wp(PRODUCT_FILE_HTML, render_product_html())
    _wp(PUBLIC_INTAKE_FORM_MD, render_public_intake_form_md())
    _wp(PUBLIC_SAFETY_AGREEMENT_MD, render_public_safety_agreement_md())
    _wp(PUBLIC_SERVICE_OVERVIEW_MD, render_public_service_overview_md())
    _wp(SHORT_DESCRIPTION_MD, render_short_description_md())
    _wp(LONG_DESCRIPTION_MD, render_long_description_md())
    _wp(FAQ_MD, render_faq_md())
    _wp(PACKAGE_DELIVERABLES_MD, render_package_deliverables_md())
    _wp(AFTER_PURCHASE_MESSAGE_MD, render_after_purchase_message_md())
    _wp(PDF_SOURCE_MD, render_pdf_source_md())
    _wp(PDF_SOURCE_HTML, render_pdf_source_html())

    if state.get("pdf_bytes"):
        write_bytes_atomic(PDF_BINARY, state["pdf_bytes"], state["plain_text"])
        written.append(str(PDF_BINARY.relative_to(PROJECT_DIR)))

    _wj(STATE_ASSETS_JSON, assets)
    _wj(STATE_LATEST_ASSETS_JSON, assets)

    for path, data in build_playbooks(assets).items():
        _wj(path, data)

    append_jsonl(AUDIT_JSONL, [{
        "ts": assets["generated_at"],
        "phase": "9.4",
        "module": "sentinel_payhip_public_client_assets",
        "status": assets["status"],
        "packages": assets["packages"],
        "faq_count": assets["faq_count"],
        "short_description_length": assets["short_description_length"],
        "pdf_generated": assets["pdf_generated"],
        "pdf_status": assets["pdf_status"],
        "live_apply": assets["live_apply"],
        "emergency_stop": assets["emergency_stop"],
        "allowed_apply_now": assets["allowed_apply_now"],
        "high_blocked": assets["high_blocked"],
        "breach": assets["breach"],
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

    # No password / credential field requested in the public form.
    for q in PUBLIC_INTAKE_QUESTIONS:
        if re.search(r"(?i)password|api key|secret|token|credential", q["label"]):
            raise AssertionError("public intake form must not request credentials")

    state = build_full_state()
    assets = state["assets"]
    if assets["live_apply"] is not False:
        raise AssertionError("live_apply must be false")
    if assets["emergency_stop"] is not True:
        raise AssertionError("emergency_stop must be true")
    if assets["allowed_apply_now"] is not False:
        raise AssertionError("allowed_apply_now must be false")
    if assets["high_blocked"] is not True:
        raise AssertionError("HIGH must stay blocked")
    if assets["autonomy_level"] not in ALLOWED_CURRENT_LEVELS:
        raise AssertionError("autonomy_level must be LEVEL_1/LEVEL_2")
    if assets["breach"]:
        raise AssertionError(f"clean assets must not breach: {assets['breach_reasons']}")
    for flag in ("requests_passwords", "stores_real_customer_data", "sends_email",
                 "network_access", "payhip_api_access", "installs_packages", "applies_changes"):
        if assets[flag] is not False:
            raise AssertionError(f"{flag} must be false")
    if assets["short_description_length"] > 500:
        raise AssertionError("short description exceeds 500 characters")
    for kw in ("safety-first", "wordpress", "security", "seo", "performance",
               "diagnosis", "review", "recommendation", "no blind autopilot"):
        if kw not in SHORT_DESCRIPTION.lower():
            raise AssertionError(f"short description missing keyword: {kw}")
    if assets["faq_count"] < 10:
        raise AssertionError("need at least 10 FAQ entries")
    if len(product_sections()) != 10:
        raise AssertionError("product file must have 10 sections")

    for blob_obj in (assets, *build_playbooks(assets).values()):
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

    # Public outputs: no secrets, real e-mails, server paths, IPs or forbidden claims.
    public_rendered = [
        render_product_md(), render_product_txt(), render_product_html(),
        render_public_intake_form_md(), render_public_safety_agreement_md(),
        render_public_service_overview_md(), render_short_description_md(),
        render_long_description_md(), render_faq_md(), render_package_deliverables_md(),
        render_after_purchase_message_md(), render_pdf_source_md(), render_pdf_source_html(),
    ]
    for blob in public_rendered:
        if SECRET_ASSIGNMENT_RE.search(blob) or LONG_HEX_RE.search(blob):
            raise AssertionError("secret-like content in public asset")
        for m in EMAIL_RE.findall(blob):
            if m.rsplit("@", 1)[-1].lower() not in ALLOWED_EMAIL_DOMAINS:
                raise AssertionError(f"real-looking e-mail in public asset: {m}")
        if INTERNAL_PATH_RE.search(blob):
            raise AssertionError("internal server path in public asset")
        if IPV4_RE.search(blob):
            raise AssertionError("IP address in public asset")
        if DISALLOWED_CLAIMS_RE.search(blob):
            raise AssertionError("forbidden marketing claim in public asset")

    # The public guard must actively reject bad public content.
    for bad in ("see /etc/passwd", "server at 203.0.113.5", "we guarantee 100% pagespeed",
                "we will bypass security"):
        try:
            _assert_public_safe(PRODUCT_FILE_MD, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"public guard failed to reject: {bad}")

    # PDF generation must be valid (or degrade cleanly).
    pdf = render_pdf_bytes(["Title", "", "Line one", "Line two"])
    if not (pdf[:5] == b"%PDF-" and pdf.rstrip().endswith(b"%%EOF")):
        raise AssertionError("pure-Python PDF is malformed")

    # Write-path guards.
    for forbidden in (
        PROJECT_DIR / "reports/latest/x.sh",
        PROJECT_DIR / "reports/latest/x.php",
        PROJECT_DIR / "state/adaptive-learning/x.service",
        PROJECT_DIR / "snapshots/x.json",
        PROJECT_DIR / "config/x.json",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")
    for ok_path in (PRODUCT_FILE_MD, PRODUCT_FILE_HTML, PDF_BINARY, STATE_ASSETS_JSON,
                    AUDIT_JSONL, PLAYBOOK_ASSETS):
        assert_allowed_write(ok_path)

    if not detect_secret_like("password=supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("The first audit is read-only and needs no login"):
        raise AssertionError("secret detector false positive on prose")

    print("payhip-public-client-assets self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], written: List[str]) -> None:
    a = state["assets"]
    print("=== Sentinel Payhip Product File + Public Client Assets (Phase 9.4) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"status: {a['status']}")
    print(f"product file status: md/txt/html ready ({len(a['product_file_sections'])} sections)")
    print("public assets status: intake form + safety agreement + service overview + "
          "deliverables + after-purchase message ready")
    print(f"description status: short ({a['short_description_length']} chars) + long "
          f"({len(a['long_description_sections'])} sections) ready")
    print(f"FAQ status: {a['faq_count']} questions ready")
    print(f"PDF source status: pdf-source.md + pdf-source.html ready")
    print(f"real PDF generated: {a['pdf_generated']} ({a['pdf_status']})")
    print(f"short description: {a['short_description']}")
    print(f"long description status: {len(a['long_description_sections'])} sections ready")
    print(f"package deliverables status: {len(a['deliverables'])} packages ready")
    print("after purchase message status: ready (no sending)")
    print(f"package names: {', '.join(a['packages'])}")
    print(f"live_apply: {a['live_apply']}")
    print(f"emergency_stop: {a['emergency_stop']}")
    print(f"allowed_apply_now: {a['allowed_apply_now']}")
    print(f"breach: {a['breach']}")
    print("what to upload to Payhip:")
    for f in a["upload_to_payhip"]:
        print(f"  - {f}")
    print("what to copy into the Payhip description:")
    for f in a["copy_into_description"]:
        print(f"  - {f}")
    print(f"recommended Git checkpoint: {a['git_checkpoint']['recommended']} "
          f"({a['git_checkpoint']['untracked_count']} untracked, "
          f"{a['git_checkpoint']['modified_count']} modified)")
    if a["git_checkpoint"]["files_sample"]:
        print("recommended Git checkpoint files (sample):")
        for f in a["git_checkpoint"]["files_sample"]:
            print(f"  - {f}")
    if a["missing_inputs"]:
        print(f"missing inputs: {', '.join(a['missing_inputs'])}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Payhip Product File + Public Client Assets (Phase 9.4). Read-only; no apply."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--build-product-file", action="store_true", help="Build product file (md/txt/html).")
    p.add_argument("--build-public-assets", action="store_true", help="Build public assets.")
    p.add_argument("--build-descriptions", action="store_true", help="Build short/long descriptions.")
    p.add_argument("--build-faq", action="store_true", help="Build public FAQ.")
    p.add_argument("--build-pdf-source", action="store_true", help="Build PDF (or PDF source md/html).")
    p.add_argument("--status", action="store_true", help="Print status summary.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    state = build_full_state()
    written = write_all_outputs(state)
    a = state["assets"]

    if args.build_product_file:
        print(f"[product-file] md/txt/html ready | sections={len(a['product_file_sections'])}")
    if args.build_public_assets:
        print(f"[public-assets] intake form, safety agreement, service overview, "
              f"deliverables, after-purchase message ready")
    if args.build_descriptions:
        print(f"[descriptions] short={a['short_description_length']} chars | "
              f"long sections={len(a['long_description_sections'])}")
    if args.build_faq:
        print(f"[faq] {a['faq_count']} questions ready")
    if args.build_pdf_source:
        print(f"[pdf] real PDF generated={a['pdf_generated']} status={a['pdf_status']} | "
              f"pdf-source md/html ready")

    if args.status or not any(
        (args.build_product_file, args.build_public_assets, args.build_descriptions,
         args.build_faq, args.build_pdf_source)
    ):
        _print_status(state, written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
