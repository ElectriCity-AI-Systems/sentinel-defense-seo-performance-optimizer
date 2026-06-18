#!/usr/bin/env python3
"""Sentinel Payhip Post-Purchase Fulfillment Board & Client Delivery Tracker (Phase 9.7).

A safe, *local* fulfillment layer for the Payhip service
"Sentinel Security, SEO & Performance Safe Optimization".

After the launch (Phase 9.6 = READY), this phase helps the owner manage buyers
manually through a clear flow:

    Payhip purchase -> buyer sends intake -> safe internal case file ->
    status board -> package workflow -> report template -> delivery checklist ->
    completion.

Everything is generated from constants as safe local templates with
placeholders. It stores NO real customer data, NO passwords, NO secrets. It is
read-only with respect to production: no apply, no upload, no website change, no
autopilot, no timer install, no SFTP/DB/Cloudflare/Nginx/WordPress write, no
network access, no Payhip API access and no e-mail send.

Invariants surfaced and enforced:
    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    HIGH stays blocked / review-only, never automatic
    no secrets, no real customer data, no server paths or IPs in outputs.
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
    ("launch_qa", PROJECT_DIR / "reports/latest/sentinel-payhip-launch-qa.json"),
    ("launch_qa_state",
     PROJECT_DIR / "state/adaptive-learning/latest_payhip_launch_qa_finalizer.json"),
]
INPUT_FILES: List[Tuple[str, Path]] = [
    ("final_copy_fields", PROJECT_DIR / "reports/latest/sentinel-payhip-final-copy-fields.txt"),
    ("final_upload_checklist",
     PROJECT_DIR / "reports/latest/sentinel-payhip-final-upload-checklist.md"),
    ("do_not_upload_list", PROJECT_DIR / "reports/latest/sentinel-payhip-do-not-upload-list.md"),
    ("export_copy_fields",
     PROJECT_DIR / "exports/payhip-upload-pack/latest/PAYHIP_COPY_FIELDS.txt"),
    ("export_upload_checklist",
     PROJECT_DIR / "exports/payhip-upload-pack/latest/PAYHIP_UPLOAD_CHECKLIST.md"),
]

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
BOARD_JSON = PROJECT_DIR / "reports/latest/sentinel-payhip-fulfillment-board.json"
BOARD_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-fulfillment-board.md"
CASE_TEMPLATE_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-case-template.md"
STATUS_FLOW_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-order-status-flow.md"
INTAKE_REVIEW_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-intake-review-console.md"
SCOPE_RISK_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-scope-risk-review.md"
DELIVERY_CHECKLISTS_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-package-delivery-checklists.md"
CLIENT_REPORT_TEMPLATE_MD = \
    PROJECT_DIR / "reports/latest/sentinel-payhip-client-report-delivery-template.md"
COMPLETION_CHECKLIST_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-completion-checklist.md"
DO_NOT_STORE_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-do-not-store-policy.md"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_JSON = STATE_DIR / "sentinel_payhip_fulfillment_board.json"
STATE_LATEST_JSON = STATE_DIR / "latest_payhip_fulfillment_board.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-payhip-fulfillment-board.jsonl"

PLAYBOOK_BOARD = PROJECT_DIR / "playbooks/sentinel-payhip-fulfillment-board.playbook.json"
PLAYBOOK_CASE = PROJECT_DIR / "playbooks/sentinel-payhip-case-template.playbook.json"
PLAYBOOK_RISK = PROJECT_DIR / "playbooks/sentinel-payhip-fulfillment-risk-review.playbook.json"

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

SCHEMA_VERSION = "payhip-fulfillment-board-9.7"

LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
LEVEL_2 = "LEVEL_2_LOW_RISK_PREP_PREVIEW"
ALLOWED_CURRENT_LEVELS = {LEVEL_1, LEVEL_2}
DEFAULT_CURRENT_LEVEL = LEVEL_2

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
    r"requested\b|warning\b|field\b|of any kind\b|reminder\b|received\b|blocked\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{40,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}
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
# Fulfillment content constants
# ---------------------------------------------------------------------------
SERVICE_TITLE = "Sentinel Security, SEO & Performance Safe Optimization"
PRODUCT_FILE = "01-service-access-instructions.pdf"
CONTACT_PLACEHOLDER = "[provider contact email to be filled in by the owner]"

PACKAGES = ["Sentinel Audit Report", "Sentinel Safe Optimization",
            "Sentinel Monitoring & Improvement"]
PACKAGE_PRICES = {
    "Sentinel Audit Report": "59 EUR",
    "Sentinel Safe Optimization": "149 EUR",
    "Sentinel Monitoring & Improvement": "99 EUR",
}

STATUS_PHASES: List[Tuple[str, str]] = [
    ("NEW_PURCHASE_MANUAL", "A new Payhip purchase was noticed; open a case manually."),
    ("WAITING_FOR_INTAKE", "Buyer was asked to send the intake; awaiting their reply."),
    ("INTAKE_RECEIVED", "Intake received; not yet reviewed."),
    ("INTAKE_REVIEWED", "Intake checked for completeness and safety."),
    ("SCOPE_CONFIRMED", "Scope and package boundaries confirmed with the buyer."),
    ("AUDIT_IN_PROGRESS", "Read-only audit / analysis is being prepared."),
    ("REPORT_DRAFT_READY", "Draft report prepared; pending internal owner review."),
    ("OWNER_REVIEW_REQUIRED", "Owner must review before anything is delivered."),
    ("CLIENT_DELIVERY_READY", "Report and delivery pack are ready to send."),
    ("DELIVERED", "Delivered to the client through the agreed channel."),
    ("COMPLETED", "Case completed and closed."),
    ("BLOCKED_MISSING_INFO", "Blocked: required (non-secret) information is missing."),
    ("BLOCKED_UNSAFE_REQUEST", "Blocked: the buyer requested an unsafe action."),
    ("REFUSED_HIGH_RISK", "Refused: a HIGH-risk action that is never auto-applied."),
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

RISK_CLASSES: Dict[str, List[str]] = {
    "READ_ONLY": [
        "Public audit",
        "SEO review",
        "Performance review",
        "Security signal interpretation",
    ],
    "DRAFT": [
        "Meta draft",
        "Internal link proposal",
        "Report text",
        "Action plan",
    ],
    "LOW": [
        "Safe copy/paste recommendation",
        "Image candidate recommendation",
        "Structured checklist",
    ],
    "MEDIUM": [
        "Canary optimization proposal",
        "Single asset replacement proposal",
        "Requires explicit approval, backup, healthcheck and rollback",
    ],
    "HIGH": [
        "Database edits",
        "Theme / plugin code edits",
        "Cloudflare WAF / firewall changes",
        "htaccess / Nginx changes",
        "Redirects",
        "Cache purge",
        "Mass automation",
        "Account credential handling",
        "Auto-login",
        "Any destructive action",
    ],
}
HIGH_POLICY = ("HIGH-risk actions are always BLOCKED or REVIEW_ONLY and are never applied "
               "automatically. The owner decides every HIGH item manually, with a documented "
               "safe alternative where possible.")

# Case template fields (placeholders only; no real data).
CASE_TEMPLATE_FIELDS: List[Tuple[str, str]] = [
    ("case_id", "CASE-YYYYMMDD-001"),
    ("selected_package", "[one of: Sentinel Audit Report / Sentinel Safe Optimization / "
                         "Sentinel Monitoring & Improvement]"),
    ("customer_alias", "[short alias, not the real full name, e.g. client-001]"),
    ("contact_placeholder", "[customer contact, e.g. customer@example.com]"),
    ("website_url_placeholder", "[your website URL, e.g. https://your-website.example.com]"),
    ("intake_status", "[WAITING_FOR_INTAKE / INTAKE_RECEIVED / INTAKE_REVIEWED]"),
    ("scope_status", "[scope pending / SCOPE_CONFIRMED]"),
    ("risk_status", "[READ_ONLY / DRAFT / LOW / MEDIUM / HIGH-review-only]"),
    ("delivery_status", "[not ready / CLIENT_DELIVERY_READY / DELIVERED / COMPLETED]"),
    ("no_password_received", "true"),
    ("secrets_received", "false"),
    ("live_apply", "false"),
    ("high_risk_blocked", "true"),
    ("notes_public", "[public, customer-facing notes only]"),
    ("notes_internal_owner_only", "[internal owner notes - never include secrets or credentials]"),
]

DO_NOT_STORE = [
    "No passwords",
    "No API keys",
    "No secret tokens",
    "No SSH keys",
    "No FTP / SFTP access data",
    "No database access data",
    "No hosting account passwords",
    "No Cloudflare account passwords",
    "No 2FA backup codes",
    "No payment data",
    "No private customer documents without explicit release",
]

INTAKE_REVIEW_ITEMS = [
    "Website URL is present and looks like a public URL placeholder.",
    "Selected package matches the Payhip purchase.",
    "Main goal is clear (SEO / Speed / Security / Stability / All).",
    "No password, API key or credential was sent (if it was, ask them to rotate it and do not store it).",
    "Known problems and context are understandable.",
    "Report language preference is noted.",
    "Consent to read-only first analysis is given.",
]

SCOPE_RISK_STEPS = [
    "Map each buyer request to a risk class (READ_ONLY / DRAFT / LOW / MEDIUM / HIGH).",
    "Confirm the package scope covers the request; if not, note it for the owner.",
    "Mark any MEDIUM item as approval + backup + healthcheck + rollback required.",
    "Mark any HIGH item as BLOCKED or REVIEW_ONLY (never automatic).",
    "Write a short scope confirmation for the buyer in plain language.",
]

CLIENT_REPORT_SECTIONS = [
    "Summary",
    "What was reviewed (read-only)",
    "Findings (SEO / Performance / Security)",
    "Risk classification",
    "Prioritized recommendations",
    "Safe next steps (review-first)",
    "What was NOT changed",
    "What remains an owner decision",
    "No-guarantee disclaimer",
    "Contact",
]

COMPLETION_PACK = {
    "client_delivery_checklist": [
        "Report reviewed by the owner.",
        "No secrets, server paths or IPs in the client report.",
        "Findings and recommendations are clear and safe.",
        "Delivery channel agreed with the client.",
        "Completion message prepared.",
    ],
    "final_safety_note": [
        "The service ran read-only first; no high-risk change was applied automatically.",
        "Any controlled change would require backup, healthcheck, rollback and owner approval.",
    ],
    "what_was_reviewed": [
        "Public SEO, performance and security signals.",
        "Risk classification of findings.",
    ],
    "what_was_not_changed": [
        "No website, theme, plugin, database, Cloudflare or server change was applied.",
    ],
    "what_remains_owner_decision": [
        "Whether to approve any MEDIUM controlled step later.",
        "Whether to start ongoing Monitoring & Improvement.",
    ],
    "next_safe_recommendations": [
        "Apply the safe, review-first recommendations at your own pace.",
        "Keep backups and a rollback path before any controlled change.",
    ],
    "no_guarantee_disclaimer": (
        "This service provides safety-first diagnosis, review and recommendations. Results "
        "depend on your website, hosting and content. We do not promise a specific search "
        "ranking or a fixed performance score, and high-risk changes always stay review-only "
        "until you explicitly approve a safe, controlled step."
    ),
}

FIRST_ORDER_MANUAL_STEPS = [
    "Open a new case from the case template and set status NEW_PURCHASE_MANUAL.",
    "Send the buyer the intake form and the read-only / no-password reminder.",
    "When the intake arrives, set INTAKE_RECEIVED and run the intake review console.",
    "Confirm scope and risk, then set SCOPE_CONFIRMED.",
    "Prepare the read-only audit and a draft report (REPORT_DRAFT_READY).",
    "Self-review as owner (OWNER_REVIEW_REQUIRED), then deliver and set COMPLETED.",
]

DO_NOT_COMMIT_NOTE = ("Export files and real customer case files are never committed. Only this "
                      "script and its playbooks should be committed.")
RECOMMENDED_GIT_CHECKPOINT = [
    "sentinel_payhip_fulfillment_board.py",
    "playbooks/sentinel-payhip-fulfillment-board.playbook.json",
    "playbooks/sentinel-payhip-case-template.playbook.json",
    "playbooks/sentinel-payhip-fulfillment-risk-review.playbook.json",
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
    src = inputs["data"].get("launch_qa_state") or inputs["data"].get("launch_qa")

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
        reasons.append("upstream launch-qa reports breach")
    return (len(reasons) > 0), reasons


# ---------------------------------------------------------------------------
# Renderers (all public-safe templates)
# ---------------------------------------------------------------------------
def render_board_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Payhip Fulfillment Board",
        "",
        f"Service: {SERVICE_TITLE}",
        f"Status: **{report['status']}** | decision-free local tracker (no upload, no apply)",
        "",
        "## How to use",
        "Track each Payhip order as one case file. Move it left-to-right through the status "
        "phases. Nothing here changes a website or sends anything.",
        "",
        "## Status phases",
    ]
    for name, desc in STATUS_PHASES:
        lines.append(f"- **{name}** - {desc}")
    lines += ["", "## Board columns (suggested)",
              "- Inbox: NEW_PURCHASE_MANUAL, WAITING_FOR_INTAKE",
              "- In review: INTAKE_RECEIVED, INTAKE_REVIEWED, SCOPE_CONFIRMED",
              "- In work: AUDIT_IN_PROGRESS, REPORT_DRAFT_READY, OWNER_REVIEW_REQUIRED",
              "- Delivery: CLIENT_DELIVERY_READY, DELIVERED, COMPLETED",
              "- Blocked: BLOCKED_MISSING_INFO, BLOCKED_UNSAFE_REQUEST, REFUSED_HIGH_RISK",
              "", "## Packages"]
    for p in PACKAGES:
        lines.append(f"- {p} ({PACKAGE_PRICES[p]})")
    lines += ["", "## First order: do this manually"]
    for s in FIRST_ORDER_MANUAL_STEPS:
        lines.append(f"1. {s}")
    lines += ["", f"_{DO_NOT_COMMIT_NOTE}_", ""]
    return "\n".join(lines) + "\n"


def render_case_template_md() -> str:
    lines = [
        "# Sentinel Payhip - Case Template (sample, placeholders only)",
        "",
        "> Copy this template per order. Use an alias, not the real full name. Never paste "
        "passwords, API keys, tokens or other credentials into a case file.",
        "",
        "```yaml",
    ]
    for key, val in CASE_TEMPLATE_FIELDS:
        lines.append(f"{key}: {val}")
    lines += ["```", "",
              "## Reminders",
              "- no_password_received stays true; the first audit needs no login.",
              "- secrets_received stays false; if a secret arrives, ask the client to rotate it "
              "and do not store it.",
              "- live_apply stays false and high_risk_blocked stays true.",
              ""]
    return "\n".join(lines) + "\n"


def render_status_flow_md() -> str:
    flow = " -> ".join(name for name, _ in STATUS_PHASES[:11])
    lines = [
        "# Sentinel Payhip - Order Status Flow",
        "",
        "## Normal flow",
        f"`{flow}`",
        "",
        "## Branch states",
        "- BLOCKED_MISSING_INFO: pause until the client provides missing (non-secret) info.",
        "- BLOCKED_UNSAFE_REQUEST: pause and explain the safe alternative.",
        "- REFUSED_HIGH_RISK: a HIGH-risk action that is never auto-applied.",
        "",
        "## Phase descriptions",
    ]
    for name, desc in STATUS_PHASES:
        lines.append(f"- **{name}**: {desc}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_intake_review_md() -> str:
    lines = ["# Sentinel Payhip - Intake Review Console", "",
             "Run this when an intake arrives. Check each item:", ""]
    for item in INTAKE_REVIEW_ITEMS:
        lines.append(f"- [ ] {item}")
    lines += ["", "## If a credential was sent anyway",
              "- Do not store it.",
              "- Ask the client to rotate / change it.",
              "- Continue read-only; the first audit needs no login.",
              ""]
    return "\n".join(lines) + "\n"


def render_scope_risk_md() -> str:
    lines = ["# Sentinel Payhip - Scope & Risk Review", "",
             "## Steps"]
    for s in SCOPE_RISK_STEPS:
        lines.append(f"- [ ] {s}")
    lines += ["", "## Risk classes"]
    for cls in ("READ_ONLY", "DRAFT", "LOW", "MEDIUM", "HIGH"):
        lines.append(f"### {cls}")
        for item in RISK_CLASSES[cls]:
            lines.append(f"- {item}")
        lines.append("")
    lines += ["## HIGH policy", HIGH_POLICY, ""]
    return "\n".join(lines) + "\n"


def render_delivery_checklists_md() -> str:
    lines = ["# Sentinel Payhip - Package Delivery Checklists", ""]
    for p in PACKAGES:
        lines.append(f"## {p} ({PACKAGE_PRICES[p]})")
        for step in PACKAGE_WORKFLOWS[p]:
            lines.append(f"- [ ] {step}")
        lines.append("")
    lines += ["## Cross-package safety gate",
              "- [ ] No HIGH-risk action executed.",
              "- [ ] No website / server / Cloudflare / database change applied.",
              "- [ ] No secrets stored in the case file.",
              ""]
    return "\n".join(lines) + "\n"


def render_client_report_template_md() -> str:
    lines = ["# Sentinel Payhip - Client Report Delivery Template", "",
             "> Fill in each section. Keep it public-safe: no server paths, IPs, secrets or "
             "raw internal logs.", ""]
    for i, sec in enumerate(CLIENT_REPORT_SECTIONS, 1):
        lines.append(f"## {i}. {sec}")
        lines.append("[...]")
        lines.append("")
    lines += [f"Contact: {CONTACT_PLACEHOLDER}", ""]
    return "\n".join(lines) + "\n"


def render_completion_checklist_md() -> str:
    cp = COMPLETION_PACK
    lines = ["# Sentinel Payhip - Completion Checklist", "",
             "## Client delivery checklist"]
    for x in cp["client_delivery_checklist"]:
        lines.append(f"- [ ] {x}")
    lines += ["", "## Final safety note"]
    for x in cp["final_safety_note"]:
        lines.append(f"- {x}")
    lines += ["", "## What was reviewed"]
    for x in cp["what_was_reviewed"]:
        lines.append(f"- {x}")
    lines += ["", "## What was NOT changed"]
    for x in cp["what_was_not_changed"]:
        lines.append(f"- {x}")
    lines += ["", "## What remains an owner decision"]
    for x in cp["what_remains_owner_decision"]:
        lines.append(f"- {x}")
    lines += ["", "## Next safe recommendations"]
    for x in cp["next_safe_recommendations"]:
        lines.append(f"- {x}")
    lines += ["", "## No-guarantee disclaimer", cp["no_guarantee_disclaimer"], ""]
    return "\n".join(lines) + "\n"


def render_do_not_store_md() -> str:
    lines = ["# Sentinel Payhip - Do Not Store Policy", "",
             "Never store any of the following in a case file, note or report:"]
    for item in DO_NOT_STORE:
        lines.append(f"- {item}")
    lines += ["",
              "If a client sends any of these, do not store it, ask them to rotate it, and "
              "continue read-only. The first audit needs no login.", ""]
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

    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.7",
        "generated_at": timestamp,
        "status": "FULFILLMENT_BOARD_READY_LOCKED" if not breach else "FULFILLMENT_BOARD_BREACH",
        "read_only": True,
        "service_title": SERVICE_TITLE,
        "product_file": PRODUCT_FILE,
        "packages": PACKAGES,
        "package_prices": PACKAGE_PRICES,
        "status_phases": [name for name, _ in STATUS_PHASES],
        "package_workflows": PACKAGE_WORKFLOWS,
        "risk_classes": RISK_CLASSES,
        "high_policy": HIGH_POLICY,
        "case_template_fields": [k for k, _ in CASE_TEMPLATE_FIELDS],
        "do_not_store": DO_NOT_STORE,
        "completion_pack_sections": list(COMPLETION_PACK.keys()),
        "first_order_manual_steps": FIRST_ORDER_MANUAL_STEPS,
        "recommended_git_checkpoint": RECOMMENDED_GIT_CHECKPOINT,
        "export_or_case_files_committed": False,
        "board_status": "READY",
        "case_template_status": "READY",
        "delivery_checklist_status": "READY",
        "risk_review_status": "READY",
        "completion_pack_status": "READY",
        "do_not_store_status": "READY",
        # safety mirror / explicit non-actions
        "autonomy_level": safety["current_level"],
        "live_apply": safety["live_apply"],
        "emergency_stop": safety["emergency_stop"],
        "allowed_apply_now": safety["allowed_apply_now"],
        "high_blocked": safety["high_blocked"],
        "high_risk_blocked": True,
        "breach": breach,
        "breach_reasons": reasons,
        "stores_real_customer_data": False,
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
        PLAYBOOK_BOARD: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-fulfillment-board",
            "generated_at": report["generated_at"],
            "status": report["status"],
            "read_only": True,
            "applies_changes": False,
            "uploads_anything": False,
            "status_phases": report["status_phases"],
            "packages": report["packages"],
            "steps": [
                "Open a case per Payhip order from the case template.",
                "Move it through the status phases left to right.",
                "Run intake review, scope & risk review, then the package workflow.",
                "Deliver via the client report template and completion checklist.",
                "Never store secrets; HIGH actions stay review-only.",
            ],
        },
        PLAYBOOK_CASE: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-case-template",
            "generated_at": report["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "fields": report["case_template_fields"],
            "do_not_store": DO_NOT_STORE,
        },
        PLAYBOOK_RISK: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-fulfillment-risk-review",
            "generated_at": report["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "risk_classes": list(RISK_CLASSES.keys()),
            "high_policy": HIGH_POLICY,
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

    wj(BOARD_JSON, report)
    w(BOARD_MD, render_board_md(report))
    w(CASE_TEMPLATE_MD, render_case_template_md())
    w(STATUS_FLOW_MD, render_status_flow_md())
    w(INTAKE_REVIEW_MD, render_intake_review_md())
    w(SCOPE_RISK_MD, render_scope_risk_md())
    w(DELIVERY_CHECKLISTS_MD, render_delivery_checklists_md())
    w(CLIENT_REPORT_TEMPLATE_MD, render_client_report_template_md())
    w(COMPLETION_CHECKLIST_MD, render_completion_checklist_md())
    w(DO_NOT_STORE_MD, render_do_not_store_md())

    wj(STATE_JSON, report)
    wj(STATE_LATEST_JSON, report)

    for path, data in build_playbooks(report).items():
        wj(path, data)

    append_jsonl(AUDIT_JSONL, [{
        "ts": report["generated_at"],
        "phase": "9.7",
        "module": "sentinel_payhip_fulfillment_board",
        "status": report["status"],
        "status_phase_count": len(report["status_phases"]),
        "package_count": len(report["packages"]),
        "do_not_store_count": len(report["do_not_store"]),
        "live_apply": report["live_apply"],
        "emergency_stop": report["emergency_stop"],
        "allowed_apply_now": report["allowed_apply_now"],
        "high_blocked": report["high_blocked"],
        "stores_real_customer_data": False,
        "stores_credentials": False,
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

    # Public-safety scanner: catch real leaks, allow safety-instruction words.
    for bad in ("see /etc/passwd here", "origin at 203.0.113.7", "we guarantee 100% pagespeed",
                "we will bypass security", "ghp_abcdefghijklmnop12345",
                "password=ABCDEFGH12345678", "contact real.person@gmail.com"):
        if not public_safety_findings(bad):
            raise AssertionError(f"public-safety scanner missed: {bad}")
    for good in ("Never store passwords, API keys, tokens, SSH keys or FTP/SFTP access data.",
                 "no_password_received: true and secrets_received: false",
                 "Contact: customer@example.com.",
                 "We do not promise a specific search ranking; review-first only."):
        if public_safety_findings(good):
            raise AssertionError(f"public-safety scanner false positive: {good}")

    # Writer must reject secrets, internal paths and IPs.
    for bad in ("token=ABCDEFGH12345678", "path /srv/sentinel-defense", "ip 198.51.100.9"):
        try:
            write_text_atomic(BOARD_MD, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"writer failed to reject: {bad}")

    # Case template must not request or store passwords/credentials.
    for key, val in CASE_TEMPLATE_FIELDS:
        if key == "no_password_received" and val != "true":
            raise AssertionError("no_password_received must be true")
        if key == "secrets_received" and val != "false":
            raise AssertionError("secrets_received must be false")
        if key == "live_apply" and val != "false":
            raise AssertionError("case live_apply must be false")
        if key == "high_risk_blocked" and val != "true":
            raise AssertionError("case high_risk_blocked must be true")
    if any(re.search(r"(?i)\bpassword\b\s*[:=]\s*[A-Za-z0-9]{6,}", v) for _, v in CASE_TEMPLATE_FIELDS):
        raise AssertionError("case template must not contain a real password value")

    # HIGH risk class must contain the dangerous actions and be policy-blocked.
    for must in ("Database edits", "Cloudflare WAF / firewall changes", "Any destructive action"):
        if must not in RISK_CLASSES["HIGH"]:
            raise AssertionError(f"HIGH risk class missing: {must}")
    if "never applied" not in HIGH_POLICY.lower():
        raise AssertionError("HIGH policy must state actions are never applied automatically")

    # Build state (read-only) and validate invariants.
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
    if len(report["status_phases"]) != 14:
        raise AssertionError("expected 14 status phases")
    if set(report["packages"]) != set(PACKAGES):
        raise AssertionError("packages mismatch")
    for flag in ("requests_passwords", "stores_real_customer_data", "stores_credentials",
                 "sends_email", "network_access", "payhip_api_access", "uploads_anything",
                 "installs_packages", "applies_changes"):
        if report[flag] is not False:
            raise AssertionError(f"{flag} must be false")

    # All rendered outputs must be public-safe.
    rendered = [
        render_board_md(report), render_case_template_md(), render_status_flow_md(),
        render_intake_review_md(), render_scope_risk_md(), render_delivery_checklists_md(),
        render_client_report_template_md(), render_completion_checklist_md(),
        render_do_not_store_md(),
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
    for ok_path in (BOARD_JSON, BOARD_MD, CASE_TEMPLATE_MD, STATE_JSON, AUDIT_JSONL, PLAYBOOK_BOARD):
        assert_allowed_write(ok_path)

    if not detect_secret_like("password=supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("The first audit is read-only and needs no login"):
        raise AssertionError("secret detector false positive on prose")

    print("payhip-fulfillment-board self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], written: List[str]) -> None:
    r = state["report"]
    print("=== Sentinel Payhip Fulfillment Board & Client Delivery Tracker (Phase 9.7) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"fulfillment board status: {r['board_status']} ({r['status']})")
    print(f"case template status: {r['case_template_status']} "
          f"({len(r['case_template_fields'])} fields)")
    print(f"delivery checklist status: {r['delivery_checklist_status']} "
          f"({len(r['packages'])} packages)")
    print(f"risk review status: {r['risk_review_status']} ({len(r['risk_classes'])} classes)")
    print(f"completion pack status: {r['completion_pack_status']} "
          f"({len(r['completion_pack_sections'])} sections)")
    print(f"do not store policy status: {r['do_not_store_status']} "
          f"({len(r['do_not_store'])} entries)")
    print("status phases:")
    for p in r["status_phases"]:
        print(f"  - {p}")
    print("package workflows:")
    for pkg in r["packages"]:
        print(f"  - {pkg} ({r['package_prices'][pkg]}): {len(r['package_workflows'][pkg])} steps")
    print(f"live_apply: {r['live_apply']}")
    print(f"emergency_stop: {r['emergency_stop']}")
    print(f"allowed_apply_now: {r['allowed_apply_now']}")
    print(f"breach: {r['breach']}")
    print("never stored for real customers:")
    for x in r["do_not_store"]:
        print(f"  - {x}")
    print("first order - do this manually:")
    for x in r["first_order_manual_steps"]:
        print(f"  - {x}")
    print("recommended Git checkpoint (script + playbooks only):")
    for x in r["recommended_git_checkpoint"]:
        print(f"  - {x}")
    print("note: case files and export files are NOT committed.")
    if r["missing_inputs"]:
        print(f"missing inputs (safe defaults used): {', '.join(r['missing_inputs'])}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Payhip Post-Purchase Fulfillment Board (Phase 9.7). "
                    "Local templates only; no upload; no apply."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--build-board", action="store_true", help="Build the fulfillment board.")
    p.add_argument("--build-case-template", action="store_true", help="Build the case template.")
    p.add_argument("--build-delivery-checklists", action="store_true",
                   help="Build package delivery checklists.")
    p.add_argument("--build-risk-review", action="store_true", help="Build the scope & risk review.")
    p.add_argument("--build-completion-pack", action="store_true", help="Build the completion pack.")
    p.add_argument("--status", action="store_true", help="Print status summary.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    state = build_full_state()
    written = write_all_outputs(state)
    r = state["report"]

    if args.build_board:
        print(f"[board] {r['status']} | {len(r['status_phases'])} phases | "
              f"{len(r['packages'])} packages")
    if args.build_case_template:
        print(f"[case-template] ready | {len(r['case_template_fields'])} fields | "
              f"reports/latest/sentinel-payhip-case-template.md")
    if args.build_delivery_checklists:
        print(f"[delivery-checklists] ready | {len(r['packages'])} package workflows")
    if args.build_risk_review:
        print(f"[risk-review] ready | {len(r['risk_classes'])} risk classes | HIGH review-only")
    if args.build_completion_pack:
        print(f"[completion-pack] ready | {len(r['completion_pack_sections'])} sections")

    if args.status or not any(
        (args.build_board, args.build_case_template, args.build_delivery_checklists,
         args.build_risk_review, args.build_completion_pack)
    ):
        _print_status(state, written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
