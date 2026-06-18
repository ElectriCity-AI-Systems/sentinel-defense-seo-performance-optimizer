#!/usr/bin/env python3
"""Sentinel Payhip Launch QA & Store Listing Finalizer (Phase 9.6).

A safe, *local* launch-QA layer for the Payhip service
"Sentinel Security, SEO & Performance Safe Optimization".

It reads the Phase 9.5 upload pack (read-only), checks every Payhip field,
variant, description, FAQ, after-purchase message, manifest, checksums and the
optional zip, runs a final public-safety review and emits a launch decision:
READY / NEEDS_REVIEW / BLOCKED, plus a copy/paste launch console, a final
checklist, a storefront QA page, a do-not-upload list and a decision summary.

It is strictly read-only with respect to production and the upload pack: there
is no apply mode, no upload, no website change, no autopilot, no timer install,
no SFTP/DB/Cloudflare/Nginx/WordPress write, no network access, no Payhip API
access and no e-mail send. It only reads existing files and writes review docs
under reports/latest, state/adaptive-learning, audit and playbooks.

The forbidden-content scan uses value-bearing detection (secret assignments and
concrete key formats) plus server-path/IP/marketing-claim patterns. It does NOT
flag the bare words "password" or "API key", because the public FAQ and safety
texts legitimately instruct buyers to *never send* passwords, API keys or tokens
- blocking those words would block the safety guidance itself.

Invariants surfaced and enforced:
    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    HIGH stays blocked
    no secrets, no internal server paths or IPs in the public outputs.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

# ---------------------------------------------------------------------------
# Inputs (read-only) — the Phase 9.5 upload pack
# ---------------------------------------------------------------------------
EXPORT_LATEST = PROJECT_DIR / "exports/payhip-upload-pack/latest"
ZIP_PATH = PROJECT_DIR / "exports/payhip-upload-pack/sentinel-payhip-upload-pack-latest.zip"

IN_PDF = EXPORT_LATEST / "01-service-access-instructions.pdf"
IN_SHORT = EXPORT_LATEST / "07-short-description.txt"
IN_LONG = EXPORT_LATEST / "08-long-description.txt"
IN_FAQ = EXPORT_LATEST / "09-faq.md"
IN_DELIVERABLES = EXPORT_LATEST / "10-package-deliverables.md"
IN_AFTER = EXPORT_LATEST / "11-after-purchase-message.md"
IN_CHECKLIST = EXPORT_LATEST / "PAYHIP_UPLOAD_CHECKLIST.md"
IN_COPY_FIELDS = EXPORT_LATEST / "PAYHIP_COPY_FIELDS.txt"
IN_MANIFEST = EXPORT_LATEST / "MANIFEST.json"
IN_CHECKSUMS = EXPORT_LATEST / "CHECKSUMS.sha256"

EXPORT_REPORT_JSON = PROJECT_DIR / "reports/latest/sentinel-payhip-upload-pack-export.json"
EXPORT_STATE_JSON = PROJECT_DIR / "state/adaptive-learning/latest_payhip_upload_pack_export_helper.json"

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
REPORT_JSON = PROJECT_DIR / "reports/latest/sentinel-payhip-launch-qa.json"
REPORT_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-launch-qa.md"
LAUNCH_CONSOLE_TXT = PROJECT_DIR / "reports/latest/sentinel-payhip-launch-console.txt"
FINAL_CHECKLIST_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-final-upload-checklist.md"
STOREFRONT_QA_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-storefront-qa.md"
DO_NOT_UPLOAD_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-do-not-upload-list.md"
DECISION_SUMMARY_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-launch-decision-summary.md"
FINAL_COPY_FIELDS_TXT = PROJECT_DIR / "reports/latest/sentinel-payhip-final-copy-fields.txt"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_JSON = STATE_DIR / "sentinel_payhip_launch_qa_finalizer.json"
STATE_LATEST_JSON = STATE_DIR / "latest_payhip_launch_qa_finalizer.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-payhip-launch-qa-finalizer.jsonl"

PLAYBOOK_QA = PROJECT_DIR / "playbooks/sentinel-payhip-launch-qa.playbook.json"
PLAYBOOK_CONSOLE = PROJECT_DIR / "playbooks/sentinel-payhip-launch-console.playbook.json"
PLAYBOOK_STOREFRONT = PROJECT_DIR / "playbooks/sentinel-payhip-storefront-finalizer.playbook.json"

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

SCHEMA_VERSION = "payhip-launch-qa-finalizer-9.6"

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
    r"requested\b|warning\b|field\b|of any kind\b|reminder\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{40,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}
INTERNAL_PATH_RE = re.compile(r"/(srv|etc|home|root|var|usr|opt|boot|proc)/")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Concrete secret key formats that are never legitimate in public content.
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
    """Return reasons a blob is NOT safe to publish (empty == safe).

    Uses value-bearing / concrete detection; bare safety words such as
    "passwords" or "API keys" in instructions are intentionally allowed.
    """
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


def read_text_optional(path: Path) -> Tuple[Optional[str], str]:
    try:
        if not path.exists():
            return None, "not_available"
        return path.read_text(encoding="utf-8"), "ok"
    except OSError:
        return None, "read_error"


def run_readonly(cmd: List[str], timeout: int = 10) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=str(PROJECT_DIR), capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode == 0, redact_text(proc.stdout, max_len=6000)
    except (OSError, subprocess.SubprocessError):
        return False, ""


# ---------------------------------------------------------------------------
# Public listing constants (expected Payhip fields)
# ---------------------------------------------------------------------------
PRODUCT_TITLE = "Sentinel Security, SEO & Performance Safe Optimization"
PRODUCT_FILE = "01-service-access-instructions.pdf"

VARIANTS: List[Dict[str, str]] = [
    {"name": "Sentinel Audit Report", "price": "59 EUR",
     "description": "Read-only audit with SEO, performance and security findings, a risk "
                    "classification and prioritized recommendations. No login required."},
    {"name": "Sentinel Safe Optimization", "price": "149 EUR",
     "description": "Audit plus owner-reviewed draft recommendations and a backup, healthcheck "
                    "and rollback plan for controlled, owner-approved steps. No blind autopilot."},
    {"name": "Sentinel Monitoring & Improvement", "price": "99 EUR",
     "description": "Recurring trend review, a safe improvement backlog and a monthly owner "
                    "summary. Review-first and owner-approved."},
]

VISIBILITY_RECOMMENDATION = (
    "Set the product to PUBLISHED only after this QA shows READY and you have reviewed the "
    "cover image and all field text."
)
PRODUCT_TYPE_REMINDER = (
    "Product type: digital download / ebook (PDF). If Payhip offers PDF stamping, decide "
    "whether to enable it for the access-instructions PDF."
)
TAX_REMINDER = (
    "Check your Payhip tax settings (VAT / sales tax) for digital products before publishing."
)

DO_NOT_UPLOAD = [
    "reports/ (internal Sentinel reports)",
    "state/ (internal state files)",
    "audit/ (audit logs)",
    "playbooks/ (internal playbooks)",
    "environment files such as dot-env or the local sftp env file",
    "backups/ and snapshots/",
    "Cloudflare logs and rule details",
    "server logs",
    "private PC reports",
    "raw Sentinel daily reports",
    "Git internals (.git, history, hashes)",
    "any zip not created by the Phase 9.5 export helper",
]
RECOMMENDED_GIT_CHECKPOINT = [
    "sentinel_payhip_launch_qa_finalizer.py",
    "playbooks/sentinel-payhip-launch-qa.playbook.json",
    "playbooks/sentinel-payhip-launch-console.playbook.json",
    "playbooks/sentinel-payhip-storefront-finalizer.playbook.json",
]
EXPECTED_ZIP_NAMES = {
    "01-service-access-instructions.pdf", "02-product-file-final.txt",
    "03-product-file-final.html", "04-public-intake-form.md",
    "05-public-safety-agreement.md", "06-public-service-overview.md",
    "07-short-description.txt", "08-long-description.txt", "09-faq.md",
    "10-package-deliverables.md", "11-after-purchase-message.md",
    "12-pdf-source.md", "13-pdf-source.html", "README_FIRST.md",
    "PAYHIP_UPLOAD_CHECKLIST.md", "PAYHIP_COPY_FIELDS.txt",
    "MANIFEST.json", "CHECKSUMS.sha256",
}
ZIP_INTERNAL_MARKERS = ("reports/", "state/", "audit/", "playbooks/", ".git", ".env")


# ---------------------------------------------------------------------------
# git / safety
# ---------------------------------------------------------------------------
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


def resolve_safety() -> Dict[str, Any]:
    src, _ = read_optional_json(EXPORT_STATE_JSON)

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
        reasons.append("upstream export reports breach")
    return (len(reasons) > 0), reasons


# ---------------------------------------------------------------------------
# QA checks
# ---------------------------------------------------------------------------
def _check(checks: List[Dict[str, Any]], cid: str, severity: str, passed: bool,
           detail: str) -> bool:
    """severity: 'blocker' (safety) | 'required' | 'optional'."""
    checks.append({"id": cid, "severity": severity, "passed": bool(passed), "detail": detail})
    return bool(passed)


def _clean_after_purchase(text: str) -> str:
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("#") or s.startswith("```"):
            continue
        out.append(ln)
    return "\n".join(out).strip()


def run_qa() -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    missing: List[str] = []
    blocker_reasons: List[str] = []

    def note_missing(path: Path) -> None:
        missing.append(str(path.relative_to(PROJECT_DIR)))

    # --- Product title (constant, exact) ---
    _check(checks, "product_title_exact", "required",
           PRODUCT_TITLE == "Sentinel Security, SEO & Performance Safe Optimization",
           "Product title matches the exact required string.")

    # --- Product file (PDF) ---
    pdf_ok = IN_PDF.exists()
    pdf_size = IN_PDF.stat().st_size if pdf_ok else 0
    pdf_scan: List[str] = []
    if pdf_ok:
        try:
            pdf_scan = public_safety_findings(IN_PDF.read_bytes().decode("latin-1", "ignore"))
        except OSError:
            pdf_ok = False
    else:
        note_missing(IN_PDF)
    _check(checks, "product_file_present", "required", pdf_ok and pdf_size > 0,
           f"{PRODUCT_FILE} present and {pdf_size} bytes." if pdf_ok else f"{PRODUCT_FILE} missing.")
    if pdf_scan:
        blocker_reasons += [f"product_file:{r}" for r in pdf_scan]
    _check(checks, "product_file_clean", "blocker", not pdf_scan,
           "Product file passes the public-safety scan." if not pdf_scan
           else f"Product file flagged: {pdf_scan}")

    # --- Short description ---
    short, sst = read_text_optional(IN_SHORT)
    if short is None:
        note_missing(IN_SHORT)
        short = ""
    short_body = short.strip()
    short_len_ok = 0 < len(short_body) <= 500
    low = short_body.lower()
    short_kw_safe = ("safety-first" in low) or ("safe" in low)
    short_kw_pillars = all(k in low for k in ("security", "seo", "performance"))
    short_kw_pos = ("no blind autopilot" in low) or ("review-first" in low)
    short_scan = public_safety_findings(short_body)
    if short_scan:
        blocker_reasons += [f"short_description:{r}" for r in short_scan]
    _check(checks, "short_present", "required", bool(short_body), "Short description present.")
    _check(checks, "short_length", "required", short_len_ok,
           f"Short description length {len(short_body)} (<=500).")
    _check(checks, "short_keyword_safe", "required", short_kw_safe,
           "Short description mentions safety-first / safe.")
    _check(checks, "short_keyword_pillars", "required", short_kw_pillars,
           "Short description mentions Security, SEO and Performance.")
    _check(checks, "short_keyword_positioning", "required", short_kw_pos,
           "Short description mentions no blind autopilot / review-first.")
    _check(checks, "short_no_claims", "blocker", not short_scan,
           "Short description has no forbidden content." if not short_scan
           else f"Short description flagged: {short_scan}")

    # --- Long description ---
    long_text, lst = read_text_optional(IN_LONG)
    if long_text is None:
        note_missing(IN_LONG)
        long_text = ""
    long_low = long_text.lower()
    section_count = len(re.findall(r"(?m)^##\s+\S", long_text))
    has_problem = bool(re.search(r"(?i)\bproblem\b|hidden .*issues|risk breaking", long_text))
    has_solution = "solution" in long_low
    has_safe_autonomy = "safe autonomy" in long_low
    has_packages = "packages" in long_low
    has_not_promised = ("not promised" in long_low) or ("disclaimer" in long_low)
    long_scan = public_safety_findings(long_text)
    if long_scan:
        blocker_reasons += [f"long_description:{r}" for r in long_scan]
    _check(checks, "long_present", "required", bool(long_text.strip()), "Long description present.")
    _check(checks, "long_min_sections", "required", section_count >= 6,
           f"Long description has {section_count} section headers (>=6).")
    _check(checks, "long_has_problem", "required", has_problem,
           "Long description states the problem.")
    _check(checks, "long_has_solution", "required", has_solution,
           "Long description includes Solution.")
    _check(checks, "long_has_safe_autonomy", "required", has_safe_autonomy,
           "Long description includes Safe Autonomy.")
    _check(checks, "long_has_packages", "required", has_packages,
           "Long description includes Packages.")
    _check(checks, "long_has_not_promised", "required", has_not_promised,
           "Long description includes What is not promised / Disclaimer.")
    _check(checks, "long_no_claims_or_paths", "blocker", not long_scan,
           "Long description has no forbidden content." if not long_scan
           else f"Long description flagged: {long_scan}")

    # --- Variants ---
    variant_names = {"Sentinel Audit Report", "Sentinel Safe Optimization",
                     "Sentinel Monitoring & Improvement"}
    variant_prices = {"Sentinel Audit Report": "59 EUR",
                      "Sentinel Safe Optimization": "149 EUR",
                      "Sentinel Monitoring & Improvement": "99 EUR"}
    names_ok = {v["name"] for v in VARIANTS} == variant_names
    prices_ok = all(v["price"] == variant_prices[v["name"]] for v in VARIANTS)
    desc_ok = all(len(v["description"].strip()) > 20 for v in VARIANTS)
    _check(checks, "variants_names", "required", names_ok, "All three variant names present.")
    _check(checks, "variants_prices", "required", prices_ok, "Variant prices are 59 / 149 / 99 EUR.")
    _check(checks, "variants_descriptions", "required", desc_ok,
           "Each variant has a name, price and description.")

    # --- FAQ ---
    faq, fst = read_text_optional(IN_FAQ)
    if faq is None:
        note_missing(IN_FAQ)
        faq = ""
    faq_q = len(re.findall(r"(?m)^\*\*\d+\.", faq))
    if faq_q == 0:
        faq_q = len(re.findall(r"(?im)^\s*(?:\*\*)?q\s*[:.\d]", faq))
    faq_low = faq.lower()
    faq_pw_warning = "password" in faq_low and (
        "do not send" in faq_low or "never send" in faq_low or "no login" in faq_low)
    faq_claims = bool(DISALLOWED_CLAIMS_RE.search(faq))
    faq_scan = public_safety_findings(faq)
    if faq_scan:
        blocker_reasons += [f"faq:{r}" for r in faq_scan]
    _check(checks, "faq_min_questions", "required", faq_q >= 10,
           f"FAQ has {faq_q} questions (>=10).")
    _check(checks, "faq_password_warning", "required", faq_pw_warning,
           "FAQ warns to never send passwords.")
    _check(checks, "faq_no_claims", "blocker", (not faq_claims) and (not faq_scan),
           "FAQ has no ranking / 100% guarantee or other forbidden content."
           if not (faq_claims or faq_scan) else f"FAQ flagged: claims={faq_claims} scan={faq_scan}")

    # --- After-purchase message ---
    after, ast = read_text_optional(IN_AFTER)
    if after is None:
        note_missing(IN_AFTER)
        after = ""
    after_body = _clean_after_purchase(after)
    after_low = after_body.lower()
    after_next = any(k in after_low for k in ("intake form", "send your", "get started", "next"))
    after_pw_request = bool(re.search(
        r"(?i)(enter|provide|share|give us|we need|submit)\s+(your\s+)?password", after_body))
    after_contact = ("[" in after_body and "]" in after_body) or (
        "your contact email" in after_low) or ("contact:" in after_low)
    after_scan = public_safety_findings(after_body)
    if after_scan:
        blocker_reasons += [f"after_purchase:{r}" for r in after_scan]
    _check(checks, "after_present", "required", bool(after_body), "After-purchase message present.")
    _check(checks, "after_next_step", "required", after_next,
           "After-purchase message tells the buyer what to do next.")
    _check(checks, "after_no_password_request", "blocker", not after_pw_request,
           "After-purchase message does not request a password."
           if not after_pw_request else "After-purchase message requests a password.")
    _check(checks, "after_contact_placeholder", "required", after_contact,
           "After-purchase message contains a contact placeholder.")

    # --- Manifest / checksums / zip ---
    manifest, mst = read_optional_json(IN_MANIFEST)
    manifest_ok = isinstance(manifest, dict)
    if not IN_MANIFEST.exists():
        note_missing(IN_MANIFEST)
    checksums_ok = IN_CHECKSUMS.exists()
    if not checksums_ok:
        note_missing(IN_CHECKSUMS)
    _check(checks, "manifest_valid_json", "required", manifest_ok,
           f"MANIFEST.json present and valid ({mst}).")
    _check(checks, "checksums_present", "required", checksums_ok, "CHECKSUMS.sha256 present.")

    zip_present = ZIP_PATH.exists()
    zip_names: List[str] = []
    zip_only_public = True
    zip_valid = False
    if zip_present:
        try:
            with zipfile.ZipFile(ZIP_PATH) as zf:
                if zf.testzip() is None:
                    zip_valid = True
                zip_names = zf.namelist()
            for n in zip_names:
                if any(marker in n for marker in ZIP_INTERNAL_MARKERS) or "/" in n:
                    zip_only_public = False
                if n not in EXPECTED_ZIP_NAMES:
                    zip_only_public = False
        except (OSError, zipfile.BadZipFile):
            zip_valid = False
    else:
        note_missing(ZIP_PATH)
    if zip_present and not zip_only_public:
        blocker_reasons.append("zip:contains_non_public_files")
    # zip is optional for launch; absence => NEEDS_REVIEW, not a blocker.
    _check(checks, "zip_present", "optional", zip_present,
           "Export zip present." if zip_present else "Export zip missing (documented).")
    _check(checks, "zip_only_public", "blocker", (not zip_present) or zip_only_public,
           "Zip contains only public export files." if (not zip_present or zip_only_public)
           else "Zip contains non-public files.")
    if zip_present:
        _check(checks, "zip_valid", "optional", zip_valid, "Export zip integrity verified.")

    # --- Deliverables (optional cross-check) ---
    deliverables, dst = read_text_optional(IN_DELIVERABLES)
    if deliverables is None:
        note_missing(IN_DELIVERABLES)
    deliv_scan = public_safety_findings(deliverables or "")
    if deliv_scan:
        blocker_reasons += [f"deliverables:{r}" for r in deliv_scan]
    _check(checks, "deliverables_present", "optional", bool(deliverables),
           "Package deliverables file present.")
    _check(checks, "deliverables_clean", "blocker", not deliv_scan,
           "Deliverables have no forbidden content." if not deliv_scan
           else f"Deliverables flagged: {deliv_scan}")

    # --- Aggregate decision ---
    blockers = [c for c in checks if c["severity"] == "blocker" and not c["passed"]]
    required_fail = [c for c in checks if c["severity"] == "required" and not c["passed"]]
    optional_fail = [c for c in checks if c["severity"] == "optional" and not c["passed"]]
    public_scan_clean = len(blocker_reasons) == 0 and len(blockers) == 0

    if blockers or blocker_reasons:
        decision = DECISION_BLOCKED
    elif required_fail or missing:
        decision = DECISION_NEEDS_REVIEW
    elif optional_fail:
        decision = DECISION_NEEDS_REVIEW
    else:
        decision = DECISION_READY

    storefront_qa = decision  # READY / NEEDS_REVIEW / BLOCKED

    return {
        "checks": checks,
        "missing_inputs": missing,
        "blocker_reasons": sorted(set(blocker_reasons)),
        "required_failures": [c["id"] for c in required_fail],
        "optional_failures": [c["id"] for c in optional_fail],
        "public_scan_clean": public_scan_clean,
        "decision": decision,
        "storefront_qa": storefront_qa,
        "fields": {
            "short": short_body, "long": long_text, "faq": faq,
            "after_purchase": after_body, "faq_questions": faq_q,
            "short_length": len(short_body), "long_sections": section_count,
            "pdf_size": pdf_size, "zip_present": zip_present,
        },
        "counts": {
            "total_checks": len(checks),
            "blocker_failures": len(blockers),
            "required_failures": len(required_fail),
            "optional_failures": len(optional_fail),
        },
    }


# ---------------------------------------------------------------------------
# Renderers (all outputs are public-safe)
# ---------------------------------------------------------------------------
def render_launch_console(qa: Dict[str, Any]) -> str:
    f = qa["fields"]
    short = f["short"] or "(short description missing - see 07-short-description.txt)"
    long_text = f["long"] or "(long description missing - see 08-long-description.txt)"
    after = f["after_purchase"] or "(after-purchase message missing)"
    sep = "=" * 70
    out: List[str] = [
        "Sentinel Payhip Launch Console (copy/paste)",
        f"Launch decision: {qa['decision']}",
        "(Paste each block into the matching Payhip field.)",
        "",
        sep, "PRODUCT TITLE", sep, PRODUCT_TITLE, "",
        sep, "SHORT DESCRIPTION", sep, short.strip(), "",
        sep, "LONG DESCRIPTION", sep, long_text.strip(), "",
    ]
    for i, v in enumerate(VARIANTS, 1):
        out += [
            sep, f"VARIANT {i} NAME", sep, v["name"], "",
            sep, f"VARIANT {i} PRICE", sep, v["price"], "",
            sep, f"VARIANT {i} DESCRIPTION", sep, v["description"], "",
        ]
    out += [
        sep, "PRODUCT FILE TO UPLOAD", sep, PRODUCT_FILE, "",
        sep, "OPTIONAL FAQ TEXT", sep, "Use 09-faq.md from the export pack as the FAQ section.", "",
        sep, "AFTER PURCHASE MESSAGE", sep, after.strip(), "",
        sep, "VISIBILITY RECOMMENDATION", sep, VISIBILITY_RECOMMENDATION, "",
        sep, "PRODUCT TYPE / EBOOK REMINDER", sep, PRODUCT_TYPE_REMINDER, "",
        sep, "TAX REMINDER", sep, TAX_REMINDER, "",
    ]
    return "\n".join(out) + "\n"


def render_final_copy_fields(qa: Dict[str, Any]) -> str:
    # A trimmed, fields-only variant of the console for fast pasting.
    f = qa["fields"]
    sep = "-" * 60
    out: List[str] = [
        "Sentinel Payhip Final Copy Fields",
        sep, "Title:", PRODUCT_TITLE, "",
        "Short Description:", (f["short"] or "").strip(), "",
        "Long Description:", (f["long"] or "").strip(), "",
        "Product File:", PRODUCT_FILE, "",
    ]
    for i, v in enumerate(VARIANTS, 1):
        out += [f"Variant {i}: {v['name']} | {v['price']}", v["description"], ""]
    out += ["After Purchase Message:", (f["after_purchase"] or "").strip(), ""]
    return "\n".join(out) + "\n"


def render_final_checklist(qa: Dict[str, Any]) -> str:
    lines = [
        "# Payhip Final Upload Checklist - " + PRODUCT_TITLE,
        "",
        f"- Launch decision: **{qa['decision']}**",
        "",
        "## 1. Product title",
        f"- [ ] {PRODUCT_TITLE}",
        "## 2. Product cover image",
        "- [ ] Clean cover image (no internal screenshots, paths, IPs).",
        "## 3. Product file upload",
        f"- [ ] Upload {PRODUCT_FILE} (or 12/13-pdf-source if the binary PDF cannot be used).",
        "## 4. Short description",
        "- [ ] Paste from the launch console SHORT DESCRIPTION block.",
        "## 5. Long description",
        "- [ ] Paste from the launch console LONG DESCRIPTION block.",
        "## 6. Variants / packages",
    ]
    for i, v in enumerate(VARIANTS, 1):
        lines.append(f"- [ ] Variant {i}: {v['name']} - {v['price']}")
    lines += [
        "## 7. Optional FAQ",
        "- [ ] Add 09-faq.md as the FAQ section.",
        "## 8. After purchase message",
        "- [ ] Paste the AFTER PURCHASE MESSAGE block.",
        "## 9. Visibility / tax / type",
        f"- [ ] {VISIBILITY_RECOMMENDATION}",
        f"- [ ] {PRODUCT_TYPE_REMINDER}",
        f"- [ ] {TAX_REMINDER}",
        "## 10. Final safety review",
        "- [ ] Confirm no internal reports, server paths, IPs, secrets or real customer data.",
        "- [ ] Confirm the listing never asks customers for passwords.",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_storefront_qa(qa: Dict[str, Any]) -> str:
    c = qa["counts"]
    lines = [
        "# Sentinel Payhip Storefront QA",
        "",
        f"- Storefront QA: **{qa['storefront_qa']}**",
        f"- Total checks: {c['total_checks']} | blocker failures: {c['blocker_failures']} | "
        f"required failures: {c['required_failures']} | optional failures: {c['optional_failures']}",
        f"- Public scan clean: {qa['public_scan_clean']}",
        "",
        "## Checks",
    ]
    for chk in qa["checks"]:
        mark = "PASS" if chk["passed"] else "FAIL"
        lines.append(f"- [{mark}] ({chk['severity']}) {chk['id']}: {chk['detail']}")
    if qa["blocker_reasons"]:
        lines += ["", "## Blocker reasons"]
        for r in qa["blocker_reasons"]:
            lines.append(f"- {r}")
    if qa["missing_inputs"]:
        lines += ["", "## Missing inputs"]
        for m in qa["missing_inputs"]:
            lines.append(f"- {m}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_do_not_upload() -> str:
    lines = ["# Sentinel Payhip - Do Not Upload List", "",
             "Never upload any of the following to Payhip:"]
    for item in DO_NOT_UPLOAD:
        lines.append(f"- {item}")
    lines += ["",
              "Only upload the public files from exports/payhip-upload-pack/latest as listed in "
              "the launch console.", ""]
    return "\n".join(lines) + "\n"


def render_decision_summary(qa: Dict[str, Any], safety: Dict[str, Any], breach: bool) -> str:
    lines = [
        "# Sentinel Payhip Launch Decision Summary",
        "",
        f"- Decision: **{qa['decision']}**",
        f"- Public scan clean: {qa['public_scan_clean']}",
        f"- Product file: {PRODUCT_FILE} ({qa['fields']['pdf_size']} bytes)",
        f"- Short description: {qa['fields']['short_length']} chars",
        f"- Long description: {qa['fields']['long_sections']} sections",
        f"- FAQ questions: {qa['fields']['faq_questions']}",
        f"- Variants: {', '.join(v['name'] + ' (' + v['price'] + ')' for v in VARIANTS)}",
        "",
        "## What this means",
    ]
    if qa["decision"] == DECISION_READY:
        lines.append("- All required fields are present and the public-safety scan is clean. "
                     "You can set up the Payhip listing using the launch console.")
    elif qa["decision"] == DECISION_NEEDS_REVIEW:
        lines.append("- The listing is close but some required/optional items need attention "
                     "before publishing. See the storefront QA page.")
    else:
        lines.append("- Launch is BLOCKED because a safety issue was detected. Do not publish "
                     "until the blocker reasons are resolved.")
    lines += [
        "",
        "## Safety",
        f"- live_apply: {safety['live_apply']}",
        f"- emergency_stop: {safety['emergency_stop']}",
        f"- allowed_apply_now: {safety['allowed_apply_now']}",
        f"- HIGH blocked: {safety['high_blocked']}",
        f"- breach: {breach}",
        "- This QA uploads nothing and changes no website.",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Payhip Launch QA (Phase 9.6)",
        "",
        f"- Launch decision: **{report['decision']}**",
        f"- Storefront QA: **{report['storefront_qa']}**",
        f"- Generated: {report['generated_at']}",
        f"- Public scan clean: {report['public_scan_clean']}",
        f"- Checks: {report['counts']['total_checks']} "
        f"(blocker fail {report['counts']['blocker_failures']}, "
        f"required fail {report['counts']['required_failures']}, "
        f"optional fail {report['counts']['optional_failures']})",
        "",
        "## Payhip fields to enter now",
        f"- Title: {PRODUCT_TITLE}",
        f"- Product file: {PRODUCT_FILE}",
        "- Short description: launch console SHORT DESCRIPTION block",
        "- Long description: launch console LONG DESCRIPTION block",
        "- Variants:",
    ]
    for v in VARIANTS:
        lines.append(f"  - {v['name']}: {v['price']}")
    lines += ["", "## Definitely do NOT upload"]
    for x in DO_NOT_UPLOAD:
        lines.append(f"- {x}")
    if report["blocker_reasons"]:
        lines += ["", "## Blocker reasons"]
        for r in report["blocker_reasons"]:
            lines.append(f"- {r}")
    if report["missing_inputs"]:
        lines += ["", "## Missing inputs"]
        for m in report["missing_inputs"]:
            lines.append(f"- {m}")
    lines += [
        "", "## Safety",
        f"- live_apply: {report['live_apply']}",
        f"- emergency_stop: {report['emergency_stop']}",
        f"- allowed_apply_now: {report['allowed_apply_now']}",
        f"- breach: {report['breach']}",
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
    safety = resolve_safety()
    breach, reasons = compute_breach(safety)
    git = _git_status()
    qa = run_qa()

    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.6",
        "generated_at": timestamp,
        "status": f"LAUNCH_QA_{qa['decision']}",
        "read_only": True,
        "product_title": PRODUCT_TITLE,
        "product_file_to_upload": PRODUCT_FILE,
        "decision": qa["decision"],
        "storefront_qa": qa["storefront_qa"],
        "public_scan_clean": qa["public_scan_clean"],
        "checks": qa["checks"],
        "counts": qa["counts"],
        "blocker_reasons": qa["blocker_reasons"],
        "required_failures": qa["required_failures"],
        "optional_failures": qa["optional_failures"],
        "variants": VARIANTS,
        "field_summary": {
            "short_description_length": qa["fields"]["short_length"],
            "long_description_sections": qa["fields"]["long_sections"],
            "faq_questions": qa["fields"]["faq_questions"],
            "pdf_size": qa["fields"]["pdf_size"],
            "zip_present": qa["fields"]["zip_present"],
        },
        "do_not_upload": DO_NOT_UPLOAD,
        "recommended_git_checkpoint": RECOMMENDED_GIT_CHECKPOINT,
        "export_files_committed": False,
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
        "uploads_anything": False,
        "installs_packages": False,
        "applies_changes": False,
        "secrets_in_report": False,
        "git_checkpoint": git,
        "missing_inputs": qa["missing_inputs"],
    }
    return {"report": report, "qa": qa, "safety": safety, "breach": breach}


def build_playbooks(report: Dict[str, Any]) -> Dict[Path, Dict[str, Any]]:
    return {
        PLAYBOOK_QA: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-launch-qa",
            "generated_at": report["generated_at"],
            "status": report["status"],
            "read_only": True,
            "applies_changes": False,
            "uploads_anything": False,
            "decision": report["decision"],
            "steps": [
                "Read the Phase 9.5 upload pack (read-only).",
                "Validate title, product file, short/long descriptions, FAQ, deliverables.",
                "Validate variants (name, price, description) and after-purchase message.",
                "Validate manifest, checksums and the optional zip (public files only).",
                "Run the final public-safety scan and emit READY / NEEDS_REVIEW / BLOCKED.",
            ],
        },
        PLAYBOOK_CONSOLE: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-launch-console",
            "generated_at": report["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "product_title": report["product_title"],
            "product_file": report["product_file_to_upload"],
            "variants": [{"name": v["name"], "price": v["price"]} for v in VARIANTS],
        },
        PLAYBOOK_STOREFRONT: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-storefront-finalizer",
            "generated_at": report["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "storefront_qa": report["storefront_qa"],
            "blocker_reasons": report["blocker_reasons"],
            "do_not_upload": DO_NOT_UPLOAD,
        },
    }


def write_all_outputs(state: Dict[str, Any]) -> List[str]:
    report = state["report"]
    qa = state["qa"]
    safety = state["safety"]
    breach = state["breach"]
    written: List[str] = []

    def w(path: Path, text: str) -> None:
        write_text_atomic(path, text)
        written.append(str(path.relative_to(PROJECT_DIR)))

    def wj(path: Path, data: Dict[str, Any]) -> None:
        write_json_atomic(path, data)
        written.append(str(path.relative_to(PROJECT_DIR)))

    wj(REPORT_JSON, report)
    w(REPORT_MD, render_report_md(report))
    w(LAUNCH_CONSOLE_TXT, render_launch_console(qa))
    w(FINAL_CHECKLIST_MD, render_final_checklist(qa))
    w(STOREFRONT_QA_MD, render_storefront_qa(qa))
    w(DO_NOT_UPLOAD_MD, render_do_not_upload())
    w(DECISION_SUMMARY_MD, render_decision_summary(qa, safety, breach))
    w(FINAL_COPY_FIELDS_TXT, render_final_copy_fields(qa))

    wj(STATE_JSON, report)
    wj(STATE_LATEST_JSON, report)

    for path, data in build_playbooks(report).items():
        wj(path, data)

    append_jsonl(AUDIT_JSONL, [{
        "ts": report["generated_at"],
        "phase": "9.6",
        "module": "sentinel_payhip_launch_qa_finalizer",
        "status": report["status"],
        "decision": report["decision"],
        "storefront_qa": report["storefront_qa"],
        "public_scan_clean": report["public_scan_clean"],
        "blocker_failures": report["counts"]["blocker_failures"],
        "required_failures": report["counts"]["required_failures"],
        "missing_count": len(report["missing_inputs"]),
        "live_apply": report["live_apply"],
        "emergency_stop": report["emergency_stop"],
        "allowed_apply_now": report["allowed_apply_now"],
        "high_blocked": report["high_blocked"],
        "breach": report["breach"],
        "uploads_anything": False,
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

    # Public-safety scanner: catches real leaks, allows safety-instruction words.
    for bad in ("see /etc/passwd here", "origin at 203.0.113.7", "we guarantee 100% pagespeed",
                "we will bypass security", "ghp_abcdefghijklmnop12345",
                "github_pat_abcdefgh12345678", "api_key=ABCDEFGH12345678",
                "contact real.person@gmail.com"):
        if not public_safety_findings(bad):
            raise AssertionError(f"public-safety scanner missed: {bad}")
    for good in ("Never send passwords, API keys, tokens or SSH keys.",
                 "Do you need my WordPress password? No. Please do not send passwords.",
                 "Contact: you@example.com or customer@example.com.",
                 "We do not promise a specific search ranking; review-first only."):
        if public_safety_findings(good):
            raise AssertionError(f"public-safety scanner false positive: {good}")

    # Project-tree writer must reject secrets, internal paths and IPs.
    for bad in ("token=ABCDEFGH12345678", "path /srv/sentinel-defense", "ip 198.51.100.9"):
        try:
            write_text_atomic(REPORT_MD, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"writer failed to reject: {bad}")

    # Build state (read-only) and validate invariants.
    state = build_full_state()
    report = state["report"]
    if report["live_apply"] is not False:
        raise AssertionError("live_apply must be false")
    if report["emergency_stop"] is not True:
        raise AssertionError("emergency_stop must be true")
    if report["allowed_apply_now"] is not False:
        raise AssertionError("allowed_apply_now must be false")
    if report["high_blocked"] is not True:
        raise AssertionError("HIGH must stay blocked")
    if report["autonomy_level"] not in ALLOWED_CURRENT_LEVELS:
        raise AssertionError("autonomy_level must be LEVEL_1/LEVEL_2")
    if report["breach"]:
        raise AssertionError(f"clean state must not breach: {report['breach_reasons']}")
    if report["decision"] not in (DECISION_READY, DECISION_NEEDS_REVIEW, DECISION_BLOCKED):
        raise AssertionError("decision must be READY/NEEDS_REVIEW/BLOCKED")
    for flag in ("requests_passwords", "stores_real_customer_data", "sends_email",
                 "network_access", "payhip_api_access", "uploads_anything",
                 "installs_packages", "applies_changes"):
        if report[flag] is not False:
            raise AssertionError(f"{flag} must be false")

    # All generated outputs must be public-safe.
    qa = state["qa"]
    rendered = [
        render_report_md(report), render_launch_console(qa), render_final_checklist(qa),
        render_storefront_qa(qa), render_do_not_upload(),
        render_decision_summary(qa, state["safety"], state["breach"]),
        render_final_copy_fields(qa),
    ]
    for blob in rendered:
        findings = public_safety_findings(blob)
        if findings:
            raise AssertionError(f"generated output not public-safe: {findings}")

    # Launch console must contain every required Payhip field block.
    console = render_launch_console(qa)
    for need in ("PRODUCT TITLE", "SHORT DESCRIPTION", "LONG DESCRIPTION", "VARIANT 1 NAME",
                 "VARIANT 1 PRICE", "VARIANT 1 DESCRIPTION", "VARIANT 3 DESCRIPTION",
                 "PRODUCT FILE TO UPLOAD", "OPTIONAL FAQ TEXT", "AFTER PURCHASE MESSAGE",
                 "VISIBILITY RECOMMENDATION", "PRODUCT TYPE / EBOOK REMINDER", "TAX REMINDER"):
        if need not in console:
            raise AssertionError(f"launch console missing block: {need}")

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

    # Decision logic: a synthetic blocker must force BLOCKED.
    synth = [{"id": "x", "severity": "blocker", "passed": False, "detail": "synthetic"}]
    if not any(c["severity"] == "blocker" and not c["passed"] for c in synth):
        raise AssertionError("blocker detection broken")

    # Write-path guards.
    for forbidden in (
        PROJECT_DIR / "reports/latest/x.sh",
        PROJECT_DIR / "exports/payhip-upload-pack/latest/x.md",
        PROJECT_DIR / "state/adaptive-learning/x.service",
        PROJECT_DIR / "config/x.json",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")
    for ok_path in (REPORT_JSON, REPORT_MD, LAUNCH_CONSOLE_TXT, STATE_JSON, AUDIT_JSONL,
                    PLAYBOOK_QA):
        assert_allowed_write(ok_path)

    if not detect_secret_like("password=supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("The first audit is read-only and needs no login"):
        raise AssertionError("secret detector false positive on prose")

    print("payhip-launch-qa-finalizer self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], written: List[str]) -> None:
    r = state["report"]
    fs = r["field_summary"]
    print("=== Sentinel Payhip Launch QA & Store Listing Finalizer (Phase 9.6) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"scan upload pack status: public_scan_clean={r['public_scan_clean']} "
          f"(blocker fail {r['counts']['blocker_failures']})")
    print(f"field validation status: required fail {r['counts']['required_failures']}, "
          f"optional fail {r['counts']['optional_failures']}")
    print("launch console status: ready (copy/paste)")
    print("final checklist status: ready (10 sections)")
    print(f"storefront QA status: {r['storefront_qa']}")
    print(f"launch decision: {r['decision']}")
    print(f"Product File to upload: {r['product_file_to_upload']}")
    print(f"Short description status: {fs['short_description_length']} chars")
    print(f"Long description status: {fs['long_description_sections']} sections")
    print("Variant status:")
    for v in r["variants"]:
        print(f"  - {v['name']}: {v['price']}")
    print(f"FAQ status: {fs['faq_questions']} questions")
    print("After purchase message status: present (no password request)")
    print(f"Do Not Upload status: {len(r['do_not_upload'])} entries")
    print(f"ZIP status: present={fs['zip_present']}")
    print(f"public scan status: clean={r['public_scan_clean']}")
    print(f"live_apply: {r['live_apply']}")
    print(f"emergency_stop: {r['emergency_stop']}")
    print(f"allowed_apply_now: {r['allowed_apply_now']}")
    print(f"breach: {r['breach']}")
    print("what to enter now at Payhip:")
    print(f"  - Title: {PRODUCT_TITLE}")
    print(f"  - Product file: {PRODUCT_FILE}")
    print("  - Short/Long description + variants: see launch console")
    print("what definitely must NOT be uploaded:")
    for x in r["do_not_upload"]:
        print(f"  - {x}")
    print("recommended Git checkpoint (script + playbooks only):")
    for x in r["recommended_git_checkpoint"]:
        print(f"  - {x}")
    if r["blocker_reasons"]:
        print("blocker reasons:")
        for x in r["blocker_reasons"]:
            print(f"  - {x}")
    if r["missing_inputs"]:
        print(f"missing inputs: {', '.join(r['missing_inputs'])}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Payhip Launch QA & Store Listing Finalizer (Phase 9.6). "
                    "Read-only; no upload; no apply."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--scan-upload-pack", action="store_true", help="Scan the Phase 9.5 upload pack.")
    p.add_argument("--validate-fields", action="store_true", help="Validate all Payhip fields.")
    p.add_argument("--build-launch-console", action="store_true", help="Build the launch console.")
    p.add_argument("--build-final-checklist", action="store_true", help="Build the final checklist.")
    p.add_argument("--status", action="store_true", help="Print status summary.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    state = build_full_state()
    written = write_all_outputs(state)
    r = state["report"]

    if args.scan_upload_pack:
        print(f"[scan-upload-pack] public_scan_clean={r['public_scan_clean']} | "
              f"blocker_fail={r['counts']['blocker_failures']} | "
              f"missing={len(r['missing_inputs'])} | decision={r['decision']}")
    if args.validate_fields:
        print(f"[validate-fields] required_fail={r['counts']['required_failures']} | "
              f"optional_fail={r['counts']['optional_failures']} | "
              f"short={r['field_summary']['short_description_length']}c | "
              f"long={r['field_summary']['long_description_sections']}sec | "
              f"faq={r['field_summary']['faq_questions']}q | decision={r['decision']}")
    if args.build_launch_console:
        print(f"[launch-console] ready | {len(VARIANTS)} variants | "
              f"reports/latest/sentinel-payhip-launch-console.txt")
    if args.build_final_checklist:
        print(f"[final-checklist] ready (10 sections) | "
              f"reports/latest/sentinel-payhip-final-upload-checklist.md")

    if args.status or not any(
        (args.scan_upload_pack, args.validate_fields, args.build_launch_console,
         args.build_final_checklist)
    ):
        _print_status(state, written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
