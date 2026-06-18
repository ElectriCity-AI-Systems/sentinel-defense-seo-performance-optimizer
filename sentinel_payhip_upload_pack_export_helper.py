#!/usr/bin/env python3
"""Sentinel Payhip Upload Pack Export Helper (Phase 9.5).

A safe, *local* export helper. It assembles the Phase 9.4 public client assets
into a clean Payhip upload folder containing only public, customer-facing files
that can be uploaded to Payhip or copied into the product listing.

It is read-only with respect to production: there is no apply mode, no website
change, no autopilot, no timer installation, no SFTP/DB/Cloudflare/Nginx/
WordPress write, no network access, no Payhip API access and no e-mail send.
It only reads existing public assets and writes a local export folder plus a
manifest, checksums, an upload checklist and copy/paste field text.

Export files are intentionally *not* part of any git checkpoint; only this
script and its playbooks should be committed later.

Invariants surfaced and enforced:
    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    HIGH stays blocked
    no secrets, no internal server paths or IPs in public export files.
"""

from __future__ import annotations

import argparse
import hashlib
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
# Export layout
# ---------------------------------------------------------------------------
EXPORT_BASE = PROJECT_DIR / "exports/payhip-upload-pack"
EXPORT_LATEST = EXPORT_BASE / "latest"
ZIP_PATH = EXPORT_BASE / "sentinel-payhip-upload-pack-latest.zip"

# Project-tree report / state / audit / playbook outputs
REPORT_JSON = PROJECT_DIR / "reports/latest/sentinel-payhip-upload-pack-export.json"
REPORT_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-upload-pack-export.md"
UPLOAD_CHECKLIST_MD = PROJECT_DIR / "reports/latest/sentinel-payhip-upload-checklist.md"
COPY_FIELDS_TXT = PROJECT_DIR / "reports/latest/sentinel-payhip-copy-fields.txt"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_JSON = STATE_DIR / "sentinel_payhip_upload_pack_export_helper.json"
STATE_LATEST_JSON = STATE_DIR / "latest_payhip_upload_pack_export_helper.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-payhip-upload-pack-export-helper.jsonl"

PLAYBOOK_EXPORT = PROJECT_DIR / "playbooks/sentinel-payhip-upload-pack-export.playbook.json"
PLAYBOOK_COPY_FIELDS = PROJECT_DIR / "playbooks/sentinel-payhip-copy-fields.playbook.json"
PLAYBOOK_CHECKLIST = PROJECT_DIR / "playbooks/sentinel-payhip-upload-checklist.playbook.json"

ALLOWED_WRITE_ROOTS = (
    EXPORT_BASE,
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

SCHEMA_VERSION = "payhip-upload-pack-export-helper-9.5"

LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
LEVEL_2 = "LEVEL_2_LOW_RISK_PREP_PREVIEW"
ALLOWED_CURRENT_LEVELS = {LEVEL_1, LEVEL_2}
DEFAULT_CURRENT_LEVEL = LEVEL_2

# ---------------------------------------------------------------------------
# Inputs (read-only, public source assets from Phase 9.4)
# ---------------------------------------------------------------------------
SAFETY_SOURCE_JSON = STATE_DIR / "latest_payhip_public_client_assets.json"

# (export_name, source_relpath, kind) — kind: "binary" | "copy" | "derive_txt"
EXPORT_PLAN: List[Tuple[str, str, str]] = [
    ("01-service-access-instructions.pdf",
     "reports/latest/sentinel-payhip-service-access-instructions.pdf", "binary"),
    ("02-product-file-final.txt",
     "reports/latest/sentinel-payhip-product-file-final.txt", "copy"),
    ("03-product-file-final.html",
     "reports/latest/sentinel-payhip-product-file-final.html", "copy"),
    ("04-public-intake-form.md",
     "reports/latest/sentinel-payhip-public-intake-form.md", "copy"),
    ("05-public-safety-agreement.md",
     "reports/latest/sentinel-payhip-public-safety-agreement.md", "copy"),
    ("06-public-service-overview.md",
     "reports/latest/sentinel-payhip-public-service-overview.md", "copy"),
    ("07-short-description.txt",
     "reports/latest/sentinel-payhip-short-description.md", "derive_txt"),
    ("08-long-description.txt",
     "reports/latest/sentinel-payhip-long-description.md", "derive_txt"),
    ("09-faq.md",
     "reports/latest/sentinel-payhip-faq.md", "copy"),
    ("10-package-deliverables.md",
     "reports/latest/sentinel-payhip-package-deliverables.md", "copy"),
    ("11-after-purchase-message.md",
     "reports/latest/sentinel-payhip-after-purchase-message.md", "copy"),
    ("12-pdf-source.md",
     "reports/latest/sentinel-payhip-pdf-source.md", "copy"),
    ("13-pdf-source.html",
     "reports/latest/sentinel-payhip-pdf-source.html", "copy"),
]

# Source files only read for description bodies / provenance.
SHORT_DESCRIPTION_SOURCE = PROJECT_DIR / "reports/latest/sentinel-payhip-short-description.md"
LONG_DESCRIPTION_SOURCE = PROJECT_DIR / "reports/latest/sentinel-payhip-long-description.md"

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
# Hard-forbidden public token patterns (secrets / aggressive claims).
FORBIDDEN_PUBLIC_TOKENS_RE = re.compile(
    r"(?i)(begin private key|github_pat_|ghp_|\bsk-[A-Za-z0-9]{8,}|\bAIza[A-Za-z0-9_\-]{8,}|"
    r"password:|passwd|\.env\b)"
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
        raise ValueError(f"Refusing to write outside allowed export roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install/secret artifact: {path}")
    if any(token in str(path) for token in FORBIDDEN_INSTALL_PATH_TOKENS):
        raise ValueError(f"Refusing to write systemd/crontab path: {path}")


def public_safety_findings(blob: str) -> List[str]:
    """Return a list of reasons a blob is NOT safe to publish (empty == safe)."""
    reasons: List[str] = []
    if INTERNAL_PATH_RE.search(blob):
        reasons.append("internal_server_path")
    if IPV4_RE.search(blob):
        reasons.append("ip_address")
    if FORBIDDEN_PUBLIC_TOKENS_RE.search(blob):
        reasons.append("forbidden_secret_token")
    if DISALLOWED_CLAIMS_RE.search(blob):
        reasons.append("disallowed_marketing_claim")
    for m in EMAIL_RE.findall(blob):
        if m.rsplit("@", 1)[-1].lower() not in ALLOWED_EMAIL_DOMAINS:
            reasons.append(f"real_email:{m}")
    return reasons


def _assert_no_secret_blob(path: Path, blob: str, allow_hex: bool = False) -> None:
    if SECRET_ASSIGNMENT_RE.search(blob):
        raise ValueError(f"Refusing to write secret-like content to {path}")
    if not allow_hex and LONG_HEX_RE.search(blob):
        raise ValueError(f"Refusing to write long-hex content to {path}")
    for m in EMAIL_RE.findall(blob):
        if m.rsplit("@", 1)[-1].lower() not in ALLOWED_EMAIL_DOMAINS:
            raise ValueError(f"Refusing to write real-looking e-mail address to {path}: {m}")


def write_text_atomic(path: Path, content: str) -> None:
    """Project-tree writer (reports/state/audit/playbooks): strict, no long hex."""
    assert_allowed_write(path)
    _assert_no_secret_blob(path, content, allow_hex=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def write_export_text(path: Path, content: str, allow_hex: bool = False) -> None:
    """Export-folder writer: public-safe + secret-safe; allow_hex for checksums/manifest."""
    assert_allowed_write(path)
    findings = public_safety_findings(content)
    if findings:
        raise ValueError(f"Refusing to write non-public content to export file {path}: {findings}")
    _assert_no_secret_blob(path, content, allow_hex=allow_hex)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_export_bytes(path: Path, data: bytes, scan_text: str) -> None:
    """Export-folder binary writer (PDF). scan_text is the decoded content scanned."""
    assert_allowed_write(path)
    findings = public_safety_findings(scan_text)
    if findings:
        raise ValueError(f"Refusing to write non-public binary to export file {path}: {findings}")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def append_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            blob = json.dumps(record, ensure_ascii=False, sort_keys=True)
            _assert_no_secret_blob(path, blob, allow_hex=False)
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
# Public listing constants (Payhip fields)
# ---------------------------------------------------------------------------
SERVICE_TITLE = "Sentinel Security, SEO & Performance Safe Optimization"
PAYHIP_PRODUCT_FILE = "01-service-access-instructions.pdf"

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

SHORT_DESCRIPTION_FALLBACK = (
    "Sentinel is a safety-first Security, SEO and Performance service for WordPress and other "
    "websites. We start with read-only diagnosis, classify risk, and deliver clear review and "
    "recommendations with an owner approval step. Controlled improvements are review-first and "
    "owner-approved - no blind autopilot, no promised rankings."
)
LONG_DESCRIPTION_FALLBACK = (
    "Sentinel is a safety-first service for Security, SEO and Performance. It starts read-only, "
    "diagnoses the real signals, classifies risk, and proposes clear, reviewed improvements. "
    "Nothing high-risk is applied on its own; you stay the owner of every final approval and any "
    "controlled change uses backup, healthcheck and rollback. Choose Audit, Safe Optimization, "
    "or Monitoring & Improvement."
)
AFTER_PURCHASE_FALLBACK = (
    "Thank you for your purchase. Please complete the short intake form and send your website "
    "URL, selected package and main goal. The first audit is read-only, so please do not send "
    "any passwords. Questions? Contact: your contact email."
)
FAQ_FALLBACK = (
    "Q: Is this an automatic repair bot? A: No. Sentinel starts read-only, classifies risk and "
    "proposes reviewed recommendations. Q: Do you need my password? A: No. The first audit is "
    "read-only. Please never send passwords."
)

DO_UPLOAD = [
    "01-service-access-instructions.pdf (Payhip Product File)",
    "02/03-product-file-final.txt/.html (alternate product file formats, optional)",
    "04-public-intake-form.md (public, no credential fields)",
    "05-public-safety-agreement.md",
    "06-public-service-overview.md",
    "09-faq.md (optional FAQ section)",
    "10-package-deliverables.md",
    "11-after-purchase-message.md (use as Payhip after-purchase note)",
    "12/13-pdf-source.md/.html (only if you cannot upload the binary PDF)",
]
DO_NOT_UPLOAD = [
    "Internal Sentinel reports (reports/latest internals, master report, diagnostics)",
    "State files, audit logs or playbooks",
    "Cloudflare rule details or security logs",
    "Server paths, IP addresses, hostnames or private PC details",
    "Secrets, API keys, tokens, private keys or environment/config secret files",
    "Real customer data or any customer passwords",
]
RECOMMENDED_GIT_CHECKPOINT = [
    "sentinel_payhip_upload_pack_export_helper.py",
    "playbooks/sentinel-payhip-upload-pack-export.playbook.json",
    "playbooks/sentinel-payhip-copy-fields.playbook.json",
    "playbooks/sentinel-payhip-upload-checklist.playbook.json",
]


# ---------------------------------------------------------------------------
# Inputs / git / safety
# ---------------------------------------------------------------------------
def _strip_md_heading(text: str) -> str:
    """Drop a leading markdown title / blank lines, keep the body."""
    out: List[str] = []
    started = False
    for ln in text.splitlines():
        if not started and (ln.strip() == "" or ln.lstrip().startswith("#")):
            continue
        started = True
        out.append(ln)
    body = "\n".join(out).strip()
    return body + "\n" if body else ""


def _read_source_body(path: Path, fallback: str) -> str:
    if path.exists() and not SENSITIVE_NAME_RE.search(path.name):
        try:
            stripped = _strip_md_heading(path.read_text(encoding="utf-8"))
            if stripped.strip():
                return stripped
        except OSError:
            pass
    return fallback.rstrip() + "\n"


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
    src, _ = read_optional_json(SAFETY_SOURCE_JSON)

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
        reasons.append("upstream public-assets reports breach")
    return (len(reasons) > 0), reasons


# ---------------------------------------------------------------------------
# Export preparation (read sources, scan, checksum) — no writes
# ---------------------------------------------------------------------------
def prepare_export_items() -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
    missing: List[str] = []
    for export_name, source_rel, kind in EXPORT_PLAN:
        source = PROJECT_DIR / source_rel
        entry: Dict[str, Any] = {
            "export_name": export_name,
            "source": source_rel,
            "kind": kind,
            "status": "missing",
            "size_bytes": 0,
            "sha256": "",
            "reasons": [],
        }
        if not source.exists() or SENSITIVE_NAME_RE.search(source.name):
            entry["status"] = "missing"
            missing.append(source_rel)
            items.append(entry)
            continue
        try:
            raw = source.read_bytes()
        except OSError:
            entry["status"] = "read_error"
            missing.append(source_rel)
            items.append(entry)
            continue

        if kind == "binary":
            scan_text = raw.decode("latin-1", "ignore")
            findings = public_safety_findings(scan_text)
            payload: Any = raw
        elif kind == "derive_txt":
            text = _strip_md_heading(raw.decode("utf-8", "replace"))
            findings = public_safety_findings(text)
            payload = text
        else:  # copy
            text = raw.decode("utf-8", "replace")
            findings = public_safety_findings(text)
            payload = text

        if findings:
            entry["status"] = "blocked"
            entry["reasons"] = findings
            items.append(entry)
            continue

        data_bytes = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        entry["status"] = "copied"
        entry["size_bytes"] = len(data_bytes)
        entry["sha256"] = hashlib.sha256(data_bytes).hexdigest()
        entry["sha256_short"] = entry["sha256"][:16]
        entry["_payload"] = payload  # bytes or text; stripped before serialization
        items.append(entry)
    return items, missing


# ---------------------------------------------------------------------------
# Generated export documents
# ---------------------------------------------------------------------------
def render_readme_first() -> str:
    lines = [
        "# README - Sentinel Payhip Upload Pack",
        "",
        "## What this folder is",
        "This folder is a ready-to-use export of the public, customer-facing files for the "
        "Payhip product \"" + SERVICE_TITLE + "\". Everything here is safe to publish.",
        "",
        "## What to upload as the Payhip Product File",
        f"- Upload **{PAYHIP_PRODUCT_FILE}** as the downloadable Product File.",
        "- If you cannot upload the binary PDF, use 12-pdf-source.md or 13-pdf-source.html instead.",
        "",
        "## What to put in the Short Description",
        "- Use **07-short-description.txt** for the Payhip short description.",
        "",
        "## What to put in the Long Description",
        "- Use **08-long-description.txt** for the Payhip long/full description.",
        "",
        "## Optional FAQ",
        "- Use **09-faq.md** as an optional FAQ section in the listing.",
        "",
        "## Copy/paste helper",
        "- **PAYHIP_COPY_FIELDS.txt** has every field (title, descriptions, variants, prices) "
        "ready to paste.",
        "- **PAYHIP_UPLOAD_CHECKLIST.md** walks through the Payhip product setup step by step.",
        "",
        "## Important safety notes",
        "- Do NOT upload internal Sentinel reports, state, audit logs or playbooks.",
        "- Do NOT ask customers for passwords. The first audit is read-only and needs no login.",
        "- MANIFEST.json and CHECKSUMS.sha256 are for your own integrity check; they are optional "
        "to upload.",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_upload_checklist() -> str:
    v = VARIANTS
    lines = [
        "# Payhip Upload Checklist - " + SERVICE_TITLE,
        "",
        "## 1. Product title",
        f"- [ ] Set the title to: {SERVICE_TITLE}",
        "",
        "## 2. Product cover image",
        "- [ ] Add a clean cover image (no screenshots of internal reports, logs, paths or IPs).",
        "",
        "## 3. Product file upload",
        f"- [ ] Upload **{PAYHIP_PRODUCT_FILE}** as the downloadable file.",
        "- [ ] If the binary PDF cannot be used, upload 12-pdf-source.md or 13-pdf-source.html.",
        "",
        "## 4. Short description",
        "- [ ] Paste the text from 07-short-description.txt (or the Short Description in "
        "PAYHIP_COPY_FIELDS.txt).",
        "",
        "## 5. Long description",
        "- [ ] Paste the text from 08-long-description.txt (or the Long Description in "
        "PAYHIP_COPY_FIELDS.txt).",
        "",
        "## 6. Variants / packages",
    ]
    for i, item in enumerate(v, 1):
        lines.append(f"- [ ] Variant {i}: {item['name']}")
    lines += [
        "",
        "## 7. Price suggestions",
    ]
    for item in v:
        lines.append(f"- [ ] {item['name']}: {item['price']}")
    lines += [
        "",
        "## 8. Visibility",
        "- [ ] Set the product visible / published once everything is reviewed.",
        "",
        "## 9. Tax / ebook settings reminder",
        "- [ ] Check Payhip tax settings and (if relevant) the ebook/PDF stamping option.",
        "",
        "## 10. Final safety review",
        "- [ ] Confirm no internal reports, server paths, IPs, secrets or real customer data "
        "are included.",
        "- [ ] Confirm the listing never asks customers for passwords.",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_copy_fields(short_desc: str, long_desc: str, after_purchase: str, faq: str) -> str:
    sep = "=" * 70
    blocks: List[str] = [
        "Sentinel Payhip Copy/Paste Fields",
        "(Copy each block into the matching Payhip field.)",
        "",
        sep, "PRODUCT TITLE", sep, SERVICE_TITLE, "",
        sep, "SHORT DESCRIPTION", sep, short_desc.strip(), "",
        sep, "LONG DESCRIPTION", sep, long_desc.strip(), "",
    ]
    for i, item in enumerate(VARIANTS, 1):
        blocks += [
            sep, f"VARIANT {i} NAME", sep, item["name"], "",
            sep, f"VARIANT {i} PRICE", sep, item["price"], "",
            sep, f"VARIANT {i} DESCRIPTION", sep, item["description"], "",
        ]
    blocks += [
        sep, "AFTER PURCHASE MESSAGE", sep, after_purchase.strip(), "",
        sep, "FAQ (OPTIONAL SECTION)", sep, faq.strip(), "",
        sep, "PRODUCT FILE TO UPLOAD", sep, PAYHIP_PRODUCT_FILE, "",
    ]
    return "\n".join(blocks) + "\n"


def render_manifest(items: List[Dict[str, Any]], generated_files: List[Dict[str, Any]],
                    timestamp: str, export_rel: str) -> str:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.5",
        "generated_at": timestamp,
        "export_folder": export_rel,
        "product_title": SERVICE_TITLE,
        "payhip_product_file": PAYHIP_PRODUCT_FILE,
        "copied_files": [
            {"name": it["export_name"], "source": it["source"], "kind": it["kind"],
             "status": it["status"], "size_bytes": it["size_bytes"], "sha256": it["sha256"],
             "reasons": it["reasons"]}
            for it in items
        ],
        "generated_files": generated_files,
        "do_not_upload": DO_NOT_UPLOAD,
    }
    return json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_checksums(all_entries: List[Tuple[str, str]]) -> str:
    lines = [f"{sha}  {name}" for name, sha in all_entries if sha]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Full build
# ---------------------------------------------------------------------------
def build_full_state() -> Dict[str, Any]:
    timestamp = utc_now()
    folder_stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safety = resolve_safety()
    breach, reasons = compute_breach(safety)
    git = _git_status()

    items, missing = prepare_export_items()

    short_desc = _read_source_body(SHORT_DESCRIPTION_SOURCE, SHORT_DESCRIPTION_FALLBACK)
    long_desc = _read_source_body(LONG_DESCRIPTION_SOURCE, LONG_DESCRIPTION_FALLBACK)
    # after-purchase + faq bodies are only used for copy-fields convenience.
    ap_src = PROJECT_DIR / "reports/latest/sentinel-payhip-after-purchase-message.md"
    faq_src = PROJECT_DIR / "reports/latest/sentinel-payhip-faq.md"
    after_purchase = _read_source_body(ap_src, AFTER_PURCHASE_FALLBACK)
    faq_body = _read_source_body(faq_src, FAQ_FALLBACK)
    # Strip code fences from the after-purchase markdown if present.
    after_purchase = after_purchase.replace("```", "").strip() + "\n"

    readme = render_readme_first()
    checklist = render_upload_checklist()
    copy_fields = render_copy_fields(short_desc, long_desc, after_purchase, faq_body)

    copied = [it for it in items if it["status"] == "copied"]
    blocked = [it for it in items if it["status"] == "blocked"]

    generated_files_meta = [
        {"name": "README_FIRST.md"},
        {"name": "PAYHIP_UPLOAD_CHECKLIST.md"},
        {"name": "PAYHIP_COPY_FIELDS.txt"},
        {"name": "MANIFEST.json"},
        {"name": "CHECKSUMS.sha256"},
    ]

    public_scan_clean = len(blocked) == 0
    status = "UPLOAD_PACK_READY_LOCKED"
    if breach:
        status = "UPLOAD_PACK_BREACH"
    elif blocked:
        status = "UPLOAD_PACK_READY_WITH_BLOCKED_FILES"
    elif missing:
        status = "UPLOAD_PACK_PARTIAL_LOCKED"

    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.5",
        "generated_at": timestamp,
        "status": status,
        "read_only": True,
        "product_title": SERVICE_TITLE,
        "payhip_product_file": PAYHIP_PRODUCT_FILE,
        "short_description_file": "07-short-description.txt",
        "long_description_file": "08-long-description.txt",
        "faq_file": "09-faq.md",
        "export_folder_latest": str(EXPORT_LATEST.relative_to(PROJECT_DIR)),
        "export_folder_timestamped": str(
            (EXPORT_BASE / folder_stamp).relative_to(PROJECT_DIR)),
        "zip_path": str(ZIP_PATH.relative_to(PROJECT_DIR)),
        "copied_count": len(copied),
        "blocked_count": len(blocked),
        "missing_count": len(missing),
        "public_asset_scan_clean": public_scan_clean,
        "copied_files": [
            {"name": it["export_name"], "source": it["source"], "status": it["status"],
             "size_bytes": it["size_bytes"], "sha256_short": it.get("sha256_short", "")}
            for it in items
        ],
        "blocked_files": [
            {"name": it["export_name"], "source": it["source"], "reasons": it["reasons"]}
            for it in blocked
        ],
        "generated_files": [g["name"] for g in generated_files_meta],
        "variants": VARIANTS,
        "do_upload": DO_UPLOAD,
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
        "installs_packages": False,
        "applies_changes": False,
        "secrets_in_report": False,
        "git_checkpoint": git,
        "missing_inputs": missing,
    }

    return {
        "report": report,
        "items": items,
        "generated": {
            "readme": readme,
            "checklist": checklist,
            "copy_fields": copy_fields,
            "generated_files_meta": generated_files_meta,
        },
        "folder_stamp": folder_stamp,
        "timestamp": timestamp,
    }


def build_playbooks(report: Dict[str, Any]) -> Dict[Path, Dict[str, Any]]:
    return {
        PLAYBOOK_EXPORT: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-upload-pack-export",
            "generated_at": report["generated_at"],
            "status": report["status"],
            "read_only": True,
            "applies_changes": False,
            "export_files_committed": False,
            "steps": [
                "Read public Phase 9.4 assets (read-only).",
                "Scan every file for server paths, IPs, secrets and forbidden claims.",
                "Copy only safe public files into exports/payhip-upload-pack/latest + timestamp.",
                "Write README, upload checklist, copy fields, manifest and checksums.",
                "Optionally build a zip; never commit export files.",
            ],
            "payhip_product_file": report["payhip_product_file"],
        },
        PLAYBOOK_COPY_FIELDS: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-copy-fields",
            "generated_at": report["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "product_title": report["product_title"],
            "variants": [{"name": v["name"], "price": v["price"]} for v in VARIANTS],
            "short_description_file": report["short_description_file"],
            "long_description_file": report["long_description_file"],
        },
        PLAYBOOK_CHECKLIST: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-payhip-upload-checklist",
            "generated_at": report["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "sections": [
                "Product title", "Product cover image", "Product file upload",
                "Short description", "Long description", "Variants / packages",
                "Price suggestions", "Visibility", "Tax / ebook settings reminder",
                "Final safety review",
            ],
        },
    }


def _write_export_folder(target: Path, state: Dict[str, Any]) -> List[str]:
    """Write all export files into one folder (latest or timestamped). Returns rel paths."""
    written: List[str] = []
    items = state["items"]
    gen = state["generated"]

    checksum_entries: List[Tuple[str, str]] = []
    for it in items:
        if it["status"] != "copied":
            continue
        out = target / it["export_name"]
        payload = it["_payload"]
        if isinstance(payload, bytes):
            write_export_bytes(out, payload, payload.decode("latin-1", "ignore"))
        else:
            write_export_text(out, payload)
        checksum_entries.append((it["export_name"], it["sha256"]))
        written.append(str(out.relative_to(PROJECT_DIR)))

    # Generated documents.
    readme = target / "README_FIRST.md"
    checklist = target / "PAYHIP_UPLOAD_CHECKLIST.md"
    copy_fields = target / "PAYHIP_COPY_FIELDS.txt"
    write_export_text(readme, gen["readme"])
    write_export_text(checklist, gen["checklist"])
    write_export_text(copy_fields, gen["copy_fields"])
    for p, content in ((readme, gen["readme"]), (checklist, gen["checklist"]),
                       (copy_fields, gen["copy_fields"])):
        checksum_entries.append((p.name, hashlib.sha256(content.encode("utf-8")).hexdigest()))
        written.append(str(p.relative_to(PROJECT_DIR)))

    # Manifest (allows hex for sha256).
    manifest_rel = str(target.relative_to(PROJECT_DIR))
    manifest_text = render_manifest(items, gen["generated_files_meta"],
                                    state["timestamp"], manifest_rel)
    manifest_path = target / "MANIFEST.json"
    write_export_text(manifest_path, manifest_text, allow_hex=True)
    checksum_entries.append(("MANIFEST.json",
                             hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()))
    written.append(str(manifest_path.relative_to(PROJECT_DIR)))

    # Checksums file last (contains all sha256 of the other files).
    checksums_text = render_checksums(checksum_entries)
    checksums_path = target / "CHECKSUMS.sha256"
    write_export_text(checksums_path, checksums_text, allow_hex=True)
    written.append(str(checksums_path.relative_to(PROJECT_DIR)))

    return written


def _build_zip(source_folder: Path) -> Tuple[bool, str]:
    """Best-effort zip of the latest export folder using stdlib zipfile."""
    try:
        assert_allowed_write(ZIP_PATH)
        ZIP_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = ZIP_PATH.with_name(f".{ZIP_PATH.name}.tmp")
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(source_folder.iterdir()):
                if f.is_file() and not f.name.startswith("."):
                    zf.write(f, arcname=f.name)
        tmp.replace(ZIP_PATH)
        return True, "ZIP_CREATED"
    except (OSError, zipfile.BadZipFile, ValueError):
        return False, "ZIP_NOT_CREATED"


def write_all_outputs(state: Dict[str, Any]) -> Dict[str, Any]:
    report = state["report"]
    written: List[str] = []

    # Export folders: latest + timestamped.
    timestamped = EXPORT_BASE / state["folder_stamp"]
    written += _write_export_folder(EXPORT_LATEST, state)
    written += _write_export_folder(timestamped, state)

    # Optional ZIP of the latest folder.
    zip_ok, zip_status = _build_zip(EXPORT_LATEST)
    report["zip_created"] = zip_ok
    report["zip_status"] = zip_status
    if zip_ok:
        written.append(str(ZIP_PATH.relative_to(PROJECT_DIR)))

    # Project-tree report twins.
    write_json_atomic(REPORT_JSON, report)
    written.append(str(REPORT_JSON.relative_to(PROJECT_DIR)))
    write_text_atomic(REPORT_MD, render_report_md(report))
    written.append(str(REPORT_MD.relative_to(PROJECT_DIR)))
    write_text_atomic(UPLOAD_CHECKLIST_MD, state["generated"]["checklist"])
    written.append(str(UPLOAD_CHECKLIST_MD.relative_to(PROJECT_DIR)))
    write_text_atomic(COPY_FIELDS_TXT, state["generated"]["copy_fields"])
    written.append(str(COPY_FIELDS_TXT.relative_to(PROJECT_DIR)))

    # State twins.
    write_json_atomic(STATE_JSON, report)
    written.append(str(STATE_JSON.relative_to(PROJECT_DIR)))
    write_json_atomic(STATE_LATEST_JSON, report)
    written.append(str(STATE_LATEST_JSON.relative_to(PROJECT_DIR)))

    # Playbooks.
    for path, data in build_playbooks(report).items():
        write_json_atomic(path, data)
        written.append(str(path.relative_to(PROJECT_DIR)))

    # Audit.
    append_jsonl(AUDIT_JSONL, [{
        "ts": report["generated_at"],
        "phase": "9.5",
        "module": "sentinel_payhip_upload_pack_export_helper",
        "status": report["status"],
        "copied_count": report["copied_count"],
        "blocked_count": report["blocked_count"],
        "missing_count": report["missing_count"],
        "zip_created": zip_ok,
        "public_asset_scan_clean": report["public_asset_scan_clean"],
        "live_apply": report["live_apply"],
        "emergency_stop": report["emergency_stop"],
        "allowed_apply_now": report["allowed_apply_now"],
        "high_blocked": report["high_blocked"],
        "breach": report["breach"],
        "export_files_committed": False,
        "secrets_in_report": False,
    }])
    written.append(str(AUDIT_JSONL.relative_to(PROJECT_DIR)))

    return {"written": written, "zip_ok": zip_ok, "zip_status": zip_status}


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Payhip Upload Pack Export (Phase 9.5)",
        "",
        f"- Status: **{report['status']}**",
        f"- Generated: {report['generated_at']}",
        f"- Export folder: `{report['export_folder_latest']}`",
        f"- Timestamped folder: `{report['export_folder_timestamped']}`",
        f"- ZIP: `{report['zip_path']}`",
        f"- Copied files: {report['copied_count']} | blocked: {report['blocked_count']} | "
        f"missing: {report['missing_count']}",
        f"- Public asset scan clean: {report['public_asset_scan_clean']}",
        "",
        "## Payhip fields",
        f"- Product title: {report['product_title']}",
        f"- Product file: `{report['payhip_product_file']}`",
        f"- Short description: `{report['short_description_file']}`",
        f"- Long description: `{report['long_description_file']}`",
        f"- FAQ (optional): `{report['faq_file']}`",
        "",
        "## Variants / prices",
    ]
    for v in report["variants"]:
        lines.append(f"- {v['name']}: {v['price']}")
    lines += ["", "## What to upload"]
    for x in report["do_upload"]:
        lines.append(f"- {x}")
    lines += ["", "## What NOT to upload"]
    for x in report["do_not_upload"]:
        lines.append(f"- {x}")
    if report["blocked_files"]:
        lines += ["", "## Blocked files (not exported)"]
        for b in report["blocked_files"]:
            lines.append(f"- {b['name']} ({b['source']}): {', '.join(b['reasons'])}")
    if report["missing_inputs"]:
        lines += ["", "## Missing inputs"]
        for m in report["missing_inputs"]:
            lines.append(f"- {m}")
    lines += [
        "", "## Safety",
        f"- live_apply: {report['live_apply']}",
        f"- emergency_stop: {report['emergency_stop']}",
        f"- allowed_apply_now: {report['allowed_apply_now']}",
        f"- HIGH blocked: {report['high_blocked']}",
        f"- breach: {report['breach']}",
        "- Export files are NOT committed; commit only the script and playbooks.",
        "",
        "## Recommended Git checkpoint (script + playbooks only)",
    ]
    for f in report["recommended_git_checkpoint"]:
        lines.append(f"- {f}")
    lines.append("")
    return "\n".join(lines) + "\n"


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
    if allowed_names != {"exports/payhip-upload-pack", "reports/latest",
                         "state/adaptive-learning", "audit", "playbooks"}:
        raise AssertionError(f"unexpected write roots: {allowed_names}")

    for bad in ("/etc/sentinel-defense.env", "deploy.key", "id_rsa", "api-token.json"):
        obj, status = read_optional_json(Path(bad))
        if obj is not None or status not in ("refused_secret_like_path", "not_available"):
            raise AssertionError(f"sensitive path not refused: {bad} -> {status}")

    # Public-safety scanner must catch bad content and pass clean content.
    for bad in ("see /etc/passwd here", "origin at 203.0.113.7", "we guarantee 100% pagespeed",
                "we will bypass security", "password: hunter2value", "github_pat_abcdefgh12345678",
                "ghp_abcdefghijklmnop12345", "contact real.person@gmail.com"):
        if not public_safety_findings(bad):
            raise AssertionError(f"public-safety scanner missed: {bad}")
    for good in ("Use 01-service-access-instructions.pdf as the product file.",
                 "Contact: you@example.com or customer@example.com.",
                 "We do not promise a specific ranking; review-first only."):
        if public_safety_findings(good):
            raise AssertionError(f"public-safety scanner false positive: {good}")

    # Export writer must reject non-public content and long-hex unless allowed.
    test_path = EXPORT_LATEST / "x.md"
    for bad in ("server /srv/sentinel-defense path", "ip 198.51.100.9", "we guarantee 100% rank"):
        try:
            write_export_text(test_path, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"export writer failed to reject: {bad}")
    sha_like = "a" * 64
    try:
        _assert_no_secret_blob(test_path, sha_like, allow_hex=False)
    except ValueError:
        pass
    else:
        raise AssertionError("long-hex must be rejected when allow_hex=False")
    _assert_no_secret_blob(test_path, sha_like, allow_hex=True)  # must not raise

    # Project-tree writer must reject long hex always (no allow_hex path).
    try:
        write_text_atomic(REPORT_MD, "checksum " + ("b" * 40))
    except ValueError:
        pass
    else:
        raise AssertionError("project-tree writer must reject long hex")

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
    if report["export_files_committed"] is not False:
        raise AssertionError("export files must not be committed")
    for flag in ("requests_passwords", "stores_real_customer_data", "sends_email",
                 "network_access", "payhip_api_access", "installs_packages", "applies_changes"):
        if report[flag] is not False:
            raise AssertionError(f"{flag} must be false")

    # Generated export documents must themselves be public-safe.
    for blob in (state["generated"]["readme"], state["generated"]["checklist"],
                 state["generated"]["copy_fields"]):
        findings = public_safety_findings(blob)
        if findings:
            raise AssertionError(f"generated export doc not public-safe: {findings}")

    # Copy fields must contain the required Payhip fields.
    cf = state["generated"]["copy_fields"]
    for need in ("PRODUCT TITLE", "SHORT DESCRIPTION", "LONG DESCRIPTION", "VARIANT 1 NAME",
                 "VARIANT 1 PRICE", "VARIANT 3 DESCRIPTION", "AFTER PURCHASE MESSAGE",
                 "FAQ (OPTIONAL SECTION)"):
        if need not in cf:
            raise AssertionError(f"copy fields missing section: {need}")
    if len(VARIANTS) != 3:
        raise AssertionError("expected 3 Payhip variants")

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
        PROJECT_DIR / "exports/payhip-upload-pack/latest/x.php",
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
    for ok_path in (EXPORT_LATEST / "01-service-access-instructions.pdf",
                    EXPORT_LATEST / "MANIFEST.json", EXPORT_LATEST / "CHECKSUMS.sha256",
                    ZIP_PATH, REPORT_JSON, AUDIT_JSONL, PLAYBOOK_EXPORT):
        assert_allowed_write(ok_path)

    if not detect_secret_like("password=supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("The first audit is read-only and needs no login"):
        raise AssertionError("secret detector false positive on prose")

    print("payhip-upload-pack-export self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], write_result: Dict[str, Any]) -> None:
    r = state["report"]
    written = write_result["written"]
    print("=== Sentinel Payhip Upload Pack Export Helper (Phase 9.5) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"self-test: run with --self-test")
    print(f"export status: {r['status']}")
    print(f"copy fields status: ready ({len(VARIANTS)} variants)")
    print(f"upload checklist status: ready (10 sections)")
    print(f"zip status: {write_result['zip_status']} (created={write_result['zip_ok']})")
    print(f"export folder: {r['export_folder_latest']}")
    print(f"timestamped folder: {r['export_folder_timestamped']}")
    if write_result["zip_ok"]:
        print(f"zip path: {r['zip_path']}")
    print(f"Product file for Payhip: {r['payhip_product_file']}")
    print(f"Short description file: {r['short_description_file']}")
    print(f"Long description file: {r['long_description_file']}")
    print("Variant names / prices:")
    for v in r["variants"]:
        print(f"  - {v['name']}: {v['price']}")
    print(f"public asset scan status: clean={r['public_asset_scan_clean']} "
          f"(copied={r['copied_count']}, blocked={r['blocked_count']}, missing={r['missing_count']})")
    print(f"live_apply: {r['live_apply']}")
    print(f"emergency_stop: {r['emergency_stop']}")
    print(f"allowed_apply_now: {r['allowed_apply_now']}")
    print(f"breach: {r['breach']}")
    print("what to upload to Payhip:")
    for x in r["do_upload"]:
        print(f"  - {x}")
    print("what NOT to upload:")
    for x in r["do_not_upload"]:
        print(f"  - {x}")
    print("recommended Git checkpoint (script + playbooks only):")
    for f in r["recommended_git_checkpoint"]:
        print(f"  - {f}")
    print("note: export files are NOT committed.")
    if r["blocked_files"]:
        print("blocked files (not exported):")
        for b in r["blocked_files"]:
            print(f"  - {b['name']}: {', '.join(b['reasons'])}")
    if r["missing_inputs"]:
        print(f"missing inputs: {', '.join(r['missing_inputs'])}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Payhip Upload Pack Export Helper (Phase 9.5). Local export only; no apply."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--build-export", action="store_true", help="Build the Payhip export folder.")
    p.add_argument("--build-copy-fields", action="store_true", help="Build copy/paste field text.")
    p.add_argument("--build-upload-checklist", action="store_true", help="Build the upload checklist.")
    p.add_argument("--build-zip", action="store_true", help="Build the optional export zip.")
    p.add_argument("--status", action="store_true", help="Print status summary.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    state = build_full_state()
    write_result = write_all_outputs(state)
    r = state["report"]

    if args.build_export:
        print(f"[export] {r['status']} | copied={r['copied_count']} blocked={r['blocked_count']} "
              f"missing={r['missing_count']} | folder={r['export_folder_latest']}")
    if args.build_copy_fields:
        print(f"[copy-fields] ready | {len(VARIANTS)} variants | "
              f"reports/latest/sentinel-payhip-copy-fields.txt")
    if args.build_upload_checklist:
        print(f"[upload-checklist] ready (10 sections) | "
              f"reports/latest/sentinel-payhip-upload-checklist.md")
    if args.build_zip:
        print(f"[zip] {write_result['zip_status']} | created={write_result['zip_ok']} | "
              f"{r['zip_path'] if write_result['zip_ok'] else '(not created)'}")

    if args.status or not any(
        (args.build_export, args.build_copy_fields, args.build_upload_checklist, args.build_zip)
    ):
        _print_status(state, write_result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
