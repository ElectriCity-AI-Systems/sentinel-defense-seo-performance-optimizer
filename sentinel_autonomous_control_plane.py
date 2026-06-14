#!/usr/bin/env python3
"""Sentinel Autonomous Learning Control Plane (Phase 9.0).

This is the central, *learning* control layer for the Sentinel website security,
SEO and performance bot. It is NOT a live autopilot. It is the safe control plane
that decides, risk-based and auditable:

- what may be observed automatically (READ_ONLY),
- what may be produced as a draft (DRAFT),
- what may be prepared as a non-productive LOW-RISK consolidation (LOW),
- what stays an owner-gated single canary (MEDIUM), and
- what is blocked / review-only forever without owner review (HIGH).

The control plane never applies anything. There is deliberately NO apply mode,
no SFTP write, no DB write, no Cloudflare write, no service start/enable via
systemctl and no timer installation. It only reads local reports/state/audit/
playbooks (and git/systemd status read-only) and writes reports, state, audit
and playbook *plans* under the allowed project roots.

Invariants enforced by this module:
    current_level in {LEVEL_1_DRAFT_ONLY, LEVEL_2_LOW_RISK_PREP_PREVIEW}
    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    every HIGH action  -> blocked / review-only
    every MEDIUM action-> owner gate required, blocked now
    no secrets in any report, state, audit or playbook output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
REPORT_JSON = PROJECT_DIR / "reports/latest/autonomous-control-plane.json"
REPORT_MD = PROJECT_DIR / "reports/latest/autonomous-control-plane.md"
CLASSIFICATION_MD = PROJECT_DIR / "reports/latest/autonomy-action-classification.md"
NEXT_ACTIONS_MD = PROJECT_DIR / "reports/latest/autonomy-next-safe-actions.md"
RISK_REGISTER_MD = PROJECT_DIR / "reports/latest/autonomy-risk-register.md"
SERVICE_POSITIONING_MD = PROJECT_DIR / "reports/latest/autonomy-service-positioning.md"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_CONTROL_PLANE_JSON = STATE_DIR / "autonomous_control_plane.json"
STATE_AUTONOMY_POLICY_JSON = STATE_DIR / "autonomy_policy.json"
STATE_ACTION_MEMORY_JSON = STATE_DIR / "action_memory.json"
STATE_NO_AUTO_APPLY_JSON = STATE_DIR / "no_auto_apply_rules.json"
STATE_SUCCESS_PATTERNS_JSON = STATE_DIR / "learned_success_patterns.json"
STATE_BLOCKED_PATTERNS_JSON = STATE_DIR / "learned_blocked_patterns.json"
STATE_LATEST_JSON = STATE_DIR / "latest_autonomous_control_plane.json"

AUDIT_JSONL = PROJECT_DIR / "audit/autonomous-control-plane.jsonl"

PLAYBOOK_CONTROL_PLANE = PROJECT_DIR / "playbooks/autonomous-control-plane.playbook.json"
PLAYBOOK_BOT = PROJECT_DIR / "playbooks/security-seo-performance-bot.playbook.json"
PLAYBOOK_ROADMAP = PROJECT_DIR / "playbooks/autonomy-level-roadmap.playbook.json"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "playbooks",
    PROJECT_DIR / "snapshots",
)
FORBIDDEN_OUTPUT_SUFFIXES = (
    ".sh", ".bash", ".zsh", ".service", ".timer", ".run", ".bin", ".py", ".php", ".env",
)
FORBIDDEN_INSTALL_PATH_TOKENS = (
    "/etc/systemd", "systemd/system", "/lib/systemd", "/usr/lib/systemd",
    "/etc/cron", "cron.d", "crontab",
)

SCHEMA_VERSION = "autonomous-control-plane-9.0"

# ---------------------------------------------------------------------------
# Autonomy levels & invariants
# ---------------------------------------------------------------------------
LEVEL_0 = "LEVEL_0_OBSERVE_ONLY"
LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
LEVEL_2 = "LEVEL_2_LOW_RISK_PREP_PREVIEW"
LEVEL_3 = "LEVEL_3_LOW_RISK_APPLY_GATED"
LEVEL_4 = "LEVEL_4_MEDIUM_CANARY_ONLY"
LEVEL_5 = "LEVEL_5_HIGH_REVIEW_ONLY"

AUTONOMY_LEVELS = [
    {
        "level": LEVEL_0,
        "summary": "Nur read-only Beobachtung und Reports. Keine Drafts.",
        "allows": ["read_only", "reports"],
        "forbids": ["drafts", "low_prep", "live_apply", "install"],
    },
    {
        "level": LEVEL_1,
        "summary": "Read-only plus Drafts und Owner Review Packs. Kein Live Apply.",
        "allows": ["read_only", "reports", "drafts", "owner_review_packs"],
        "forbids": ["low_prep_apply", "live_apply", "install"],
    },
    {
        "level": LEVEL_2,
        "summary": "Read-only, Drafts und LOW-RISK Prepare/Staging-Vorschlaege. Kein Live Apply ohne Owner.",
        "allows": ["read_only", "reports", "drafts", "low_risk_prepare", "git_safe_staging_suggestions"],
        "forbids": ["live_apply", "install", "medium_auto_apply", "high_auto_apply"],
    },
    {
        "level": LEVEL_3,
        "summary": "Nur spaeter: LOW-RISK Apply, nur Allowlist, Backup/Healthcheck/Rollback Pflicht, Owner gibt einzelne Aktionen frei.",
        "allows": ["low_risk_allowlist_apply_owner_gated"],
        "forbids": ["mass_apply", "medium_auto_apply", "high_auto_apply"],
        "future_only": True,
    },
    {
        "level": LEVEL_4,
        "summary": "Nur einzelne Canary-Aktionen mit Owner Approval, Backup, Pre/Post Healthcheck, Rollback. Keine Massenoptimierung.",
        "allows": ["single_medium_canary_owner_gated"],
        "forbids": ["mass_apply", "high_auto_apply"],
        "future_only": True,
    },
    {
        "level": LEVEL_5,
        "summary": "HIGH bleibt blockiert: nur Review/Dokumentation, niemals automatischer Apply.",
        "allows": ["review_only", "documentation"],
        "forbids": ["high_auto_apply"],
    },
]
ALLOWED_CURRENT_LEVELS = {LEVEL_1, LEVEL_2}
CURRENT_LEVEL = LEVEL_2  # LEVEL_2_LOW_RISK_PREP_PREVIEW (read-only preview only)

# Hard, non-negotiable runtime invariants for this phase.
LIVE_APPLY = False
EMERGENCY_STOP = True
ALLOWED_APPLY_NOW = False

# ---------------------------------------------------------------------------
# Classification taxonomy
# ---------------------------------------------------------------------------
READ_ONLY = "READ_ONLY"
DRAFT = "DRAFT"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CLASS_ORDER = [READ_ONLY, DRAFT, LOW, MEDIUM, HIGH]

DOMAIN_SECURITY = "security"
DOMAIN_SEO = "seo"
DOMAIN_PERFORMANCE = "performance"
DOMAIN_RELIABILITY = "reliability"
DOMAIN_LEARNING = "learning"

# Each entry: id, domain, description, classification.
# disposition + gates are derived from classification (see classify_actions()).
ACTION_CATALOG: List[Dict[str, str]] = [
    # --- READ_ONLY -----------------------------------------------------------
    {"id": "check_status", "domain": DOMAIN_RELIABILITY, "classification": READ_ONLY,
     "description": "Bot- und Report-Status pruefen."},
    {"id": "read_reports", "domain": DOMAIN_RELIABILITY, "classification": READ_ONLY,
     "description": "Vorhandene reports/latest und state read-only lesen."},
    {"id": "http_head_get_public", "domain": DOMAIN_PERFORMANCE, "classification": READ_ONLY,
     "description": "Oeffentliches HTML per HEAD/GET read-only abrufen (kein Login)."},
    {"id": "git_status_log", "domain": DOMAIN_RELIABILITY, "classification": READ_ONLY,
     "description": "git status/log read-only erfassen."},
    {"id": "systemctl_status", "domain": DOMAIN_RELIABILITY, "classification": READ_ONLY,
     "description": "systemctl status/timer read-only pruefen (kein start/enable)."},
    {"id": "validate_json", "domain": DOMAIN_RELIABILITY, "classification": READ_ONLY,
     "description": "Report-JSON auf Wohlgeformtheit pruefen."},
    {"id": "cloudflare_challenge_diagnosis", "domain": DOMAIN_SECURITY, "classification": READ_ONLY,
     "description": "Cloudflare Challenge / Bot Fight Mode read-only diagnostizieren (curl/403 interpretieren)."},
    {"id": "scan_observation_xmlrpc_wplogin", "domain": DOMAIN_SECURITY, "classification": READ_ONLY,
     "description": "xml-rpc / wp-login / fake-scans / actuator-scans nur defensiv beobachten, keine Gegenangriffe."},
    {"id": "robots_sitemap_check", "domain": DOMAIN_SEO, "classification": READ_ONLY,
     "description": "robots.txt / sitemap read-only pruefen."},
    {"id": "diagnose_5xx_origin_pressure", "domain": DOMAIN_RELIABILITY, "classification": READ_ONLY,
     "description": "5xx/502/504/524 klassifizieren: origin_php_or_upstream_error vs cloudflare_to_origin_timeout."},
    {"id": "rolling_window_decay_read", "domain": DOMAIN_RELIABILITY, "classification": READ_ONLY,
     "description": "Rolling-window decay und 24h low-growth Evidence read-only auswerten."},

    # --- DRAFT ---------------------------------------------------------------
    {"id": "seo_meta_draft", "domain": DOMAIN_SEO, "classification": DRAFT,
     "description": "Title/Meta/Canonical/OG/Twitter Cards Draft schreiben (kein Live Apply)."},
    {"id": "seo_internal_links_draft", "domain": DOMAIN_SEO, "classification": DRAFT,
     "description": "Interne-Links- und Content-Outline-Draft erstellen."},
    {"id": "owner_review_pack", "domain": DOMAIN_SEO, "classification": DRAFT,
     "description": "Owner Review Pack / Copy-paste Pack erzeugen."},
    {"id": "write_playbook", "domain": DOMAIN_LEARNING, "classification": DRAFT,
     "description": "Playbook (Review-Plan) schreiben, installiert nichts."},
    {"id": "write_report_policy_proposal", "domain": DOMAIN_LEARNING, "classification": DRAFT,
     "description": "Report / Policy-Vorschlag als Draft erzeugen."},
    {"id": "git_commit_suggestion", "domain": DOMAIN_RELIABILITY, "classification": DRAFT,
     "description": "Git-Commit-Vorschlag formulieren (kein automatischer Commit/Push)."},
    {"id": "perf_image_candidate_draft", "domain": DOMAIN_PERFORMANCE, "classification": DRAFT,
     "description": "Image-/WebP/JPG-Kandidaten als Draft listen."},

    # --- LOW (non-productive, no website change) -----------------------------
    {"id": "local_report_cleanup", "domain": DOMAIN_LEARNING, "classification": LOW,
     "description": "Lokale Reportbereinigung (kein produktiver Website-Change)."},
    {"id": "bot_state_consolidation", "domain": DOMAIN_LEARNING, "classification": LOW,
     "description": "Interne Bot-State-Konsolidierung im Projektbaum."},
    {"id": "candidate_list_update", "domain": DOMAIN_PERFORMANCE, "classification": LOW,
     "description": "Kandidatenlisten read-only aktualisieren (keine Website-Aenderung)."},

    # --- MEDIUM (single canary, owner gate, backup/healthcheck/rollback) -----
    {"id": "single_image_canary", "domain": DOMAIN_PERFORMANCE, "classification": MEDIUM,
     "description": "Einzelne Bild-Canary-Optimierung, nur mit Backup/Healthcheck/Rollback/Owner Gate."},
    {"id": "single_safe_file_sftp_replace", "domain": DOMAIN_PERFORMANCE, "classification": MEDIUM,
     "description": "Einzelne sichere Datei per SFTP ersetzen, nur mit Backup/Healthcheck/Rollback/Owner Gate."},

    # --- HIGH (blocked / review-only forever) --------------------------------
    {"id": "database_change", "domain": DOMAIN_SEO, "classification": HIGH,
     "description": "DB-Aenderung."},
    {"id": "fse_template_change", "domain": DOMAIN_SEO, "classification": HIGH,
     "description": "FSE / Posts / Pages / Templates aendern."},
    {"id": "theme_plugin_code_change", "domain": DOMAIN_PERFORMANCE, "classification": HIGH,
     "description": "Theme-/Plugin-Code aendern."},
    {"id": "htaccess_change", "domain": DOMAIN_PERFORMANCE, "classification": HIGH,
     "description": ".htaccess aendern."},
    {"id": "nginx_change", "domain": DOMAIN_RELIABILITY, "classification": HIGH,
     "description": "Nginx-Konfiguration aendern."},
    {"id": "cloudflare_waf_change", "domain": DOMAIN_SECURITY, "classification": HIGH,
     "description": "Cloudflare/WAF/Firewall-Regel aendern (immer HIGH oder Owner Review)."},
    {"id": "cache_purge", "domain": DOMAIN_PERFORMANCE, "classification": HIGH,
     "description": "Cache Purge."},
    {"id": "redirect_change", "domain": DOMAIN_SEO, "classification": HIGH,
     "description": "Redirects aendern."},
    {"id": "broad_sftp_operation", "domain": DOMAIN_PERFORMANCE, "classification": HIGH,
     "description": "Breite SFTP-Operation ueber mehrere Dateien."},
    {"id": "cron_systemd_timer_install", "domain": DOMAIN_RELIABILITY, "classification": HIGH,
     "description": "Cron-/systemd-Timer installieren."},
    {"id": "mass_optimization", "domain": DOMAIN_PERFORMANCE, "classification": HIGH,
     "description": "Massenoptimierung."},
    {"id": "blocking_security_rule", "domain": DOMAIN_SECURITY, "classification": HIGH,
     "description": "Security-Regel mit Blockwirkung (breite Blockade ohne Beweis verboten)."},
    {"id": "jsonld_fse_db_schema_change", "domain": DOMAIN_SEO, "classification": HIGH,
     "description": "JSON-LD/FSE/DB-Schema-Aenderung: HIGH oder streng review-only."},
]

# no_auto_apply rules must always cover at least these scope tokens.
NO_AUTO_APPLY_REQUIRED_TOKENS = (
    "database", "fse", "cloudflare", "nginx", "htaccess", "cache_purge", "mass_apply",
)

# ---------------------------------------------------------------------------
# Ingest safety
# ---------------------------------------------------------------------------
SENSITIVE_NAME_RE = re.compile(
    r"(?i)(\.env\b|sftp.*env|\.pem$|\.key$|id_rsa|id_ed25519|\.p12$|\.pfx$|"
    r"secret|token|credential|password|passwd|\.htpasswd|api[_-]?key|private[_-]?key)"
)
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".tiff",
    ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".pdf", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".bin", ".so", ".o",
}
MAX_INGEST_BYTES = 262_144  # 256 KiB; above this we keep metadata only.
INGEST_GLOBS = (
    ("reports/latest", "*.json"),
    ("reports/latest", "*.md"),
    ("state/adaptive-learning", "*.json"),
    ("state/adaptive-learning", "*.jsonl"),
    ("audit", "*.jsonl"),
    ("playbooks", "*.json"),
)

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"set-cookie|credential|x-api-key|access[_-]?key|private[_-]?key)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|"
    r"authorization|set-cookie|x-api-key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{40,}\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def detect_secret_like(value: Any) -> bool:
    text = "" if value is None else str(value)
    return bool(SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


def redact_text(value: Any, default: str = "-", max_len: int = 400) -> str:
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


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed control-plane roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install/secret artifact: {path}")
    if any(token in str(path) for token in FORBIDDEN_INSTALL_PATH_TOKENS):
        raise ValueError(f"Refusing to write systemd/crontab path: {path}")


def _assert_no_secret_blob(path: Path, blob: str) -> None:
    if SECRET_ASSIGNMENT_RE.search(blob) or LONG_HEX_RE.search(blob):
        raise ValueError(f"Refusing to write secret-like content to {path}")


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


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                h.update(chunk)
    except OSError:
        return "unavailable"
    return h.hexdigest()


def run_readonly(cmd: List[str], timeout: int = 10) -> Tuple[bool, str]:
    """Run a strictly read-only command, capturing redacted stdout."""
    try:
        proc = subprocess.run(
            cmd, cwd=str(PROJECT_DIR), capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode == 0, redact_text(proc.stdout, max_len=4000)
    except (OSError, subprocess.SubprocessError):
        return False, ""


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------
STATUS_KEYS = (
    "status", "overall_status", "action_status", "overall", "dedup_status",
    "autonomy_policy_status", "emergency_stop", "live_apply", "apply_status",
    "breach", "apply_breach",
)


def _extract_status_signals(data: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(data, dict):
        for key in STATUS_KEYS:
            if key in data:
                out[key] = redact_text(data[key], max_len=80)
    return out


def ingest_file(rel_dir: str, path: Path) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "path": str(path.relative_to(PROJECT_DIR)),
        "dir": rel_dir,
        "size_bytes": None,
        "sha256": "unavailable",
        "content_ingested": False,
        "reason": None,
        "signals": {},
    }
    try:
        size = path.stat().st_size
    except OSError:
        entry["reason"] = "stat_error"
        return entry
    entry["size_bytes"] = size
    entry["sha256"] = sha256_file(path)

    if SENSITIVE_NAME_RE.search(path.name):
        entry["reason"] = "metadata_only_sensitive_name"
        return entry
    if path.suffix.lower() in BINARY_EXT:
        entry["reason"] = "metadata_only_binary"
        return entry
    if size > MAX_INGEST_BYTES:
        entry["reason"] = "metadata_only_too_large"
        return entry

    # Safe to look at structured signals only (never raw content stored).
    if path.suffix.lower() == ".json":
        data, status = read_optional_json(path)
        entry["reason"] = status
        if status == "ok":
            entry["content_ingested"] = True
            entry["signals"] = _extract_status_signals(data)
    else:
        entry["reason"] = "metadata_only_text"  # md/jsonl: keep metadata, no content storage
        entry["content_ingested"] = False
    return entry


def build_ingest() -> Dict[str, Any]:
    files: List[Dict[str, Any]] = []
    skipped_sensitive = 0
    for rel_dir, pattern in INGEST_GLOBS:
        base = PROJECT_DIR / rel_dir
        if not base.exists():
            continue
        for path in sorted(base.glob(pattern)):
            if not path.is_file():
                continue
            entry = ingest_file(rel_dir, path)
            if entry["reason"] == "metadata_only_sensitive_name":
                skipped_sensitive += 1
            files.append(entry)

    git_ok, git_log = run_readonly(["git", "log", "--oneline", "-20"])
    status_ok, git_status = run_readonly(["git", "status", "--short"])
    git_status_lines = [ln for ln in git_status.splitlines() if ln.strip()]
    untracked = sum(1 for ln in git_status_lines if ln.startswith("??"))
    modified = len(git_status_lines) - untracked

    timers = {}
    for timer in (
        "cloudflare-daily-monitor.timer", "sentinel-defense.timer",
        "sentinel-master.timer", "sentinel-daily-mail.timer",
    ):
        ok, out = run_readonly(["systemctl", "is-active", timer], timeout=5)
        timers[timer] = out.strip() or ("unavailable" if not ok else "unknown")

    return {
        "generated_at": utc_now(),
        "file_count": len(files),
        "files_content_ingested": sum(1 for f in files if f["content_ingested"]),
        "files_metadata_only": sum(1 for f in files if not f["content_ingested"]),
        "skipped_sensitive_name": skipped_sensitive,
        "files": files,
        "git": {
            "log_available": git_ok,
            "recent_log": git_log.splitlines()[:20],
            "status_available": status_ok,
            "untracked_count": untracked,
            "modified_count": modified,
            "tracked_changes_sample": [redact_text(ln, max_len=120) for ln in git_status_lines[:15]],
        },
        "systemd_timers_readonly": timers,
        "secrets_ingested": False,
        "note": "Read-only ingest. Sensitive/binary/oversized files keep metadata (name+sha256) only.",
    }


# ---------------------------------------------------------------------------
# Action classification
# ---------------------------------------------------------------------------
def classify_actions() -> Dict[str, Any]:
    classified: List[Dict[str, Any]] = []
    counts = {c: 0 for c in CLASS_ORDER}
    for action in ACTION_CATALOG:
        cls = action["classification"]
        counts[cls] = counts.get(cls, 0) + 1
        if cls == READ_ONLY:
            disposition, owner_gate, productive_write = "allowed_read_only", False, False
            requires_bhr = False
        elif cls == DRAFT:
            disposition, owner_gate, productive_write = "allowed_draft_only", False, False
            requires_bhr = False
        elif cls == LOW:
            disposition, owner_gate, productive_write = "allowed_non_productive_only", False, False
            requires_bhr = False
        elif cls == MEDIUM:
            disposition, owner_gate, productive_write = "owner_gate_required_blocked_now", True, True
            requires_bhr = True
        else:  # HIGH
            disposition, owner_gate, productive_write = "blocked_review_only", True, True
            requires_bhr = True
        classified.append({
            "id": action["id"],
            "domain": action["domain"],
            "classification": cls,
            "description": action["description"],
            "disposition": disposition,
            "auto_apply_allowed_now": False,
            "owner_gate_required": owner_gate,
            "requires_backup_healthcheck_rollback": requires_bhr,
            "productive_website_write": productive_write,
            "blocked": cls == HIGH,
        })
    return {
        "generated_at": utc_now(),
        "counts": counts,
        "total": len(classified),
        "actions": classified,
    }


# ---------------------------------------------------------------------------
# Autonomy map + policy
# ---------------------------------------------------------------------------
def observed_runtime_signals() -> Dict[str, Any]:
    """Read-only observation of runtime lock / autonomy policy for transparency."""
    out = {"emergency_stop_observed": None, "autonomy_enabled_observed": None, "lock_status": "not_available"}
    lock, status = read_optional_json(PROJECT_DIR / "config/autonomy-runtime-lock.json")
    out["lock_status"] = status
    if isinstance(lock, dict):
        out["emergency_stop_observed"] = bool(lock.get("emergency_stop"))
        out["autonomy_enabled_observed"] = bool(lock.get("autonomy_enabled"))
    return out


def build_autonomy_map() -> Dict[str, Any]:
    observed = observed_runtime_signals()
    return {
        "generated_at": utc_now(),
        "current_level": CURRENT_LEVEL,
        "allowed_current_levels": sorted(ALLOWED_CURRENT_LEVELS),
        "live_apply": LIVE_APPLY,
        "emergency_stop": EMERGENCY_STOP,
        "allowed_apply_now": ALLOWED_APPLY_NOW,
        "levels": AUTONOMY_LEVELS,
        "observed_runtime": observed,
        "note": (
            "Control plane only. current_level is a read-only preview level; "
            "no live apply, no install, emergency stop active."
        ),
    }


def build_no_auto_apply_rules() -> Dict[str, Any]:
    rules = [
        {"scope": "database", "rule": "Niemals automatische DB-Aenderung.", "classification": HIGH},
        {"scope": "fse", "rule": "Niemals automatische FSE/Posts/Pages/Templates-Aenderung.", "classification": HIGH},
        {"scope": "theme_plugin_code", "rule": "Niemals automatische Theme-/Plugin-Code-Aenderung.", "classification": HIGH},
        {"scope": "htaccess", "rule": "Niemals automatische .htaccess-Aenderung.", "classification": HIGH},
        {"scope": "nginx", "rule": "Niemals automatische Nginx-Aenderung.", "classification": HIGH},
        {"scope": "cloudflare", "rule": "Niemals automatische Cloudflare/WAF-Aenderung; fremde Regeln nie modifizieren.", "classification": HIGH},
        {"scope": "cache_purge", "rule": "Niemals automatischer Cache Purge.", "classification": HIGH},
        {"scope": "redirects", "rule": "Niemals automatische Redirect-Aenderung.", "classification": HIGH},
        {"scope": "broad_sftp", "rule": "Keine breiten SFTP-Operationen; nur einzelne erlaubte Datei, owner-gated.", "classification": HIGH},
        {"scope": "cron_systemd_timer", "rule": "Niemals automatische Cron-/systemd-Timer-Installation.", "classification": HIGH},
        {"scope": "mass_apply", "rule": "Niemals Massenoptimierung / Mass Apply.", "classification": HIGH},
        {"scope": "blocking_security_rule", "rule": "Keine breite Blockade/Block-Regel ohne Beweis; keine Gegenangriffe.", "classification": HIGH},
        {"scope": "secrets", "rule": "Secrets niemals lesen, speichern oder ausgeben.", "classification": HIGH},
    ]
    return {
        "generated_at": utc_now(),
        "rules": rules,
        "scopes": [r["scope"] for r in rules],
        "required_tokens_present": all(
            any(tok in r["scope"] for r in rules) for tok in NO_AUTO_APPLY_REQUIRED_TOKENS
        ),
        "count": len(rules),
    }


# ---------------------------------------------------------------------------
# Learning memory
# ---------------------------------------------------------------------------
DEFAULT_SUCCESS_PATTERNS = [
    {"id": "medium_image_canary_success", "domain": DOMAIN_PERFORMANCE,
     "pattern": "Einzelner MEDIUM Image Canary mit Backup/Healthcheck/Rollback war erfolgreich (Phase 8.13).",
     "confidence": "high", "reinforce": True},
    {"id": "ai_radio_microcache_hit", "domain": DOMAIN_PERFORMANCE,
     "pattern": "AI-Radio NowPlaying Microcache deployed und HIT-confirmed.",
     "confidence": "high", "reinforce": True},
    {"id": "git_safety_checkpoint", "domain": DOMAIN_RELIABILITY,
     "pattern": "Git-Safety-Checkpoint vor Aenderungen schuetzt zuverlaessig (rollback-fhig).",
     "confidence": "high", "reinforce": True},
    {"id": "stable_healthcheck_pattern", "domain": DOMAIN_RELIABILITY,
     "pattern": "Stabile Pre/Post-Healthchecks (200/3xx + Marker) sind ein positives Muster.",
     "confidence": "medium", "reinforce": True},
    {"id": "jsonld_slim_graph_safe", "domain": DOMAIN_SEO,
     "pattern": "Schlanker JSON-LD Graph (RadioStation+MusicGroup) ohne Duplikate vorbereitet (Phase 6.2).",
     "confidence": "medium", "reinforce": True},
]
DEFAULT_BLOCKED_PATTERNS = [
    {"id": "under_threshold_candidate_blocked", "domain": DOMAIN_PERFORMANCE,
     "pattern": "Kandidat unter Threshold wird blockiert und gemerkt, nicht angewandt.",
     "confidence": "high", "enforce": True},
    {"id": "high_actions_blocked", "domain": DOMAIN_SECURITY,
     "pattern": "HIGH-Aktionen (DB/FSE/Cloudflare/Nginx/.htaccess) bleiben dauerhaft blockiert.",
     "confidence": "high", "enforce": True},
    {"id": "regression_memory", "domain": DOMAIN_RELIABILITY,
     "pattern": "Erkannte Regressionen werden gemerkt und fuehren zu Rollback statt Re-Apply.",
     "confidence": "high", "enforce": True},
    {"id": "secret_scan_false_positive", "domain": DOMAIN_SECURITY,
     "pattern": "False positives im Secret-Scan werden gemerkt, ohne den Scanner zu schwaechen.",
     "confidence": "medium", "enforce": True},
    {"id": "no_premature_waf_rule", "domain": DOMAIN_SECURITY,
     "pattern": "Keine vorschnellen WAF-Regeln bei 5xx/Origin-Pressure ohne Beweis.",
     "confidence": "high", "enforce": True},
]


def _merge_patterns(existing: Any, defaults: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}
    if isinstance(existing, dict):
        for item in existing.get("patterns", []):
            if isinstance(item, dict) and item.get("id"):
                by_id[item["id"]] = item
    for item in defaults:
        prev = by_id.get(item["id"], {})
        merged = dict(item)
        merged["observed_count"] = int(prev.get("observed_count", 0)) + 1
        merged["first_seen"] = prev.get("first_seen", utc_now())
        merged["last_seen"] = utc_now()
        by_id[item["id"]] = merged
    return sorted(by_id.values(), key=lambda x: (-int(x.get("observed_count", 0)), x.get("id", "")))


def build_learning_memory() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    prev_success, _ = read_optional_json(STATE_SUCCESS_PATTERNS_JSON)
    prev_blocked, _ = read_optional_json(STATE_BLOCKED_PATTERNS_JSON)
    success = {
        "generated_at": utc_now(),
        "patterns": _merge_patterns(prev_success, DEFAULT_SUCCESS_PATTERNS),
    }
    blocked = {
        "generated_at": utc_now(),
        "patterns": _merge_patterns(prev_blocked, DEFAULT_BLOCKED_PATTERNS),
    }
    return success, blocked


# ---------------------------------------------------------------------------
# Next safe actions
# ---------------------------------------------------------------------------
def build_next_actions(ingest: Dict[str, Any], autonomy_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions = [
        {"id": "review_website_critical_origin", "classification": READ_ONLY, "domain": DOMAIN_RELIABILITY,
         "action": "Website CRITICAL read-only diagnostizieren: 5xx/origin/Cloudflare-zu-Origin-Timeout vs SentinelDefense; keine WAF-Regel.",
         "owner_gate": False},
        {"id": "interpret_bot_fight_mode", "classification": READ_ONLY, "domain": DOMAIN_SECURITY,
         "action": "Cloudflare Bot Fight Mode (curl/403 Challenge) als Ursache fuer Checker-403 dokumentieren, keine Aenderung.",
         "owner_gate": False},
        {"id": "next_image_candidate_draft", "classification": DRAFT, "domain": DOMAIN_PERFORMANCE,
         "action": "Naechsten read-only ausgewaehlten Image-Kandidaten (Phase 8.14) als Owner-Review-Draft aufbereiten.",
         "owner_gate": False},
        {"id": "jsonld_dedup_owner_review", "classification": DRAFT, "domain": DOMAIN_SEO,
         "action": "Schlanken JSON-LD De-Dup-Plugin (Phase 6.2) als Owner-Review-Pack belassen, kein Upload ohne Owner-Approval.",
         "owner_gate": False},
        {"id": "rolling_window_lowgrowth_read", "classification": READ_ONLY, "domain": DOMAIN_RELIABILITY,
         "action": "Rolling-window decay + 24h low-growth Evidence read-only auswerten, bevor irgendeine MEDIUM-Aktion vorgeschlagen wird.",
         "owner_gate": False},
        {"id": "single_image_canary_owner_gate", "classification": MEDIUM, "domain": DOMAIN_PERFORMANCE,
         "action": "Einzelne naechste Bild-Canary NUR mit Owner Approval + Backup/Healthcheck/Rollback (blockiert bis Freigabe).",
         "owner_gate": True},
    ]
    if autonomy_map["emergency_stop"]:
        for a in actions:
            a["blocked_now"] = a["classification"] in (MEDIUM, HIGH) or a["owner_gate"]
            a["live_apply"] = False
    git = ingest.get("git", {})
    if (git.get("untracked_count", 0) + git.get("modified_count", 0)) > 0:
        actions.append({
            "id": "git_safety_checkpoint_suggestion", "classification": DRAFT, "domain": DOMAIN_RELIABILITY,
            "action": "Git-Safety-Checkpoint (commit-suggestion) empfehlen: untracked/modified Dateien sichern. Kein automatischer Push.",
            "owner_gate": False, "blocked_now": False, "live_apply": False,
        })
    return actions


def git_checkpoint_recommended(ingest: Dict[str, Any]) -> bool:
    git = ingest.get("git", {})
    return (git.get("untracked_count", 0) + git.get("modified_count", 0)) > 0


# ---------------------------------------------------------------------------
# Service positioning
# ---------------------------------------------------------------------------
SERVICE_POSITIONING_TEXT = """# Sentinel Security, SEO & Performance Bot — Service Positioning

**Safe Autonomy statt blindem Autopilot.**

Sentinel ist ein lernender, defensiver Bot fuer WordPress-Websites hinter
Cloudflare. Er arbeitet diagnose-, review- und evidenzbasiert: jede potenzielle
Aenderung durchlaeuft Diagnose, Owner Review, Backup, Healthcheck und Rollback.

## Was Sentinel macht
- **Security:** Cloudflare-Challenge-/Bot-Fight-Mode-Diagnose, defensive Scan-Beobachtung
  (xml-rpc/wp-login/Actuator), WAF/Firewall nur als HIGH/Owner-Review. Keine Gegenangriffe.
- **SEO:** Title/Meta/Canonical/OG/Twitter, Schema/JSON-LD-Konflikte, interne Links,
  Content-Outline-Drafts, robots/sitemap-Checks — zunaechst als Draft / Owner Review.
- **Performance:** Image-Candidates, WebP/JPG-Canary, HTML-Size, Inline-CSS, Scripts,
  cache-expires, External Embeds, AI-Radio/NowPlaying-Cache — MEDIUM nur als einzelner
  Canary mit Owner Gate, HIGH niemals automatisch.
- **Reliability:** 5xx/502/504/524-Klassifikation, origin_php_or_upstream_error vs
  cloudflare_to_origin_timeout, rolling-window decay, 24h low-growth evidence.

## Wie Sentinel arbeitet
Diagnose -> Review -> Backup -> Healthcheck -> Rollback. Read-only by default,
auditierbar, risikobasiert. HIGH-Risk-Aktionen werden niemals ohne Owner Review live.

## Pakete
1. **Audit** — read-only Security/SEO/Performance-Bestandsaufnahme mit Reports.
2. **Safe Optimization** — Drafts, Owner Review Packs, einzelne owner-gated Canary-Optimierungen
   mit Backup/Healthcheck/Rollback.
3. **Monitoring & Improvement** — laufende Beobachtung, Lernspeicher, Risk Register,
   kontrollierte Verbesserungsvorschlaege.

## Klarstellung
Keine 100%-Heilungsversprechen. Keine HIGH-Risk-Live-Aktionen ohne Owner Review.
Kein blinder Autopilot — sichere, kontrollierte, lernende Autonomie.
"""


# ---------------------------------------------------------------------------
# Full state assembly + breach
# ---------------------------------------------------------------------------
def compute_breach(autonomy_map: Dict[str, Any], classification: Dict[str, Any],
                   no_auto_apply: Dict[str, Any]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if autonomy_map["live_apply"] is not False:
        reasons.append("live_apply must be false")
    if autonomy_map["emergency_stop"] is not True:
        reasons.append("emergency_stop must be true")
    if autonomy_map["allowed_apply_now"] is not False:
        reasons.append("allowed_apply_now must be false")
    if autonomy_map["current_level"] not in ALLOWED_CURRENT_LEVELS:
        reasons.append(f"current_level {autonomy_map['current_level']} not allowed")
    for action in classification["actions"]:
        if action["auto_apply_allowed_now"]:
            reasons.append(f"action {action['id']} must not auto-apply now")
        if action["classification"] == HIGH and not action["blocked"]:
            reasons.append(f"HIGH action {action['id']} not blocked")
        if action["classification"] == MEDIUM and not action["owner_gate_required"]:
            reasons.append(f"MEDIUM action {action['id']} missing owner gate")
        if action["classification"] == LOW and action["productive_website_write"]:
            reasons.append(f"LOW action {action['id']} must not write productively")
    for token in NO_AUTO_APPLY_REQUIRED_TOKENS:
        if not any(token in r["scope"] for r in no_auto_apply["rules"]):
            reasons.append(f"no_auto_apply missing required scope token: {token}")
    return (len(reasons) > 0), reasons


def build_full_state() -> Dict[str, Any]:
    ingest = build_ingest()
    classification = classify_actions()
    autonomy_map = build_autonomy_map()
    no_auto_apply = build_no_auto_apply_rules()
    success, blocked = build_learning_memory()
    next_actions = build_next_actions(ingest, autonomy_map)
    breach, breach_reasons = compute_breach(autonomy_map, classification, no_auto_apply)

    policy = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "current_level": CURRENT_LEVEL,
        "allowed_current_levels": sorted(ALLOWED_CURRENT_LEVELS),
        "live_apply": LIVE_APPLY,
        "emergency_stop": EMERGENCY_STOP,
        "allowed_apply_now": ALLOWED_APPLY_NOW,
        "levels": AUTONOMY_LEVELS,
        "no_auto_apply_rules": no_auto_apply["rules"],
        "no_auto_apply_count": no_auto_apply["count"],
        "note": "Control-plane policy only. No live apply, no install, no timer, emergency stop active.",
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.0",
        "module": "sentinel_autonomous_control_plane",
        "generated_at": utc_now(),
        "current_level": CURRENT_LEVEL,
        "live_apply": LIVE_APPLY,
        "emergency_stop": EMERGENCY_STOP,
        "allowed_apply_now": ALLOWED_APPLY_NOW,
        "is_live_autopilot": False,
        "action_classification_counts": classification["counts"],
        "action_total": classification["total"],
        "no_auto_apply_rules_count": no_auto_apply["count"],
        "no_auto_apply_required_tokens_present": no_auto_apply["required_tokens_present"],
        "top_success_patterns": [p["id"] for p in success["patterns"][:5]],
        "top_blocked_patterns": [p["id"] for p in blocked["patterns"][:5]],
        "next_safe_actions": [a["id"] for a in next_actions],
        "git_checkpoint_recommended": git_checkpoint_recommended(ingest),
        "ingest_summary": {
            "file_count": ingest["file_count"],
            "files_content_ingested": ingest["files_content_ingested"],
            "files_metadata_only": ingest["files_metadata_only"],
            "skipped_sensitive_name": ingest["skipped_sensitive_name"],
            "secrets_ingested": ingest["secrets_ingested"],
        },
        "secrets_in_report": False,
        "breach": breach,
        "breach_reasons": breach_reasons,
        "status": "CONTROL_PLANE_BREACH" if breach else "CONTROL_PLANE_SAFE_LOCKED",
        "service_positioning_summary": (
            "Safe Autonomy statt blindem Autopilot: Diagnose, Review, Backup, Healthcheck, "
            "Rollback. WordPress/Cloudflare/SEO/Performance. Pakete: Audit, Safe Optimization, "
            "Monitoring & Improvement."
        ),
    }

    return {
        "report": report,
        "policy": policy,
        "ingest": ingest,
        "classification": classification,
        "autonomy_map": autonomy_map,
        "no_auto_apply": no_auto_apply,
        "success": success,
        "blocked": blocked,
        "next_actions": next_actions,
        "breach": breach,
        "breach_reasons": breach_reasons,
    }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def render_report_md(state: Dict[str, Any]) -> str:
    r = state["report"]
    lines = [
        "# Sentinel Autonomous Learning Control Plane (Phase 9.0)",
        "",
        f"- Generated: {r['generated_at']}",
        f"- Current level: **{r['current_level']}**",
        f"- live_apply: `{r['live_apply']}` | emergency_stop: `{r['emergency_stop']}` | allowed_apply_now: `{r['allowed_apply_now']}`",
        f"- Live autopilot: `{r['is_live_autopilot']}`",
        f"- Status: **{r['status']}** | breach: `{r['breach']}`",
        "",
        "## Action classification counts",
    ]
    for cls in CLASS_ORDER:
        lines.append(f"- {cls}: {r['action_classification_counts'].get(cls, 0)}")
    lines += [
        f"- Total: {r['action_total']}",
        "",
        "## Learning",
        f"- Top success patterns: {', '.join(r['top_success_patterns'])}",
        f"- Top blocked patterns: {', '.join(r['top_blocked_patterns'])}",
        f"- no-auto-apply rules: {r['no_auto_apply_rules_count']} (required tokens present: {r['no_auto_apply_required_tokens_present']})",
        "",
        "## Ingest",
        f"- Files: {r['ingest_summary']['file_count']} "
        f"(content: {r['ingest_summary']['files_content_ingested']}, "
        f"metadata-only: {r['ingest_summary']['files_metadata_only']}, "
        f"sensitive-skipped: {r['ingest_summary']['skipped_sensitive_name']})",
        f"- Secrets ingested: {r['ingest_summary']['secrets_ingested']}",
        f"- Git checkpoint recommended: {r['git_checkpoint_recommended']}",
        "",
        "## Next safe actions",
    ]
    for a in state["next_actions"]:
        gate = " [OWNER GATE]" if a.get("owner_gate") else ""
        blocked = " [BLOCKED NOW]" if a.get("blocked_now") else ""
        lines.append(f"- ({a['classification']}/{a['domain']}) {a['action']}{gate}{blocked}")
    if r["breach"]:
        lines += ["", "## BREACH REASONS"] + [f"- {x}" for x in r["breach_reasons"]]
    lines += [
        "",
        "## Service positioning",
        r["service_positioning_summary"],
        "",
        "_Control plane only. Veraendert die Website nicht. Aktiviert keinen Autopilot._",
    ]
    return "\n".join(lines) + "\n"


def render_classification_md(state: Dict[str, Any]) -> str:
    c = state["classification"]
    lines = [
        "# Autonomy Action Classification",
        "",
        f"Generated: {c['generated_at']} | Total: {c['total']}",
        "",
        "| Class | Count |",
        "| --- | --- |",
    ]
    for cls in CLASS_ORDER:
        lines.append(f"| {cls} | {c['counts'].get(cls, 0)} |")
    lines += ["", "| Action | Domain | Class | Disposition | Owner gate | B/H/R | Blocked |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for a in c["actions"]:
        lines.append(
            f"| {a['id']} | {a['domain']} | {a['classification']} | {a['disposition']} | "
            f"{a['owner_gate_required']} | {a['requires_backup_healthcheck_rollback']} | {a['blocked']} |"
        )
    lines += ["", "_HIGH = blocked/review-only. MEDIUM = owner gate, blocked now. "
              "LOW = non-productive. Nichts wird jetzt automatisch angewandt._"]
    return "\n".join(lines) + "\n"


def render_next_actions_md(state: Dict[str, Any]) -> str:
    lines = ["# Autonomy — Next Safe Actions", "",
             f"Generated: {state['report']['generated_at']}",
             f"Git checkpoint recommended: {state['report']['git_checkpoint_recommended']}", ""]
    for a in state["next_actions"]:
        lines += [
            f"## {a['id']} ({a['classification']} / {a['domain']})",
            f"- {a['action']}",
            f"- owner_gate: {a.get('owner_gate', False)} | blocked_now: {a.get('blocked_now', False)} | live_apply: {a.get('live_apply', False)}",
            "",
        ]
    return "\n".join(lines) + "\n"


def render_risk_register_md(state: Dict[str, Any]) -> str:
    lines = ["# Autonomy Risk Register", "",
             f"Generated: {state['report']['generated_at']}", "",
             "## No-Auto-Apply Rules (HIGH scopes)",
             "", "| Scope | Rule | Class |", "| --- | --- | --- |"]
    for rule in state["no_auto_apply"]["rules"]:
        lines.append(f"| {rule['scope']} | {rule['rule']} | {rule['classification']} |")
    lines += ["", "## Learned blocked patterns (enforced)", ""]
    for p in state["blocked"]["patterns"]:
        lines.append(f"- **{p['id']}** ({p['domain']}, {p.get('confidence')}): {p['pattern']}")
    lines += ["", "## Learned success patterns (reinforced)", ""]
    for p in state["success"]["patterns"]:
        lines.append(f"- **{p['id']}** ({p['domain']}, {p.get('confidence')}): {p['pattern']}")
    lines += ["", "_HIGH bleibt blockiert. Keine breite Blockade ohne Beweis. Keine Gegenangriffe._"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------
def build_playbooks(state: Dict[str, Any]) -> Dict[Path, Dict[str, Any]]:
    control_plane = {
        "name": "autonomous-control-plane",
        "phase": "9.0",
        "kind": "review_only_control_plane",
        "applies_anything": False,
        "live_apply": False,
        "emergency_stop": True,
        "steps": [
            {"step": "ingest", "type": READ_ONLY, "desc": "Read reports/state/audit/playbooks/git/systemd read-only."},
            {"step": "classify-actions", "type": READ_ONLY, "desc": "Classify every action READ_ONLY/DRAFT/LOW/MEDIUM/HIGH."},
            {"step": "build-autonomy-map", "type": READ_ONLY, "desc": "Build LEVEL_0..LEVEL_5 map; current level preview."},
            {"step": "draft-next-actions", "type": DRAFT, "desc": "Draft safe next actions (no apply)."},
            {"step": "policy-report", "type": READ_ONLY, "desc": "Emit policy + risk register."},
            {"step": "status", "type": READ_ONLY, "desc": "Emit status summary."},
        ],
        "forbidden": ["apply", "sftp_write", "db_write", "cloudflare_write", "systemctl_start_enable", "timer_install"],
        "current_level": state["autonomy_map"]["current_level"],
    }
    bot = {
        "name": "security-seo-performance-bot",
        "kind": "domain_model",
        "domains": {
            "security": ["cloudflare_challenge_diagnosis", "bot_fight_mode_interpretation",
                         "waf_high_or_owner_review", "defensive_scan_observation", "no_counterattack"],
            "seo": ["title_meta_canonical_og_twitter", "schema_jsonld_conflicts", "internal_links",
                    "content_outline_drafts", "robots_sitemap_readonly", "jsonld_fse_db_high_or_review_only"],
            "performance": ["image_candidates", "webp_jpg_canary", "html_size", "inline_css", "scripts",
                            "cache_expires", "external_embeds", "ai_radio_cache", "5xx_origin_pressure",
                            "medium_canary_owner_gate", "high_never_auto"],
            "reliability": ["5xx_diagnostics", "502_504_524_classification", "origin_php_or_upstream_error",
                            "cloudflare_to_origin_timeout", "rolling_window_decay", "low_growth_24h_evidence",
                            "no_premature_waf_rule"],
            "learning": ["success_patterns", "blocked_patterns", "regressions", "stable_healthchecks",
                         "secret_scan_false_positives", "git_checkpoint_success", "no_go_paths"],
        },
        "live_apply": False,
        "emergency_stop": True,
    }
    roadmap = {
        "name": "autonomy-level-roadmap",
        "kind": "roadmap",
        "levels": AUTONOMY_LEVELS,
        "current_level": state["autonomy_map"]["current_level"],
        "allowed_current_levels": sorted(ALLOWED_CURRENT_LEVELS),
        "progression_requires": ["owner_approval", "backup", "healthcheck", "rollback", "audit"],
        "live_apply": False,
        "emergency_stop": True,
        "note": "LEVEL_3+/LEVEL_4 are future-only and never auto-enabled by this module.",
    }
    return {
        PLAYBOOK_CONTROL_PLANE: control_plane,
        PLAYBOOK_BOT: bot,
        PLAYBOOK_ROADMAP: roadmap,
    }


# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------
def write_all_outputs(state: Dict[str, Any]) -> List[str]:
    written: List[str] = []

    def _wj(path: Path, data: Dict[str, Any]) -> None:
        write_json_atomic(path, data)
        written.append(str(path.relative_to(PROJECT_DIR)))

    def _wt(path: Path, text: str) -> None:
        write_text_atomic(path, text)
        written.append(str(path.relative_to(PROJECT_DIR)))

    # Reports
    _wj(REPORT_JSON, state["report"])
    _wt(REPORT_MD, render_report_md(state))
    _wt(CLASSIFICATION_MD, render_classification_md(state))
    _wt(NEXT_ACTIONS_MD, render_next_actions_md(state))
    _wt(RISK_REGISTER_MD, render_risk_register_md(state))
    _wt(SERVICE_POSITIONING_MD, SERVICE_POSITIONING_TEXT)

    # State
    _wj(STATE_CONTROL_PLANE_JSON, {
        "schema_version": SCHEMA_VERSION,
        "generated_at": state["report"]["generated_at"],
        "report": state["report"],
        "autonomy_map": state["autonomy_map"],
        "classification_counts": state["classification"]["counts"],
        "ingest_summary": state["report"]["ingest_summary"],
    })
    _wj(STATE_AUTONOMY_POLICY_JSON, state["policy"])
    _wj(STATE_ACTION_MEMORY_JSON, {
        "schema_version": SCHEMA_VERSION,
        "generated_at": state["report"]["generated_at"],
        "actions": state["classification"]["actions"],
        "counts": state["classification"]["counts"],
    })
    _wj(STATE_NO_AUTO_APPLY_JSON, state["no_auto_apply"])
    _wj(STATE_SUCCESS_PATTERNS_JSON, state["success"])
    _wj(STATE_BLOCKED_PATTERNS_JSON, state["blocked"])
    _wj(STATE_LATEST_JSON, state["report"])

    # Playbooks
    for path, data in build_playbooks(state).items():
        _wj(path, data)

    # Audit
    append_jsonl(AUDIT_JSONL, [{
        "ts": state["report"]["generated_at"],
        "phase": "9.0",
        "module": "sentinel_autonomous_control_plane",
        "current_level": state["report"]["current_level"],
        "live_apply": state["report"]["live_apply"],
        "emergency_stop": state["report"]["emergency_stop"],
        "allowed_apply_now": state["report"]["allowed_apply_now"],
        "status": state["report"]["status"],
        "breach": state["report"]["breach"],
        "git_checkpoint_recommended": state["report"]["git_checkpoint_recommended"],
        "secrets_in_report": False,
    }])
    written.append(str(AUDIT_JSONL.relative_to(PROJECT_DIR)))
    return written


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def run_self_test() -> int:
    full_src = Path(__file__).read_text(encoding="utf-8")

    # Scan the module source for forbidden capabilities, but exclude this
    # self-test function itself: it necessarily contains the trigger literals
    # inside its detection patterns and would otherwise match itself.
    _st = full_src.find("\ndef run_self_test")
    _end = full_src.find("\ndef ", _st + 1) if _st != -1 else -1
    src = full_src[:_st] + (full_src[_end:] if _end != -1 else "") if _st != -1 else full_src

    if re.search(r"add_argument\([\"']--apply", src):
        raise AssertionError("module must not define --apply")
    forbidden_capabilities = [
        ("sftp write", re.compile(r"\.put\(|sftp\.put|paramiko")),
        ("db write", re.compile(r"(?i)\b(INSERT INTO|UPDATE .+ SET|DELETE FROM|\$wpdb|wpdb->)")),
        ("cloudflare write", re.compile(r"(?i)api\.cloudflare\.com|cloudflare.*(PUT|POST|PATCH|DELETE)")),
        ("systemctl start/enable", re.compile(r"systemctl\s+(start|enable|restart|stop|disable)")),
        ("rm -rf", re.compile(r"rm\s+-rf|shutil\.rmtree")),
    ]
    for label, pattern in forbidden_capabilities:
        if pattern.search(src):
            raise AssertionError(f"forbidden capability present in source: {label}")

    classification = classify_actions()
    autonomy_map = build_autonomy_map()
    no_auto_apply = build_no_auto_apply_rules()

    # Invariants.
    if autonomy_map["live_apply"] is not False:
        raise AssertionError("live_apply must be false")
    if autonomy_map["emergency_stop"] is not True:
        raise AssertionError("emergency_stop must be true")
    if autonomy_map["allowed_apply_now"] is not False:
        raise AssertionError("allowed_apply_now must be false")
    if autonomy_map["current_level"] not in ALLOWED_CURRENT_LEVELS:
        raise AssertionError("current_level must be LEVEL_1/LEVEL_2")

    for a in classification["actions"]:
        if a["auto_apply_allowed_now"]:
            raise AssertionError(f"{a['id']} must not auto-apply now")
        if a["classification"] == HIGH and not a["blocked"]:
            raise AssertionError(f"HIGH action not blocked: {a['id']}")
        if a["classification"] == MEDIUM and not a["owner_gate_required"]:
            raise AssertionError(f"MEDIUM action missing owner gate: {a['id']}")
        if a["classification"] == LOW and a["productive_website_write"]:
            raise AssertionError(f"LOW action must not write productively: {a['id']}")
    if classification["counts"][HIGH] < 1 or classification["counts"][MEDIUM] < 1:
        raise AssertionError("expected HIGH and MEDIUM actions present")

    # no_auto_apply must cover required scopes.
    for token in NO_AUTO_APPLY_REQUIRED_TOKENS:
        if not any(token in r["scope"] for r in no_auto_apply["rules"]):
            raise AssertionError(f"no_auto_apply missing required token: {token}")

    # Breach detection: clean state must NOT breach.
    state = build_full_state()
    if state["breach"]:
        raise AssertionError(f"clean control plane must not breach: {state['breach_reasons']}")
    if state["report"]["status"] != "CONTROL_PLANE_SAFE_LOCKED":
        raise AssertionError("clean control plane status must be SAFE_LOCKED")

    # Tampered inputs must breach.
    bad_map = dict(autonomy_map, live_apply=True)
    if not compute_breach(bad_map, classification, no_auto_apply)[0]:
        raise AssertionError("live_apply=True did not breach")
    bad_map = dict(autonomy_map, emergency_stop=False)
    if not compute_breach(bad_map, classification, no_auto_apply)[0]:
        raise AssertionError("emergency_stop=False did not breach")
    bad_cls = json.loads(json.dumps(classification))
    for a in bad_cls["actions"]:
        if a["classification"] == HIGH:
            a["blocked"] = False
            break
    if not compute_breach(autonomy_map, bad_cls, no_auto_apply)[0]:
        raise AssertionError("unblocked HIGH did not breach")

    # No secrets in any rendered output.
    for blob in (render_report_md(state), render_classification_md(state),
                 render_next_actions_md(state), render_risk_register_md(state),
                 SERVICE_POSITIONING_TEXT, json.dumps(state["report"]),
                 json.dumps(state["policy"]), json.dumps(state["no_auto_apply"])):
        if SECRET_ASSIGNMENT_RE.search(blob) or LONG_HEX_RE.search(blob):
            raise AssertionError("secret-like content in output")

    # Write-path guards.
    for forbidden in (
        PROJECT_DIR / "reports/latest/x.sh",
        PROJECT_DIR / "reports/latest/x.php",
        PROJECT_DIR / "state/adaptive-learning/x.service",
        PROJECT_DIR / "config/x.json",
        PROJECT_DIR / "etc/systemd/x.json",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")
    for ok_path in (REPORT_JSON, STATE_AUTONOMY_POLICY_JSON, AUDIT_JSONL, PLAYBOOK_CONTROL_PLANE):
        assert_allowed_write(ok_path)

    if not detect_secret_like("password=supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("status=OK"):
        raise AssertionError("secret detector false positive")

    print("autonomous-control-plane self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], written: List[str]) -> None:
    r = state["report"]
    print("=== Sentinel Autonomous Learning Control Plane (Phase 9.0) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"current_level: {r['current_level']}")
    print(f"live_apply: {r['live_apply']}")
    print(f"emergency_stop: {r['emergency_stop']}")
    print(f"allowed_apply_now: {r['allowed_apply_now']}")
    counts = r["action_classification_counts"]
    print("action classification counts:")
    for cls in CLASS_ORDER:
        print(f"  {cls}: {counts.get(cls, 0)}")
    print(f"top learned success patterns: {', '.join(r['top_success_patterns'])}")
    print(f"top learned blocked patterns: {', '.join(r['top_blocked_patterns'])}")
    print(f"no-auto-apply rules count: {r['no_auto_apply_rules_count']}")
    print(f"next safe actions: {', '.join(r['next_safe_actions'])}")
    print(f"service positioning: {r['service_positioning_summary']}")
    print(f"breach: {r['breach']}")
    print(f"git checkpoint recommended: {r['git_checkpoint_recommended']}")
    print(f"status: {r['status']}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Autonomous Learning Control Plane (Phase 9.0). Read-only; no apply."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--ingest", action="store_true", help="Read-only ingest of reports/state/audit/playbooks/git/systemd.")
    p.add_argument("--classify-actions", action="store_true", help="Classify all actions.")
    p.add_argument("--build-autonomy-map", action="store_true", help="Build the LEVEL_0..LEVEL_5 autonomy map.")
    p.add_argument("--draft-next-actions", action="store_true", help="Draft safe next actions (no apply).")
    p.add_argument("--policy-report", action="store_true", help="Emit policy + risk register.")
    p.add_argument("--status", action="store_true", help="Print status summary.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    # Every command performs the full read-only build and writes all outputs,
    # then prints the section relevant to the chosen command. There is no apply.
    state = build_full_state()
    written = write_all_outputs(state)
    r = state["report"]

    if args.ingest:
        ing = state["ingest"]
        print(f"[ingest] files={ing['file_count']} content={ing['files_content_ingested']} "
              f"metadata_only={ing['files_metadata_only']} sensitive_skipped={ing['skipped_sensitive_name']} "
              f"secrets_ingested={ing['secrets_ingested']}")
        print(f"[ingest] git untracked={ing['git']['untracked_count']} modified={ing['git']['modified_count']}")
        print(f"[ingest] timers={ing['systemd_timers_readonly']}")
    if args.classify_actions:
        print(f"[classify] counts={state['classification']['counts']} total={state['classification']['total']}")
    if args.build_autonomy_map:
        print(f"[autonomy-map] current_level={r['current_level']} live_apply={r['live_apply']} "
              f"emergency_stop={r['emergency_stop']} allowed_apply_now={r['allowed_apply_now']}")
    if args.draft_next_actions:
        print(f"[next-actions] {', '.join(r['next_safe_actions'])}")
    if args.policy_report:
        print(f"[policy] no_auto_apply_rules={r['no_auto_apply_rules_count']} "
              f"required_tokens_present={r['no_auto_apply_required_tokens_present']} breach={r['breach']}")

    # --status (or no specific subcommand) prints the full summary.
    if args.status or not any(
        (args.ingest, args.classify_actions, args.build_autonomy_map, args.draft_next_actions, args.policy_report)
    ):
        _print_status(state, written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
