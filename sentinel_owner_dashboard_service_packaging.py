#!/usr/bin/env python3
"""Sentinel Owner Dashboard & Service Packaging (Phase 9.1).

A safe, read-only owner-facing dashboard and service-packaging layer on top of
the Phase 9.0 Autonomous Learning Control Plane. It turns the control-plane
state into:

- a clear owner dashboard (Markdown + JSON): what Sentinel may do automatically
  now, what it must never do automatically, and what needs owner approval;
- a service offer structure (Audit / Safe Optimization / Monitoring & Improvement)
  with product texts and an English sales page;
- a customer policy ("Safe Autonomy instead of a blind autopilot");
- an internal LEVEL_3/LEVEL_4 roadmap (documentation only, never activated).

This module changes nothing on the website. There is deliberately no apply mode,
no SFTP write, no DB write, no Cloudflare write, no service start/enable via
systemctl and no timer installation. It only reads local Phase 9.0 reports/state
(plus git status read-only) and writes reports/state/audit/playbook files under
the allowed project roots.

Invariants surfaced and enforced:
    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    current_level in {LEVEL_1_DRAFT_ONLY, LEVEL_2_LOW_RISK_PREP_PREVIEW}
    every HIGH action  -> blocked / review-only
    every MEDIUM action-> owner gate (backup/healthcheck/rollback)
    no secrets in any report, state, audit or playbook output.
"""

from __future__ import annotations

import argparse
import hashlib
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
DASHBOARD_JSON = PROJECT_DIR / "reports/latest/sentinel-owner-dashboard.json"
DASHBOARD_MD = PROJECT_DIR / "reports/latest/sentinel-owner-dashboard.md"
OWNER_NEXT_ACTIONS_MD = PROJECT_DIR / "reports/latest/sentinel-owner-next-actions.md"
SERVICE_PACKAGES_MD = PROJECT_DIR / "reports/latest/sentinel-service-packages.md"
SALES_PAGE_MD = PROJECT_DIR / "reports/latest/sentinel-service-sales-page.md"
SAFE_AUTONOMY_POLICY_MD = PROJECT_DIR / "reports/latest/sentinel-safe-autonomy-policy.md"
LEVEL_ROADMAP_MD = PROJECT_DIR / "reports/latest/sentinel-level-roadmap.md"
CLIENT_DELIVERABLES_MD = PROJECT_DIR / "reports/latest/sentinel-client-deliverables.md"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_OWNER_DASHBOARD_JSON = STATE_DIR / "sentinel_owner_dashboard.json"
STATE_SERVICE_PACKAGING_JSON = STATE_DIR / "sentinel_service_packaging.json"
STATE_LATEST_OWNER_DASHBOARD_JSON = STATE_DIR / "latest_owner_dashboard.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-owner-dashboard-service-packaging.jsonl"

PLAYBOOK_DASHBOARD = PROJECT_DIR / "playbooks/sentinel-owner-dashboard.playbook.json"
PLAYBOOK_SERVICE = PROJECT_DIR / "playbooks/sentinel-service-packaging.playbook.json"
PLAYBOOK_ROADMAP = PROJECT_DIR / "playbooks/sentinel-safe-autonomy-roadmap.playbook.json"

# Output is restricted to exactly these roots (Phase 9.1 spec).
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

SCHEMA_VERSION = "owner-dashboard-service-packaging-9.1"

# ---------------------------------------------------------------------------
# Autonomy levels (must mirror Phase 9.0)
# ---------------------------------------------------------------------------
LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
LEVEL_2 = "LEVEL_2_LOW_RISK_PREP_PREVIEW"
LEVEL_3 = "LEVEL_3_LOW_RISK_APPLY_GATED"
LEVEL_4 = "LEVEL_4_MEDIUM_CANARY_ONLY"
LEVEL_5 = "LEVEL_5_HIGH_REVIEW_ONLY"
ALLOWED_CURRENT_LEVELS = {LEVEL_1, LEVEL_2}
DEFAULT_CURRENT_LEVEL = LEVEL_2

READ_ONLY = "READ_ONLY"
DRAFT = "DRAFT"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CLASS_ORDER = [READ_ONLY, DRAFT, LOW, MEDIUM, HIGH]

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
INPUT_JSON: List[Tuple[str, Path]] = [
    ("control_plane", PROJECT_DIR / "reports/latest/autonomous-control-plane.json"),
    ("autonomy_policy", STATE_DIR / "autonomy_policy.json"),
    ("action_memory", STATE_DIR / "action_memory.json"),
    ("no_auto_apply", STATE_DIR / "no_auto_apply_rules.json"),
    ("success_patterns", STATE_DIR / "learned_success_patterns.json"),
    ("blocked_patterns", STATE_DIR / "learned_blocked_patterns.json"),
]
INPUT_MD: List[Tuple[str, Path]] = [
    ("control_plane_md", PROJECT_DIR / "reports/latest/autonomous-control-plane.md"),
    ("action_classification_md", PROJECT_DIR / "reports/latest/autonomy-action-classification.md"),
    ("next_safe_actions_md", PROJECT_DIR / "reports/latest/autonomy-next-safe-actions.md"),
    ("risk_register_md", PROJECT_DIR / "reports/latest/autonomy-risk-register.md"),
    ("service_positioning_md", PROJECT_DIR / "reports/latest/autonomy-service-positioning.md"),
]

# ---------------------------------------------------------------------------
# Secret handling
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
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{40,}\b")


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
        raise ValueError(f"Refusing to write outside allowed dashboard roots: {path}")
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


def run_readonly(cmd: List[str], timeout: int = 10) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=str(PROJECT_DIR), capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode == 0, redact_text(proc.stdout, max_len=6000)
    except (OSError, subprocess.SubprocessError):
        return False, ""


# ---------------------------------------------------------------------------
# Service packages, roadmap, policy, sales page (structured content)
# ---------------------------------------------------------------------------
SERVICE_PACKAGES: List[Dict[str, Any]] = [
    {
        "id": "sentinel_audit",
        "name": "Sentinel Audit Report",
        "risk_level": READ_ONLY,
        "tagline": "Read-only Bestandsaufnahme Ihrer Website: Security, SEO und Performance auf einen Blick.",
        "scope": [
            "Read-only Analyse (keine Aenderungen an der Website)",
            "SEO-, Performance- und Security-Report",
            "Risikoanalyse (LOW / MEDIUM / HIGH)",
            "Priorisierte Massnahmenliste",
        ],
        "changes": "keine Aenderungen",
        "deliverables": [
            "SEO/Performance/Security Audit-Report (Markdown + JSON)",
            "Risk Register mit Klassifizierung",
            "Prioritaetenliste mit empfohlener Reihenfolge",
            "Owner-Zusammenfassung",
        ],
    },
    {
        "id": "sentinel_safe_optimization",
        "name": "Sentinel Safe Optimization",
        "risk_level": MEDIUM,
        "tagline": "Sichere, kontrollierte Optimierung: Drafts, Owner Review und einzelne Canary-Schritte mit Rollback.",
        "scope": [
            "Alles aus dem Audit",
            "Drafts (SEO/Meta/JSON-LD/Performance) zur Freigabe",
            "Owner Review Packs (Copy-paste-fertig)",
            "Ausgewaehlte LOW-RISK Vorbereitungen (nicht produktiv)",
            "Einzelne MEDIUM Canary-Optimierungen NUR mit Owner Approval",
            "Backup, Pre/Post-Healthcheck und Rollback bei jeder Canary",
        ],
        "changes": "nur einzelne, owner-freigegebene Canary-Schritte mit Backup/Healthcheck/Rollback",
        "deliverables": [
            "Audit-Report",
            "Konkrete Optimierungs-Drafts",
            "Owner Review Pack je Massnahme",
            "Canary-Protokoll (Backup-, Healthcheck-, Rollback-Nachweis)",
        ],
    },
    {
        "id": "sentinel_monitoring_improvement",
        "name": "Sentinel Monitoring & Improvement",
        "risk_level": MEDIUM,
        "tagline": "Laufende Beobachtung und kontrollierte Verbesserung mit monatlichem Owner Review.",
        "scope": [
            "Wiederkehrende Reports",
            "Trend-Monitoring (SEO/Performance)",
            "5xx / Origin / Cloudflare Beobachtung (read-only)",
            "SEO & Performance Roadmap",
            "Kontrollierte Micro-Optimierungen (owner-gated)",
            "Monatlicher Owner Review",
        ],
        "changes": "kontrollierte Micro-Optimierungen, owner-gated, mit Backup/Healthcheck/Rollback",
        "deliverables": [
            "Monatlicher Trend- und Status-Report",
            "Fortschritts-Roadmap",
            "Beobachtungs-Log (5xx/Origin/Cloudflare)",
            "Monatliches Owner-Review-Protokoll",
        ],
    },
]

ROADMAP_LEVELS: List[Dict[str, Any]] = [
    {
        "level": LEVEL_1,
        "title": "Draft Only",
        "state": "current_safe_baseline",
        "summary": "Read-only plus Drafts und Owner Review Packs. Kein Live Apply.",
        "prerequisites": [],
    },
    {
        "level": LEVEL_2,
        "title": "Low-Risk Prep Preview",
        "state": "current_control_plane_preview",
        "summary": "Read-only, Drafts und LOW-RISK Prepare-Vorschau. Kein Live Apply ohne Owner.",
        "prerequisites": [],
    },
    {
        "level": LEVEL_3,
        "title": "Low-Risk Apply (Gated)",
        "state": "future_only",
        "summary": "Spaeter: LOW-RISK Apply nur aus Allowlist, owner-freigegeben.",
        "prerequisites": [
            "emergency_stop reviewed",
            "owner policy signed",
            "allowlist defined",
            "backup/healthcheck/rollback tested",
            "Git checkpoint required",
            "no HIGH",
            "no MEDIUM without explicit approval",
        ],
    },
    {
        "level": LEVEL_4,
        "title": "Medium Canary Only",
        "state": "future_only",
        "summary": "Spaeter: einzelne Canary-Aktionen, owner-gated.",
        "prerequisites": [
            "one candidate at a time",
            "owner gate",
            "rollback mandatory",
            "no mass apply",
        ],
    },
    {
        "level": LEVEL_5,
        "title": "High Review Only",
        "state": "permanent",
        "summary": "HIGH bleibt dauerhaft review-only, niemals automatischer Apply.",
        "prerequisites": ["permanently review-only"],
    },
]

SAFE_AUTONOMY_PRINCIPLES: List[str] = [
    "Sentinel is not a reckless autopilot.",
    "Diagnosis first.",
    "Review before sensitive action.",
    "Backup before apply.",
    "Healthcheck before and after.",
    "Rollback plan ready.",
    "HIGH-risk never automatic.",
    "MEDIUM only as a single Canary with an Owner Gate.",
    "LOW only allowlisted and prepared (non-productive).",
    "Live apply remains off unless explicitly enabled in a later, reviewed phase.",
]

PRIMARY_SALES_HEADLINE = (
    "Safe Autonomy for Your Website: Security, SEO and Speed Without the Risk of a Blind Autopilot"
)
SALES_SUBHEADLINE = (
    "Sentinel diagnoses, drafts and improves your WordPress site behind Cloudflare with backups, "
    "healthchecks and rollback. Read-only by default. You approve every sensitive change."
)
NOT_PROMISED = [
    "No guarantee of a perfect 100% PageSpeed score.",
    "No blind autopilot and no unattended mass changes.",
    "No HIGH-risk changes (database, themes, plugins, redirects, firewall) without explicit owner review.",
    "No counter-attacks and no broad blocking without evidence.",
]


def sales_page_text(packages: List[Dict[str, Any]]) -> str:
    cards = []
    for pkg in packages:
        bullets = "\n".join(f"  - {s}" for s in pkg["scope"])
        cards.append(
            f"### {pkg['name']}\n"
            f"_{pkg['tagline']}_\n\n"
            f"{bullets}\n\n"
            f"Changes: {pkg['changes']}\n"
        )
    not_promised = "\n".join(f"- {x}" for x in NOT_PROMISED)
    principles = "\n".join(f"- {x}" for x in SAFE_AUTONOMY_PRINCIPLES)
    return (
        f"# {PRIMARY_SALES_HEADLINE}\n\n"
        f"## {SALES_SUBHEADLINE}\n\n"
        "## The Problem\n"
        "Most website tools either do nothing useful on their own, or they auto-apply risky "
        "changes that break SEO, layout or uptime. WordPress sites behind Cloudflare are hit by "
        "bot scans, 5xx/origin pressure, slow images and duplicate or conflicting structured data "
        "- and a single careless automated change can take the site down or tank rankings.\n\n"
        "## The Solution\n"
        "Sentinel is a defensive, learning Security, SEO & Performance bot. It observes and "
        "diagnoses first, then proposes improvements as reviewable drafts. Sensitive changes are "
        "never automatic: each one is gated by backup, pre/post healthcheck and a rollback plan, "
        "and you approve it.\n\n"
        "## Why Safe Autonomy Matters\n"
        "Autonomy is only valuable if it is trustworthy. Sentinel earns trust by being read-only by "
        "default, auditable, and risk-classified. It learns which safe optimizations worked and "
        "remembers which actions must stay blocked - so it gets better without getting reckless.\n\n"
        f"{principles}\n\n"
        "## What Is Included\n"
        + "\n\n".join(cards)
        + "\n## What Is Not Promised\n"
        f"{not_promised}\n\n"
        "## Get Started\n"
        "Start with a **Sentinel Audit Report** to see exactly where your site stands - no changes, "
        "no risk. Then choose **Safe Optimization** or ongoing **Monitoring & Improvement**.\n\n"
        "**Call to action:** Request your Sentinel Audit today.\n\n"
        "---\n"
        "_Disclaimer: Sentinel does not promise a 100% PageSpeed score, is not a blind autopilot, "
        "and never performs HIGH-risk changes without owner review._\n"
    )


# ---------------------------------------------------------------------------
# Read inputs (read-only, missing-tolerant)
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
    files_sample = []
    for ln in lines[:15]:
        # keep only the path token, redacted; never store raw blobs
        name = ln[3:].strip() if len(ln) > 3 else ln.strip()
        files_sample.append(redact_text(name, max_len=120))
    return {
        "log_available": log_ok,
        "recent_log": log_out.splitlines()[:15],
        "status_available": st_ok,
        "untracked_count": untracked,
        "modified_count": modified,
        "checkpoint_recommended": (untracked + modified) > 0,
        "files_sample": files_sample,
    }


# ---------------------------------------------------------------------------
# Resolve safety state + action groups
# ---------------------------------------------------------------------------
def resolve_safety(inputs: Dict[str, Any]) -> Dict[str, Any]:
    cp = inputs["data"].get("control_plane")
    policy = inputs["data"].get("autonomy_policy")

    def pick(key: str, default: Any) -> Any:
        if isinstance(cp, dict) and key in cp:
            return cp[key]
        if isinstance(policy, dict) and key in policy:
            return policy[key]
        return default

    live = bool(pick("live_apply", False))
    estop = bool(pick("emergency_stop", True))
    aan = bool(pick("allowed_apply_now", False))
    level = pick("current_level", DEFAULT_CURRENT_LEVEL)
    upstream_breach = bool(cp.get("breach")) if isinstance(cp, dict) else False
    upstream_status = cp.get("status") if isinstance(cp, dict) else "not_available"
    return {
        "live_apply": live,
        "emergency_stop": estop,
        "allowed_apply_now": aan,
        "current_level": level,
        "upstream_breach": upstream_breach,
        "upstream_status": upstream_status,
        "control_plane_available": isinstance(cp, dict),
    }


def _action_groups(inputs: Dict[str, Any]) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, int]]:
    am = inputs["data"].get("action_memory")
    groups: Dict[str, List[Dict[str, Any]]] = {c: [] for c in CLASS_ORDER}
    counts: Dict[str, int] = {c: 0 for c in CLASS_ORDER}
    if isinstance(am, dict) and isinstance(am.get("actions"), list):
        for a in am["actions"]:
            if not isinstance(a, dict):
                continue
            cls = a.get("classification")
            if cls not in groups:
                continue
            groups[cls].append({
                "id": a.get("id"),
                "domain": a.get("domain"),
                "description": redact_text(a.get("description"), max_len=200),
                "disposition": a.get("disposition"),
                "owner_gate_required": bool(a.get("owner_gate_required")),
                "blocked": bool(a.get("blocked")),
            })
        if isinstance(am.get("counts"), dict):
            for c in CLASS_ORDER:
                counts[c] = int(am["counts"].get(c, len(groups[c])))
        else:
            counts = {c: len(groups[c]) for c in CLASS_ORDER}
    else:
        # fallback to control plane counts only
        cp = inputs["data"].get("control_plane")
        if isinstance(cp, dict) and isinstance(cp.get("action_classification_counts"), dict):
            for c in CLASS_ORDER:
                counts[c] = int(cp["action_classification_counts"].get(c, 0))
    return groups, counts


def _top_patterns(inputs: Dict[str, Any], key_cp: str, key_state: str) -> List[str]:
    cp = inputs["data"].get("control_plane")
    if isinstance(cp, dict) and isinstance(cp.get(key_cp), list) and cp[key_cp]:
        return [redact_text(x, max_len=80) for x in cp[key_cp][:5]]
    state = inputs["data"].get(key_state)
    if isinstance(state, dict) and isinstance(state.get("patterns"), list):
        return [redact_text(p.get("id"), max_len=80) for p in state["patterns"][:5]]
    return []


# ---------------------------------------------------------------------------
# Dashboard assembly
# ---------------------------------------------------------------------------
SECRETS_GUARDRAIL = "secrets: never read, store or output"


def build_dashboard_data(inputs: Dict[str, Any]) -> Dict[str, Any]:
    safety = resolve_safety(inputs)
    groups, counts = _action_groups(inputs)
    git = _git_status()
    no_auto_apply = inputs["data"].get("no_auto_apply")
    na_count = int(no_auto_apply.get("count")) if isinstance(no_auto_apply, dict) and no_auto_apply.get("count") else 0
    na_scopes = no_auto_apply.get("scopes", []) if isinstance(no_auto_apply, dict) else []

    cp = inputs["data"].get("control_plane")
    next_safe_actions = cp.get("next_safe_actions", []) if isinstance(cp, dict) else []

    top_success = _top_patterns(inputs, "top_success_patterns", "success_patterns")
    top_blocked = _top_patterns(inputs, "top_blocked_patterns", "blocked_patterns")

    def describe(items: List[Dict[str, Any]]) -> List[str]:
        out = []
        for a in items:
            out.append(f"{a['id']} — {a['description']}")
        return out

    may_now = (
        describe(groups[READ_ONLY])
        + describe(groups[DRAFT])
        + [f"{a['id']} — {a['description']} (nicht produktiv)" for a in groups[LOW]]
    )
    if not may_now:
        may_now = [
            "Read-only Diagnose und Reports",
            "Drafts und Owner Review Packs",
            "LOW-RISK Vorbereitung (nicht produktiv)",
        ]
    must_never = describe(groups[HIGH]) + [SECRETS_GUARDRAIL]
    if not groups[HIGH]:
        must_never = [
            "DB / FSE / Theme- & Plugin-Code aendern",
            ".htaccess / Nginx / Cloudflare / WAF aendern",
            "Cache Purge / Redirects / Massenoptimierung / breite SFTP-Operationen",
            "Cron-/systemd-Timer installieren; Block-Regeln ohne Beweis",
            SECRETS_GUARDRAIL,
        ]
    needs_owner = describe(groups[MEDIUM]) or [
        "Einzelne Bild-Canary-Optimierung (Backup/Healthcheck/Rollback)",
        "Einzelne sichere Datei per SFTP ersetzen (Backup/Healthcheck/Rollback)",
    ]

    breach, breach_reasons = compute_breach(safety, groups, na_scopes)

    if breach:
        bot_status = "DASHBOARD_BREACH"
    elif safety["emergency_stop"] and not safety["live_apply"] and not safety["allowed_apply_now"]:
        bot_status = "SAFE_LOCKED_READONLY_AND_DRAFT_READY"
    else:
        bot_status = "REVIEW_REQUIRED"

    return {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.1",
        "module": "sentinel_owner_dashboard_service_packaging",
        "generated_at": utc_now(),
        "current_bot_status": bot_status,
        "autonomy_level": safety["current_level"],
        "live_apply": safety["live_apply"],
        "emergency_stop": safety["emergency_stop"],
        "allowed_apply_now": safety["allowed_apply_now"],
        "breach": breach,
        "breach_reasons": breach_reasons,
        "is_live_autopilot": False,
        "upstream": {
            "control_plane_available": safety["control_plane_available"],
            "control_plane_status": redact_text(safety["upstream_status"], max_len=80),
            "control_plane_breach": safety["upstream_breach"],
        },
        "action_counts": counts,
        "actions": {
            "read_only": groups[READ_ONLY],
            "draft": groups[DRAFT],
            "low": groups[LOW],
            "medium_owner_gated": groups[MEDIUM],
            "high_blocked": groups[HIGH],
        },
        "top_success_patterns": top_success,
        "top_blocked_patterns": top_blocked,
        "no_auto_apply_rules_count": na_count,
        "no_auto_apply_scopes": na_scopes,
        "git_checkpoint": {
            "recommended": git["checkpoint_recommended"],
            "untracked_count": git["untracked_count"],
            "modified_count": git["modified_count"],
            "files_sample": git["files_sample"],
        },
        "next_safe_actions": [redact_text(x, max_len=80) for x in next_safe_actions],
        "may_do_automatically_now": may_now,
        "must_never_do_automatically": must_never,
        "needs_owner_approval": needs_owner,
        "service_packages": [p["name"] for p in SERVICE_PACKAGES],
        "missing_inputs": inputs["missing_inputs"],
        "secrets_in_report": False,
        "status": bot_status,
    }


def build_owner_next_actions(dash: Dict[str, Any]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = [
        {"id": "review_owner_dashboard", "classification": READ_ONLY,
         "action": "Owner-Dashboard pruefen (Status, was automatisch erlaubt ist, was Freigabe braucht).",
         "owner_gate": False, "blocked_now": False},
    ]
    for aid in dash["next_safe_actions"]:
        items.append({
            "id": f"control_plane::{aid}", "classification": "FROM_CONTROL_PLANE",
            "action": f"Naechste sichere Aktion aus der Control Plane: {aid}.",
            "owner_gate": False, "blocked_now": False,
        })
    items.append({
        "id": "decide_service_package", "classification": DRAFT,
        "action": "Service-Paket fuer Angebot/Einsatz auswaehlen (Audit / Safe Optimization / Monitoring & Improvement).",
        "owner_gate": False, "blocked_now": False,
    })
    items.append({
        "id": "single_medium_canary_decision", "classification": MEDIUM,
        "action": "Naechste einzelne MEDIUM Canary (z. B. Bild) nur mit Owner Approval + Backup/Healthcheck/Rollback freigeben oder zurueckstellen.",
        "owner_gate": True, "blocked_now": True,
    })
    items.append({
        "id": "sign_safe_autonomy_policy", "classification": DRAFT,
        "action": "Safe-Autonomy-Policy lesen und (vor jeder LEVEL_3-Ueberlegung) als Owner unterschreiben.",
        "owner_gate": False, "blocked_now": False,
    })
    if dash["git_checkpoint"]["recommended"]:
        items.append({
            "id": "create_git_checkpoint", "classification": DRAFT,
            "action": f"Git-Safety-Checkpoint fuer {dash['git_checkpoint']['untracked_count']} untracked / "
                      f"{dash['git_checkpoint']['modified_count']} modified Dateien empfehlen (kein Auto-Push).",
            "owner_gate": False, "blocked_now": False,
        })
    items.append({
        "id": "keep_emergency_stop", "classification": READ_ONLY,
        "action": "Emergency Stop aktiv lassen, bis alle LEVEL_3-Voraussetzungen geprueft und unterschrieben sind.",
        "owner_gate": False, "blocked_now": False,
    })
    return items


# ---------------------------------------------------------------------------
# Breach
# ---------------------------------------------------------------------------
def compute_breach(safety: Dict[str, Any], groups: Dict[str, List[Dict[str, Any]]],
                   no_auto_apply_scopes: List[str]) -> Tuple[bool, List[str]]:
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
        reasons.append("upstream control plane reports breach")
    for a in groups.get(HIGH, []):
        if not a.get("blocked"):
            reasons.append(f"HIGH action {a.get('id')} not blocked")
    for a in groups.get(MEDIUM, []):
        if not a.get("owner_gate_required"):
            reasons.append(f"MEDIUM action {a.get('id')} missing owner gate")
    return (len(reasons) > 0), reasons


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def render_dashboard_md(dash: Dict[str, Any]) -> str:
    a = dash["actions"]

    def block(title: str, items: List[Dict[str, Any]]) -> List[str]:
        out = [f"### {title} ({len(items)})"]
        if not items:
            out.append("- (keine)")
        for it in items:
            flags = []
            if it.get("owner_gate_required"):
                flags.append("OWNER GATE")
            if it.get("blocked"):
                flags.append("BLOCKED")
            suffix = f" [{', '.join(flags)}]" if flags else ""
            out.append(f"- `{it['id']}` ({it['domain']}): {it['description']}{suffix}")
        return out

    lines = [
        "# Sentinel Owner Dashboard (Phase 9.1)",
        "",
        f"- Generated: {dash['generated_at']}",
        f"- Current bot status: **{dash['current_bot_status']}**",
        f"- Autonomy level: **{dash['autonomy_level']}**",
        f"- live_apply: `{dash['live_apply']}` | emergency_stop: `{dash['emergency_stop']}` | "
        f"allowed_apply_now: `{dash['allowed_apply_now']}` | breach: `{dash['breach']}`",
        f"- Live autopilot: `{dash['is_live_autopilot']}`",
        f"- Upstream control plane: available={dash['upstream']['control_plane_available']}, "
        f"status={dash['upstream']['control_plane_status']}, breach={dash['upstream']['control_plane_breach']}",
        "",
        "## Action overview",
        f"- READ_ONLY: {dash['action_counts'].get(READ_ONLY, 0)} | DRAFT: {dash['action_counts'].get(DRAFT, 0)} | "
        f"LOW: {dash['action_counts'].get(LOW, 0)} | MEDIUM: {dash['action_counts'].get(MEDIUM, 0)} | "
        f"HIGH: {dash['action_counts'].get(HIGH, 0)}",
        "",
    ]
    lines += block("READ_ONLY actions", a["read_only"]) + [""]
    lines += block("DRAFT actions", a["draft"]) + [""]
    lines += block("LOW actions (non-productive)", a["low"]) + [""]
    lines += block("MEDIUM actions (owner-gated)", a["medium_owner_gated"]) + [""]
    lines += block("HIGH actions (blocked / review-only)", a["high_blocked"]) + [""]
    lines += [
        "## Learning",
        f"- Top success patterns: {', '.join(dash['top_success_patterns']) or '-'}",
        f"- Top blocked patterns: {', '.join(dash['top_blocked_patterns']) or '-'}",
        f"- No-auto-apply rules: {dash['no_auto_apply_rules_count']} ({', '.join(dash['no_auto_apply_scopes']) or '-'})",
        "",
        "## Git checkpoint",
        f"- Recommended: {dash['git_checkpoint']['recommended']} "
        f"(untracked={dash['git_checkpoint']['untracked_count']}, modified={dash['git_checkpoint']['modified_count']})",
        "",
        "## Next safe actions",
    ] + [f"- {x}" for x in (dash["next_safe_actions"] or ["-"])] + [
        "",
        "## What Sentinel may do automatically now",
    ] + [f"- {x}" for x in dash["may_do_automatically_now"]] + [
        "",
        "## What Sentinel must never do automatically",
    ] + [f"- {x}" for x in dash["must_never_do_automatically"]] + [
        "",
        "## What needs owner approval",
    ] + [f"- {x}" for x in dash["needs_owner_approval"]]
    if dash["missing_inputs"]:
        lines += ["", "## Missing inputs"] + [f"- {x}" for x in dash["missing_inputs"]]
    if dash["breach"]:
        lines += ["", "## BREACH REASONS"] + [f"- {x}" for x in dash["breach_reasons"]]
    lines += ["", "_Read-only dashboard. Veraendert die Website nicht. Aktiviert keinen Autopilot._"]
    return "\n".join(lines) + "\n"


def render_owner_next_actions_md(dash: Dict[str, Any], items: List[Dict[str, Any]]) -> str:
    lines = ["# Sentinel — Owner Next Actions", "",
             f"Generated: {dash['generated_at']}",
             f"Git checkpoint recommended: {dash['git_checkpoint']['recommended']}", ""]
    for it in items:
        gate = " [OWNER GATE]" if it.get("owner_gate") else ""
        blocked = " [BLOCKED NOW]" if it.get("blocked_now") else ""
        lines += [f"## {it['id']} ({it['classification']}){gate}{blocked}", f"- {it['action']}", ""]
    lines += ["_Keine dieser Aktionen wird automatisch ausgefuehrt. MEDIUM bleibt owner-gated und blockiert._"]
    return "\n".join(lines) + "\n"


def render_service_packages_md() -> str:
    lines = ["# Sentinel Service Packages", ""]
    for i, pkg in enumerate(SERVICE_PACKAGES, 1):
        lines += [
            f"## Paket {i}: {pkg['name']}",
            f"_{pkg['tagline']}_",
            f"- Risiko-Level: **{pkg['risk_level']}**",
            f"- Aenderungen: {pkg['changes']}",
            "",
            "**Umfang:**",
        ] + [f"- {s}" for s in pkg["scope"]] + ["", "**Deliverables:**"] + [f"- {d}" for d in pkg["deliverables"]] + [""]
    lines += ["_Alle Pakete: read-only by default. MEDIUM nur als einzelner owner-gated Canary mit "
              "Backup/Healthcheck/Rollback. HIGH niemals automatisch._"]
    return "\n".join(lines) + "\n"


def render_client_deliverables_md() -> str:
    lines = ["# Sentinel Client Deliverables", "",
             "Was der Kunde je Paket konkret erhaelt:", ""]
    for pkg in SERVICE_PACKAGES:
        lines += [f"## {pkg['name']}"] + [f"- {d}" for d in pkg["deliverables"]] + [""]
    lines += ["_Keine Live-Aenderung ohne Owner-Freigabe. Jede sensible Aktion mit Backup/Healthcheck/Rollback._"]
    return "\n".join(lines) + "\n"


def render_safe_autonomy_policy_md() -> str:
    principles = "\n".join(f"- {p}" for p in SAFE_AUTONOMY_PRINCIPLES)
    return (
        "# Sentinel Safe Autonomy Policy\n\n"
        "**Safe Autonomy instead of a blind autopilot.**\n\n"
        f"{principles}\n\n"
        "## Operating cycle\n"
        "Diagnose -> Review -> Backup -> Healthcheck -> Rollback. Read-only by default, auditable, "
        "risk-classified. Live apply stays off (`live_apply=false`, `emergency_stop=true`, "
        "`allowed_apply_now=false`) unless explicitly enabled in a later, reviewed phase.\n\n"
        "## Risk handling\n"
        "- HIGH-risk actions are blocked / review-only forever.\n"
        "- MEDIUM actions run only as a single Canary behind an Owner Gate, with backup, pre/post "
        "healthcheck and a rollback plan.\n"
        "- LOW actions are only allowlisted and prepared, never productive.\n"
        "- READ_ONLY and DRAFT are safe to use continuously.\n"
    )


def render_level_roadmap_md(dash: Dict[str, Any]) -> str:
    lines = ["# Sentinel Autonomy Level Roadmap", "",
             f"Current level: **{dash['autonomy_level']}** "
             f"(allowed now: {', '.join(sorted(ALLOWED_CURRENT_LEVELS))})", "",
             "_Internal roadmap only. No level is activated by this module._", ""]
    for lvl in ROADMAP_LEVELS:
        lines += [f"## {lvl['level']} — {lvl['title']}",
                  f"- State: `{lvl['state']}`",
                  f"- {lvl['summary']}"]
        if lvl["prerequisites"]:
            lines += ["- Prerequisites:"] + [f"  - {p}" for p in lvl["prerequisites"]]
        lines += [""]
    lines += ["_LEVEL_3 and LEVEL_4 are future-only and never auto-enabled. "
              "LEVEL_5 (HIGH) is permanently review-only._"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------
def build_playbooks(dash: Dict[str, Any]) -> Dict[Path, Dict[str, Any]]:
    dashboard_pb = {
        "name": "sentinel-owner-dashboard",
        "phase": "9.1",
        "kind": "review_only_dashboard",
        "applies_anything": False,
        "live_apply": False,
        "emergency_stop": True,
        "steps": [
            {"step": "build-dashboard", "type": READ_ONLY, "desc": "Render owner dashboard from control-plane state."},
            {"step": "build-owner-next-actions", "type": DRAFT, "desc": "Draft owner next actions (no apply)."},
            {"step": "status", "type": READ_ONLY, "desc": "Print dashboard status summary."},
        ],
        "forbidden": ["apply", "sftp_write", "db_write", "cloudflare_write", "service_start_enable", "timer_install"],
        "current_level": dash["autonomy_level"],
    }
    service_pb = {
        "name": "sentinel-service-packaging",
        "kind": "service_offer",
        "packages": SERVICE_PACKAGES,
        "sales_headline": PRIMARY_SALES_HEADLINE,
        "not_promised": NOT_PROMISED,
        "live_apply": False,
        "emergency_stop": True,
    }
    roadmap_pb = {
        "name": "sentinel-safe-autonomy-roadmap",
        "kind": "roadmap",
        "levels": ROADMAP_LEVELS,
        "current_level": dash["autonomy_level"],
        "allowed_current_levels": sorted(ALLOWED_CURRENT_LEVELS),
        "principles": SAFE_AUTONOMY_PRINCIPLES,
        "live_apply": False,
        "emergency_stop": True,
        "note": "LEVEL_3/LEVEL_4 future-only; never auto-enabled by this module.",
    }
    return {
        PLAYBOOK_DASHBOARD: dashboard_pb,
        PLAYBOOK_SERVICE: service_pb,
        PLAYBOOK_ROADMAP: roadmap_pb,
    }


# ---------------------------------------------------------------------------
# Full state + write
# ---------------------------------------------------------------------------
def build_full_state() -> Dict[str, Any]:
    inputs = read_inputs()
    dash = build_dashboard_data(inputs)
    owner_next = build_owner_next_actions(dash)
    packaging = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": dash["generated_at"],
        "packages": SERVICE_PACKAGES,
        "sales_headline": PRIMARY_SALES_HEADLINE,
        "sales_subheadline": SALES_SUBHEADLINE,
        "not_promised": NOT_PROMISED,
        "principles": SAFE_AUTONOMY_PRINCIPLES,
        "roadmap_levels": ROADMAP_LEVELS,
    }
    return {"inputs": inputs, "dashboard": dash, "owner_next": owner_next, "packaging": packaging}


def write_all_outputs(state: Dict[str, Any]) -> List[str]:
    dash = state["dashboard"]
    written: List[str] = []

    def _wj(path: Path, data: Dict[str, Any]) -> None:
        write_json_atomic(path, data)
        written.append(str(path.relative_to(PROJECT_DIR)))

    def _wt(path: Path, text: str) -> None:
        write_text_atomic(path, text)
        written.append(str(path.relative_to(PROJECT_DIR)))

    _wj(DASHBOARD_JSON, dash)
    _wt(DASHBOARD_MD, render_dashboard_md(dash))
    _wt(OWNER_NEXT_ACTIONS_MD, render_owner_next_actions_md(dash, state["owner_next"]))
    _wt(SERVICE_PACKAGES_MD, render_service_packages_md())
    _wt(SALES_PAGE_MD, sales_page_text(SERVICE_PACKAGES))
    _wt(SAFE_AUTONOMY_POLICY_MD, render_safe_autonomy_policy_md())
    _wt(LEVEL_ROADMAP_MD, render_level_roadmap_md(dash))
    _wt(CLIENT_DELIVERABLES_MD, render_client_deliverables_md())

    _wj(STATE_OWNER_DASHBOARD_JSON, dash)
    _wj(STATE_SERVICE_PACKAGING_JSON, state["packaging"])
    _wj(STATE_LATEST_OWNER_DASHBOARD_JSON, dash)

    for path, data in build_playbooks(dash).items():
        _wj(path, data)

    append_jsonl(AUDIT_JSONL, [{
        "ts": dash["generated_at"],
        "phase": "9.1",
        "module": "sentinel_owner_dashboard_service_packaging",
        "current_bot_status": dash["current_bot_status"],
        "autonomy_level": dash["autonomy_level"],
        "live_apply": dash["live_apply"],
        "emergency_stop": dash["emergency_stop"],
        "allowed_apply_now": dash["allowed_apply_now"],
        "breach": dash["breach"],
        "git_checkpoint_recommended": dash["git_checkpoint"]["recommended"],
        "missing_inputs": dash["missing_inputs"],
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
    # Prose-safe capability scan: match real code, not marketing text.
    forbidden_capabilities = [
        ("sftp write", re.compile(r"paramiko|sftp\.put\(|\.put\(\s")),
        ("db write", re.compile(r"\$wpdb|wpdb->|cursor\.\w+\(|\.execute\(|pymysql|psycopg|MySQLdb|"
                                r"DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET")),
        ("cloudflare write", re.compile(r"api\.cloudflare\.com|requests\.(put|post|patch|delete)\(|"
                                        r"httpx\.(put|post|patch|delete)\(")),
        ("service start/enable", re.compile(r"systemctl\s+(start|enable|restart|stop|disable)\b")),
        ("rm -rf", re.compile(r"rm\s+-rf|shutil\.rmtree")),
    ]
    for label, pattern in forbidden_capabilities:
        if pattern.search(src):
            raise AssertionError(f"forbidden capability present in source: {label}")

    # Output roots must be exactly the four allowed.
    allowed_names = {str(r.relative_to(PROJECT_DIR)) for r in ALLOWED_WRITE_ROOTS}
    if allowed_names != {"reports/latest", "state/adaptive-learning", "audit", "playbooks"}:
        raise AssertionError(f"unexpected write roots: {allowed_names}")

    # Read-only sensitive-path refusal.
    for bad in ("/etc/sentinel-defense.env", "deploy.key", "id_rsa", "api-token.json"):
        obj, status = read_optional_json(Path(bad))
        if obj is not None or status not in ("refused_secret_like_path", "not_available"):
            raise AssertionError(f"sensitive path not refused: {bad} -> {status}")

    # Build full state with real inputs -> must be safe & non-breaching.
    state = build_full_state()
    dash = state["dashboard"]
    if dash["live_apply"] is not False:
        raise AssertionError("live_apply must be false")
    if dash["emergency_stop"] is not True:
        raise AssertionError("emergency_stop must be true")
    if dash["allowed_apply_now"] is not False:
        raise AssertionError("allowed_apply_now must be false")
    if dash["autonomy_level"] not in ALLOWED_CURRENT_LEVELS:
        raise AssertionError("autonomy_level must be LEVEL_1/LEVEL_2")
    for a in dash["actions"]["high_blocked"]:
        if not a["blocked"]:
            raise AssertionError(f"HIGH action not blocked: {a['id']}")
    for a in dash["actions"]["medium_owner_gated"]:
        if not a["owner_gate_required"]:
            raise AssertionError(f"MEDIUM action missing owner gate: {a['id']}")
    if dash["breach"]:
        raise AssertionError(f"clean dashboard must not breach: {dash['breach_reasons']}")
    # JSON validity of all structured outputs.
    for blob_obj in (dash, state["packaging"], *build_playbooks(dash).values()):
        json.dumps(blob_obj)

    # Breach detection on tampered safety.
    base_safety = {"live_apply": False, "emergency_stop": True, "allowed_apply_now": False,
                   "current_level": LEVEL_2, "upstream_breach": False}
    empty_groups = {c: [] for c in CLASS_ORDER}
    if compute_breach(base_safety, empty_groups, [])[0]:
        raise AssertionError("clean safety must not breach")
    for tamper in ({"live_apply": True}, {"emergency_stop": False}, {"allowed_apply_now": True},
                   {"current_level": "LEVEL_4_MEDIUM_CANARY_ONLY"}, {"upstream_breach": True}):
        if not compute_breach(dict(base_safety, **tamper), empty_groups, [])[0]:
            raise AssertionError(f"tamper did not breach: {tamper}")
    unblocked_high = {**empty_groups, HIGH: [{"id": "x", "blocked": False}]}
    if not compute_breach(base_safety, unblocked_high, [])[0]:
        raise AssertionError("unblocked HIGH did not breach")

    # No secrets in any rendered output.
    rendered = [
        render_dashboard_md(dash), render_owner_next_actions_md(dash, state["owner_next"]),
        render_service_packages_md(), sales_page_text(SERVICE_PACKAGES),
        render_safe_autonomy_policy_md(), render_level_roadmap_md(dash),
        render_client_deliverables_md(), json.dumps(dash), json.dumps(state["packaging"]),
    ]
    for blob in rendered:
        if SECRET_ASSIGNMENT_RE.search(blob) or LONG_HEX_RE.search(blob):
            raise AssertionError("secret-like content in output")

    # Write-path guards.
    for forbidden in (
        PROJECT_DIR / "reports/latest/x.sh",
        PROJECT_DIR / "reports/latest/x.php",
        PROJECT_DIR / "state/adaptive-learning/x.service",
        PROJECT_DIR / "snapshots/x.json",      # snapshots NOT allowed in 9.1
        PROJECT_DIR / "config/x.json",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")
    for ok_path in (DASHBOARD_JSON, STATE_OWNER_DASHBOARD_JSON, AUDIT_JSONL, PLAYBOOK_DASHBOARD):
        assert_allowed_write(ok_path)

    if not detect_secret_like("password=supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("status=OK"):
        raise AssertionError("secret detector false positive")

    print("owner-dashboard-service-packaging self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], written: List[str]) -> None:
    dash = state["dashboard"]
    print("=== Sentinel Owner Dashboard & Service Packaging (Phase 9.1) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"dashboard status: {dash['current_bot_status']}")
    print(f"service packages status: {len(SERVICE_PACKAGES)} packages ready")
    print(f"owner next actions status: {len(state['owner_next'])} actions drafted")
    print(f"roadmap status: {len(ROADMAP_LEVELS)} levels documented (no activation)")
    print(f"current autonomy level: {dash['autonomy_level']}")
    print(f"live_apply: {dash['live_apply']}")
    print(f"emergency_stop: {dash['emergency_stop']}")
    print(f"allowed_apply_now: {dash['allowed_apply_now']}")
    print(f"breach: {dash['breach']}")
    print(f"package names: {', '.join(dash['service_packages'])}")
    print(f"strongest sales headline: {PRIMARY_SALES_HEADLINE}")
    print(f"what Sentinel may do now: {len(dash['may_do_automatically_now'])} items "
          f"(READ_ONLY+DRAFT+LOW)")
    print(f"what Sentinel must not do: {len(dash['must_never_do_automatically'])} items (HIGH + secrets)")
    print(f"recommended Git checkpoint: {dash['git_checkpoint']['recommended']} "
          f"({dash['git_checkpoint']['untracked_count']} untracked, {dash['git_checkpoint']['modified_count']} modified)")
    if dash["git_checkpoint"]["files_sample"]:
        print("recommended Git checkpoint files (sample):")
        for f in dash["git_checkpoint"]["files_sample"]:
            print(f"  - {f}")
    if dash["missing_inputs"]:
        print(f"missing inputs: {', '.join(dash['missing_inputs'])}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Owner Dashboard & Service Packaging (Phase 9.1). Read-only; no apply."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--build-dashboard", action="store_true", help="Build the owner dashboard.")
    p.add_argument("--build-service-packages", action="store_true", help="Build service packages + sales page.")
    p.add_argument("--build-owner-next-actions", action="store_true", help="Build owner next actions.")
    p.add_argument("--build-roadmap", action="store_true", help="Build the autonomy level roadmap.")
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
    dash = state["dashboard"]

    if args.build_dashboard:
        print(f"[dashboard] status={dash['current_bot_status']} level={dash['autonomy_level']} "
              f"live_apply={dash['live_apply']} emergency_stop={dash['emergency_stop']} "
              f"allowed_apply_now={dash['allowed_apply_now']} breach={dash['breach']}")
    if args.build_service_packages:
        print(f"[service-packages] {', '.join(p['name'] for p in SERVICE_PACKAGES)}")
        print(f"[service-packages] headline: {PRIMARY_SALES_HEADLINE}")
    if args.build_owner_next_actions:
        print(f"[owner-next-actions] {len(state['owner_next'])} actions: "
              f"{', '.join(i['id'] for i in state['owner_next'])}")
    if args.build_roadmap:
        print(f"[roadmap] current={dash['autonomy_level']} levels={', '.join(l['level'] for l in ROADMAP_LEVELS)}")

    if args.status or not any(
        (args.build_dashboard, args.build_service_packages, args.build_owner_next_actions, args.build_roadmap)
    ):
        _print_status(state, written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
