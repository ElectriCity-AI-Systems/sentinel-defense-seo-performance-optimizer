#!/usr/bin/env python3
"""Sentinel Autonomy Policy Layer (Phase 1.5).

Central, policy-only decision layer for the Sentinel bot system.

This module decides *whether* a future action would ever be allowed to run.
It NEVER applies live changes. It only produces policy decisions, risk
classifications, owner-approval requirements and audit records.

Hard safety guarantees (enforced structurally in this module):
  * No live SEO changes.
  * No WordPress file changes.
  * No .htaccess changes.
  * No Cloudflare rule changes.
  * No Nginx configuration changes.
  * No external write access.
  * No secrets, tokens, cookies or Authorization data in any output.
  * No automatic execution of productive actions.
  * Every decision stays policy-only / dry-run (apply_status == "not_applied").
  * Writes are only ever allowed under:
        /srv/sentinel-defense/reports/latest
        /srv/sentinel-defense/drafts
        /srv/sentinel-defense/audit

There is intentionally NO apply function in this module.
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

# --- Output targets ---------------------------------------------------------
REPORT_MD = PROJECT_DIR / "reports/latest/autonomy-policy-report.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"
AUDIT_JSONL = PROJECT_DIR / "audit/autonomy-policy-decisions.jsonl"

# --- Optional inputs (must never crash when missing) ------------------------
INPUT_EDITORIAL_REVIEW = PROJECT_DIR / "drafts/seo/homepage-editorial-review.json"
INPUT_SEO_OPTIMIZER_REPORT = PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.json"
INPUT_MASTER_REPORT = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
OPTIONAL_INPUTS = (
    INPUT_EDITORIAL_REVIEW,
    INPUT_SEO_OPTIMIZER_REPORT,
    INPUT_MASTER_REPORT,
)

# --- Allowed write roots (the only paths this module may ever write) --------
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "autonomy-policy-1.5"

# Anything matching this pattern is redacted from every output.
SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|credential|set-cookie|x-api-key|access[_-]?key)"
)


# ===========================================================================
# Autonomy levels
# ===========================================================================
LEVEL_0_READ_ONLY = "LEVEL_0_READ_ONLY"
LEVEL_1_DRAFT_ONLY = "LEVEL_1_DRAFT_ONLY"
LEVEL_2_SUPERVISED_LOW_RISK = "LEVEL_2_SUPERVISED_LOW_RISK"
LEVEL_3_GUARDED_AUTONOMOUS_LOW_RISK = "LEVEL_3_GUARDED_AUTONOMOUS_LOW_RISK"
LEVEL_4_ADAPTIVE_SAFE_AUTONOMY = "LEVEL_4_ADAPTIVE_SAFE_AUTONOMY"

AUTONOMY_LEVEL_ORDER = [
    LEVEL_0_READ_ONLY,
    LEVEL_1_DRAFT_ONLY,
    LEVEL_2_SUPERVISED_LOW_RISK,
    LEVEL_3_GUARDED_AUTONOMOUS_LOW_RISK,
    LEVEL_4_ADAPTIVE_SAFE_AUTONOMY,
]

AUTONOMY_LEVEL_DESCRIPTIONS = {
    LEVEL_0_READ_ONLY: (
        "Read inputs and write reports only. No drafts with apply intent. "
        "No productive changes."
    ),
    LEVEL_1_DRAFT_ONLY: (
        "Generate proposals and drafts. apply_status stays not_applied. "
        "No productive changes."
    ),
    LEVEL_2_SUPERVISED_LOW_RISK: (
        "LOW-risk actions may be prepared as apply-safe candidates. "
        "Application only after explicit owner approval. "
        "Backup, healthcheck and rollback must exist."
    ),
    LEVEL_3_GUARDED_AUTONOMOUS_LOW_RISK: (
        "Only very safe LOW-risk actions could later run automatically. "
        "Not yet activated; disabled by default. Requires backup, healthcheck, "
        "rollback, audit log and an explicit allowlist."
    ),
    LEVEL_4_ADAPTIVE_SAFE_AUTONOMY: (
        "Future stage only. Not activated. MEDIUM and HIGH always remain "
        "approval-required."
    ),
}

# Sentinels for actions that have no level at which they auto-run.
REQUIRES_OWNER_APPROVAL_ALWAYS = "NEVER_AUTONOMOUS_REQUIRES_OWNER_APPROVAL"
BLOCKED_NOT_PERMITTED = "BLOCKED_NOT_PERMITTED_FOR_AUTONOMY"

# The currently active level. Conservative default for Phase 1.5.
DEFAULT_AUTONOMY_LEVEL = LEVEL_1_DRAFT_ONLY

# Guarded autonomous level is disabled by default and must stay disabled.
AUTONOMY_CONFIG = {
    "current_level": DEFAULT_AUTONOMY_LEVEL,
    "level_3_enabled": False,
    "level_4_enabled": False,
    # Allowlist for the (still inactive) LEVEL_3 guarded autonomous path.
    "level_3_allowlist": (
        "report_dashboard_update",
    ),
}


# ===========================================================================
# Risk classification
# ===========================================================================
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

# action_type -> risk class. Unknown action types are treated as HIGH.
RISK_BY_ACTION_TYPE = {
    # ---- LOW -------------------------------------------------------------
    "meta_draft_prepare": RISK_LOW,
    "schema_draft_prepare": RISK_LOW,
    "editorial_review_write": RISK_LOW,
    "internal_link_suggestion": RISK_LOW,
    "alt_text_suggestion": RISK_LOW,
    "report_dashboard_update": RISK_LOW,
    # ---- MEDIUM ----------------------------------------------------------
    "cms_content_change": RISK_MEDIUM,
    "internal_links_live": RISK_MEDIUM,
    "blog_structure_live": RISK_MEDIUM,
    "lazy_loading_change": RISK_MEDIUM,
    "yoast_seo_field_set": RISK_MEDIUM,
    # ---- HIGH ------------------------------------------------------------
    "htaccess_change": RISK_HIGH,
    "cloudflare_rules_change": RISK_HIGH,
    "nginx_change": RISK_HIGH,
    "redirect_change": RISK_HIGH,
    "service_worker_change": RISK_HIGH,
    "js_minify": RISK_HIGH,
    "player_radio_code_change": RISK_HIGH,
    "security_waf_botfight_change": RISK_HIGH,
    "dns_domain_redirect_change": RISK_HIGH,
}

# Default execution mode per action type. LOW defaults to a non-applying draft;
# inherently live action types default to "apply" intent.
DEFAULT_MODE_BY_RISK = {
    RISK_LOW: "draft",
    RISK_MEDIUM: "apply",
    RISK_HIGH: "apply",
}

APPLY_MODES = {"apply", "live"}


# ===========================================================================
# Helpers (mirrors the safety helpers used by the SEO safe optimizer)
# ===========================================================================
def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(value: Any, default: str = "-", max_len: int = 300) -> str:
    """Return a single-line, secret-safe string."""
    if value is None:
        return default
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(
            f"Refusing to write outside allowed Sentinel autonomy roots: {path}"
        )


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Any) -> None:
    write_text_atomic(
        path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )


def append_jsonl_atomic(path: Path, records: List[Dict[str, Any]]) -> None:
    """Append audit records as JSON lines (never rewrites prior history)."""
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = "".join(
        json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n" for rec in records
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write(lines)


def level_rank(level: str) -> int:
    try:
        return AUTONOMY_LEVEL_ORDER.index(level)
    except ValueError:
        return -1


def read_optional_json(path: Path) -> Tuple[Optional[Any], str]:
    """Read JSON if present; never raise. Returns (data, status)."""
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


# ===========================================================================
# Core policy evaluation
# ===========================================================================
def classify_risk(action_type: str) -> str:
    return RISK_BY_ACTION_TYPE.get(action_type, RISK_HIGH)


def capability(action: Dict[str, Any], name: str) -> bool:
    caps = action.get("capabilities") or {}
    return bool(caps.get(name, False))


def evaluate_action(
    action: Dict[str, Any],
    current_level: str = DEFAULT_AUTONOMY_LEVEL,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate a single proposed action and return a policy decision.

    The decision is policy-only: apply_status is ALWAYS "not_applied" and no
    side effect on production is ever produced.
    """
    cfg = config or AUTONOMY_CONFIG
    action_type = str(action.get("action_type", "unknown")).strip() or "unknown"
    action_id = redact_text(action.get("action_id") or f"auto:{action_type}", max_len=120)
    known_type = action_type in RISK_BY_ACTION_TYPE

    risk = classify_risk(action_type)
    mode = str(action.get("mode") or DEFAULT_MODE_BY_RISK.get(risk, "apply")).lower()
    is_apply_intent = (mode in APPLY_MODES) or (risk in (RISK_MEDIUM, RISK_HIGH))

    # Safeguards required before any future live application.
    requires_backup = is_apply_intent
    requires_healthcheck = is_apply_intent
    requires_rollback = is_apply_intent

    # Decision defaults — conservative.
    allowed_now = False
    requires_owner_approval = False
    autonomy_level_required = BLOCKED_NOT_PERMITTED
    reasons: List[str] = []

    if not known_type:
        reasons.append(
            f"Unknown action_type '{redact_text(action_type, max_len=60)}' "
            "-> treated as HIGH risk and blocked."
        )

    if risk == RISK_HIGH:
        # HIGH is always blocked, regardless of level.
        allowed_now = False
        requires_owner_approval = True
        autonomy_level_required = BLOCKED_NOT_PERMITTED
        reasons.append(
            "HIGH-risk action (infrastructure / security / production code). "
            "Never auto-applied; blocked at every autonomy level."
        )

    elif risk == RISK_MEDIUM:
        # MEDIUM always requires owner approval and is never autonomous.
        allowed_now = False
        requires_owner_approval = True
        autonomy_level_required = REQUIRES_OWNER_APPROVAL_ALWAYS
        reasons.append(
            "MEDIUM-risk action (live content / SEO field / structure change). "
            "Always requires explicit owner approval; never auto-applied."
        )

    else:  # RISK_LOW
        if not is_apply_intent:
            # Draft / preparation only — the safe default for LOW.
            autonomy_level_required = LEVEL_1_DRAFT_ONLY
            requires_owner_approval = False
            allowed_now = level_rank(current_level) >= level_rank(LEVEL_1_DRAFT_ONLY)
            if allowed_now:
                reasons.append(
                    "LOW-risk draft/preparation only. Allowed to be written as a "
                    "draft; apply_status stays not_applied."
                )
            else:
                reasons.append(
                    "LOW-risk draft requires at least LEVEL_1_DRAFT_ONLY. Current "
                    "level only permits reading and report writing."
                )
        else:
            # LOW with apply intent: prepare candidate, never auto-apply now.
            autonomy_level_required = LEVEL_3_GUARDED_AUTONOMOUS_LOW_RISK
            requires_owner_approval = True
            safeguards_ok = (
                capability(action, "backup")
                and capability(action, "healthcheck")
                and capability(action, "rollback")
                and capability(action, "audit_log")
            )
            allowlisted = action_type in tuple(cfg.get("level_3_allowlist", ()))
            level3_active = bool(cfg.get("level_3_enabled")) and current_level == (
                LEVEL_3_GUARDED_AUTONOMOUS_LOW_RISK
            )
            # Even with everything in place, LEVEL_3 is disabled by default,
            # so allowed_now stays False in Phase 1.5.
            allowed_now = level3_active and safeguards_ok and allowlisted
            if allowed_now:
                reasons.append(
                    "LOW-risk apply candidate on guarded autonomous level with "
                    "backup, healthcheck, rollback, audit log and allowlist."
                )
            else:
                missing = []
                if not cfg.get("level_3_enabled"):
                    missing.append("LEVEL_3 disabled by default")
                if not safeguards_ok:
                    missing.append("backup/healthcheck/rollback/audit-log incomplete")
                if not allowlisted:
                    missing.append("not in LEVEL_3 allowlist")
                reasons.append(
                    "LOW-risk apply candidate may be PREPARED under "
                    "LEVEL_2_SUPERVISED_LOW_RISK but only applied after explicit "
                    "owner approval. Autonomous apply blocked: "
                    + "; ".join(missing)
                    + "."
                )

    decision = {
        "action_id": action_id,
        "action_type": action_type,
        "risk_classification": risk,
        "autonomy_level_required": autonomy_level_required,
        "allowed_now": bool(allowed_now),
        "requires_owner_approval": bool(requires_owner_approval),
        "requires_backup": bool(requires_backup),
        "requires_healthcheck": bool(requires_healthcheck),
        "requires_rollback": bool(requires_rollback),
        "reason": " ".join(reasons),
        # Policy-only layer: never applied, never live.
        "apply_status": "not_applied",
    }
    return decision


# ===========================================================================
# Default action catalog + optional-input enrichment
# ===========================================================================
def default_action_catalog() -> List[Dict[str, Any]]:
    """Representative actions covering every risk class and both LOW modes."""
    catalog: List[Dict[str, Any]] = [
        # LOW — draft / preparation
        {"action_id": "low-meta-draft", "action_type": "meta_draft_prepare"},
        {"action_id": "low-schema-draft", "action_type": "schema_draft_prepare"},
        {"action_id": "low-editorial-review", "action_type": "editorial_review_write"},
        {"action_id": "low-internal-link-suggest", "action_type": "internal_link_suggestion"},
        {"action_id": "low-alt-text-suggest", "action_type": "alt_text_suggestion"},
        {"action_id": "low-report-update", "action_type": "report_dashboard_update"},
        # LOW — apply-intent candidate (must stay blocked for autonomy in 1.5)
        {
            "action_id": "low-report-update-apply-candidate",
            "action_type": "report_dashboard_update",
            "mode": "apply",
            "capabilities": {
                "backup": True,
                "healthcheck": True,
                "rollback": True,
                "audit_log": True,
            },
        },
        # MEDIUM — always owner-approval required
        {"action_id": "med-cms-content", "action_type": "cms_content_change"},
        {"action_id": "med-internal-links-live", "action_type": "internal_links_live"},
        {"action_id": "med-blog-structure", "action_type": "blog_structure_live"},
        {"action_id": "med-lazy-loading", "action_type": "lazy_loading_change"},
        {"action_id": "med-yoast-field", "action_type": "yoast_seo_field_set"},
        # HIGH — always blocked
        {"action_id": "high-htaccess", "action_type": "htaccess_change"},
        {"action_id": "high-cloudflare", "action_type": "cloudflare_rules_change"},
        {"action_id": "high-nginx", "action_type": "nginx_change"},
        {"action_id": "high-redirect", "action_type": "redirect_change"},
        {"action_id": "high-service-worker", "action_type": "service_worker_change"},
        {"action_id": "high-js-minify", "action_type": "js_minify"},
        {"action_id": "high-player-radio", "action_type": "player_radio_code_change"},
        {"action_id": "high-waf-botfight", "action_type": "security_waf_botfight_change"},
        {"action_id": "high-dns-redirect", "action_type": "dns_domain_redirect_change"},
    ]
    return catalog


def collect_input_context() -> Dict[str, Any]:
    """Read optional inputs safely. Never raises; never echoes secrets."""
    context: Dict[str, Any] = {"inputs": []}

    editorial, editorial_status = read_optional_json(INPUT_EDITORIAL_REVIEW)
    context["inputs"].append(
        {"path": str(INPUT_EDITORIAL_REVIEW), "status": editorial_status}
    )
    if isinstance(editorial, dict):
        summary = editorial.get("summary") or {}
        context["editorial_review"] = {
            "apply_status": redact_text(editorial.get("apply_status"), default="-"),
            "proposal_count": len(editorial.get("proposals", []))
            if isinstance(editorial.get("proposals"), list)
            else 0,
            "high_risk_count": int(summary.get("high_risk_count", 0) or 0),
            "all_not_applied": bool(summary.get("all_not_applied", True)),
        }

    optimizer, optimizer_status = read_optional_json(INPUT_SEO_OPTIMIZER_REPORT)
    context["inputs"].append(
        {"path": str(INPUT_SEO_OPTIMIZER_REPORT), "status": optimizer_status}
    )
    if isinstance(optimizer, dict):
        context["seo_optimizer"] = {
            "status": redact_text(optimizer.get("status"), default="-"),
            "productive_change": bool(optimizer.get("productive_change", False)),
            "findings_count": len(optimizer.get("findings", []))
            if isinstance(optimizer.get("findings"), list)
            else 0,
        }

    master, master_status = read_optional_json(INPUT_MASTER_REPORT)
    context["inputs"].append(
        {"path": str(INPUT_MASTER_REPORT), "status": master_status}
    )
    if isinstance(master, dict):
        context["master_report"] = {
            "overall_master_status": redact_text(
                master.get("overall_master_status"), default="-"
            ),
            "website_status": redact_text(master.get("website_status"), default="-"),
        }

    return context


# ===========================================================================
# Report building
# ===========================================================================
def build_policy_report(
    actions: List[Dict[str, Any]],
    current_level: str = DEFAULT_AUTONOMY_LEVEL,
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    cfg = config or AUTONOMY_CONFIG
    decisions = [evaluate_action(a, current_level=current_level, config=cfg) for a in actions]

    allowed_now_count = sum(1 for d in decisions if d["allowed_now"])
    blocked_count = sum(1 for d in decisions if not d["allowed_now"])
    owner_approval_count = sum(1 for d in decisions if d["requires_owner_approval"])
    high_risk_count = sum(1 for d in decisions if d["risk_classification"] == RISK_HIGH)
    medium_risk_count = sum(1 for d in decisions if d["risk_classification"] == RISK_MEDIUM)
    low_risk_count = sum(1 for d in decisions if d["risk_classification"] == RISK_LOW)

    policy_summary = (
        f"Autonomy Policy Layer evaluated {len(decisions)} action(s) under "
        f"{current_level}. {allowed_now_count} allowed now (draft/policy-only), "
        f"{blocked_count} blocked, {owner_approval_count} require owner approval, "
        f"{high_risk_count} HIGH-risk blocked. No live, productive or external "
        "change is performed by this layer; every decision is policy-only and "
        "apply_status stays not_applied."
    )

    next_safe_steps = [
        "Keep current level at LEVEL_1_DRAFT_ONLY; continue producing drafts only.",
        "Generate/refresh LOW-risk drafts (meta, schema, editorial review, "
        "internal-link and alt-text suggestions) — never applied.",
        "Route every MEDIUM-risk action through explicit owner approval before "
        "any future application.",
        "Keep all HIGH-risk actions (htaccess, Cloudflare, Nginx, redirects, "
        "service worker, JS minify, player/radio code, WAF/Bot Fight, DNS) "
        "permanently blocked from autonomy.",
        "Before considering LEVEL_2, ensure backup, healthcheck and rollback "
        "exist for any LOW-risk apply candidate.",
        "LEVEL_3 stays disabled; do not enable guarded autonomy without an "
        "explicit allowlist plus audit logging.",
    ]

    context = collect_input_context()

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "policy_only": True,
        "dry_run": True,
        "productive_change": False,
        "secrets_output": False,
        "current_autonomy_level": current_level,
        "default_autonomy_level": DEFAULT_AUTONOMY_LEVEL,
        "autonomy_levels": [
            {
                "level": level,
                "rank": rank,
                "description": AUTONOMY_LEVEL_DESCRIPTIONS[level],
                "active": level == current_level,
            }
            for rank, level in enumerate(AUTONOMY_LEVEL_ORDER)
        ],
        "autonomy_config": {
            "current_level": cfg.get("current_level"),
            "level_3_enabled": bool(cfg.get("level_3_enabled")),
            "level_4_enabled": bool(cfg.get("level_4_enabled")),
            "level_3_allowlist": list(cfg.get("level_3_allowlist", ())),
        },
        "forbidden_mutations": {
            "live_seo": False,
            "wordpress": False,
            "htaccess": False,
            "cloudflare": False,
            "nginx": False,
            "external_write": False,
        },
        "allowed_write_roots": [str(root) for root in ALLOWED_WRITE_ROOTS],
        "risk_classification_catalog": {
            RISK_LOW: sorted(t for t, r in RISK_BY_ACTION_TYPE.items() if r == RISK_LOW),
            RISK_MEDIUM: sorted(t for t, r in RISK_BY_ACTION_TYPE.items() if r == RISK_MEDIUM),
            RISK_HIGH: sorted(t for t, r in RISK_BY_ACTION_TYPE.items() if r == RISK_HIGH),
        },
        "evaluated_actions_count": len(decisions),
        "allowed_now_count": allowed_now_count,
        "blocked_count": blocked_count,
        "owner_approval_required_count": owner_approval_count,
        "high_risk_count": high_risk_count,
        "medium_risk_count": medium_risk_count,
        "low_risk_count": low_risk_count,
        "policy_summary": policy_summary,
        "next_safe_steps": next_safe_steps,
        "decisions": decisions,
        "input_context": context,
        "report_outputs": [str(REPORT_MD), str(REPORT_JSON)],
        "audit_output": str(AUDIT_JSONL),
    }
    return report, decisions


def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Sentinel Autonomy Policy Report (Phase 1.5)")
    lines.append("")
    lines.append(f"- Generated (UTC): `{report['generated_at_utc']}`")
    lines.append(f"- Current autonomy level: **{report['current_autonomy_level']}**")
    lines.append(f"- Default autonomy level: `{report['default_autonomy_level']}`")
    lines.append("- Mode: **policy-only / dry-run** (no live, productive or external change)")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Evaluated actions: **{report['evaluated_actions_count']}**")
    lines.append(f"- Allowed now (draft/policy-only): **{report['allowed_now_count']}**")
    lines.append(f"- Blocked: **{report['blocked_count']}**")
    lines.append(f"- Owner approval required: **{report['owner_approval_required_count']}**")
    lines.append(f"- HIGH-risk (always blocked): **{report['high_risk_count']}**")
    lines.append("")
    lines.append(report["policy_summary"])
    lines.append("")

    lines.append("## Autonomy Levels")
    lines.append("")
    for entry in report["autonomy_levels"]:
        marker = " (active)" if entry["active"] else ""
        lines.append(f"- **{entry['level']}**{marker}: {entry['description']}")
    cfg = report["autonomy_config"]
    lines.append("")
    lines.append(
        f"- LEVEL_3 enabled: `{cfg['level_3_enabled']}` · "
        f"LEVEL_4 enabled: `{cfg['level_4_enabled']}`"
    )
    lines.append("")

    lines.append("## Risk Classification")
    lines.append("")
    for risk in (RISK_LOW, RISK_MEDIUM, RISK_HIGH):
        types = report["risk_classification_catalog"].get(risk, [])
        lines.append(f"- **{risk}**: {', '.join(f'`{t}`' for t in types)}")
    lines.append("")

    lines.append("## Decisions")
    lines.append("")
    lines.append(
        "| action_id | action_type | risk | allowed_now | owner_approval | "
        "level_required | apply_status |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for d in report["decisions"]:
        lines.append(
            f"| {d['action_id']} | `{d['action_type']}` | {d['risk_classification']} | "
            f"{str(d['allowed_now']).lower()} | "
            f"{str(d['requires_owner_approval']).lower()} | "
            f"`{d['autonomy_level_required']}` | {d['apply_status']} |"
        )
    lines.append("")

    lines.append("## Optional Input Context")
    lines.append("")
    for item in report["input_context"].get("inputs", []):
        lines.append(f"- `{item['path']}` — {item['status']}")
    lines.append("")

    lines.append("## Next Safe Steps")
    lines.append("")
    for step in report["next_safe_steps"]:
        lines.append(f"- {step}")
    lines.append("")

    lines.append("## Safety")
    lines.append("")
    lines.append("- No live SEO change, no WordPress/.htaccess/Cloudflare/Nginx change.")
    lines.append("- No external writes; no secrets/tokens/cookies/authorization in output.")
    lines.append("- All decisions are policy-only; `apply_status` stays `not_applied`.")
    lines.append(
        "- Writes restricted to: "
        + ", ".join(f"`{r}`" for r in report["allowed_write_roots"])
        + "."
    )
    lines.append("")
    return "\n".join(lines)


def build_audit_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    generated = report["generated_at_utc"]
    level = report["current_autonomy_level"]
    records = []
    for d in report["decisions"]:
        records.append(
            {
                "timestamp_utc": generated,
                "schema_version": SCHEMA_VERSION,
                "current_autonomy_level": level,
                "action_id": d["action_id"],
                "action_type": d["action_type"],
                "risk_classification": d["risk_classification"],
                "autonomy_level_required": d["autonomy_level_required"],
                "allowed_now": d["allowed_now"],
                "requires_owner_approval": d["requires_owner_approval"],
                "requires_backup": d["requires_backup"],
                "requires_healthcheck": d["requires_healthcheck"],
                "requires_rollback": d["requires_rollback"],
                "apply_status": d["apply_status"],
                "policy_only": True,
            }
        )
    return records


# ===========================================================================
# Self-tests
# ===========================================================================
def run_self_tests() -> int:
    # Write-path guard: allowed roots pass, forbidden roots raise.
    assert_allowed_write(REPORT_JSON)
    assert_allowed_write(AUDIT_JSONL)
    assert_allowed_write(PROJECT_DIR / "drafts/seo/x.json")
    for forbidden in (
        Path("/etc/nginx/sentinel-test.conf"),
        Path("/srv/sentinel-defense/sentinel_master.py"),
        Path("/var/www/.htaccess"),
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path was not rejected: {forbidden}")

    # HIGH action must be blocked.
    high = evaluate_action({"action_type": "htaccess_change"})
    assert high["risk_classification"] == RISK_HIGH
    assert high["allowed_now"] is False
    assert high["autonomy_level_required"] == BLOCKED_NOT_PERMITTED
    assert high["apply_status"] == "not_applied"

    # Unknown action type is conservatively HIGH and blocked.
    unknown = evaluate_action({"action_type": "totally_unknown_thing"})
    assert unknown["risk_classification"] == RISK_HIGH
    assert unknown["allowed_now"] is False

    # MEDIUM action must require owner approval and stay blocked.
    medium = evaluate_action({"action_type": "yoast_seo_field_set"})
    assert medium["risk_classification"] == RISK_MEDIUM
    assert medium["requires_owner_approval"] is True
    assert medium["allowed_now"] is False
    assert medium["autonomy_level_required"] == REQUIRES_OWNER_APPROVAL_ALWAYS
    assert medium["apply_status"] == "not_applied"

    # LOW draft is allowed at the default level but never applied.
    low_draft = evaluate_action({"action_type": "meta_draft_prepare"})
    assert low_draft["risk_classification"] == RISK_LOW
    assert low_draft["allowed_now"] is True
    assert low_draft["requires_owner_approval"] is False
    assert low_draft["apply_status"] == "not_applied"

    # LOW at LEVEL_0 cannot even draft (read-only).
    low_at_l0 = evaluate_action(
        {"action_type": "meta_draft_prepare"}, current_level=LEVEL_0_READ_ONLY
    )
    assert low_at_l0["allowed_now"] is False

    # LOW apply candidate: blocked for autonomy by default, approval required.
    low_apply = evaluate_action(
        {
            "action_type": "report_dashboard_update",
            "mode": "apply",
            "capabilities": {
                "backup": True,
                "healthcheck": True,
                "rollback": True,
                "audit_log": True,
            },
        }
    )
    assert low_apply["risk_classification"] == RISK_LOW
    assert low_apply["allowed_now"] is False
    assert low_apply["requires_owner_approval"] is True
    assert low_apply["requires_backup"] is True
    assert low_apply["requires_rollback"] is True
    assert low_apply["apply_status"] == "not_applied"

    # Missing inputs must not crash.
    data, status = read_optional_json(PROJECT_DIR / "drafts/seo/__does_not_exist__.json")
    assert data is None and status == "not_available"
    context = collect_input_context()
    assert "inputs" in context

    # Secret-bearing free text must be redacted.
    secret_action = evaluate_action(
        {"action_id": "Authorization: Bearer abc123", "action_type": "meta_draft_prepare"}
    )
    assert secret_action["action_id"] == "[redacted]"

    # Full report build: invariants hold and no secrets leak.
    report, decisions = build_policy_report(default_action_catalog())
    assert report["current_autonomy_level"] == LEVEL_1_DRAFT_ONLY
    assert report["productive_change"] is False
    assert report["secrets_output"] is False
    assert report["evaluated_actions_count"] == len(decisions)
    assert report["high_risk_count"] >= 1
    assert all(d["apply_status"] == "not_applied" for d in decisions)
    assert all(
        d["allowed_now"] is False
        for d in decisions
        if d["risk_classification"] in (RISK_MEDIUM, RISK_HIGH)
    )
    # No actual secret VALUES may leak. (Policy vocabulary such as the field
    # name "secrets_output" legitimately contains the word "secret"; redaction
    # of real secret-bearing values is covered by the secret_action test above.)
    leaky = build_policy_report(
        [{"action_id": "Bearer sk-live-shouldnotappear-123", "action_type": "meta_draft_prepare"}]
    )[0]
    leaky_serialized = json.dumps(leaky, ensure_ascii=False)
    assert "sk-live-shouldnotappear-123" not in leaky_serialized
    assert "Bearer sk-live" not in leaky_serialized

    md = render_markdown(report)
    assert "Autonomy Policy Report" in md
    audit_records = build_audit_records(report)
    assert len(audit_records) == len(decisions)
    assert all(rec["apply_status"] == "not_applied" for rec in audit_records)

    print("autonomy-policy self-tests: OK")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Autonomy Policy Layer (policy-only / dry-run)."
    )
    parser.add_argument(
        "--level",
        default=DEFAULT_AUTONOMY_LEVEL,
        choices=AUTONOMY_LEVEL_ORDER,
        help="Autonomy level to evaluate under (default: LEVEL_1_DRAFT_ONLY).",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in safety/policy tests.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()

    config = dict(AUTONOMY_CONFIG)
    config["current_level"] = args.level

    report, _ = build_policy_report(
        default_action_catalog(), current_level=args.level, config=config
    )
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_markdown(report))
    append_jsonl_atomic(AUDIT_JSONL, build_audit_records(report))

    print(f"Autonomy policy report (JSON): {REPORT_JSON}")
    print(f"Autonomy policy report (MD):   {REPORT_MD}")
    print(f"Autonomy audit log (JSONL):    {AUDIT_JSONL}")
    print(
        f"Level={report['current_autonomy_level']} "
        f"evaluated={report['evaluated_actions_count']} "
        f"allowed_now={report['allowed_now_count']} "
        f"blocked={report['blocked_count']} "
        f"owner_approval={report['owner_approval_required_count']} "
        f"high_risk={report['high_risk_count']} "
        "(policy-only, apply_status=not_applied)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
