#!/usr/bin/env python3
"""Sentinel Safe Apply Candidate Registry (Phase 3.0).

Builds a strict local registry of LOW-risk candidates that may be prepared for
future controlled autonomy. This is not an apply mechanism: it performs no
network access, no WordPress login, no API calls, and no production writes.
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

INPUT_READINESS = PROJECT_DIR / "drafts/owner/autonomous-improvement-readiness.json"
INPUT_OWNER_SUMMARY = PROJECT_DIR / "reports/latest/owner-daily-action-summary.json"
INPUT_AUTONOMY_POLICY = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"
INPUT_APPROVAL_QUEUE = PROJECT_DIR / "drafts/approval/owner-approval-queue.json"
INPUT_MANUAL_CHECKLIST = PROJECT_DIR / "drafts/manual/manual-apply-checklist.json"
INPUT_POST_VALIDATION = PROJECT_DIR / "reports/latest/post-manual-validation-report.json"
INPUT_MASTER = PROJECT_DIR / "reports/latest/sentinel-master-report.json"

REGISTRY_JSON = PROJECT_DIR / "drafts/apply/safe-apply-candidate-registry.json"
REGISTRY_MD = PROJECT_DIR / "drafts/apply/safe-apply-candidate-registry.md"
REPORT_JSON = PROJECT_DIR / "reports/latest/safe-apply-candidate-registry-report.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-apply-candidate-registry-report.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-apply-candidate-registry.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/apply",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "safe-apply-candidate-registry-3.0"

APPLY_NOT_APPLIED = "not_applied"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

READINESS_DRAFT_ONLY = "AUTONOMY_READY_DRAFT_ONLY"
READINESS_MONITOR_ONLY = "AUTONOMY_MONITOR_ONLY"

REGISTERED_DRAFT_ONLY = "REGISTERED_DRAFT_ONLY"
REGISTERED_VALIDATION_ONLY = "REGISTERED_VALIDATION_ONLY"
NOT_REGISTERED_MISSING_GUARDS = "NOT_REGISTERED_MISSING_GUARDS"
BLOCKED_NOT_ALLOWED = "BLOCKED_NOT_ALLOWED"
MONITOR_ONLY = "MONITOR_ONLY"

ALLOWED_CANDIDATE_TYPES = {
    "report_update_only",
    "draft_refresh_only",
    "owner_summary_only",
    "validation_only",
    "seo_meta_draft_prepare",
    "seo_social_draft_prepare",
    "image_status_check",
    "width_height_check",
    "internal_link_suggestion_prepare",
}

PROHIBITED_CANDIDATE_TYPES = {
    "wordpress_live_write",
    "yoast_live_write",
    "cloudflare_change",
    "nginx_change",
    "htaccess_change",
    "dns_change",
    "redirect_change",
    "service_worker_change",
    "js_minify",
    "player_radio_code_change",
    "waf_botfight_change",
}

REQUIRED_GUARDS = [
    "explicit_allowlist",
    "owner_disable_switch",
    "audit_log",
    "max_scope_defined",
    "pre_healthcheck",
    "post_healthcheck",
    "rollback_plan",
    "backup_available",
    "post_validation",
]

PROHIBITED_ACTIONS = [
    "wordpress_live_write",
    "yoast_live_write",
    "cloudflare_change",
    "nginx_change",
    "htaccess_change",
    "dns_change",
    "redirect_change",
    "service_worker_change",
    "js_minify",
    "player_radio_code_change",
    "waf_botfight_change",
    "network_access",
    "api_access",
    "credential_collection",
]

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|credential|session)\s*[:=]\s*[^\s,;]+"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(value: Any, default: str = "-", max_len: int = 900) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def sanitize_value(value: Any, *, max_len: int = 2600) -> Any:
    if isinstance(value, dict):
        safe: Dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if SECRETISH_RE.search(key_text):
                safe[key_text] = "[redacted]"
            else:
                safe[key_text] = sanitize_value(child, max_len=max_len)
        return safe
    if isinstance(value, list):
        return [sanitize_value(item, max_len=max_len) for item in value]
    if isinstance(value, str) or value is None:
        return redact_text(value, default="", max_len=max_len)
    if isinstance(value, (int, float, bool)):
        return value
    return redact_text(value, default="", max_len=max_len)


def parse_count(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float):
        return max(int(value), 0)
    if isinstance(value, str):
        try:
            return max(int(float(value.strip())), 0)
        except ValueError:
            return 0
    return 0


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed registry roots: {path}")


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


def read_optional_json(path: Path) -> Tuple[Optional[Any], str]:
    if ".env" in str(path).lower() or SECRETISH_RE.search(path.name):
        return None, "refused_secret_like_path"
    if path.suffix.lower() != ".json":
        return None, "unsupported_suffix"
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


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY}:
        return risk
    return RISK_REVIEW_ONLY


def load_inputs() -> Tuple[Dict[str, Optional[Any]], Dict[str, str]]:
    sources = {
        "autonomous_improvement_readiness": INPUT_READINESS,
        "owner_daily_action_summary": INPUT_OWNER_SUMMARY,
        "autonomy_policy": INPUT_AUTONOMY_POLICY,
        "owner_approval_queue": INPUT_APPROVAL_QUEUE,
        "manual_apply_checklist": INPUT_MANUAL_CHECKLIST,
        "post_manual_validation": INPUT_POST_VALIDATION,
        "sentinel_master": INPUT_MASTER,
    }
    data: Dict[str, Optional[Any]] = {}
    statuses: Dict[str, str] = {}
    for name, path in sources.items():
        value, status = read_optional_json(path)
        data[name] = value
        statuses[name] = status
    return data, statuses


def readiness_candidates_from(data: Optional[Any]) -> List[Dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("readiness_candidates"), list):
        return []
    return [item for item in data["readiness_candidates"] if isinstance(item, dict)]


def combined_text(item: Dict[str, Any]) -> str:
    fields = (
        "title",
        "impact_area",
        "source",
        "source_id",
        "current_status",
        "possible_future_autonomous_action",
        "reason",
    )
    return " ".join(redact_text(item.get(key), default="", max_len=500) for key in fields).lower()


def infer_candidate_type(item: Dict[str, Any]) -> str:
    text = combined_text(item)
    if "cloudflare" in text or "waf" in text:
        return "cloudflare_change" if "bot fight" not in text else "waf_botfight_change"
    if "nginx" in text:
        return "nginx_change"
    if ".htaccess" in text or "htaccess" in text:
        return "htaccess_change"
    if "dns" in text:
        return "dns_change"
    if "redirect" in text:
        return "redirect_change"
    if "service worker" in text:
        return "service_worker_change"
    if "js minify" in text or "javascript minify" in text or "minify/defer" in text:
        return "js_minify"
    if "player" in text or "radio code" in text:
        return "player_radio_code_change"
    if "wordpress live" in text or "cms write" in text:
        return "wordpress_live_write"
    if "yoast live" in text:
        return "yoast_live_write"
    if "validation" in text or "post-manual" in text:
        return "validation_only"
    if "owner summary" in text or "summary" in text:
        return "owner_summary_only"
    if "report" in text:
        return "report_update_only"
    if "open graph" in text or "opengraph" in text or "twitter" in text or "social" in text:
        return "seo_social_draft_prepare"
    if "meta description" in text or "title" in text:
        return "seo_meta_draft_prepare"
    if "internal link" in text:
        return "internal_link_suggestion_prepare"
    if "width" in text or "height" in text or "dimension" in text:
        return "width_height_check"
    if "image" in text or "webp" in text:
        return "image_status_check"
    if "draft" in text or "checklist" in text:
        return "draft_refresh_only"
    return "draft_refresh_only"


def allowed_future_scope(candidate_type: str) -> str:
    if candidate_type == "validation_only":
        return "Generate local validation reports only; no CMS, network, or production writes."
    if candidate_type == "owner_summary_only":
        return "Generate local owner summaries only under Sentinel report/draft paths."
    if candidate_type == "report_update_only":
        return "Refresh local Sentinel reports only."
    return "Prepare local drafts/checklists only; no live WordPress, SEO plugin, or infrastructure writes."


def missing_guards_for_registry_status(registry_status: str, source_missing: List[Any]) -> List[str]:
    if registry_status in {REGISTERED_DRAFT_ONLY, REGISTERED_VALIDATION_ONLY, MONITOR_ONLY, BLOCKED_NOT_ALLOWED}:
        return []
    normalized = [redact_text(item, max_len=160) for item in source_missing if item]
    if normalized:
        return normalized
    return list(REQUIRED_GUARDS)


def registry_status_for(item: Dict[str, Any], candidate_type: str) -> Tuple[str, str]:
    risk = normalize_risk(item.get("risk_classification"))
    readiness_status = str(item.get("readiness_status") or "")
    apply_status = str(item.get("apply_status") or "")
    if apply_status != APPLY_NOT_APPLIED:
        return BLOCKED_NOT_ALLOWED, "Source apply_status is not not_applied; registry breach requires review."
    if readiness_status == READINESS_MONITOR_ONLY:
        return MONITOR_ONLY, "Candidate is diagnostic/monitor-only."
    if risk == RISK_HIGH:
        return BLOCKED_NOT_ALLOWED, "HIGH-risk candidates are never registered."
    if candidate_type in PROHIBITED_CANDIDATE_TYPES:
        return BLOCKED_NOT_ALLOWED, "Candidate type is prohibited for safe registry registration."
    if risk in {RISK_MEDIUM, RISK_REVIEW_ONLY}:
        return NOT_REGISTERED_MISSING_GUARDS, "MEDIUM/REVIEW_ONLY candidates are not registry-ready."
    if risk != RISK_LOW:
        return NOT_REGISTERED_MISSING_GUARDS, "Risk classification is not LOW."
    if readiness_status != READINESS_DRAFT_ONLY:
        return NOT_REGISTERED_MISSING_GUARDS, "Readiness status is not AUTONOMY_READY_DRAFT_ONLY."
    if candidate_type not in ALLOWED_CANDIDATE_TYPES:
        return BLOCKED_NOT_ALLOWED, "Candidate type is not allowlisted."
    if candidate_type == "validation_only":
        return REGISTERED_VALIDATION_ONLY, "LOW/not_applied validation-only candidate is registered for future local-only validation."
    return REGISTERED_DRAFT_ONLY, "LOW/not_applied draft-only candidate is registered for future local-only draft preparation."


def normalize_candidate(item: Dict[str, Any], index: int) -> Dict[str, Any]:
    candidate_type = infer_candidate_type(item)
    registry_status, reason = registry_status_for(item, candidate_type)
    source_missing = item.get("missing_guards") if isinstance(item.get("missing_guards"), list) else []
    return {
        "candidate_id": f"safe_apply_candidate:{index:03d}",
        "source_id": redact_text(item.get("source_id") or item.get("readiness_id"), max_len=220),
        "source_readiness_id": redact_text(item.get("readiness_id"), max_len=120),
        "title": redact_text(item.get("title"), max_len=320),
        "impact_area": redact_text(item.get("impact_area"), max_len=120),
        "candidate_type": candidate_type,
        "current_status": redact_text(item.get("current_status"), max_len=180),
        "risk_classification": normalize_risk(item.get("risk_classification")),
        "allowed_future_scope": allowed_future_scope(candidate_type),
        "prohibited_actions": list(PROHIBITED_ACTIONS),
        "required_guards": list(REQUIRED_GUARDS),
        "missing_guards": missing_guards_for_registry_status(registry_status, source_missing),
        "readiness_status": redact_text(item.get("readiness_status"), max_len=160),
        "registry_status": registry_status,
        "apply_status": APPLY_NOT_APPLIED if item.get("apply_status") == APPLY_NOT_APPLIED else redact_text(item.get("apply_status"), max_len=80),
        "reason": reason,
    }


def registry_breach(candidates: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    for candidate in candidates:
        registered = candidate.get("registry_status") in {REGISTERED_DRAFT_ONLY, REGISTERED_VALIDATION_ONLY}
        if candidate.get("apply_status") != APPLY_NOT_APPLIED:
            reasons.append(f"{candidate.get('candidate_id')}: apply_status != not_applied")
        if registered and candidate.get("risk_classification") == RISK_HIGH:
            reasons.append(f"{candidate.get('candidate_id')}: HIGH registered")
        if registered and candidate.get("risk_classification") in {RISK_MEDIUM, RISK_REVIEW_ONLY}:
            reasons.append(f"{candidate.get('candidate_id')}: MEDIUM/REVIEW_ONLY registered")
        if registered and candidate.get("candidate_type") in PROHIBITED_CANDIDATE_TYPES:
            reasons.append(f"{candidate.get('candidate_id')}: prohibited candidate_type registered")
    return bool(reasons), reasons


def summarize(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        REGISTERED_DRAFT_ONLY: 0,
        REGISTERED_VALIDATION_ONLY: 0,
        NOT_REGISTERED_MISSING_GUARDS: 0,
        BLOCKED_NOT_ALLOWED: 0,
        MONITOR_ONLY: 0,
    }
    for candidate in candidates:
        status = candidate.get("registry_status")
        if status in counts:
            counts[status] += 1
    breach, breach_reasons = registry_breach(candidates)
    return {
        "candidate_count": len(candidates),
        "registered_draft_only_count": counts[REGISTERED_DRAFT_ONLY],
        "registered_validation_only_count": counts[REGISTERED_VALIDATION_ONLY],
        "not_registered_missing_guards_count": counts[NOT_REGISTERED_MISSING_GUARDS],
        "blocked_not_allowed_count": counts[BLOCKED_NOT_ALLOWED],
        "monitor_only_count": counts[MONITOR_ONLY],
        "registry_breach": breach,
        "registry_breach_reasons": breach_reasons,
    }


def build_registry(data: Optional[Any], input_statuses: Dict[str, str], generated_at: Optional[str] = None) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    readiness_items = readiness_candidates_from(data)
    candidates = [normalize_candidate(item, index + 1) for index, item in enumerate(readiness_items)]
    summary = summarize(candidates)
    status = "REGISTRY_WARNING" if summary["registry_breach"] else ("NO_READINESS_AVAILABLE" if not readiness_items else "READY_FOR_REVIEW")
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated,
        "status": status,
        "read_only": True,
        "network_access": False,
        "wordpress_login": False,
        "api_access": False,
        "apply_function": False,
        "productive_change": False,
        "secrets_output": False,
        "allowed_write_roots": [str(path) for path in ALLOWED_WRITE_ROOTS],
        "input_statuses": input_statuses,
        "summary": summary,
        "registered_candidates": [
            candidate
            for candidate in candidates
            if candidate.get("registry_status") in {REGISTERED_DRAFT_ONLY, REGISTERED_VALIDATION_ONLY}
        ],
        "candidates": candidates,
        "groups": {
            REGISTERED_DRAFT_ONLY: [candidate for candidate in candidates if candidate.get("registry_status") == REGISTERED_DRAFT_ONLY],
            REGISTERED_VALIDATION_ONLY: [candidate for candidate in candidates if candidate.get("registry_status") == REGISTERED_VALIDATION_ONLY],
            NOT_REGISTERED_MISSING_GUARDS: [candidate for candidate in candidates if candidate.get("registry_status") == NOT_REGISTERED_MISSING_GUARDS],
            BLOCKED_NOT_ALLOWED: [candidate for candidate in candidates if candidate.get("registry_status") == BLOCKED_NOT_ALLOWED],
            MONITOR_ONLY: [candidate for candidate in candidates if candidate.get("registry_status") == MONITOR_ONLY],
        },
        "required_guards": list(REQUIRED_GUARDS),
        "allowed_candidate_types": sorted(ALLOWED_CANDIDATE_TYPES),
        "prohibited_candidate_types": sorted(PROHIBITED_CANDIDATE_TYPES),
        "outputs": {
            "registry_json": str(REGISTRY_JSON),
            "registry_md": str(REGISTRY_MD),
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_markdown(registry: Dict[str, Any], *, report_title: str) -> str:
    summary = registry.get("summary") if isinstance(registry.get("summary"), dict) else {}
    lines = [
        f"# {report_title}",
        "",
        f"- Generated (UTC): `{registry.get('generated_at_utc')}`",
        f"- Status: `{registry.get('status')}`",
        f"- Candidates: `{summary.get('candidate_count')}`",
        f"- Registered draft-only: `{summary.get('registered_draft_only_count')}`",
        f"- Registered validation-only: `{summary.get('registered_validation_only_count')}`",
        f"- Not registered, missing guards: `{summary.get('not_registered_missing_guards_count')}`",
        f"- Blocked not allowed: `{summary.get('blocked_not_allowed_count')}`",
        f"- Monitor-only: `{summary.get('monitor_only_count')}`",
        f"- Registry breach: `{summary.get('registry_breach')}`",
        "",
        "## Registered Scope",
        "",
        "- Registry-only; no apply mechanism.",
        "- Registered candidates are limited to local drafts, reports, summaries, checks, or validation-only preparation.",
        "- Live WordPress/Yoast/Cloudflare/Nginx/.htaccess/DNS changes remain prohibited.",
        "",
        "## Candidates",
        "",
        "| Candidate ID | Registry Status | Type | Risk | Impact | Title |",
        "|---|---|---|---|---|---|",
    ]
    for candidate in registry.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        lines.append(
            "| "
            f"`{redact_text(candidate.get('candidate_id'), max_len=80)}` | "
            f"`{redact_text(candidate.get('registry_status'), max_len=80)}` | "
            f"`{redact_text(candidate.get('candidate_type'), max_len=80)}` | "
            f"`{redact_text(candidate.get('risk_classification'), max_len=80)}` | "
            f"`{redact_text(candidate.get('impact_area'), max_len=80)}` | "
            f"{redact_text(candidate.get('title'), max_len=160)} |"
        )
    lines.extend(
        [
            "",
            "## Required Guards For Future Live Autonomy",
            "",
        ]
    )
    for guard in registry.get("required_guards", []):
        lines.append(f"- `{redact_text(guard, max_len=120)}`")
    lines.extend(
        [
            "",
            "## Safety Boundaries",
            "",
            "- Keine Live-Aenderungen.",
            "- Kein WordPress-Login, keine API, kein Netzwerkzugriff.",
            "- Keine WordPress-, .htaccess-, Cloudflare-, Nginx- oder DNS-Aenderung.",
            "- Alle Kandidaten bleiben `apply_status=not_applied`.",
            "",
        ]
    )
    return "\n".join(lines)


def audit_record(registry: Dict[str, Any]) -> Dict[str, Any]:
    summary = registry.get("summary") if isinstance(registry.get("summary"), dict) else {}
    return {
        "timestamp_utc": registry.get("generated_at_utc"),
        "schema_version": SCHEMA_VERSION,
        "status": registry.get("status"),
        "candidate_count": summary.get("candidate_count"),
        "registered_draft_only_count": summary.get("registered_draft_only_count"),
        "registered_validation_only_count": summary.get("registered_validation_only_count"),
        "not_registered_missing_guards_count": summary.get("not_registered_missing_guards_count"),
        "blocked_not_allowed_count": summary.get("blocked_not_allowed_count"),
        "monitor_only_count": summary.get("monitor_only_count"),
        "registry_breach": summary.get("registry_breach"),
        "productive_change": False,
        "network_access": False,
        "apply_function": False,
    }


def write_outputs(registry: Dict[str, Any]) -> None:
    write_json_atomic(REGISTRY_JSON, registry)
    write_text_atomic(REGISTRY_MD, render_markdown(registry, report_title="Safe Apply Candidate Registry"))
    write_json_atomic(REPORT_JSON, registry)
    write_text_atomic(REPORT_MD, render_markdown(registry, report_title="Safe Apply Candidate Registry Report"))
    append_jsonl(AUDIT_JSONL, [audit_record(registry)])


def run_self_test() -> int:
    empty = build_registry(None, {"autonomous_improvement_readiness": "not_available"}, "2026-06-10T00:00:00Z")
    if empty.get("status") != "NO_READINESS_AVAILABLE":
        raise AssertionError("missing readiness did not produce NO_READINESS_AVAILABLE")

    sample = {
        "readiness_candidates": [
            {
                "readiness_id": "r1",
                "source_id": "low:title",
                "title": "Title draft",
                "impact_area": "SEO",
                "risk_classification": "LOW",
                "readiness_status": READINESS_DRAFT_ONLY,
                "apply_status": APPLY_NOT_APPLIED,
            },
            {
                "readiness_id": "r2",
                "source_id": "high:cloudflare",
                "title": "Cloudflare change",
                "impact_area": "Technical",
                "risk_classification": "HIGH",
                "readiness_status": READINESS_DRAFT_ONLY,
                "apply_status": APPLY_NOT_APPLIED,
            },
            {
                "readiness_id": "r3",
                "source_id": "medium:lazy",
                "title": "Lazy loading live change",
                "impact_area": "Performance",
                "risk_classification": "MEDIUM",
                "readiness_status": READINESS_DRAFT_ONLY,
                "apply_status": APPLY_NOT_APPLIED,
            },
            {
                "readiness_id": "r4",
                "source_id": "review:schema",
                "title": "Schema review_only",
                "impact_area": "SEO",
                "risk_classification": "REVIEW_ONLY",
                "readiness_status": READINESS_DRAFT_ONLY,
                "apply_status": APPLY_NOT_APPLIED,
            },
            {
                "readiness_id": "r5",
                "source_id": "bad:apply",
                "title": "Bad apply status",
                "impact_area": "SEO",
                "risk_classification": "LOW",
                "readiness_status": READINESS_DRAFT_ONLY,
                "apply_status": "applied",
            },
            {
                "readiness_id": "r6",
                "source_id": "validation:post",
                "title": "Post manual validation",
                "impact_area": "Technical",
                "risk_classification": "LOW",
                "readiness_status": READINESS_DRAFT_ONLY,
                "apply_status": APPLY_NOT_APPLIED,
            },
        ]
    }
    registry = build_registry(sample, {"autonomous_improvement_readiness": "ok"}, "2026-06-10T00:01:00Z")
    by_source = {candidate["source_id"]: candidate for candidate in registry["candidates"]}
    if by_source["low:title"]["registry_status"] != REGISTERED_DRAFT_ONLY:
        raise AssertionError("LOW draft candidate was not registered")
    if by_source["high:cloudflare"]["registry_status"] != BLOCKED_NOT_ALLOWED:
        raise AssertionError("HIGH candidate was not blocked")
    if by_source["medium:lazy"]["registry_status"] == REGISTERED_DRAFT_ONLY:
        raise AssertionError("MEDIUM candidate was registered")
    if by_source["review:schema"]["registry_status"] == REGISTERED_DRAFT_ONLY:
        raise AssertionError("REVIEW_ONLY candidate was registered")
    if by_source["high:cloudflare"]["candidate_type"] not in PROHIBITED_CANDIDATE_TYPES:
        raise AssertionError("prohibited candidate type was not detected")
    if not registry["summary"]["registry_breach"]:
        raise AssertionError("apply_status != not_applied did not produce registry_breach")
    if any(candidate.get("apply_status") != APPLY_NOT_APPLIED for candidate in registry["registered_candidates"]):
        raise AssertionError("registered candidate apply_status changed")
    try:
        assert_allowed_write(PROJECT_DIR / "forbidden/safe-apply-registry.json")
    except ValueError:
        pass
    else:
        raise AssertionError("forbidden write path was not rejected")
    print("safe-apply-candidate-registry self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Safe Apply Candidate Registry.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory registry safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    data, statuses = load_inputs()
    registry = build_registry(data.get("autonomous_improvement_readiness"), statuses)
    write_outputs(registry)
    summary = registry.get("summary") if isinstance(registry.get("summary"), dict) else {}
    print(
        "Safe Apply Candidate Registry written: "
        f"{REGISTRY_MD} "
        f"(draft_only={summary.get('registered_draft_only_count')}, "
        f"validation_only={summary.get('registered_validation_only_count')}, "
        f"blocked={summary.get('blocked_not_allowed_count')})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
