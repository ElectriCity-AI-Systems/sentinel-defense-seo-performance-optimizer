#!/usr/bin/env python3
"""Build the central Sentinel master report.

The script is intentionally local and defensive:
- reads local JSON reports only
- writes a summarized Markdown/JSON master report
- appends a compact JSONL history entry
- never performs network calls or production mutations
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import sentinel_canonical_truth as canonical_truth


PROJECT_DIR = Path("/srv/sentinel-defense")

DEFAULT_WEBSITE_JSON = PROJECT_DIR / "reports/latest/sentinel-defense-report.json"
DEFAULT_LOCAL_JSON = PROJECT_DIR / "inbox/local/local-defense-report.json"
DEFAULT_PRIVATE_PC_JSON = PROJECT_DIR / "inbox/private-pc/local-defense-report.json"
DEFAULT_OUT_MD = PROJECT_DIR / "reports/latest/sentinel-master-report.md"
DEFAULT_OUT_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
DEFAULT_HISTORY = PROJECT_DIR / "reports/history/sentinel-master-history.jsonl"
DEFAULT_CHALLENGE_DIAGNOSIS_JSON = PROJECT_DIR / "reports/latest/cloudflare-challenge-diagnosis.json"
DEFAULT_SOURCEMAP_JSON = PROJECT_DIR / "reports/latest/sourcemap-prevention-report.json"
DEFAULT_AI_RADIO_TIMEOUT_JSON = PROJECT_DIR / "reports/latest/ai-radio-api-timeout-diagnosis.json"
DEFAULT_AUTONOMY_POLICY_JSON = PROJECT_DIR / "reports/latest/autonomy-policy-report.json"
DEFAULT_AUTONOMY_AUDIT_JSONL = PROJECT_DIR / "audit/autonomy-policy-decisions.jsonl"
DEFAULT_SEO_OPTIMIZER_JSON = PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.json"
DEFAULT_EDITORIAL_REVIEW_JSON = PROJECT_DIR / "drafts/seo/homepage-editorial-review.json"
DEFAULT_MICROCACHE_STATUS_JSON = PROJECT_DIR / "reports/latest/ai-radio-nowplaying-microcache-status.json"
DEFAULT_PERF_AUDIT_JSON = PROJECT_DIR / "reports/latest/performance-safe-audit-report.json"
DEFAULT_ROADMAP_JSON = PROJECT_DIR / "reports/latest/safe-improvement-roadmap-report.json"
DEFAULT_APPROVAL_QUEUE_JSON = PROJECT_DIR / "reports/latest/owner-approval-queue-report.json"
DEFAULT_OWNER_CLI_REPORT_JSON = PROJECT_DIR / "reports/latest/owner-approval-cli-report.json"
DEFAULT_DRAFT_EXECUTION_PLAN_JSON = PROJECT_DIR / "reports/latest/draft-execution-plan-report.json"
DEFAULT_OWNER_REVIEW_PACK_JSON = PROJECT_DIR / "reports/latest/owner-review-pack-report.json"
DEFAULT_MANUAL_APPLY_CHECKLIST_JSON = PROJECT_DIR / "reports/latest/manual-apply-checklist-report.json"
DEFAULT_MANUAL_COMPLETION_TRACKER_JSON = PROJECT_DIR / "reports/latest/manual-completion-tracker-report.json"
DEFAULT_POST_MANUAL_VALIDATION_JSON = PROJECT_DIR / "reports/latest/post-manual-validation-report.json"
DEFAULT_OWNER_DAILY_ACTION_SUMMARY_JSON = PROJECT_DIR / "reports/latest/owner-daily-action-summary.json"
DEFAULT_SAFE_APPLY_REGISTRY_JSON = PROJECT_DIR / "reports/latest/safe-apply-candidate-registry-report.json"
DEFAULT_SAFE_APPLY_GUARD_JSON = PROJECT_DIR / "reports/latest/safe-apply-guard-check-report.json"
DEFAULT_SAFE_APPLY_SCOPE_JSON = PROJECT_DIR / "reports/latest/safe-apply-scope-allowlist-report.json"
DEFAULT_SAFE_APPLY_DRY_RUN_JSON = PROJECT_DIR / "reports/latest/safe-apply-dry-run-plan-report.json"
DEFAULT_SAFE_APPLY_PREFLIGHT_JSON = PROJECT_DIR / "reports/latest/safe-apply-preflight-validation-report.json"
DEFAULT_AUTONOMY_RUNTIME_LOCK_JSON = PROJECT_DIR / "reports/latest/autonomy-runtime-lock-report.json"
DEFAULT_SAFE_DRAFT_AUTONOMY_RUNNER_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-runner-report.json"
DEFAULT_SAFE_DRAFT_AUTONOMY_VERIFIER_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-verifier-report.json"
DEFAULT_SAFE_DRAFT_AUTONOMY_SCHEDULER_PLAN_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-scheduler-plan.json"
DEFAULT_SAFE_DRAFT_AUTONOMY_TIMER_DRAFT_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-draft-report.json"
DEFAULT_SAFE_DRAFT_AUTONOMY_TIMER_INSTALL_REVIEW_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-timer-install-review-report.json"
DEFAULT_OWNER_MANUAL_TIMER_INSTALL_PACKET_JSON = PROJECT_DIR / "reports/latest/owner-manual-timer-install-packet-report.json"
DEFAULT_OWNER_TIMER_INSTALL_DECISION_GATE_JSON = PROJECT_DIR / "reports/latest/owner-timer-install-decision-gate-report.json"
DEFAULT_MANUAL_TIMER_INSTALL_COMMAND_PREVIEW_JSON = PROJECT_DIR / "reports/latest/manual-timer-install-command-preview-report.json"
DEFAULT_OWNER_TIMER_INSTALL_EVIDENCE_PACK_JSON = PROJECT_DIR / "reports/latest/owner-timer-install-evidence-pack-report.json"
DEFAULT_SAFE_DRAFT_AUTONOMY_FINAL_SAFETY_JSON = PROJECT_DIR / "reports/latest/safe-draft-autonomy-final-safety-report.json"
DEFAULT_MANUAL_EVIDENCE_REVIEW_DASHBOARD_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-dashboard.json"
DEFAULT_MANUAL_EVIDENCE_REVIEW_COMPLETION_TRACKER_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-tracker.json"
DEFAULT_MANUAL_EVIDENCE_REVIEW_COMPLETION_GATE_JSON = PROJECT_DIR / "reports/latest/manual-evidence-review-completion-gate.json"
DEFAULT_OWNER_EVIDENCE_REVIEW_CONSOLE_JSON = PROJECT_DIR / "reports/latest/owner-evidence-review-console.json"
DEFAULT_FINAL_OWNER_DECISION_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json"
DEFAULT_MASTER_CRITICAL_CAUSE_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/master-critical-cause-snapshot.json"
DEFAULT_ROLLING_WINDOW_DECAY_OBSERVER_JSON = PROJECT_DIR / "reports/latest/rolling-window-decay-observer.json"
DEFAULT_LOW_GROWTH_READINESS_TIMELINE_JSON = PROJECT_DIR / "reports/latest/low-growth-readiness-timeline.json"
DEFAULT_MANUAL_WEBSITE_RECHECK_GATE_JSON = PROJECT_DIR / "reports/latest/manual-website-recheck-gate.json"
DEFAULT_LOW_RISK_AUTONOMY_READINESS_GATE_JSON = PROJECT_DIR / "reports/latest/low-risk-autonomy-readiness-gate.json"
DEFAULT_LOW_RISK_POLICY_BOUNDARY_DRAFT_JSON = PROJECT_DIR / "reports/latest/low-risk-policy-boundary-draft.json"
DEFAULT_LOW_RISK_POLICY_OWNER_REVIEW_TRACKER_JSON = PROJECT_DIR / "reports/latest/low-risk-policy-owner-review-tracker.json"
DEFAULT_LOW_RISK_POLICY_REVIEW_COMPLETION_GATE_JSON = PROJECT_DIR / "reports/latest/low-risk-policy-review-completion-gate.json"
DEFAULT_LOW_RISK_AUTONOMY_FINAL_SAFETY_SEAL_JSON = PROJECT_DIR / "reports/latest/low-risk-autonomy-final-safety-seal.json"
DEFAULT_SAFE_END_SUMMARY_JSON = PROJECT_DIR / "reports/latest/safe-end-summary.json"
DEFAULT_SAFE_END_ARCHIVE_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/safe-end-archive-snapshot.json"
DEFAULT_SAFE_END_ARCHIVE_INTEGRITY_VERIFIER_JSON = PROJECT_DIR / "reports/latest/safe-end-archive-integrity-verifier.json"
DEFAULT_CONCRETE_SEO_PERFORMANCE_OPTIMIZER_JSON = PROJECT_DIR / "reports/latest/concrete-seo-performance-optimizer.json"
DEFAULT_SAFE_SFTP_SEO_APPLY_LANE_JSON = PROJECT_DIR / "reports/latest/safe-sftp-seo-apply-lane.json"
DEFAULT_PRODUCTION_PIPELINE_JSON = PROJECT_DIR / "reports/latest/sentinel-production-pipeline.json"
DEFAULT_NOWPLAYING_RECOVERY_JSON = PROJECT_DIR / "reports/latest/sentinel-nowplaying-recovery.json"
PRIVATE_PC_CONFIRMATION_DOCS = (
    PROJECT_DIR / "docs/sentinel-current-state.md",
    PROJECT_DIR / "docs/goal-ok-status.md",
)

STATUS_OK = "OK"
STATUS_WARNING = "WARNING"
STATUS_CRITICAL = "CRITICAL"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_WATCH = "WATCH"

CORRELATION_ACTION_CANDIDATE = "ACTION_CANDIDATE"
CORRELATION_WATCH = "WATCH"
CORRELATION_UNKNOWN = "UNKNOWN"

ACTION_APPLY_CANDIDATE = "APPLY_CANDIDATE"
ACTION_LOCAL_ATTENTION = "LOCAL_ATTENTION"
ACTION_WATCH_ONLY = "WATCH_ONLY"
ACTION_WARNING_REVIEW = "WARNING_REVIEW"
ACTION_OK = "OK"
ACTION_UNKNOWN = "UNKNOWN"

SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|authorization|credential|smtp)",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|credential)"
    r"\s*[:=]\s*[^\s,;]+"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_status(value: Any) -> str:
    if not isinstance(value, str):
        return STATUS_UNKNOWN
    status = value.strip().upper()
    if status in {STATUS_OK, STATUS_WARNING, STATUS_CRITICAL, STATUS_UNKNOWN}:
        return status
    return STATUS_UNKNOWN


def normalize_signal_status(value: Any) -> str:
    if not isinstance(value, str):
        return STATUS_UNKNOWN
    status = value.strip().upper()
    if status in {STATUS_OK, STATUS_WARNING, STATUS_CRITICAL, STATUS_WATCH, STATUS_UNKNOWN}:
        return status
    return STATUS_UNKNOWN


def normalize_correlation(value: Any) -> str:
    if not isinstance(value, str):
        return CORRELATION_UNKNOWN
    correlation = value.strip().upper()
    if correlation:
        return correlation
    return CORRELATION_UNKNOWN


def redact_text(value: Any, max_len: int = 320) -> str:
    text = str(value)
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = BEARER_RE.sub("Bearer <redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def safe_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    return redact_text(value)


def read_json(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str], bool]:
    if not path.exists():
        return None, "missing", False
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        return None, f"invalid json: {exc}", True
    except OSError as exc:
        return None, f"read failed: {exc}", True
    if not isinstance(data, dict):
        return None, "json root is not an object", True
    return data, None, True


def read_challenge_diagnosis(path: Path) -> Dict[str, Any]:
    data, error, exists = read_json(path)
    if not exists or error or not data:
        return {
            "present": False,
            "path": str(path),
            "error": error or "not found",
        }
    return {
        "present": True,
        "path": str(path),
        "verdict": data.get("verdict"),
        "confidence": data.get("confidence"),
        "botfight_share_percent": (
            data.get("security_actions_analysis", {})
            .get("source_breakdown", {})
            .get("botFight", {})
            .get("share_percent")
        ),
        "sentineldefense_assessment": (
            data.get("sentineldefense_status", {})
            .get("assessment")
        ),
        "top_recommendation": (
            data.get("recommendations", [{}])[0].get("action")
            if data.get("recommendations")
            else None
        ),
        "full_report_path": str(path),
    }


def read_last_audit_timestamp(path: Path) -> Optional[str]:
    """Best-effort read of the most recent autonomy audit timestamp.

    Read-only; never raises. Returns None when unavailable.
    """
    try:
        if not path.exists():
            return None
        last_line = ""
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line
        if not last_line:
            return None
        entry = json.loads(last_line)
    except (OSError, ValueError):
        return None
    if isinstance(entry, dict):
        ts = entry.get("timestamp_utc")
        return safe_text(ts) if ts is not None else None
    return None


def summarize_autonomy_policy(
    data: Optional[Dict[str, Any]],
    path: Path,
    error: Optional[str],
    exists: bool,
    audit_path: Path = DEFAULT_AUTONOMY_AUDIT_JSONL,
) -> Dict[str, Any]:
    """Summarize the optional Autonomy Policy Layer report.

    Read-only. The Master never derives a *better* status from this layer;
    a detected policy breach can only escalate the action status.
    """
    if not exists or error or not isinstance(data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(path),
            "error": error or "not found",
            "recommendation": "run sentinel_autonomy_policy.py",
            "policy_breach": False,
            "policy_only": None,
            "apply_status_summary": None,
            "current_autonomy_level": None,
            "evaluated_actions_count": 0,
            "allowed_now_count": 0,
            "blocked_count": 0,
            "owner_approval_required_count": 0,
            "high_risk_count": 0,
            "last_audit_timestamp": read_last_audit_timestamp(audit_path),
        }

    decisions = data.get("decisions") if isinstance(data.get("decisions"), list) else []
    policy_only = bool(data.get("policy_only", False))

    high_risk_allowed_now = 0
    not_applied_count = 0
    other_apply_status_count = 0
    for decision in decisions:
        if not isinstance(decision, dict):
            continue
        risk = str(decision.get("risk_classification", "")).strip().upper()
        if risk == "HIGH" and bool(decision.get("allowed_now")):
            high_risk_allowed_now += 1
        apply_status = str(decision.get("apply_status", "not_applied")).strip()
        if apply_status == "not_applied":
            not_applied_count += 1
        else:
            other_apply_status_count += 1

    all_not_applied = other_apply_status_count == 0
    if all_not_applied:
        apply_status_summary = (
            f"all_not_applied ({not_applied_count}/{len(decisions)})"
            if decisions
            else "all_not_applied"
        )
    else:
        apply_status_summary = (
            f"{other_apply_status_count} action(s) not in not_applied state"
        )

    # Policy breach conditions (any of these forces at least WARNING_REVIEW):
    #   * policy_only is false
    #   * a HIGH-risk action reports allowed_now=true
    #   * any apply_status is not "not_applied" (no approved gate exists yet)
    policy_breach = (
        (not policy_only)
        or (high_risk_allowed_now > 0)
        or (not all_not_applied)
    )

    return {
        "present": True,
        "status": "WARNING_REVIEW" if policy_breach else "OK",
        "path": str(path),
        "policy_breach": policy_breach,
        "current_autonomy_level": safe_text(data.get("current_autonomy_level")),
        "evaluated_actions_count": parse_count(data.get("evaluated_actions_count")),
        "allowed_now_count": parse_count(data.get("allowed_now_count")),
        "blocked_count": parse_count(data.get("blocked_count")),
        "owner_approval_required_count": parse_count(data.get("owner_approval_required_count")),
        "high_risk_count": parse_count(data.get("high_risk_count")),
        "high_risk_allowed_now_count": high_risk_allowed_now,
        "policy_only": policy_only,
        "apply_status_summary": apply_status_summary,
        "last_audit_timestamp": read_last_audit_timestamp(audit_path)
        or safe_text(data.get("generated_at_utc")),
        "report_generated_at_utc": safe_text(data.get("generated_at_utc")),
    }


def escalate_action_status_for_autonomy(action_status: str) -> str:
    """On an autonomy policy breach the action status must be at least
    WARNING_REVIEW. Never downgrade an already action-requiring status."""
    softer = {ACTION_OK, ACTION_UNKNOWN, ACTION_WATCH_ONLY}
    if action_status in softer:
        return ACTION_WARNING_REVIEW
    return action_status


def _finding_status_map(findings: Any) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not isinstance(findings, list):
        return result
    for item in findings:
        if isinstance(item, dict) and item.get("signal"):
            result[str(item.get("signal"))] = str(item.get("status", "unknown"))
    return result


def summarize_seo_safe_optimizer(
    seo_data: Optional[Dict[str, Any]],
    seo_path: Path,
    seo_error: Optional[str],
    seo_exists: bool,
    editorial_data: Optional[Dict[str, Any]],
    editorial_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional read-only SEO Safe Optimizer report.

    Purely informational: never changes the Master status. SEO output is
    draft-only / review-only and is never applied by Sentinel.
    """
    if not seo_exists or seo_error or not isinstance(seo_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(seo_path),
            "error": seo_error or "not found",
            "recommendation": "run sentinel_seo_safe_optimizer.py",
            "highest_risk": None,
            "productive_change": False,
            "improved_drafts_available": False,
            "next_safe_seo_steps": [],
        }

    findings = _finding_status_map(seo_data.get("findings"))
    risk_classification = seo_data.get("risk_classification") if isinstance(seo_data.get("risk_classification"), dict) else {}
    highest_risk = str(risk_classification.get("highest_risk", "UNKNOWN")).upper()

    improved = seo_data.get("improved_drafts_summary")
    improved_available = bool(improved) if isinstance(improved, (dict, list)) else False

    safe_steps = seo_data.get("safe_next_steps")
    if not isinstance(safe_steps, list):
        safe_steps = []

    editorial_summary: Dict[str, Any] = {}
    if editorial_exists and isinstance(editorial_data, dict):
        raw_summary = editorial_data.get("summary") if isinstance(editorial_data.get("summary"), dict) else {}
        editorial_summary = {
            "apply_status": safe_text(editorial_data.get("apply_status")),
            "proposal_count": parse_count(raw_summary.get("proposal_count")),
            "improve_count": parse_count(raw_summary.get("improve_count")),
            "review_only_count": parse_count(raw_summary.get("review_only_count")),
            "high_risk_count": parse_count(raw_summary.get("high_risk_count")),
            "all_not_applied": bool(raw_summary.get("all_not_applied", True)),
        }
    else:
        editorial_summary = {"present": False}

    return {
        "present": True,
        "status": safe_text(seo_data.get("status")),
        "path": str(seo_path),
        "highest_risk": highest_risk,
        "productive_change": bool(seo_data.get("productive_change", False)),
        "read_only": bool(seo_data.get("read_only", True)),
        "title_status": findings.get("title", "unknown"),
        "meta_description_status": findings.get("meta_description", "unknown"),
        "canonical_status": findings.get("canonical", "unknown"),
        "open_graph_status": findings.get("open_graph", "unknown"),
        "twitter_cards_status": findings.get("twitter_cards", "unknown"),
        "schema_status": findings.get("schema_json_ld", "unknown"),
        "robots_status": findings.get("robots_txt", "unknown"),
        "sitemap_status": findings.get("sitemap", "unknown"),
        "editorial_review_summary": editorial_summary,
        "improved_drafts_available": improved_available,
        "next_safe_seo_steps": [safe_text(step) for step in safe_steps[:8]],
    }


def summarize_performance_safe_improvement(
    ai_radio_summary: Dict[str, Any],
    sourcemap_summary: Dict[str, Any],
    website_summary: Dict[str, Any],
    microcache_data: Optional[Dict[str, Any]],
    microcache_exists: bool,
    audit_data: Optional[Dict[str, Any]] = None,
    audit_exists: bool = False,
) -> Dict[str, Any]:
    """Conservative, read-only performance improvement visibility.

    Prefers the dedicated Performance Safe Audit report
    (reports/latest/performance-safe-audit-report.json) when present, and
    otherwise derives statuses from already-collected local reports. Missing
    data is marked NOT_AVAILABLE and never crashes. This layer recommends only;
    it never applies a performance change.
    """
    NA = "NOT_AVAILABLE"

    # --- Preferred source: dedicated Performance Safe Audit report -------
    if audit_exists and isinstance(audit_data, dict):
        steps = audit_data.get("next_safe_performance_steps")
        if not isinstance(steps, list):
            steps = []
        return {
            "present": True,
            "status": "READ_ONLY",
            "source": "performance_safe_audit",
            "read_only": True,
            "productive_change": False,
            "audit_highest_risk": safe_text(audit_data.get("highest_risk")),
            "cache_status": safe_text(audit_data.get("cache_header_status")),
            "image_optimization_status": safe_text(audit_data.get("image_optimization_status")),
            "lazy_loading_status": safe_text(audit_data.get("lazy_loading_status")),
            "external_embed_risk": safe_text(audit_data.get("external_embed_risk")),
            "render_blocking_risk": safe_text(audit_data.get("render_blocking_risk")),
            "ai_radio_nowplaying_cache_status": safe_text(audit_data.get("ai_radio_nowplaying_cache_status")),
            "source_map_status": safe_text(audit_data.get("source_map_status")),
            "origin_5xx_status": safe_text(audit_data.get("origin_5xx_status")),
            "next_safe_performance_steps": [safe_text(step) for step in steps[:8]],
        }

    # --- AI-Radio NowPlaying microcache ---------------------------------
    ai_remediation = ai_radio_summary.get("microcache_remediation") if isinstance(ai_radio_summary.get("microcache_remediation"), dict) else {}
    microcache_deployed = ai_remediation.get("microcache_deployed")
    local_validation = ai_remediation.get("local_validation")
    if microcache_deployed is None and microcache_exists and isinstance(microcache_data, dict):
        microcache_deployed = microcache_data.get("microcache_deployed")
        local_validation = microcache_data.get("local_validation")
    if microcache_deployed is True:
        ai_radio_cache_status = "MICROCACHE_DEPLOYED"
    elif microcache_deployed is False:
        ai_radio_cache_status = "MICROCACHE_NOT_DEPLOYED"
    else:
        ai_radio_cache_status = NA

    # --- Origin 5xx / cache from website origin-pressure breakdown ------
    origin_pressure = website_summary.get("origin_pressure_breakdown") if isinstance(website_summary.get("origin_pressure_breakdown"), dict) else {}
    origin_5xx_status = safe_text(origin_pressure.get("status")) if origin_pressure.get("status") else NA
    cache_interpretation = origin_pressure.get("cache_status_interpretation")
    if cache_interpretation:
        cache_status = safe_text(cache_interpretation)
    elif microcache_deployed is True:
        cache_status = "ORIGIN_MICROCACHE_ACTIVE"
    else:
        cache_status = NA

    # --- Source map status ----------------------------------------------
    source_map_status = safe_text(sourcemap_summary.get("status")) if sourcemap_summary.get("present") else NA

    # --- Not measured by any current read-only source -------------------
    image_optimization_status = NA
    lazy_loading_status = NA
    external_embed_risk = NA

    next_steps = [
        "Performance bleibt read-only/observe: keine Cache-, Bild- oder Embed-Aenderung automatisch.",
        "AI-Radio NowPlaying 504-Fenster ueber 24h Rolling-Window beobachten, keine neue WAF-Regel.",
        "SourceMap-Minify-Kandidaten bleiben review-only bis Owner-Freigabe.",
        "Bild-/Lazy-Loading-/Embed-Optimierung erst nach dediziertem read-only Performance-Audit bewerten.",
    ]

    has_any = any(
        v != NA
        for v in (ai_radio_cache_status, origin_5xx_status, cache_status, source_map_status)
    )

    return {
        "present": has_any,
        "status": "READ_ONLY" if has_any else NA,
        "source": "derived",
        "read_only": True,
        "productive_change": False,
        "cache_status": cache_status,
        "image_optimization_status": image_optimization_status,
        "lazy_loading_status": lazy_loading_status,
        "external_embed_risk": external_embed_risk,
        "ai_radio_nowplaying_cache_status": ai_radio_cache_status,
        "ai_radio_local_validation": safe_text(local_validation) if local_validation else NA,
        "source_map_status": source_map_status,
        "origin_5xx_status": origin_5xx_status,
        "next_safe_performance_steps": next_steps,
    }


def summarize_roadmap(
    roadmap_data: Optional[Dict[str, Any]],
    roadmap_path: Path,
    roadmap_error: Optional[str],
    roadmap_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Improvement Roadmap report.

    Informational only: never changes the Master status.
    """
    if not roadmap_exists or roadmap_error or not isinstance(roadmap_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(roadmap_path),
            "recommendation": "run sentinel_safe_improvement_roadmap.py",
            "roadmap_next_safe_count": 0,
            "roadmap_owner_review_count": 0,
            "roadmap_blocked_high_count": 0,
            "roadmap_monitor_only_count": 0,
            "top_5_next_safe_steps": [],
        }
    summary = roadmap_data.get("summary") if isinstance(roadmap_data.get("summary"), dict) else {}
    top_steps_raw = roadmap_data.get("top_5_next_safe_steps")
    top_steps: List[Dict[str, Any]] = []
    if isinstance(top_steps_raw, list):
        for entry in top_steps_raw[:5]:
            if isinstance(entry, dict):
                top_steps.append({
                    "roadmap_id": safe_text(entry.get("roadmap_id")),
                    "suggested_next_step": safe_text(entry.get("suggested_next_step")),
                })
    return {
        "present": True,
        "status": safe_text(roadmap_data.get("status")),
        "path": str(roadmap_path),
        "roadmap_item_count": parse_count(summary.get("roadmap_item_count")),
        "roadmap_next_safe_count": parse_count(summary.get("next_safe_count")),
        "roadmap_owner_review_count": parse_count(summary.get("owner_review_count")),
        "roadmap_blocked_high_count": parse_count(summary.get("blocked_high_count")),
        "roadmap_monitor_only_count": parse_count(summary.get("monitor_only_count")),
        "top_5_next_safe_steps": top_steps,
    }


def summarize_approval_queue(
    queue_data: Optional[Dict[str, Any]],
    queue_path: Path,
    queue_error: Optional[str],
    queue_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Owner Approval Queue report.

    Informational only: the queue alone never changes the Master status. A
    queue breach (HIGH not blocked, or apply_status != not_applied) is surfaced
    so the action status can be escalated to at least WARNING_REVIEW.
    """
    if not queue_exists or queue_error or not isinstance(queue_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(queue_path),
            "recommendation": "run sentinel_owner_approval_queue.py",
            "queue_breach": False,
            "pending_owner_review_count": 0,
            "approved_for_draft_only_count": 0,
            "monitor_only_count": 0,
            "blocked_high_risk_count": 0,
            "reconcile_enabled": False,
            "preserved_decisions_count": 0,
            "stale_items_count": 0,
            "security_overrides_count": 0,
            "top_pending_items": [],
        }
    summary = queue_data.get("summary") if isinstance(queue_data.get("summary"), dict) else {}
    top_raw = queue_data.get("top_pending_items")
    top_pending: List[Dict[str, Any]] = []
    if isinstance(top_raw, list):
        for entry in top_raw[:5]:
            if isinstance(entry, dict):
                top_pending.append({
                    "queue_id": safe_text(entry.get("queue_id")),
                    "title": safe_text(entry.get("title")),
                    "impact_area": safe_text(entry.get("impact_area")),
                    "risk_classification": safe_text(entry.get("risk_classification")),
                })
    return {
        "present": True,
        "status": safe_text(queue_data.get("status")),
        "path": str(queue_path),
        "queue_breach": bool(queue_data.get("queue_breach", False)),
        "queue_item_count": parse_count(summary.get("queue_item_count")),
        "pending_owner_review_count": parse_count(summary.get("pending_owner_review_count")),
        "approved_for_draft_only_count": parse_count(summary.get("approved_for_draft_only_count")),
        "monitor_only_count": parse_count(summary.get("monitor_only_count")),
        "blocked_high_risk_count": parse_count(summary.get("blocked_high_risk_count")),
        "reconcile_enabled": bool(queue_data.get("reconcile_enabled", False)),
        "preserved_decisions_count": parse_count(queue_data.get("preserved_decisions_count")),
        "stale_items_count": parse_count(queue_data.get("stale_items_count")),
        "security_overrides_count": parse_count(queue_data.get("security_overrides_count")),
        "top_pending_items": top_pending,
    }


def summarize_owner_cli(
    cli_data: Optional[Dict[str, Any]],
    cli_path: Path,
    cli_error: Optional[str],
    cli_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Owner Approval CLI report (last owner action).

    Informational only: a valid owner comment/decision never worsens the
    Master status. Only a policy breach (HIGH approved or apply_status !=
    not_applied) escalates.
    """
    if not cli_exists or cli_error or not isinstance(cli_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(cli_path),
            "queue_policy_breach": False,
            "last_owner_action": None,
            "last_owner_action_allowed": None,
            "last_owner_action_queue_id": None,
            "last_owner_action_status_change": None,
        }
    return {
        "present": True,
        "status": "OK",
        "path": str(cli_path),
        "queue_policy_breach": bool(cli_data.get("queue_policy_breach", False)),
        "last_owner_action": safe_text(cli_data.get("last_owner_action")),
        "last_owner_action_allowed": bool(cli_data.get("last_owner_action_allowed")),
        "last_owner_action_queue_id": safe_text(cli_data.get("last_owner_action_queue_id")),
        "last_owner_action_status_change": safe_text(cli_data.get("last_owner_action_status_change")),
        "generated_at_utc": safe_text(cli_data.get("generated_at_utc")),
    }


def summarize_draft_execution_planner(
    planner_data: Optional[Dict[str, Any]],
    planner_path: Path,
    planner_error: Optional[str],
    planner_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Draft Execution Planner report.

    Informational only when all execution items remain LOW/not_applied. A real
    breach (HIGH included or apply_status != not_applied) may escalate to
    WARNING_REVIEW.
    """
    if not planner_exists or planner_error or not isinstance(planner_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(planner_path),
            "recommendation": "run sentinel_draft_execution_planner.py",
            "planner_breach": False,
            "execution_items_count": 0,
            "excluded_items_count": 0,
            "ready_for_manual_copy_count": 0,
            "high_included_count": 0,
            "apply_status_summary": {
                "all_not_applied": True,
                "not_applied_count": 0,
                "other_apply_status_count": 0,
            },
            "draft_types": [],
        }

    execution_items = planner_data.get("execution_items") if isinstance(planner_data.get("execution_items"), list) else []
    draft_types: List[str] = []
    for item in execution_items:
        if not isinstance(item, dict):
            continue
        draft_type = safe_text(item.get("draft_type"))
        if draft_type not in draft_types:
            draft_types.append(draft_type)
        if len(draft_types) >= 10:
            break

    apply_summary_raw = planner_data.get("apply_status_summary")
    apply_summary = apply_summary_raw if isinstance(apply_summary_raw, dict) else {}
    other_apply = parse_count(apply_summary.get("other_apply_status_count"))
    high_included = parse_count(planner_data.get("high_included_count"))
    planner_breach = bool(planner_data.get("planner_breach", False)) or other_apply > 0 or high_included > 0

    return {
        "present": True,
        "status": safe_text(planner_data.get("status")),
        "path": str(planner_path),
        "planner_breach": planner_breach,
        "execution_items_count": parse_count(planner_data.get("execution_items_count")),
        "excluded_items_count": parse_count(planner_data.get("excluded_items_count")),
        "ready_for_manual_copy_count": parse_count(planner_data.get("ready_for_manual_copy_count")),
        "high_included_count": high_included,
        "apply_status_summary": {
            "all_not_applied": bool(apply_summary.get("all_not_applied", False)),
            "not_applied_count": parse_count(apply_summary.get("not_applied_count")),
            "other_apply_status_count": other_apply,
        },
        "draft_types": draft_types,
        "read_only": bool(planner_data.get("read_only", False)),
        "network_access": bool(planner_data.get("network_access", False)),
        "apply_function": bool(planner_data.get("apply_function", False)),
        "productive_change": bool(planner_data.get("productive_change", False)),
    }


def summarize_owner_review_pack(
    pack_data: Optional[Dict[str, Any]],
    pack_path: Path,
    pack_error: Optional[str],
    pack_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Owner Review Pack.

    The pack alone is manual/review-only and must not worsen status. It can
    only escalate if it exposes a policy breach: non-not_applied items, or
    HIGH/MEDIUM/REVIEW_ONLY items marked ready_for_copy.
    """
    if not pack_exists or pack_error or not isinstance(pack_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(pack_path),
            "recommendation": "run sentinel_owner_review_pack.py",
            "review_pack_breach": False,
            "review_items_count": 0,
            "ready_for_owner_review_count": 0,
            "ready_for_copy_count": 0,
            "excluded_count": 0,
            "high_or_medium_ready_count": 0,
            "apply_status_summary": {
                "all_not_applied": True,
                "not_applied_count": 0,
                "other_apply_status_count": 0,
            },
            "sections": [],
        }

    review_items = pack_data.get("review_items") if isinstance(pack_data.get("review_items"), list) else []
    sections: List[str] = []
    high_or_medium_ready_count = parse_count(pack_data.get("high_or_medium_ready_count"))
    for item in review_items:
        if not isinstance(item, dict):
            continue
        section = safe_text(item.get("section"))
        if section not in sections:
            sections.append(section)
        if bool(item.get("ready_for_copy")) and safe_text(item.get("risk_classification")) in {"HIGH", "MEDIUM", "REVIEW_ONLY"}:
            high_or_medium_ready_count += 1
        if len(sections) >= 10:
            break

    apply_summary_raw = pack_data.get("apply_status_summary")
    apply_summary = apply_summary_raw if isinstance(apply_summary_raw, dict) else {}
    other_apply = parse_count(apply_summary.get("other_apply_status_count"))
    review_pack_breach = bool(pack_data.get("review_pack_breach", False)) or other_apply > 0 or high_or_medium_ready_count > 0

    return {
        "present": True,
        "status": safe_text(pack_data.get("status")),
        "path": str(pack_path),
        "review_pack_breach": review_pack_breach,
        "review_items_count": parse_count(pack_data.get("review_items_count")),
        "ready_for_owner_review_count": parse_count(pack_data.get("ready_for_owner_review_count")),
        "ready_for_copy_count": parse_count(pack_data.get("ready_for_copy_count")),
        "excluded_count": parse_count(pack_data.get("excluded_count")),
        "high_or_medium_ready_count": high_or_medium_ready_count,
        "apply_status_summary": {
            "all_not_applied": bool(apply_summary.get("all_not_applied", False)),
            "not_applied_count": parse_count(apply_summary.get("not_applied_count")),
            "other_apply_status_count": other_apply,
        },
        "sections": sections,
        "read_only": bool(pack_data.get("read_only", False)),
        "network_access": bool(pack_data.get("network_access", False)),
        "apply_function": bool(pack_data.get("apply_function", False)),
        "productive_change": bool(pack_data.get("productive_change", False)),
    }


def summarize_manual_apply_checklist(
    checklist_data: Optional[Dict[str, Any]],
    checklist_path: Path,
    checklist_error: Optional[str],
    checklist_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Manual Apply Checklist.

    The checklist alone is manual and non-productive. It can only escalate when
    it reports productive_change=true, apply_status != not_applied, or
    HIGH/MEDIUM items included in the checklist.
    """
    if not checklist_exists or checklist_error or not isinstance(checklist_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(checklist_path),
            "recommendation": "run sentinel_manual_apply_checklist.py",
            "checklist_breach": False,
            "checklist_items_count": 0,
            "ready_for_manual_apply_review_count": 0,
            "excluded_count": 0,
            "high_medium_included_count": 0,
            "apply_status_summary": {
                "all_not_applied": True,
                "not_applied_count": 0,
                "other_apply_status_count": 0,
            },
            "sections": [],
        }

    items = checklist_data.get("checklist_items") if isinstance(checklist_data.get("checklist_items"), list) else []
    sections: List[str] = []
    high_medium_included_count = parse_count(checklist_data.get("high_medium_included_count"))
    for item in items:
        if not isinstance(item, dict):
            continue
        section = safe_text(item.get("section"))
        if section not in sections:
            sections.append(section)
        if safe_text(item.get("risk_classification")) in {"HIGH", "MEDIUM"}:
            high_medium_included_count += 1
        if len(sections) >= 10:
            break

    apply_summary_raw = checklist_data.get("apply_status_summary")
    apply_summary = apply_summary_raw if isinstance(apply_summary_raw, dict) else {}
    other_apply = parse_count(apply_summary.get("other_apply_status_count"))
    productive_change = bool(checklist_data.get("productive_change", False))
    checklist_breach = (
        bool(checklist_data.get("checklist_breach", False))
        or productive_change
        or other_apply > 0
        or high_medium_included_count > 0
    )

    return {
        "present": True,
        "status": safe_text(checklist_data.get("status")),
        "path": str(checklist_path),
        "checklist_breach": checklist_breach,
        "checklist_items_count": parse_count(checklist_data.get("checklist_items_count")),
        "ready_for_manual_apply_review_count": parse_count(checklist_data.get("ready_for_manual_apply_review_count")),
        "excluded_count": parse_count(checklist_data.get("excluded_count")),
        "high_medium_included_count": high_medium_included_count,
        "review_only_included_count": parse_count(checklist_data.get("review_only_included_count")),
        "apply_status_summary": {
            "all_not_applied": bool(apply_summary.get("all_not_applied", False)),
            "not_applied_count": parse_count(apply_summary.get("not_applied_count")),
            "other_apply_status_count": other_apply,
        },
        "sections": sections,
        "read_only": bool(checklist_data.get("read_only", False)),
        "network_access": bool(checklist_data.get("network_access", False)),
        "wordpress_login": bool(checklist_data.get("wordpress_login", False)),
        "api_access": bool(checklist_data.get("api_access", False)),
        "apply_function": bool(checklist_data.get("apply_function", False)),
        "productive_change": productive_change,
    }


def summarize_manual_completion_tracker(
    tracker_data: Optional[Dict[str, Any]],
    tracker_path: Path,
    tracker_error: Optional[str],
    tracker_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Manual Completion Tracker report.

    Completion progress is informational. The tracker can only escalate when it
    reports a breach: apply_status changed away from not_applied,
    HIGH/MEDIUM completed, or productive_change=true.
    """
    if not tracker_exists or tracker_error or not isinstance(tracker_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(tracker_path),
            "recommendation": "run sentinel_manual_completion_tracker.py list",
            "completion_breach": False,
            "checklist_items_count": 0,
            "completed_count": 0,
            "in_progress_count": 0,
            "skipped_count": 0,
            "needs_review_count": 0,
            "unchecked_count": 0,
            "high_medium_completed_count": 0,
            "last_owner_completion_action": None,
            "apply_status_summary": {
                "all_not_applied": True,
                "not_applied_count": 0,
                "other_apply_status_count": 0,
            },
            "productive_change": False,
        }

    apply_summary_raw = tracker_data.get("apply_status_summary")
    apply_summary = apply_summary_raw if isinstance(apply_summary_raw, dict) else {}
    other_apply = parse_count(apply_summary.get("other_apply_status_count"))
    high_medium_completed_count = parse_count(tracker_data.get("high_medium_completed_count"))
    productive_change = bool(tracker_data.get("productive_change", False))
    completion_breach = (
        bool(tracker_data.get("completion_breach", False))
        or other_apply > 0
        or high_medium_completed_count > 0
        or productive_change
    )
    last_action_raw = tracker_data.get("last_owner_completion_action")
    last_action: Optional[Dict[str, Any]] = None
    if isinstance(last_action_raw, dict):
        last_action = {
            "timestamp_utc": safe_text(last_action_raw.get("timestamp_utc")),
            "command": safe_text(last_action_raw.get("command")),
            "checklist_id": safe_text(last_action_raw.get("checklist_id")),
            "note": safe_text(last_action_raw.get("note")),
        }

    return {
        "present": True,
        "status": safe_text(tracker_data.get("status")),
        "path": str(tracker_path),
        "completion_breach": completion_breach,
        "checklist_items_count": parse_count(tracker_data.get("checklist_items_count")),
        "completed_count": parse_count(tracker_data.get("completed_count")),
        "in_progress_count": parse_count(tracker_data.get("in_progress_count")),
        "skipped_count": parse_count(tracker_data.get("skipped_count")),
        "needs_review_count": parse_count(tracker_data.get("needs_review_count")),
        "unchecked_count": parse_count(tracker_data.get("unchecked_count")),
        "high_medium_completed_count": high_medium_completed_count,
        "last_owner_completion_action": last_action,
        "apply_status_summary": {
            "all_not_applied": bool(apply_summary.get("all_not_applied", False)),
            "not_applied_count": parse_count(apply_summary.get("not_applied_count")),
            "other_apply_status_count": other_apply,
        },
        "productive_change": productive_change,
        "network_access": bool(tracker_data.get("network_access", False)),
        "api_access": bool(tracker_data.get("api_access", False)),
        "wordpress_login": bool(tracker_data.get("wordpress_login", False)),
        "apply_function": bool(tracker_data.get("apply_function", False)),
    }


def summarize_post_manual_validation(
    validation_data: Optional[Dict[str, Any]],
    validation_path: Path,
    validation_error: Optional[str],
    validation_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Post-Manual Validation report.

    Missing local snapshots are informational only. This layer can only
    escalate when it reports a real safety violation: productive_change=true,
    network/apply behavior, HIGH/MEDIUM checklist items, or apply_status other
    than not_applied.
    """
    if not validation_exists or validation_error or not isinstance(validation_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "validation_status": "NOT_AVAILABLE",
            "path": str(validation_path),
            "recommendation": "run sentinel_post_manual_validation.py",
            "seo_validation_status": "NOT_AVAILABLE",
            "performance_validation_status": "NOT_AVAILABLE",
            "safety_validation_status": "NOT_AVAILABLE",
            "checklist_items_count": 0,
            "validation_warning_count": 0,
            "validation_available": False,
            "safety_violation": False,
            "productive_change": False,
            "network_access": False,
            "apply_function": False,
        }

    seo_validation = validation_data.get("seo_validation") if isinstance(validation_data.get("seo_validation"), dict) else {}
    performance_validation = (
        validation_data.get("performance_validation")
        if isinstance(validation_data.get("performance_validation"), dict)
        else {}
    )
    safety_validation = (
        validation_data.get("safety_validation")
        if isinstance(validation_data.get("safety_validation"), dict)
        else {}
    )
    productive_change = bool(validation_data.get("productive_change", False))
    network_access = bool(validation_data.get("network_access", False))
    apply_function = bool(validation_data.get("apply_function", False))
    safety_warning_count = parse_count(safety_validation.get("warning_count"))
    safety_violation = (
        safe_text(validation_data.get("status")) == "VALIDATION_WARNING"
        or safe_text(safety_validation.get("status")) == "WARNING"
        or safety_warning_count > 0
        or productive_change
        or network_access
        or apply_function
    )

    return {
        "present": True,
        "status": safe_text(validation_data.get("status")),
        "validation_status": safe_text(validation_data.get("status")),
        "path": str(validation_path),
        "seo_validation_status": safe_text(seo_validation.get("status")),
        "performance_validation_status": safe_text(performance_validation.get("status")),
        "safety_validation_status": safe_text(safety_validation.get("status")),
        "checklist_items_count": parse_count(validation_data.get("checklist_items_count")),
        "validation_warning_count": parse_count(validation_data.get("validation_warning_count")),
        "validation_available": bool(validation_data.get("validation_available", False)),
        "safety_violation": safety_violation,
        "productive_change": productive_change,
        "network_access": network_access,
        "apply_function": apply_function,
        "no_network_default": bool(validation_data.get("no_network_default", False)),
        "no_apply_function": bool(validation_data.get("no_apply_function", False)),
        "next_owner_steps": (
            validation_data.get("next_owner_steps")
            if isinstance(validation_data.get("next_owner_steps"), list)
            else []
        ),
    }


def summarize_owner_daily_action_summary(
    owner_data: Optional[Dict[str, Any]],
    owner_path: Path,
    owner_error: Optional[str],
    owner_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Owner Daily Action Summary report.

    The summary is informational unless it reports a real safety, completion,
    or autonomy breach.
    """
    if not owner_exists or owner_error or not isinstance(owner_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "owner_status": "NOT_AVAILABLE",
            "path": str(owner_path),
            "recommendation": "run sentinel_owner_daily_action_summary.py",
            "summary_breach": False,
            "recommended_next_owner_action": None,
            "open_manual_items": 0,
            "completed_manual_items": 0,
            "in_progress_manual_items": 0,
            "needs_review_items": 0,
            "skipped_items": 0,
            "blocked_high_risk_items": 0,
            "autonomy_ready_draft_only_count": 0,
            "ready_after_owner_approval_count": 0,
            "not_ready_missing_guards_count": 0,
            "blocked_high_risk_count": 0,
            "monitor_only_count": 0,
            "next_safe_autonomy_build_step": None,
        }

    owner_summary = (
        owner_data.get("owner_daily_action_summary")
        if isinstance(owner_data.get("owner_daily_action_summary"), dict)
        else {}
    )
    readiness = (
        owner_data.get("autonomous_improvement_readiness")
        if isinstance(owner_data.get("autonomous_improvement_readiness"), dict)
        else {}
    )
    summary_breach = (
        bool(owner_summary.get("safety_violation", False))
        or bool(owner_summary.get("completion_breach", False))
        or bool(owner_summary.get("autonomy_breach", False))
    )
    return {
        "present": True,
        "status": safe_text(owner_data.get("status")),
        "owner_status": safe_text(owner_summary.get("overall_owner_status") or owner_data.get("status")),
        "path": str(owner_path),
        "summary_breach": summary_breach,
        "recommended_next_owner_action": safe_text(owner_summary.get("recommended_next_owner_action")),
        "open_manual_items": parse_count(owner_summary.get("open_manual_items")),
        "completed_manual_items": parse_count(owner_summary.get("completed_manual_items")),
        "in_progress_manual_items": parse_count(owner_summary.get("in_progress_manual_items")),
        "needs_review_items": parse_count(owner_summary.get("needs_review_items")),
        "skipped_items": parse_count(owner_summary.get("skipped_items")),
        "blocked_high_risk_items": parse_count(owner_summary.get("blocked_high_risk_items")),
        "autonomy_ready_draft_only_count": parse_count(readiness.get("autonomy_ready_draft_only_count")),
        "ready_after_owner_approval_count": parse_count(readiness.get("ready_after_owner_approval_count")),
        "not_ready_missing_guards_count": parse_count(readiness.get("not_ready_missing_guards_count")),
        "blocked_high_risk_count": parse_count(readiness.get("blocked_high_risk_count")),
        "monitor_only_count": parse_count(readiness.get("monitor_only_count")),
        "next_safe_autonomy_build_step": safe_text(readiness.get("next_safe_autonomy_build_step")),
        "safety_violation": bool(owner_summary.get("safety_violation", False)),
        "completion_breach": bool(owner_summary.get("completion_breach", False)),
        "autonomy_breach": bool(owner_summary.get("autonomy_breach", False)),
        "read_only": bool(owner_data.get("read_only", False)),
        "network_access": bool(owner_data.get("network_access", False)),
        "apply_function": bool(owner_data.get("apply_function", False)),
        "productive_change": bool(owner_data.get("productive_change", False)),
    }


def summarize_safe_apply_candidate_registry(
    registry_data: Optional[Dict[str, Any]],
    registry_path: Path,
    registry_error: Optional[str],
    registry_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Apply Candidate Registry.

    The registry is not an apply mechanism. It can only escalate if it reports
    a registry breach: HIGH/MEDIUM registered, prohibited candidate type
    registered, or apply_status not equal to not_applied.
    """
    if not registry_exists or registry_error or not isinstance(registry_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(registry_path),
            "recommendation": "run sentinel_safe_apply_candidate_registry.py",
            "registered_draft_only_count": 0,
            "registered_validation_only_count": 0,
            "not_registered_missing_guards_count": 0,
            "blocked_not_allowed_count": 0,
            "monitor_only_count": 0,
            "registry_breach": False,
            "candidate_count": 0,
        }

    summary = registry_data.get("summary") if isinstance(registry_data.get("summary"), dict) else {}
    registry_breach = bool(summary.get("registry_breach", False)) or bool(registry_data.get("registry_breach", False))
    return {
        "present": True,
        "status": safe_text(registry_data.get("status")),
        "path": str(registry_path),
        "registered_draft_only_count": parse_count(summary.get("registered_draft_only_count")),
        "registered_validation_only_count": parse_count(summary.get("registered_validation_only_count")),
        "not_registered_missing_guards_count": parse_count(summary.get("not_registered_missing_guards_count")),
        "blocked_not_allowed_count": parse_count(summary.get("blocked_not_allowed_count")),
        "monitor_only_count": parse_count(summary.get("monitor_only_count")),
        "registry_breach": registry_breach,
        "registry_breach_reasons": (
            summary.get("registry_breach_reasons")
            if isinstance(summary.get("registry_breach_reasons"), list)
            else []
        ),
        "candidate_count": parse_count(summary.get("candidate_count")),
        "read_only": bool(registry_data.get("read_only", False)),
        "network_access": bool(registry_data.get("network_access", False)),
        "api_access": bool(registry_data.get("api_access", False)),
        "wordpress_login": bool(registry_data.get("wordpress_login", False)),
        "apply_function": bool(registry_data.get("apply_function", False)),
        "productive_change": bool(registry_data.get("productive_change", False)),
    }


def summarize_safe_apply_guard_check(
    guard_data: Optional[Dict[str, Any]],
    guard_path: Path,
    guard_error: Optional[str],
    guard_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Apply Guard Requirements Check."""
    if not guard_exists or guard_error or not isinstance(guard_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(guard_path),
            "recommendation": "run sentinel_safe_apply_guard_checker.py",
            "guards_ready_draft_only_count": 0,
            "guards_ready_validation_only_count": 0,
            "guards_missing_for_autonomy_count": 0,
            "guards_blocked_not_allowed_count": 0,
            "guards_monitor_only_count": 0,
            "guard_breach": False,
            "candidate_count": 0,
        }

    summary = guard_data.get("summary") if isinstance(guard_data.get("summary"), dict) else {}
    guard_breach = bool(summary.get("guard_breach", False)) or bool(guard_data.get("guard_breach", False))
    return {
        "present": True,
        "status": safe_text(guard_data.get("status")),
        "path": str(guard_path),
        "guards_ready_draft_only_count": parse_count(summary.get("guards_ready_draft_only_count")),
        "guards_ready_validation_only_count": parse_count(summary.get("guards_ready_validation_only_count")),
        "guards_missing_for_autonomy_count": parse_count(summary.get("guards_missing_for_autonomy_count")),
        "guards_blocked_not_allowed_count": parse_count(summary.get("guards_blocked_not_allowed_count")),
        "guards_monitor_only_count": parse_count(summary.get("guards_monitor_only_count")),
        "guard_breach": guard_breach,
        "guard_breach_reasons": (
            summary.get("guard_breach_reasons")
            if isinstance(summary.get("guard_breach_reasons"), list)
            else []
        ),
        "candidate_count": parse_count(summary.get("candidate_count")),
        "read_only": bool(guard_data.get("read_only", False)),
        "network_access": bool(guard_data.get("network_access", False)),
        "api_access": bool(guard_data.get("api_access", False)),
        "wordpress_login": bool(guard_data.get("wordpress_login", False)),
        "apply_function": bool(guard_data.get("apply_function", False)),
        "productive_change": bool(guard_data.get("productive_change", False)),
    }


def summarize_safe_apply_scope_manager(
    scope_data: Optional[Dict[str, Any]],
    scope_path: Path,
    scope_error: Optional[str],
    scope_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Apply Scope & Allowlist Manager (Phase 3.2).

    The scope report is allowlist-only and never applies anything. It can only
    escalate the master action status if it reports a scope breach (HIGH/MEDIUM
    in allowed scope, prohibited candidate_type or path allowed, or apply_status
    not equal to not_applied).
    """
    if not scope_exists or scope_error or not isinstance(scope_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(scope_path),
            "recommendation": "run sentinel_safe_apply_scope_manager.py",
            "scope_allowed_draft_only_count": 0,
            "scope_allowed_validation_only_count": 0,
            "scope_not_allowed_missing_guards_count": 0,
            "scope_blocked_high_risk_count": 0,
            "scope_monitor_only_count": 0,
            "scope_breach": False,
            "candidate_count": 0,
        }

    summary = scope_data.get("summary") if isinstance(scope_data.get("summary"), dict) else {}
    scope_breach = bool(summary.get("scope_breach", False)) or bool(scope_data.get("scope_breach", False))
    return {
        "present": True,
        "status": safe_text(scope_data.get("status")),
        "path": str(scope_path),
        "scope_allowed_draft_only_count": parse_count(summary.get("scope_allowed_draft_only_count")),
        "scope_allowed_validation_only_count": parse_count(summary.get("scope_allowed_validation_only_count")),
        "scope_not_allowed_missing_guards_count": parse_count(summary.get("scope_not_allowed_missing_guards_count")),
        "scope_blocked_high_risk_count": parse_count(summary.get("scope_blocked_high_risk_count")),
        "scope_monitor_only_count": parse_count(summary.get("scope_monitor_only_count")),
        "scope_breach": scope_breach,
        "scope_breach_reasons": (
            summary.get("scope_breach_reasons")
            if isinstance(summary.get("scope_breach_reasons"), list)
            else []
        ),
        "candidate_count": parse_count(summary.get("candidate_count")),
        "read_only": bool(scope_data.get("read_only", False)),
        "network_access": bool(scope_data.get("network_access", False)),
        "api_access": bool(scope_data.get("api_access", False)),
        "wordpress_login": bool(scope_data.get("wordpress_login", False)),
        "apply_function": bool(scope_data.get("apply_function", False)),
        "productive_change": bool(scope_data.get("productive_change", False)),
    }


def summarize_safe_apply_dry_run_planner(
    dry_run_data: Optional[Dict[str, Any]],
    dry_run_path: Path,
    dry_run_error: Optional[str],
    dry_run_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Apply Dry-Run Planner (Phase 3.3).

    The dry-run plan applies nothing. It can only escalate the master action
    status if it reports a dry-run breach (HIGH/MEDIUM in a ready plan,
    can_execute_now, a network/API/login requirement, a prohibited write path,
    or apply_status not equal to not_applied).
    """
    if not dry_run_exists or dry_run_error or not isinstance(dry_run_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(dry_run_path),
            "recommendation": "run sentinel_safe_apply_dry_run_planner.py",
            "dry_run_ready_draft_only_count": 0,
            "dry_run_ready_validation_only_count": 0,
            "dry_run_not_ready_missing_guards_count": 0,
            "dry_run_blocked_high_risk_count": 0,
            "dry_run_monitor_only_count": 0,
            "dry_run_breach": False,
            "candidate_count": 0,
        }

    summary = dry_run_data.get("summary") if isinstance(dry_run_data.get("summary"), dict) else {}
    dry_run_breach = bool(summary.get("dry_run_breach", False)) or bool(dry_run_data.get("dry_run_breach", False))
    return {
        "present": True,
        "status": safe_text(dry_run_data.get("status")),
        "path": str(dry_run_path),
        "dry_run_ready_draft_only_count": parse_count(summary.get("dry_run_ready_draft_only_count")),
        "dry_run_ready_validation_only_count": parse_count(summary.get("dry_run_ready_validation_only_count")),
        "dry_run_not_ready_missing_guards_count": parse_count(summary.get("dry_run_not_ready_missing_guards_count")),
        "dry_run_blocked_high_risk_count": parse_count(summary.get("dry_run_blocked_high_risk_count")),
        "dry_run_monitor_only_count": parse_count(summary.get("dry_run_monitor_only_count")),
        "dry_run_breach": dry_run_breach,
        "dry_run_breach_reasons": (
            summary.get("dry_run_breach_reasons")
            if isinstance(summary.get("dry_run_breach_reasons"), list)
            else []
        ),
        "candidate_count": parse_count(summary.get("candidate_count")),
        "read_only": bool(dry_run_data.get("read_only", False)),
        "network_access": bool(dry_run_data.get("network_access", False)),
        "api_access": bool(dry_run_data.get("api_access", False)),
        "wordpress_login": bool(dry_run_data.get("wordpress_login", False)),
        "apply_function": bool(dry_run_data.get("apply_function", False)),
        "productive_change": bool(dry_run_data.get("productive_change", False)),
    }


def summarize_safe_apply_preflight_validator(
    preflight_data: Optional[Dict[str, Any]],
    preflight_path: Path,
    preflight_error: Optional[str],
    preflight_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Apply Preflight Validator (Phase 3.4).

    The preflight validator applies nothing. It can only escalate the master
    action status if it reports a preflight breach (can_execute_now, apply_status
    not equal to not_applied, HIGH/MEDIUM ready, a live apply function, a
    network/API/login requirement, or a prohibited write path).
    """
    if not preflight_exists or preflight_error or not isinstance(preflight_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(preflight_path),
            "recommendation": "run sentinel_safe_apply_preflight_validator.py",
            "preflight_ready_draft_only_count": 0,
            "preflight_ready_validation_only_count": 0,
            "preflight_not_ready_count": 0,
            "preflight_blocked_count": 0,
            "preflight_monitor_only_count": 0,
            "preflight_breach": False,
            "global_missing_requirements": [],
            "candidate_count": 0,
        }

    summary = preflight_data.get("summary") if isinstance(preflight_data.get("summary"), dict) else {}
    preflight_breach = bool(summary.get("preflight_breach", False)) or bool(preflight_data.get("preflight_breach", False))
    global_missing = summary.get("global_missing_requirements")
    if not isinstance(global_missing, list):
        global_missing = preflight_data.get("global_missing_requirements")
    return {
        "present": True,
        "status": safe_text(preflight_data.get("status")),
        "path": str(preflight_path),
        "preflight_ready_draft_only_count": parse_count(summary.get("preflight_ready_draft_only_count")),
        "preflight_ready_validation_only_count": parse_count(summary.get("preflight_ready_validation_only_count")),
        "preflight_not_ready_count": parse_count(summary.get("preflight_not_ready_count")),
        "preflight_blocked_count": parse_count(summary.get("preflight_blocked_count")),
        "preflight_monitor_only_count": parse_count(summary.get("preflight_monitor_only_count")),
        "preflight_breach": preflight_breach,
        "preflight_breach_reasons": (
            summary.get("preflight_breach_reasons")
            if isinstance(summary.get("preflight_breach_reasons"), list)
            else []
        ),
        "global_missing_requirements": global_missing if isinstance(global_missing, list) else [],
        "candidate_count": parse_count(summary.get("candidate_count")),
        "read_only": bool(preflight_data.get("read_only", False)),
        "network_access": bool(preflight_data.get("network_access", False)),
        "api_access": bool(preflight_data.get("api_access", False)),
        "wordpress_login": bool(preflight_data.get("wordpress_login", False)),
        "apply_function": bool(preflight_data.get("apply_function", False)),
        "productive_change": bool(preflight_data.get("productive_change", False)),
    }


def summarize_autonomy_runtime_lock(
    lock_data: Optional[Dict[str, Any]],
    lock_path: Path,
    lock_error: Optional[str],
    lock_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Owner Autonomy Runtime Lock (Phase 3.5).

    The runtime lock applies nothing. It can only escalate the master action
    status if it reports a runtime_lock_breach (live_apply_enabled, missing
    owner disable switch, a blocked mode in allowed_modes, an unsafe emergency
    stop state, or apply_status not equal to not_applied).
    """
    if not lock_exists or lock_error or not isinstance(lock_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(lock_path),
            "recommendation": "run sentinel_autonomy_runtime_lock.py status",
            "autonomy_enabled": False,
            "draft_only_enabled": False,
            "validation_only_enabled": False,
            "live_apply_enabled": False,
            "owner_disable_switch": True,
            "emergency_stop": True,
            "max_autonomy_level": "LEVEL_1_DRAFT_ONLY",
            "runtime_lock_breach": False,
        }

    return {
        "present": True,
        "status": safe_text(lock_data.get("status")),
        "path": str(lock_path),
        "autonomy_enabled": bool(lock_data.get("autonomy_enabled", False)),
        "draft_only_enabled": bool(lock_data.get("draft_only_enabled", False)),
        "validation_only_enabled": bool(lock_data.get("validation_only_enabled", False)),
        "live_apply_enabled": bool(lock_data.get("live_apply_enabled", False)),
        "owner_disable_switch": bool(lock_data.get("owner_disable_switch", False)),
        "emergency_stop": bool(lock_data.get("emergency_stop", False)),
        "max_autonomy_level": safe_text(lock_data.get("max_autonomy_level")),
        "allowed_modes": lock_data.get("allowed_modes") if isinstance(lock_data.get("allowed_modes"), list) else [],
        "blocked_modes": lock_data.get("blocked_modes") if isinstance(lock_data.get("blocked_modes"), list) else [],
        "last_owner_lock_action": lock_data.get("last_owner_lock_action") if isinstance(lock_data.get("last_owner_lock_action"), dict) else {},
        "runtime_lock_breach": bool(lock_data.get("runtime_lock_breach", False)),
        "runtime_lock_breach_reasons": (
            lock_data.get("runtime_lock_breach_reasons")
            if isinstance(lock_data.get("runtime_lock_breach_reasons"), list)
            else []
        ),
        "read_only": bool(lock_data.get("read_only", False)),
        "network_access": bool(lock_data.get("network_access", False)),
        "api_access": bool(lock_data.get("api_access", False)),
        "wordpress_login": bool(lock_data.get("wordpress_login", False)),
        "apply_function": bool(lock_data.get("apply_function", False)),
        "productive_change": bool(lock_data.get("productive_change", False)),
    }


def summarize_safe_draft_autonomy_runner(
    runner_data: Optional[Dict[str, Any]],
    runner_path: Path,
    runner_error: Optional[str],
    runner_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Draft-Only Autonomous Runner (Phase 3.6).

    The runner only refreshes draft/report/validation files and applies nothing
    live. It can only escalate the master action status if it reports a
    runner_breach (live_apply, productive_change, apply_status != not_applied,
    HIGH/MEDIUM executed, a prohibited action, a write outside allowed paths, a
    network/API/login requirement, or execution under emergency_stop).
    """
    if not runner_exists or runner_error or not isinstance(runner_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(runner_path),
            "recommendation": "run sentinel_safe_draft_autonomy_runner.py",
            "runner_status": "NOT_AVAILABLE",
            "executed_draft_only_count": 0,
            "executed_validation_only_count": 0,
            "skipped_count": 0,
            "blocked_by_runtime_lock_count": 0,
            "blocked_by_emergency_stop_count": 0,
            "runner_breach": False,
        }

    summary = runner_data.get("summary") if isinstance(runner_data.get("summary"), dict) else {}
    runner_breach = bool(summary.get("runner_breach", False)) or bool(runner_data.get("runner_breach", False))
    return {
        "present": True,
        "status": safe_text(runner_data.get("status")),
        "path": str(runner_path),
        "runner_status": safe_text(runner_data.get("runner_status")),
        "executed_draft_only_count": parse_count(summary.get("executed_draft_only_count")),
        "executed_validation_only_count": parse_count(summary.get("executed_validation_only_count")),
        "skipped_count": parse_count(summary.get("skipped_count")),
        "blocked_by_runtime_lock_count": parse_count(summary.get("blocked_by_runtime_lock_count")),
        "blocked_by_emergency_stop_count": parse_count(summary.get("blocked_by_emergency_stop_count")),
        "runner_breach": runner_breach,
        "runner_breach_reasons": (
            summary.get("runner_breach_reasons")
            if isinstance(summary.get("runner_breach_reasons"), list)
            else []
        ),
        "candidate_count": parse_count(summary.get("candidate_count")),
        "live_apply": bool(runner_data.get("live_apply", False)),
        "live_apply_function": bool(runner_data.get("live_apply_function", False)),
        "network_access": bool(runner_data.get("network_access", False)),
        "api_access": bool(runner_data.get("api_access", False)),
        "wordpress_login": bool(runner_data.get("wordpress_login", False)),
        "productive_change": bool(runner_data.get("productive_change", False)),
        "apply_status": safe_text(runner_data.get("apply_status")),
    }


def summarize_safe_draft_autonomy_verifier(
    verifier_data: Optional[Dict[str, Any]],
    verifier_path: Path,
    verifier_error: Optional[str],
    verifier_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Draft Autonomy Output Verifier (Phase 3.7).

    The verifier is read-only and applies nothing. It can only escalate the
    master action status if it reports a verifier_breach (output outside allowed
    paths, secret pattern, invalid JSON, live_apply, productive_change,
    apply_status != not_applied, a forbidden path, or a network/API/login
    requirement on a runner output).
    """
    if not verifier_exists or verifier_error or not isinstance(verifier_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(verifier_path),
            "recommendation": "run sentinel_safe_draft_autonomy_verifier.py",
            "verifier_status": "NOT_AVAILABLE",
            "verified_safe_outputs_count": 0,
            "missing_outputs_count": 0,
            "invalid_json_count": 0,
            "forbidden_path_count": 0,
            "secret_pattern_count": 0,
            "verifier_breach": False,
        }

    summary = verifier_data.get("summary") if isinstance(verifier_data.get("summary"), dict) else {}
    verifier_breach = bool(summary.get("verifier_breach", False)) or bool(verifier_data.get("verifier_breach", False))
    return {
        "present": True,
        "status": safe_text(verifier_data.get("status")),
        "path": str(verifier_path),
        "verifier_status": safe_text(verifier_data.get("verifier_status")),
        "verified_safe_outputs_count": parse_count(summary.get("verified_safe_outputs_count")),
        "missing_outputs_count": parse_count(summary.get("missing_outputs_count")),
        "invalid_json_count": parse_count(summary.get("invalid_json_count")),
        "forbidden_path_count": parse_count(summary.get("forbidden_path_count")),
        "secret_pattern_count": parse_count(summary.get("secret_pattern_count")),
        "live_apply_count": parse_count(summary.get("live_apply_count")),
        "productive_change_count": parse_count(summary.get("productive_change_count")),
        "apply_status_changed_count": parse_count(summary.get("apply_status_changed_count")),
        "verifier_breach": verifier_breach,
        "verifier_breach_reasons": (
            summary.get("verifier_breach_reasons")
            if isinstance(summary.get("verifier_breach_reasons"), list)
            else []
        ),
        "last_runner_status": safe_text(summary.get("last_runner_status")),
        "last_runner_executed_count": parse_count(summary.get("last_runner_executed_count")),
        "live_apply": bool(verifier_data.get("live_apply", False)),
        "live_apply_function": bool(verifier_data.get("live_apply_function", False)),
        "network_access": bool(verifier_data.get("network_access", False)),
        "api_access": bool(verifier_data.get("api_access", False)),
        "wordpress_login": bool(verifier_data.get("wordpress_login", False)),
        "productive_change": bool(verifier_data.get("productive_change", False)),
        "apply_status": safe_text(verifier_data.get("apply_status")),
    }


def summarize_safe_draft_autonomy_scheduler_plan(
    plan_data: Optional[Dict[str, Any]],
    plan_path: Path,
    plan_error: Optional[str],
    plan_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Draft Autonomy Scheduler Plan (Phase 3.8).

    The scheduler plan is review-only: it installs no timer and applies nothing.
    It can only escalate the master action status if it reports a
    scheduler_breach (can_install_timer_now, timer_installation_status changed,
    a prohibited/live-apply/network command, can_execute_live, apply_status !=
    not_applied, or a systemd/crontab write path).
    """
    if not plan_exists or plan_error or not isinstance(plan_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(plan_path),
            "recommendation": "run sentinel_safe_draft_autonomy_scheduler_plan.py",
            "scheduler_status": "NOT_AVAILABLE",
            "planned_frequency": "-",
            "timer_installation_status": "not_installed",
            "can_install_timer_now": False,
            "owner_review_required": False,
            "scheduler_breach": False,
        }

    summary = plan_data.get("summary") if isinstance(plan_data.get("summary"), dict) else {}
    scheduler_breach = bool(summary.get("scheduler_breach", False)) or bool(plan_data.get("scheduler_breach", False))
    return {
        "present": True,
        "status": safe_text(plan_data.get("status")),
        "path": str(plan_path),
        "scheduler_status": safe_text(plan_data.get("scheduler_status")),
        "planned_frequency": safe_text(plan_data.get("planned_frequency")),
        "planned_sequence_count": parse_count(summary.get("planned_sequence_count")),
        "timer_installation_status": safe_text(plan_data.get("timer_installation_status")),
        "can_install_timer_now": bool(plan_data.get("can_install_timer_now", False)),
        "can_execute_live": bool(plan_data.get("can_execute_live", False)),
        "owner_review_required": bool(plan_data.get("owner_review_required", False)),
        "scheduler_breach": scheduler_breach,
        "scheduler_breach_reasons": (
            summary.get("scheduler_breach_reasons")
            if isinstance(summary.get("scheduler_breach_reasons"), list)
            else []
        ),
        "blocked_reason": safe_text(plan_data.get("blocked_reason")),
        "timer_installed": bool(plan_data.get("timer_installed", False)),
        "systemd_file_written": bool(plan_data.get("systemd_file_written", False)),
        "crontab_file_written": bool(plan_data.get("crontab_file_written", False)),
        "network_access": bool(plan_data.get("network_access", False)),
        "productive_change": bool(plan_data.get("productive_change", False)),
        "apply_status": safe_text(plan_data.get("apply_status")),
    }


def summarize_safe_draft_autonomy_timer_draft(
    timer_data: Optional[Dict[str, Any]],
    timer_path: Path,
    timer_error: Optional[str],
    timer_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Draft Autonomy Timer Draft Pack (Phase 3.9).

    The timer-draft module only writes review-only systemd/timer DRAFTS under
    drafts/apply; it installs no timer and applies nothing. It can only escalate
    the master action status if it reports a timer_draft_breach (a real
    systemd/cron write path, an installed timer, can_install_timer_now,
    can_execute_live, live_apply, apply_status != not_applied, a prohibited /
    network / live-apply command in an executable position, or a secret-like
    Environment value).
    """
    if not timer_exists or timer_error or not isinstance(timer_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(timer_path),
            "recommendation": "run sentinel_safe_draft_autonomy_timer_draft.py",
            "timer_draft_status": "NOT_AVAILABLE",
            "timer_installation_status": "not_installed",
            "service_draft_written": False,
            "timer_draft_written": False,
            "owner_review_required": False,
            "timer_draft_breach": False,
        }

    summary = timer_data.get("summary") if isinstance(timer_data.get("summary"), dict) else {}
    timer_draft_breach = bool(summary.get("timer_draft_breach", False)) or bool(timer_data.get("timer_draft_breach", False))
    return {
        "present": True,
        "status": safe_text(timer_data.get("status")),
        "path": str(timer_path),
        "timer_draft_status": safe_text(timer_data.get("timer_draft_status")),
        "timer_installation_status": safe_text(timer_data.get("timer_installation_status")),
        "service_draft_written": bool(timer_data.get("service_draft_written", False)),
        "timer_draft_written": bool(timer_data.get("timer_draft_written", False)),
        "install_review_written": bool(timer_data.get("install_review_written", False)),
        "rollback_review_written": bool(timer_data.get("rollback_review_written", False)),
        "can_install_timer_now": bool(timer_data.get("can_install_timer_now", False)),
        "can_execute_live": bool(timer_data.get("can_execute_live", False)),
        "owner_review_required": bool(timer_data.get("owner_review_required", False)),
        "timer_draft_breach": timer_draft_breach,
        "timer_draft_breach_reasons": (
            summary.get("timer_draft_breach_reasons")
            if isinstance(summary.get("timer_draft_breach_reasons"), list)
            else []
        ),
        "blocked_reason": safe_text(timer_data.get("blocked_reason")),
        "systemd_file_written": bool(timer_data.get("systemd_file_written", False)),
        "crontab_file_written": bool(timer_data.get("crontab_file_written", False)),
        "live_apply": bool(timer_data.get("live_apply", False)),
        "network_access": bool(timer_data.get("network_access", False)),
        "apply_status": safe_text(timer_data.get("apply_status")),
    }


def summarize_safe_draft_autonomy_timer_install_review(
    review_data: Optional[Dict[str, Any]],
    review_path: Path,
    review_error: Optional[str],
    review_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Draft Autonomy Timer Install Reviewer (Phase 4.0).

    The reviewer only assesses install-readiness of the Phase 3.9 drafts and
    writes review-only outputs; it installs nothing. It can only escalate the
    master action status if it reports an install_reviewer_breach (a real
    systemd/cron write, an installed timer, can_install_timer_now,
    can_execute_live, live_apply, apply_status != not_applied, an active
    forbidden/network/systemctl/live-apply line in a draft, or a secret-like
    Environment value). Emergency-stop only blocks; it is not a breach.
    """
    if not review_exists or review_error or not isinstance(review_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(review_path),
            "recommendation": "run sentinel_safe_draft_autonomy_timer_install_reviewer.py",
            "install_review_status": "NOT_AVAILABLE",
            "timer_installation_status": "not_installed",
            "can_install_timer_now": False,
            "owner_review_required": False,
            "install_reviewer_breach": False,
        }

    summary = review_data.get("summary") if isinstance(review_data.get("summary"), dict) else {}
    install_reviewer_breach = bool(summary.get("install_reviewer_breach", False)) or bool(review_data.get("install_reviewer_breach", False))
    return {
        "present": True,
        "status": safe_text(review_data.get("status")),
        "path": str(review_path),
        "install_review_status": safe_text(review_data.get("install_review_status")),
        "timer_installation_status": safe_text(review_data.get("timer_installation_status")),
        "can_install_timer_now": bool(review_data.get("can_install_timer_now", False)),
        "can_execute_live": bool(review_data.get("can_execute_live", False)),
        "service_draft_safe": bool(review_data.get("service_draft_safe", False)),
        "timer_draft_safe": bool(review_data.get("timer_draft_safe", False)),
        "install_review_safe": bool(review_data.get("install_review_safe", False)),
        "rollback_review_safe": bool(review_data.get("rollback_review_safe", False)),
        "owner_review_required": bool(review_data.get("owner_review_required", False)),
        "install_reviewer_breach": install_reviewer_breach,
        "install_reviewer_breach_reasons": (
            summary.get("install_reviewer_breach_reasons")
            if isinstance(summary.get("install_reviewer_breach_reasons"), list)
            else []
        ),
        "blocked_reason": safe_text(review_data.get("blocked_reason")),
        "safe_checks_passed_count": parse_count(review_data.get("safe_checks_passed_count")),
        "safe_checks_failed_count": parse_count(review_data.get("safe_checks_failed_count")),
        "systemd_file_written": bool(review_data.get("systemd_file_written", False)),
        "crontab_file_written": bool(review_data.get("crontab_file_written", False)),
        "live_apply": bool(review_data.get("live_apply", False)),
        "apply_status": safe_text(review_data.get("apply_status")),
    }


def summarize_owner_manual_timer_install_packet(
    packet_data: Optional[Dict[str, Any]],
    packet_path: Path,
    packet_error: Optional[str],
    packet_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Owner Manual Timer Install Packet (Phase 4.1).

    The packet is documentation/checklists only. It may only affect the master
    action status when it reports a packet_breach such as install_allowed_now,
    can_install_timer_now, installed timer state, live apply, executable output,
    forbidden path, or secret-like output.
    """
    if not packet_exists or packet_error or not isinstance(packet_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(packet_path),
            "recommendation": "run sentinel_owner_manual_timer_install_packet.py",
            "packet_status": "NOT_AVAILABLE",
            "owner_review_required": True,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "timer_installation_status": "not_installed",
            "emergency_stop_active": False,
            "packet_breach": False,
        }

    summary = packet_data.get("summary") if isinstance(packet_data.get("summary"), dict) else {}
    packet_breach = bool(summary.get("packet_breach", False)) or bool(packet_data.get("packet_breach", False))
    return {
        "present": True,
        "status": safe_text(packet_data.get("status")),
        "path": str(packet_path),
        "packet_status": safe_text(packet_data.get("packet_status")),
        "owner_review_required": bool(packet_data.get("owner_review_required", True)),
        "install_allowed_now": bool(packet_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(packet_data.get("can_install_timer_now", False)),
        "timer_installation_status": safe_text(packet_data.get("timer_installation_status")),
        "timer_installation_status_summary": safe_text(summary.get("timer_installation_status")),
        "emergency_stop_active": bool(packet_data.get("emergency_stop_active", False)),
        "install_review_status": safe_text(packet_data.get("install_review_status")),
        "safe_checks_passed_count": parse_count(packet_data.get("safe_checks_passed_count")),
        "safe_checks_failed_count": parse_count(packet_data.get("safe_checks_failed_count")),
        "packet_breach": packet_breach,
        "packet_breach_reasons": (
            summary.get("packet_breach_reasons")
            if isinstance(summary.get("packet_breach_reasons"), list)
            else []
        ),
        "blocked_reason": safe_text(packet_data.get("blocked_reason")),
        "live_apply": bool(packet_data.get("live_apply", False)),
        "live_apply_function": bool(packet_data.get("live_apply_function", False)),
        "can_execute_live": bool(packet_data.get("can_execute_live", False)),
        "systemd_file_written": bool(packet_data.get("systemd_file_written", False)),
        "crontab_file_written": bool(packet_data.get("crontab_file_written", False)),
        "shell_script_generated": bool(packet_data.get("shell_script_generated", False)),
        "executable_install_file_generated": bool(packet_data.get("executable_install_file_generated", False)),
        "secrets_output": bool(packet_data.get("secrets_output", False)),
        "apply_status": safe_text(packet_data.get("apply_status")),
    }


def summarize_owner_timer_install_decision_gate(
    decision_data: Optional[Dict[str, Any]],
    decision_path: Path,
    decision_error: Optional[str],
    decision_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Owner Timer Install Decision Gate (Phase 4.2).

    The gate records owner intent only. It does not install a timer and may
    escalate only when it reports decision_breach.
    """
    if not decision_exists or decision_error or not isinstance(decision_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(decision_path),
            "recommendation": "run sentinel_owner_timer_install_decision_gate.py status",
            "decision_status": "not_reviewed",
            "manual_install_allowed": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "decision_breach": False,
        }

    summary = decision_data.get("summary") if isinstance(decision_data.get("summary"), dict) else {}
    decision_breach = bool(summary.get("decision_breach", False)) or bool(decision_data.get("decision_breach", False))
    return {
        "present": True,
        "status": safe_text(decision_data.get("status")),
        "path": str(decision_path),
        "gate_status": safe_text(decision_data.get("gate_status")),
        "decision_status": safe_text(decision_data.get("decision_status")),
        "manual_install_allowed": bool(decision_data.get("manual_install_allowed", False)),
        "install_allowed_now": bool(decision_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(decision_data.get("can_install_timer_now", False)),
        "emergency_stop_active": bool(decision_data.get("emergency_stop_active", False)),
        "owner_acknowledged_no_live_apply": bool(decision_data.get("owner_acknowledged_no_live_apply", False)),
        "owner_acknowledged_manual_only": bool(decision_data.get("owner_acknowledged_manual_only", False)),
        "owner_acknowledged_rollback": bool(decision_data.get("owner_acknowledged_rollback", False)),
        "owner_acknowledged_emergency_stop": bool(decision_data.get("owner_acknowledged_emergency_stop", False)),
        "decision_breach": decision_breach,
        "decision_breach_reasons": (
            summary.get("decision_breach_reasons")
            if isinstance(summary.get("decision_breach_reasons"), list)
            else []
        ),
        "last_owner_decision_action": (
            decision_data.get("last_owner_decision_action")
            if isinstance(decision_data.get("last_owner_decision_action"), dict)
            else {}
        ),
        "blocked_reason": safe_text(decision_data.get("blocked_reason")),
        "live_apply": bool(decision_data.get("live_apply", False)),
        "can_execute_live": bool(decision_data.get("can_execute_live", False)),
        "systemd_file_written": bool(decision_data.get("systemd_file_written", False)),
        "crontab_file_written": bool(decision_data.get("crontab_file_written", False)),
        "apply_status": safe_text(decision_data.get("apply_status")),
    }


def summarize_manual_timer_install_command_preview(
    preview_data: Optional[Dict[str, Any]],
    preview_path: Path,
    preview_error: Optional[str],
    preview_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Manual Timer Install Command Preview (Phase 4.3).

    The preview writes Markdown/JSON documentation only. It can only escalate
    when preview_breach is true.
    """
    if not preview_exists or preview_error or not isinstance(preview_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(preview_path),
            "recommendation": "run sentinel_manual_timer_install_command_preview.py",
            "preview_status": "NOT_AVAILABLE",
            "manual_install_allowed": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "command_preview_written": False,
            "preview_breach": False,
        }

    summary = preview_data.get("summary") if isinstance(preview_data.get("summary"), dict) else {}
    preview_breach = bool(summary.get("preview_breach", False)) or bool(preview_data.get("preview_breach", False))
    return {
        "present": True,
        "status": safe_text(preview_data.get("status")),
        "path": str(preview_path),
        "preview_status": safe_text(preview_data.get("preview_status")),
        "decision_status": safe_text(preview_data.get("decision_status")),
        "manual_install_allowed": bool(preview_data.get("manual_install_allowed", False)),
        "install_allowed_now": bool(preview_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(preview_data.get("can_install_timer_now", False)),
        "emergency_stop_active": bool(preview_data.get("emergency_stop_active", False)),
        "command_preview_written": bool(preview_data.get("command_preview_written", False)),
        "shell_script_generated": bool(preview_data.get("shell_script_generated", False)),
        "systemd_file_written": bool(preview_data.get("systemd_file_written", False)),
        "crontab_file_written": bool(preview_data.get("crontab_file_written", False)),
        "live_apply": bool(preview_data.get("live_apply", False)),
        "can_execute_live": bool(preview_data.get("can_execute_live", False)),
        "apply_status": safe_text(preview_data.get("apply_status")),
        "preview_breach": preview_breach,
        "preview_breach_reasons": (
            summary.get("preview_breach_reasons")
            if isinstance(summary.get("preview_breach_reasons"), list)
            else []
        ),
        "blocked_reason": safe_text(preview_data.get("blocked_reason")),
    }


def summarize_owner_timer_install_evidence_pack(
    evidence_data: Optional[Dict[str, Any]],
    evidence_path: Path,
    evidence_error: Optional[str],
    evidence_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Owner Timer Install Evidence Pack (Phase 4.4).

    The evidence pack writes only templates/documentation. It can only escalate
    when evidence_pack_breach is true.
    """
    if not evidence_exists or evidence_error or not isinstance(evidence_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(evidence_path),
            "recommendation": "run sentinel_owner_timer_install_evidence_pack.py",
            "evidence_pack_status": "NOT_AVAILABLE",
            "manual_install_allowed": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "evidence_template_written": False,
            "evidence_pack_breach": False,
        }

    summary = evidence_data.get("summary") if isinstance(evidence_data.get("summary"), dict) else {}
    evidence_breach = bool(summary.get("evidence_pack_breach", False)) or bool(evidence_data.get("evidence_pack_breach", False))
    return {
        "present": True,
        "status": safe_text(evidence_data.get("status")),
        "path": str(evidence_path),
        "evidence_pack_status": safe_text(evidence_data.get("evidence_pack_status")),
        "decision_status": safe_text(evidence_data.get("decision_status")),
        "preview_status": safe_text(evidence_data.get("preview_status")),
        "manual_install_allowed": bool(evidence_data.get("manual_install_allowed", False)),
        "install_allowed_now": bool(evidence_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(evidence_data.get("can_install_timer_now", False)),
        "emergency_stop_active": bool(evidence_data.get("emergency_stop_active", False)),
        "evidence_template_written": bool(evidence_data.get("evidence_template_written", False)),
        "shell_script_generated": bool(evidence_data.get("shell_script_generated", False)),
        "systemd_file_written": bool(evidence_data.get("systemd_file_written", False)),
        "crontab_file_written": bool(evidence_data.get("crontab_file_written", False)),
        "live_apply": bool(evidence_data.get("live_apply", False)),
        "can_execute_live": bool(evidence_data.get("can_execute_live", False)),
        "apply_status": safe_text(evidence_data.get("apply_status")),
        "evidence_pack_breach": evidence_breach,
        "evidence_pack_breach_reasons": (
            summary.get("evidence_pack_breach_reasons")
            if isinstance(summary.get("evidence_pack_breach_reasons"), list)
            else []
        ),
        "blocked_reason": safe_text(evidence_data.get("blocked_reason")),
    }


def summarize_safe_draft_autonomy_final_safety(
    final_data: Optional[Dict[str, Any]],
    final_path: Path,
    final_error: Optional[str],
    final_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe Draft Autonomy Final Safety Report (Phase 4.5)."""
    if not final_exists or final_error or not isinstance(final_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(final_path),
            "recommendation": "run sentinel_safe_draft_autonomy_final_safety_report.py",
            "final_safety_status": "NOT_AVAILABLE",
            "draft_only_autonomy_ready": False,
            "timer_installation_allowed_now": False,
            "live_apply_allowed": False,
            "emergency_stop_active": False,
            "total_breach_count": 0,
            "final_safety_breach": False,
        }

    summary = final_data.get("summary") if isinstance(final_data.get("summary"), dict) else {}
    final_breach = bool(summary.get("final_safety_breach", False)) or bool(final_data.get("final_safety_breach", False))
    return {
        "present": True,
        "status": safe_text(final_data.get("status")),
        "path": str(final_path),
        "final_safety_status": safe_text(final_data.get("final_safety_status")),
        "draft_only_autonomy_ready": bool(final_data.get("draft_only_autonomy_ready", False)),
        "draft_only_runner_verified": bool(final_data.get("draft_only_runner_verified", False)),
        "timer_installation_ready_for_owner_review": bool(final_data.get("timer_installation_ready_for_owner_review", False)),
        "timer_installation_allowed_now": bool(final_data.get("timer_installation_allowed_now", False)),
        "live_apply_allowed": bool(final_data.get("live_apply_allowed", False)),
        "can_execute_live": bool(final_data.get("can_execute_live", False)),
        "can_install_timer_now": bool(final_data.get("can_install_timer_now", False)),
        "emergency_stop_active": bool(final_data.get("emergency_stop_active", False)),
        "total_breach_count": parse_count(final_data.get("total_breach_count")),
        "total_phase_count": parse_count(final_data.get("total_phase_count")),
        "safe_phase_count": parse_count(final_data.get("safe_phase_count")),
        "blocked_phase_count": parse_count(final_data.get("blocked_phase_count")),
        "final_safety_breach": final_breach,
        "final_safety_breach_reasons": (
            summary.get("final_safety_breach_reasons")
            if isinstance(summary.get("final_safety_breach_reasons"), list)
            else []
        ),
        "final_recommended_owner_action": safe_text(final_data.get("final_recommended_owner_action")),
        "live_apply": bool(final_data.get("live_apply", False)),
        "network_access": bool(final_data.get("network_access", False)),
        "api_access": bool(final_data.get("api_access", False)),
        "wordpress_login": bool(final_data.get("wordpress_login", False)),
        "systemd_file_written": bool(final_data.get("systemd_file_written", False)),
        "crontab_file_written": bool(final_data.get("crontab_file_written", False)),
        "shell_script_generated": bool(final_data.get("shell_script_generated", False)),
        "apply_status": safe_text(final_data.get("apply_status")),
    }


def summarize_manual_evidence_review_dashboard(
    dashboard_data: Optional[Dict[str, Any]],
    dashboard_path: Path,
    dashboard_error: Optional[str],
    dashboard_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Manual Evidence Review Dashboard (Phase 4.6)."""
    if not dashboard_exists or dashboard_error or not isinstance(dashboard_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(dashboard_path),
            "recommendation": "run sentinel_manual_evidence_review_dashboard.py",
            "dashboard_status": "NOT_AVAILABLE",
            "emergency_stop_active": False,
            "total_breaches": 0,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "dashboard_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(dashboard_data.get("status")),
        "path": str(dashboard_path),
        "dashboard_status": safe_text(dashboard_data.get("dashboard_status")),
        "dashboard_breach": bool(dashboard_data.get("dashboard_breach", False)),
        "emergency_stop_active": bool(dashboard_data.get("emergency_stop_active", False)),
        "total_breaches": parse_count(dashboard_data.get("total_breaches")),
        "safe_chain_count": parse_count(dashboard_data.get("safe_chain_count")),
        "blocked_chain_count": parse_count(dashboard_data.get("blocked_chain_count")),
        "evidence_docs_available_count": parse_count(dashboard_data.get("evidence_docs_available_count")),
        "evidence_docs_missing_count": parse_count(dashboard_data.get("evidence_docs_missing_count")),
        "timer_installation_status": safe_text(dashboard_data.get("timer_installation_status")),
        "timer_installation_allowed_now": bool(dashboard_data.get("timer_installation_allowed_now", False)),
        "install_allowed_now": bool(dashboard_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(dashboard_data.get("can_install_timer_now", False)),
        "live_apply": bool(dashboard_data.get("live_apply", False)),
        "live_apply_allowed": bool(dashboard_data.get("live_apply_allowed", False)),
        "can_execute_live": bool(dashboard_data.get("can_execute_live", False)),
        "systemd_file_written": bool(dashboard_data.get("systemd_file_written", False)),
        "crontab_file_written": bool(dashboard_data.get("crontab_file_written", False)),
        "apply_status": safe_text(dashboard_data.get("apply_status")),
        "final_recommended_owner_action": safe_text(dashboard_data.get("final_recommended_owner_action")),
        "next_safe_step": safe_text(dashboard_data.get("next_safe_step")),
        "open_owner_evidence_items_count": parse_count(dashboard_data.get("open_owner_evidence_items_count")),
        "blocked_items_count": parse_count(dashboard_data.get("blocked_items_count")),
    }


def summarize_manual_evidence_review_completion_tracker(
    tracker_data: Optional[Dict[str, Any]],
    tracker_path: Path,
    tracker_error: Optional[str],
    tracker_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Manual Evidence Review Completion Tracker (Phase 4.7)."""
    if not tracker_exists or tracker_error or not isinstance(tracker_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(tracker_path),
            "recommendation": "run sentinel_manual_evidence_review_completion_tracker.py list",
            "tracker_status": "NOT_AVAILABLE",
            "reviewed_count": 0,
            "unchecked_count": 0,
            "needs_work_count": 0,
            "blocked_count": 0,
            "skipped_count": 0,
            "completion_percent": 0,
            "tracker_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(tracker_data.get("tracker_status")),
        "path": str(tracker_path),
        "tracker_status": safe_text(tracker_data.get("tracker_status")),
        "total_items": parse_count(tracker_data.get("total_items")),
        "reviewed_count": parse_count(tracker_data.get("reviewed_count")),
        "unchecked_count": parse_count(tracker_data.get("unchecked_count")),
        "needs_work_count": parse_count(tracker_data.get("needs_work_count")),
        "blocked_count": parse_count(tracker_data.get("blocked_count")),
        "skipped_count": parse_count(tracker_data.get("skipped_count")),
        "completion_percent": tracker_data.get("completion_percent", 0),
        "all_required_reviewed": bool(tracker_data.get("all_required_reviewed", False)),
        "emergency_stop_active": bool(tracker_data.get("emergency_stop_active", False)),
        "install_allowed_now": bool(tracker_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(tracker_data.get("can_install_timer_now", False)),
        "live_apply": bool(tracker_data.get("live_apply", False)),
        "can_execute_live": bool(tracker_data.get("can_execute_live", False)),
        "tracker_breach": bool(tracker_data.get("tracker_breach", False)),
        "next_owner_action": safe_text(tracker_data.get("next_owner_action")),
    }


def summarize_manual_evidence_review_completion_gate(
    gate_data: Optional[Dict[str, Any]],
    gate_path: Path,
    gate_error: Optional[str],
    gate_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Manual Evidence Review Completion Gate (Phase 4.8)."""
    if not gate_exists or gate_error or not isinstance(gate_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(gate_path),
            "recommendation": "run sentinel_manual_evidence_review_completion_gate.py",
            "gate_status": "NOT_AVAILABLE",
            "reviewed_count": 0,
            "total_items": 0,
            "completion_percent": 0,
            "all_required_reviewed": False,
            "gate_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(gate_data.get("gate_status")),
        "path": str(gate_path),
        "gate_status": safe_text(gate_data.get("gate_status")),
        "total_items": parse_count(gate_data.get("total_items")),
        "reviewed_count": parse_count(gate_data.get("reviewed_count")),
        "unchecked_count": parse_count(gate_data.get("unchecked_count")),
        "needs_work_count": parse_count(gate_data.get("needs_work_count")),
        "blocked_count": parse_count(gate_data.get("blocked_count")),
        "skipped_count": parse_count(gate_data.get("skipped_count")),
        "completion_percent": gate_data.get("completion_percent", 0),
        "all_required_reviewed": bool(gate_data.get("all_required_reviewed", False)),
        "emergency_stop_active": bool(gate_data.get("emergency_stop_active", False)),
        "install_allowed_now": bool(gate_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(gate_data.get("can_install_timer_now", False)),
        "can_execute_live": bool(gate_data.get("can_execute_live", False)),
        "live_apply": bool(gate_data.get("live_apply", False)),
        "apply_status": safe_text(gate_data.get("apply_status")),
        "gate_breach": bool(gate_data.get("gate_breach", False)),
        "next_owner_action": safe_text(gate_data.get("next_owner_action")),
        "reason": safe_text(gate_data.get("reason")),
    }


def summarize_owner_evidence_review_console(
    console_data: Optional[Dict[str, Any]],
    console_path: Path,
    console_error: Optional[str],
    console_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Owner Evidence Review Console (Phase 4.9)."""
    if not console_exists or console_error or not isinstance(console_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(console_path),
            "recommendation": "run sentinel_owner_evidence_review_console.py",
            "console_status": "NOT_AVAILABLE",
            "reviewed_count": 0,
            "total_items": 0,
            "open_items_count": 0,
            "next_recommended_item": "",
            "console_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(console_data.get("console_status")),
        "path": str(console_path),
        "console_status": safe_text(console_data.get("console_status")),
        "total_items": parse_count(console_data.get("total_items")),
        "reviewed_count": parse_count(console_data.get("reviewed_count")),
        "unchecked_count": parse_count(console_data.get("unchecked_count")),
        "needs_work_count": parse_count(console_data.get("needs_work_count")),
        "blocked_count": parse_count(console_data.get("blocked_count")),
        "skipped_count": parse_count(console_data.get("skipped_count")),
        "open_items_count": parse_count(console_data.get("open_items_count")),
        "emergency_stop_active": bool(console_data.get("emergency_stop_active", False)),
        "install_allowed_now": bool(console_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(console_data.get("can_install_timer_now", False)),
        "can_execute_live": bool(console_data.get("can_execute_live", False)),
        "live_apply": bool(console_data.get("live_apply", False)),
        "apply_status": safe_text(console_data.get("apply_status")),
        "console_breach": bool(console_data.get("console_breach", False)),
        "next_recommended_item": safe_text(console_data.get("next_recommended_item")),
        "next_owner_action": safe_text(console_data.get("next_owner_action")),
    }


def summarize_final_owner_decision_snapshot(
    snapshot_data: Optional[Dict[str, Any]],
    snapshot_path: Path,
    snapshot_error: Optional[str],
    snapshot_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Final Owner Decision Snapshot (Phase 5.0)."""
    if not snapshot_exists or snapshot_error or not isinstance(snapshot_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(snapshot_path),
            "recommendation": "run sentinel_final_owner_decision_snapshot.py",
            "snapshot_status": "NOT_AVAILABLE",
            "review_completed": False,
            "reviewed_count": 0,
            "total_items": 0,
            "emergency_stop_active": False,
            "install_allowed_now": False,
            "snapshot_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(snapshot_data.get("snapshot_status")),
        "path": str(snapshot_path),
        "snapshot_status": safe_text(snapshot_data.get("snapshot_status")),
        "review_completed": bool(snapshot_data.get("review_completed", False)),
        "reviewed_count": parse_count(snapshot_data.get("reviewed_count")),
        "total_items": parse_count(snapshot_data.get("total_items")),
        "completion_percent": snapshot_data.get("completion_percent", 0),
        "emergency_stop_active": bool(snapshot_data.get("emergency_stop_active", False)),
        "install_allowed_now": bool(snapshot_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(snapshot_data.get("can_install_timer_now", False)),
        "can_execute_live": bool(snapshot_data.get("can_execute_live", False)),
        "live_apply": bool(snapshot_data.get("live_apply", False)),
        "apply_status": safe_text(snapshot_data.get("apply_status")),
        "timer_installation_status": safe_text(snapshot_data.get("timer_installation_status")),
        "total_breaches": parse_count(snapshot_data.get("total_breaches")),
        "owner_decision_required_for_any_install": bool(snapshot_data.get("owner_decision_required_for_any_install", True)),
        "snapshot_breach": bool(snapshot_data.get("snapshot_breach", False)),
        "recommended_owner_action": safe_text(snapshot_data.get("recommended_owner_action")),
    }


def summarize_master_critical_cause_snapshot(
    snapshot_data: Optional[Dict[str, Any]],
    snapshot_path: Path,
    snapshot_error: Optional[str],
    snapshot_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Master Critical Cause Snapshot (Phase 5.1)."""
    if not snapshot_exists or snapshot_error or not isinstance(snapshot_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(snapshot_path),
            "recommendation": "run sentinel_master_critical_cause_snapshot.py",
            "critical_snapshot_status": "NOT_AVAILABLE",
            "critical_caused_by_autonomy": False,
            "critical_caused_by_website": False,
            "autonomy_total_breaches": 0,
            "snapshot_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(snapshot_data.get("critical_snapshot_status")),
        "path": str(snapshot_path),
        "critical_snapshot_status": safe_text(snapshot_data.get("critical_snapshot_status")),
        "master_status": safe_text(snapshot_data.get("master_status")),
        "action_status": safe_text(snapshot_data.get("action_status")),
        "critical_caused_by_autonomy": bool(snapshot_data.get("critical_caused_by_autonomy", False)),
        "critical_caused_by_website": bool(snapshot_data.get("critical_caused_by_website", False)),
        "critical_caused_by_rolling_window": bool(snapshot_data.get("critical_caused_by_rolling_window", False)),
        "critical_caused_by_sourcemap": bool(snapshot_data.get("critical_caused_by_sourcemap", False)),
        "autonomy_total_breaches": parse_count(snapshot_data.get("autonomy_total_breaches")),
        "final_owner_snapshot_breach": bool(snapshot_data.get("final_owner_snapshot_breach", False)),
        "emergency_stop_active": bool(snapshot_data.get("emergency_stop_active", False)),
        "install_allowed_now": bool(snapshot_data.get("install_allowed_now", False)),
        "live_apply": bool(snapshot_data.get("live_apply", False)),
        "recommended_owner_action": safe_text(snapshot_data.get("recommended_owner_action")),
        "snapshot_breach": bool(snapshot_data.get("snapshot_breach", False)),
    }


def summarize_rolling_window_decay_observer(
    observer_data: Optional[Dict[str, Any]],
    observer_path: Path,
    observer_error: Optional[str],
    observer_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Rolling Window Decay Observer (Phase 5.2)."""
    if not observer_exists or observer_error or not isinstance(observer_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(observer_path),
            "recommendation": "run sentinel_rolling_window_decay_observer.py",
            "decay_status": "NOT_AVAILABLE",
            "trend": "unknown",
            "delta_5xx": None,
            "delta_504": None,
            "observation_required": True,
            "snapshot_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(observer_data.get("decay_status")),
        "path": str(observer_path),
        "decay_status": safe_text(observer_data.get("decay_status")),
        "trend": safe_text(observer_data.get("trend")),
        "master_status": safe_text(observer_data.get("master_status")),
        "website_critical": bool(observer_data.get("website_critical", False)),
        "autonomy_cause": bool(observer_data.get("autonomy_cause", False)),
        "website_cause": bool(observer_data.get("website_cause", False)),
        "rolling_window_cause": bool(observer_data.get("rolling_window_cause", False)),
        "sourcemap_warning": bool(observer_data.get("sourcemap_warning", False)),
        "current_5xx_total": parse_count(observer_data.get("current_5xx_total")),
        "previous_5xx_total": observer_data.get("previous_5xx_total"),
        "delta_5xx": observer_data.get("delta_5xx"),
        "current_504_total": observer_data.get("current_504_total"),
        "previous_504_total": observer_data.get("previous_504_total"),
        "delta_504": observer_data.get("delta_504"),
        "current_sourcemap_404_total": parse_count(observer_data.get("current_sourcemap_404_total")),
        "previous_sourcemap_404_total": observer_data.get("previous_sourcemap_404_total"),
        "delta_sourcemap_404": observer_data.get("delta_sourcemap_404"),
        "history_points": parse_count(observer_data.get("history_points")),
        "observation_required": bool(observer_data.get("observation_required", True)),
        "recommended_owner_action": safe_text(observer_data.get("recommended_owner_action")),
        "snapshot_breach": bool(observer_data.get("snapshot_breach", False)),
    }


def summarize_low_growth_readiness_timeline(
    timeline_data: Optional[Dict[str, Any]],
    timeline_path: Path,
    timeline_error: Optional[str],
    timeline_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Low-Growth Readiness Timeline (Phase 5.3)."""
    if not timeline_exists or timeline_error or not isinstance(timeline_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(timeline_path),
            "recommendation": "run sentinel_low_growth_readiness_timeline.py",
            "timeline_status": "NOT_AVAILABLE",
            "last_trend": "unknown",
            "consecutive_stable_or_decreasing_points": 0,
            "manual_recheck_recommended": False,
            "snapshot_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(timeline_data.get("timeline_status")),
        "path": str(timeline_path),
        "timeline_status": safe_text(timeline_data.get("timeline_status")),
        "total_points": parse_count(timeline_data.get("total_points")),
        "increasing_points": parse_count(timeline_data.get("increasing_points")),
        "stable_points": parse_count(timeline_data.get("stable_points")),
        "decreasing_points": parse_count(timeline_data.get("decreasing_points")),
        "last_trend": safe_text(timeline_data.get("last_trend")),
        "consecutive_stable_or_decreasing_points": parse_count(timeline_data.get("consecutive_stable_or_decreasing_points")),
        "latest_5xx_total": timeline_data.get("latest_5xx_total"),
        "latest_504_total": timeline_data.get("latest_504_total"),
        "latest_delta_5xx": timeline_data.get("latest_delta_5xx"),
        "latest_delta_504": timeline_data.get("latest_delta_504"),
        "readiness_level": safe_text(timeline_data.get("readiness_level")),
        "manual_recheck_recommended": bool(timeline_data.get("manual_recheck_recommended", False)),
        "observation_required": bool(timeline_data.get("observation_required", True)),
        "recommended_owner_action": safe_text(timeline_data.get("recommended_owner_action")),
        "snapshot_breach": bool(timeline_data.get("snapshot_breach", False)),
    }


def summarize_manual_website_recheck_gate(
    gate_data: Optional[Dict[str, Any]],
    gate_path: Path,
    gate_error: Optional[str],
    gate_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Manual Website Recheck Gate (Phase 5.4)."""
    if not gate_exists or gate_error or not isinstance(gate_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(gate_path),
            "recommendation": "run sentinel_manual_website_recheck_gate.py",
            "gate_status": "NOT_AVAILABLE",
            "manual_recheck_recommended": False,
            "last_trend": "unknown",
            "consecutive_stable_or_decreasing_points": 0,
            "gate_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(gate_data.get("gate_status")),
        "path": str(gate_path),
        "gate_status": safe_text(gate_data.get("gate_status")),
        "manual_recheck_recommended": bool(gate_data.get("manual_recheck_recommended", False)),
        "timeline_status": safe_text(gate_data.get("timeline_status")),
        "decay_status": safe_text(gate_data.get("decay_status")),
        "last_trend": safe_text(gate_data.get("last_trend")),
        "consecutive_stable_or_decreasing_points": parse_count(gate_data.get("consecutive_stable_or_decreasing_points")),
        "total_points": parse_count(gate_data.get("total_points")),
        "latest_5xx_total": gate_data.get("latest_5xx_total"),
        "latest_504_total": gate_data.get("latest_504_total"),
        "latest_delta_5xx": gate_data.get("latest_delta_5xx"),
        "latest_delta_504": gate_data.get("latest_delta_504"),
        "master_status": safe_text(gate_data.get("master_status")),
        "critical_caused_by_website": bool(gate_data.get("critical_caused_by_website", False)),
        "critical_caused_by_autonomy": bool(gate_data.get("critical_caused_by_autonomy", False)),
        "emergency_stop_active": bool(gate_data.get("emergency_stop_active", False)),
        "recommended_owner_action": safe_text(gate_data.get("recommended_owner_action")),
        "gate_breach": bool(gate_data.get("gate_breach", False)),
    }


def summarize_low_risk_autonomy_readiness_gate(
    gate_data: Optional[Dict[str, Any]],
    gate_path: Path,
    gate_error: Optional[str],
    gate_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Low-Risk Autonomy Readiness Gate (Phase 5.5)."""
    if not gate_exists or gate_error or not isinstance(gate_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(gate_path),
            "recommendation": "run sentinel_low_risk_autonomy_readiness_gate.py",
            "readiness_status": "NOT_AVAILABLE",
            "low_risk_autonomy_allowed_now": False,
            "low_risk_policy_draft_allowed": False,
            "owner_policy_review_required": True,
            "readiness_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(gate_data.get("readiness_status")),
        "path": str(gate_path),
        "readiness_status": safe_text(gate_data.get("readiness_status")),
        "low_risk_autonomy_allowed_now": bool(gate_data.get("low_risk_autonomy_allowed_now", False)),
        "low_risk_policy_draft_allowed": bool(gate_data.get("low_risk_policy_draft_allowed", False)),
        "owner_policy_review_required": bool(gate_data.get("owner_policy_review_required", True)),
        "manual_recheck_recommended": bool(gate_data.get("manual_recheck_recommended", False)),
        "manual_recheck_gate_status": safe_text(gate_data.get("manual_recheck_gate_status")),
        "timeline_status": safe_text(gate_data.get("timeline_status")),
        "decay_status": safe_text(gate_data.get("decay_status")),
        "consecutive_stable_or_decreasing_points": parse_count(gate_data.get("consecutive_stable_or_decreasing_points")),
        "emergency_stop_active": bool(gate_data.get("emergency_stop_active", False)),
        "autonomy_total_breaches": parse_count(gate_data.get("autonomy_total_breaches")),
        "final_owner_snapshot_breach": bool(gate_data.get("final_owner_snapshot_breach", False)),
        "recommended_owner_action": safe_text(gate_data.get("recommended_owner_action")),
        "readiness_breach": bool(gate_data.get("readiness_breach", False)),
    }


def summarize_low_risk_policy_boundary_draft(
    policy_data: Optional[Dict[str, Any]],
    policy_path: Path,
    policy_error: Optional[str],
    policy_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional LOW-RISK Policy Boundary Draft (Phase 5.6)."""
    if not policy_exists or policy_error or not isinstance(policy_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(policy_path),
            "recommendation": "run sentinel_low_risk_policy_boundary_draft.py",
            "policy_status": "NOT_AVAILABLE",
            "owner_policy_review_required": True,
            "policy_activation_allowed": False,
            "low_risk_draft_only_count": 0,
            "high_never_auto_apply_count": 0,
            "policy_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(policy_data.get("policy_status")),
        "path": str(policy_path),
        "policy_status": safe_text(policy_data.get("policy_status")),
        "emergency_stop_active": bool(policy_data.get("emergency_stop_active", False)),
        "owner_policy_review_required": bool(policy_data.get("owner_policy_review_required", True)),
        "policy_activation_allowed": bool(policy_data.get("policy_activation_allowed", False)),
        "low_risk_autonomy_allowed_now": bool(policy_data.get("low_risk_autonomy_allowed_now", False)),
        "low_risk_draft_only_count": parse_count(policy_data.get("low_risk_draft_only_count")),
        "low_risk_review_only_count": parse_count(policy_data.get("low_risk_review_only_count")),
        "low_risk_potential_future_apply_count": parse_count(policy_data.get("low_risk_potential_future_apply_count")),
        "medium_owner_approval_required_count": parse_count(policy_data.get("medium_owner_approval_required_count")),
        "high_never_auto_apply_count": parse_count(policy_data.get("high_never_auto_apply_count")),
        "forbidden_count": parse_count(policy_data.get("forbidden_count")),
        "recommended_owner_action": safe_text(policy_data.get("recommended_owner_action")),
        "policy_breach": bool(policy_data.get("policy_breach", False)),
    }


def summarize_low_risk_policy_owner_review_tracker(
    tracker_data: Optional[Dict[str, Any]],
    tracker_path: Path,
    tracker_error: Optional[str],
    tracker_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional LOW-RISK Policy Owner Review Tracker (Phase 5.7)."""
    if not tracker_exists or tracker_error or not isinstance(tracker_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(tracker_path),
            "recommendation": "run sentinel_low_risk_policy_owner_review_tracker.py",
            "tracker_status": "NOT_AVAILABLE",
            "reviewed_count": 0,
            "total_required": 8,
            "unchecked_count": 8,
            "needs_work_count": 0,
            "completion_percent": 0,
            "all_required_reviewed": False,
            "emergency_stop_active": None,
            "low_risk_autonomy_allowed_now": False,
            "policy_activation_allowed": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "live_apply": False,
            "apply_status": "not_applied",
            "tracker_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(tracker_data.get("tracker_status")),
        "path": str(tracker_path),
        "tracker_status": safe_text(tracker_data.get("tracker_status")),
        "reviewed_count": parse_count(tracker_data.get("reviewed_count")),
        "total_required": parse_count(tracker_data.get("total_required")),
        "total_items": parse_count(tracker_data.get("total_items")),
        "unchecked_count": parse_count(tracker_data.get("unchecked_count")),
        "needs_work_count": parse_count(tracker_data.get("needs_work_count")),
        "completion_percent": tracker_data.get("completion_percent"),
        "all_required_reviewed": bool(tracker_data.get("all_required_reviewed", False)),
        "emergency_stop_active": bool(tracker_data.get("emergency_stop_active", False)),
        "low_risk_autonomy_allowed_now": bool(tracker_data.get("low_risk_autonomy_allowed_now", False)),
        "policy_activation_allowed": bool(tracker_data.get("policy_activation_allowed", False)),
        "install_allowed_now": bool(tracker_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(tracker_data.get("can_install_timer_now", False)),
        "live_apply": bool(tracker_data.get("live_apply", False)),
        "apply_status": safe_text(tracker_data.get("apply_status")),
        "recommended_owner_action": safe_text(tracker_data.get("recommended_owner_action") or tracker_data.get("next_owner_action")),
        "tracker_breach": bool(tracker_data.get("tracker_breach", False)),
    }


def summarize_low_risk_policy_review_completion_gate(
    gate_data: Optional[Dict[str, Any]],
    gate_path: Path,
    gate_error: Optional[str],
    gate_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional LOW-RISK Policy Review Completion Gate (Phase 5.8)."""
    if not gate_exists or gate_error or not isinstance(gate_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(gate_path),
            "recommendation": "run sentinel_low_risk_policy_review_completion_gate.py",
            "gate_status": "NOT_AVAILABLE",
            "reviewed_count": 0,
            "total_required": 8,
            "completion_percent": 0,
            "all_required_reviewed": False,
            "emergency_stop_active": None,
            "low_risk_autonomy_allowed_now": False,
            "policy_activation_allowed": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "live_apply": False,
            "apply_status": "not_applied",
            "gate_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(gate_data.get("gate_status")),
        "path": str(gate_path),
        "gate_status": safe_text(gate_data.get("gate_status")),
        "tracker_status": safe_text(gate_data.get("tracker_status")),
        "reviewed_count": parse_count(gate_data.get("reviewed_count")),
        "total_required": parse_count(gate_data.get("total_required")),
        "completion_percent": gate_data.get("completion_percent"),
        "all_required_reviewed": bool(gate_data.get("all_required_reviewed", False)),
        "emergency_stop_active": bool(gate_data.get("emergency_stop_active", False)),
        "low_risk_autonomy_allowed_now": bool(gate_data.get("low_risk_autonomy_allowed_now", False)),
        "policy_activation_allowed": bool(gate_data.get("policy_activation_allowed", False)),
        "owner_policy_review_required": bool(gate_data.get("owner_policy_review_required", True)),
        "install_allowed_now": bool(gate_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(gate_data.get("can_install_timer_now", False)),
        "live_apply": bool(gate_data.get("live_apply", False)),
        "apply_status": safe_text(gate_data.get("apply_status")),
        "recommended_owner_action": safe_text(gate_data.get("recommended_owner_action")),
        "gate_breach": bool(gate_data.get("gate_breach", False)),
    }


def summarize_low_risk_autonomy_final_safety_seal(
    seal_data: Optional[Dict[str, Any]],
    seal_path: Path,
    seal_error: Optional[str],
    seal_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional LOW-RISK Autonomy Final Safety Seal (Phase 5.9)."""
    if not seal_exists or seal_error or not isinstance(seal_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(seal_path),
            "recommendation": "run sentinel_low_risk_autonomy_final_safety_seal.py",
            "seal_status": "NOT_AVAILABLE",
            "review_completed": False,
            "reviewed_count": 0,
            "total_required": 8,
            "emergency_stop_active": None,
            "low_risk_autonomy_allowed_now": False,
            "policy_activation_allowed": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "live_apply": False,
            "apply_status": "not_applied",
            "total_breaches": 0,
            "seal_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(seal_data.get("seal_status")),
        "path": str(seal_path),
        "seal_status": safe_text(seal_data.get("seal_status")),
        "review_completed": bool(seal_data.get("review_completed", False)),
        "reviewed_count": parse_count(seal_data.get("reviewed_count")),
        "total_required": parse_count(seal_data.get("total_required")),
        "emergency_stop_active": bool(seal_data.get("emergency_stop_active", False)),
        "low_risk_autonomy_allowed_now": bool(seal_data.get("low_risk_autonomy_allowed_now", False)),
        "policy_activation_allowed": bool(seal_data.get("policy_activation_allowed", False)),
        "install_allowed_now": bool(seal_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(seal_data.get("can_install_timer_now", False)),
        "live_apply": bool(seal_data.get("live_apply", False)),
        "apply_status": safe_text(seal_data.get("apply_status")),
        "total_breaches": parse_count(seal_data.get("total_breaches")),
        "recommended_owner_action": safe_text(seal_data.get("recommended_owner_action")),
        "seal_breach": bool(seal_data.get("seal_breach", False)),
    }


def summarize_safe_end_summary(
    safe_end_data: Optional[Dict[str, Any]],
    safe_end_path: Path,
    safe_end_error: Optional[str],
    safe_end_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe End Summary (Phase 5.10)."""
    if not safe_end_exists or safe_end_error or not isinstance(safe_end_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(safe_end_path),
            "recommendation": "run sentinel_safe_end_summary.py",
            "safe_end_status": "NOT_AVAILABLE",
            "evidence_review_complete": False,
            "final_owner_snapshot_complete": False,
            "website_recheck_recommended": False,
            "low_risk_policy_review_complete": False,
            "low_risk_final_seal_complete": False,
            "emergency_stop_active": None,
            "low_risk_autonomy_allowed_now": False,
            "policy_activation_allowed": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "live_apply": False,
            "apply_status": "not_applied",
            "total_breaches": 0,
            "safe_end_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(safe_end_data.get("safe_end_status")),
        "path": str(safe_end_path),
        "safe_end_status": safe_text(safe_end_data.get("safe_end_status")),
        "evidence_review_complete": bool(safe_end_data.get("evidence_review_complete", False)),
        "final_owner_snapshot_complete": bool(safe_end_data.get("final_owner_snapshot_complete", False)),
        "website_recheck_recommended": bool(safe_end_data.get("website_recheck_recommended", False)),
        "low_risk_policy_review_complete": bool(safe_end_data.get("low_risk_policy_review_complete", False)),
        "low_risk_final_seal_complete": bool(safe_end_data.get("low_risk_final_seal_complete", False)),
        "emergency_stop_active": bool(safe_end_data.get("emergency_stop_active", False)),
        "low_risk_autonomy_allowed_now": bool(safe_end_data.get("low_risk_autonomy_allowed_now", False)),
        "policy_activation_allowed": bool(safe_end_data.get("policy_activation_allowed", False)),
        "install_allowed_now": bool(safe_end_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(safe_end_data.get("can_install_timer_now", False)),
        "live_apply": bool(safe_end_data.get("live_apply", False)),
        "apply_status": safe_text(safe_end_data.get("apply_status")),
        "total_breaches": parse_count(safe_end_data.get("total_breaches")),
        "recommended_owner_action": safe_text(safe_end_data.get("recommended_owner_action")),
        "safe_end_breach": bool(safe_end_data.get("safe_end_breach", False)),
    }


def summarize_safe_end_archive_snapshot(
    archive_data: Optional[Dict[str, Any]],
    archive_path: Path,
    archive_error: Optional[str],
    archive_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe-End Archive Snapshot (Phase 5.11)."""
    if not archive_exists or archive_error or not isinstance(archive_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(archive_path),
            "recommendation": "run sentinel_safe_end_archive_snapshot.py",
            "archive_status": "NOT_AVAILABLE",
            "archive_path": "",
            "copied_file_count": 0,
            "checksum_count": 0,
            "safe_end_status": "NOT_AVAILABLE",
            "emergency_stop_active": None,
            "low_risk_autonomy_allowed_now": False,
            "policy_activation_allowed": False,
            "install_allowed_now": False,
            "can_install_timer_now": False,
            "live_apply": False,
            "apply_status": "not_applied",
            "total_breaches": 0,
            "archive_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(archive_data.get("archive_status")),
        "path": str(archive_path),
        "archive_status": safe_text(archive_data.get("archive_status")),
        "archive_path": safe_text(archive_data.get("archive_path"), default=""),
        "manifest_path": safe_text(archive_data.get("manifest_path"), default=""),
        "copied_file_count": parse_count(archive_data.get("copied_file_count")),
        "checksum_count": parse_count(archive_data.get("checksum_count")),
        "safe_end_status": safe_text(archive_data.get("safe_end_status")),
        "emergency_stop_active": bool(archive_data.get("emergency_stop_active", False)),
        "low_risk_autonomy_allowed_now": bool(archive_data.get("low_risk_autonomy_allowed_now", False)),
        "policy_activation_allowed": bool(archive_data.get("policy_activation_allowed", False)),
        "install_allowed_now": bool(archive_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(archive_data.get("can_install_timer_now", False)),
        "live_apply": bool(archive_data.get("live_apply", False)),
        "apply_status": safe_text(archive_data.get("apply_status")),
        "total_breaches": parse_count(archive_data.get("total_breaches")),
        "recommended_owner_action": safe_text(archive_data.get("recommended_owner_action")),
        "archive_breach": bool(archive_data.get("archive_breach", False)),
    }


def summarize_safe_end_archive_integrity_verifier(
    integrity_data: Optional[Dict[str, Any]],
    integrity_path: Path,
    integrity_error: Optional[str],
    integrity_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Safe-End Archive Integrity Verifier (Phase 5.12)."""
    if not integrity_exists or integrity_error or not isinstance(integrity_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(integrity_path),
            "recommendation": "run sentinel_safe_end_archive_integrity_verifier.py",
            "integrity_status": "NOT_AVAILABLE",
            "verified_checksum_count": 0,
            "checksum_mismatch_count": 0,
            "forbidden_artifact_count": 0,
            "integrity_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(integrity_data.get("integrity_status")),
        "path": str(integrity_path),
        "integrity_status": safe_text(integrity_data.get("integrity_status")),
        "latest_archive_path": safe_text(integrity_data.get("latest_archive_path"), default=""),
        "manifest_file_count": parse_count(integrity_data.get("manifest_file_count")),
        "checksum_file_count": parse_count(integrity_data.get("checksum_file_count")),
        "verified_checksum_count": parse_count(integrity_data.get("verified_checksum_count")),
        "missing_file_count": parse_count(integrity_data.get("missing_file_count")),
        "checksum_mismatch_count": parse_count(integrity_data.get("checksum_mismatch_count")),
        "forbidden_artifact_count": parse_count(integrity_data.get("forbidden_artifact_count")),
        "restore_executed": bool(integrity_data.get("restore_executed", False)),
        "safe_end_status": safe_text(integrity_data.get("safe_end_status")),
        "archive_status": safe_text(integrity_data.get("archive_status")),
        "emergency_stop_active": bool(integrity_data.get("emergency_stop_active", False)),
        "low_risk_autonomy_allowed_now": bool(integrity_data.get("low_risk_autonomy_allowed_now", False)),
        "policy_activation_allowed": bool(integrity_data.get("policy_activation_allowed", False)),
        "install_allowed_now": bool(integrity_data.get("install_allowed_now", False)),
        "can_install_timer_now": bool(integrity_data.get("can_install_timer_now", False)),
        "live_apply": bool(integrity_data.get("live_apply", False)),
        "apply_status": safe_text(integrity_data.get("apply_status")),
        "recommended_owner_action": safe_text(integrity_data.get("recommended_owner_action")),
        "integrity_breach": bool(integrity_data.get("integrity_breach", False)),
    }


def summarize_safe_sftp_seo_apply_lane(
    lane_data: Optional[Dict[str, Any]],
    lane_path: Path,
    lane_error: Optional[str],
    lane_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Phase 6.1 Safe SFTP SEO Apply Lane.

    Informational only. A successful apply must NOT make the Master OK; only a
    real apply_breach can escalate the review status.
    """
    if not lane_exists or lane_error or not isinstance(lane_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(lane_path),
            "recommendation": "run sentinel_safe_sftp_seo_apply_lane.py dry-run",
            "apply_lane_status": "NOT_AVAILABLE",
            "mode": "none",
            "uploaded": False,
            "healthcheck_status": "not_run",
            "rollback_status": "not_run",
            "changed_file_count": 0,
            "apply_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(lane_data.get("apply_lane_status")),
        "path": str(lane_path),
        "apply_lane_status": safe_text(lane_data.get("apply_lane_status")),
        "mode": safe_text(lane_data.get("mode")),
        "target_file": safe_text(lane_data.get("target_file")),
        "uploaded": bool(lane_data.get("uploaded", False)),
        "healthcheck_status": safe_text(lane_data.get("healthcheck_status")),
        "rollback_status": safe_text(lane_data.get("rollback_status")),
        "changed_file_count": parse_count(lane_data.get("changed_file_count")),
        "allowed_target_only": bool(lane_data.get("allowed_target_only", True)),
        "live_apply": bool(lane_data.get("live_apply", False)),
        "apply_status": safe_text(lane_data.get("apply_status")),
        "recommended_owner_action": safe_text(lane_data.get("recommended_owner_action")),
        "apply_breach": bool(lane_data.get("apply_breach", False)),
    }


def summarize_concrete_seo_performance_optimizer(
    optimizer_data: Optional[Dict[str, Any]],
    optimizer_path: Path,
    optimizer_error: Optional[str],
    optimizer_exists: bool,
) -> Dict[str, Any]:
    """Summarize the optional Phase 6.0 concrete SEO/performance pack.

    This summary is informational. It must not make the Master OK; only a real
    optimizer_breach can escalate the review status.
    """
    if not optimizer_exists or optimizer_error or not isinstance(optimizer_data, dict):
        return {
            "present": False,
            "status": "NOT_AVAILABLE",
            "path": str(optimizer_path),
            "recommendation": "run sentinel_concrete_seo_performance_optimizer.py",
            "optimizer_status": "NOT_AVAILABLE",
            "total_recommendations": 0,
            "copy_paste_owner_apply_count": 0,
            "diagnostic_only_count": 0,
            "optimizer_breach": False,
        }
    return {
        "present": True,
        "status": safe_text(optimizer_data.get("optimizer_status")),
        "path": str(optimizer_path),
        "optimizer_status": safe_text(optimizer_data.get("optimizer_status")),
        "seo_pack_created": bool(optimizer_data.get("seo_pack_created", False)),
        "performance_pack_created": bool(optimizer_data.get("performance_pack_created", False)),
        "wordpress_copy_paste_pack_created": bool(optimizer_data.get("wordpress_copy_paste_pack_created", False)),
        "jsonld_pack_created": bool(optimizer_data.get("jsonld_pack_created", False)),
        "internal_linking_pack_created": bool(optimizer_data.get("internal_linking_pack_created", False)),
        "image_pack_created": bool(optimizer_data.get("image_pack_created", False)),
        "origin_5xx_pack_created": bool(optimizer_data.get("origin_5xx_pack_created", False)),
        "total_recommendations": parse_count(optimizer_data.get("total_recommendations")),
        "draft_only_count": parse_count(optimizer_data.get("draft_only_count")),
        "copy_paste_owner_apply_count": parse_count(optimizer_data.get("copy_paste_owner_apply_count")),
        "owner_review_required_count": parse_count(optimizer_data.get("owner_review_required_count")),
        "diagnostic_only_count": parse_count(optimizer_data.get("diagnostic_only_count")),
        "do_not_apply_automatically_count": parse_count(optimizer_data.get("do_not_apply_automatically_count")),
        "live_apply": bool(optimizer_data.get("live_apply", False)),
        "install_allowed_now": bool(optimizer_data.get("install_allowed_now", False)),
        "policy_activation_allowed": bool(optimizer_data.get("policy_activation_allowed", False)),
        "low_risk_autonomy_allowed_now": bool(optimizer_data.get("low_risk_autonomy_allowed_now", False)),
        "apply_status": safe_text(optimizer_data.get("apply_status")),
        "optimizer_breach": bool(optimizer_data.get("optimizer_breach", False)),
    }


def status_counts(items: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {STATUS_OK: 0, STATUS_WARNING: 0, STATUS_CRITICAL: 0, STATUS_UNKNOWN: 0}
    for item in items:
        counts[normalize_status(item.get("status"))] += 1
    return counts


def safe_item(item: Dict[str, Any], preferred_label: str = "label") -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key in (
        preferred_label,
        "name",
        "metric",
        "key",
        "signal",
        "category",
        "title",
        "detail",
        "status",
        "value",
        "recommendation",
    ):
        if key not in item or SECRET_KEY_RE.search(key):
            continue
        value = item.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = redact_text(value)
    return result


def non_ok_items(items: Iterable[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    for item in items:
        if normalize_status(item.get("status")) in {STATUS_WARNING, STATUS_CRITICAL, STATUS_UNKNOWN}:
            selected.append(safe_item(item))
        if len(selected) >= limit:
            break
    return selected


def v2_status_rank(status: Any) -> int:
    return {
        STATUS_CRITICAL: 0,
        STATUS_WARNING: 1,
        STATUS_WATCH: 2,
        STATUS_OK: 3,
        STATUS_UNKNOWN: 4,
    }.get(normalize_signal_status(status), 5)


def safe_list(value: Any, limit: int = 5) -> List[str]:
    if not isinstance(value, list):
        return []
    result: List[str] = []
    for item in value:
        if isinstance(item, (str, int, float, bool)) or item is None:
            result.append(redact_text(item, max_len=160))
        if len(result) >= limit:
            break
    return result


def parse_count(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except ValueError:
            return 0
    return 0


def safe_v2_finding(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "signal_id": redact_text(item.get("signal_id", "-"), max_len=120),
        "status": normalize_signal_status(item.get("status")),
        "count": parse_count(item.get("count")),
        "paths": safe_list(item.get("paths")),
        "user_agents": safe_list(item.get("user_agents"), limit=4),
        "countries": safe_list(item.get("countries"), limit=5),
        "explanation": redact_text(item.get("explanation", "-"), max_len=420),
        "recommendation": redact_text(item.get("recommendation", "-"), max_len=420),
    }


def sorted_v2_findings(items: Iterable[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    safe_items = [safe_v2_finding(item) for item in items if isinstance(item, dict)]
    safe_items.sort(key=lambda item: (v2_status_rank(item.get("status")), -parse_count(item.get("count")), item.get("signal_id", "")))
    return safe_items[:limit]


def safe_count_items(value: Any, key: str, limit: int = 5) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: List[Dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                key: redact_text(item.get(key, "-"), max_len=160),
                "count": parse_count(item.get("count")),
            }
        )
        if len(items) >= limit:
            break
    return items


def safe_origin_path(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "path": redact_text(item.get("path", "-"), max_len=220),
        "count": parse_count(item.get("count")),
        "statuses": safe_count_items(item.get("statuses"), "status"),
        "countries": safe_count_items(item.get("countries"), "country"),
        "cache_status": safe_count_items(item.get("cache_status"), "cache_status"),
        "user_agent_groups": safe_count_items(item.get("user_agent_groups"), "group"),
        "classification": redact_text(item.get("classification", "-"), max_len=120),
        "classification_reason": redact_text(item.get("classification_reason", "-"), max_len=360),
        "request_shape": redact_text(item.get("request_shape", "-"), max_len=120),
        "request_shape_reason": redact_text(item.get("request_shape_reason", "-"), max_len=360),
        "actor_signal": redact_text(item.get("actor_signal", "-"), max_len=120),
        "actor_signal_reason": redact_text(item.get("actor_signal_reason", "-"), max_len=360),
        "failure_mode": redact_text(item.get("failure_mode", "-"), max_len=120),
        "failure_mode_reason": redact_text(item.get("failure_mode_reason", "-"), max_len=360),
        "combined_rule_scope": redact_text(item.get("combined_rule_scope", "-"), max_len=120),
        "actual_5xx_traffic_covered_by_combined_rule": bool(
            item.get("actual_5xx_traffic_covered_by_combined_rule")
        ),
        "combined_rule_reason": redact_text(item.get("combined_rule_reason", "-"), max_len=360),
    }


def safe_origin_status_gap(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": redact_text(item.get("status", "-"), max_len=40),
        "status_24h_count": parse_count(item.get("status_24h_count")),
        "detailed_count": parse_count(item.get("detailed_count")),
        "unclassified_count": parse_count(item.get("unclassified_count")),
        "detail_coverage_percent": item.get("detail_coverage_percent"),
        "status_only_classification": redact_text(item.get("status_only_classification", "-"), max_len=120),
        "status_only_reason": redact_text(item.get("status_only_reason", "-"), max_len=360),
    }


def summarize_origin_pressure(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    paths = value.get("top_5xx_paths") if isinstance(value.get("top_5xx_paths"), list) else []
    status_gap = value.get("status_detail_gap") if isinstance(value.get("status_detail_gap"), list) else []
    coverage = (
        value.get("sentinel_combined_rule_coverage")
        if isinstance(value.get("sentinel_combined_rule_coverage"), list)
        else []
    )
    return {
        "status": redact_text(value.get("status", "-"), max_len=80),
        "interpretation": redact_text(value.get("interpretation", "-"), max_len=520),
        "status_policy": redact_text(value.get("status_policy", "-"), max_len=520),
        "status_24h_total_5xx": parse_count(value.get("status_24h_total_5xx")),
        "observed_5xx_detail_count": parse_count(value.get("observed_5xx_detail_count")),
        "detail_coverage_percent": value.get("detail_coverage_percent"),
        "unclassified_5xx_from_status_aggregate": parse_count(
            value.get("unclassified_5xx_from_status_aggregate")
        ),
        "unknown_share_percent": value.get("unknown_share_percent"),
        "detail_completeness_status": redact_text(value.get("detail_completeness_status", "-"), max_len=120),
        "diagnostic_gap": redact_text(value.get("diagnostic_gap", "-"), max_len=520),
        "status_inclusive_classification_scope": redact_text(
            value.get("status_inclusive_classification_scope", "-"), max_len=520
        ),
        "cache_status_interpretation": redact_text(value.get("cache_status_interpretation", "-"), max_len=520),
        "top_5xx_status_codes": safe_count_items(value.get("top_5xx_status_codes"), "status", limit=8),
        "status_detail_gap": [safe_origin_status_gap(item) for item in status_gap[:8] if isinstance(item, dict)],
        "status_only_gap_classification": safe_count_items(
            value.get("status_only_gap_classification"), "classification", limit=8
        ),
        "top_5xx_countries": safe_count_items(value.get("top_5xx_countries"), "country", limit=8),
        "top_5xx_classification": safe_count_items(value.get("top_5xx_classification"), "classification", limit=8),
        "top_5xx_status_inclusive_classification": safe_count_items(
            value.get("top_5xx_status_inclusive_classification"), "classification", limit=8
        ),
        "top_5xx_request_shapes": safe_count_items(value.get("top_5xx_request_shapes"), "request_shape", limit=8),
        "top_5xx_actor_signals": safe_count_items(value.get("top_5xx_actor_signals"), "actor_signal", limit=8),
        "top_5xx_failure_modes": safe_count_items(value.get("top_5xx_failure_modes"), "failure_mode", limit=8),
        "top_5xx_cache_status": safe_count_items(value.get("top_5xx_cache_status"), "cache_status", limit=6),
        "top_5xx_user_agent_groups": safe_count_items(value.get("top_5xx_user_agent_groups"), "group", limit=8),
        "top_5xx_paths": [safe_origin_path(item) for item in paths[:8] if isinstance(item, dict)],
        "sentinel_combined_rule_coverage": [
            {
                "path": redact_text(item.get("path", "-"), max_len=220),
                "count": parse_count(item.get("count")),
                "combined_rule_scope": redact_text(item.get("combined_rule_scope", "-"), max_len=120),
                "actual_5xx_traffic_covered_by_combined_rule": bool(
                    item.get("actual_5xx_traffic_covered_by_combined_rule")
                ),
                "reason": redact_text(item.get("reason", "-"), max_len=360),
            }
            for item in coverage[:8]
            if isinstance(item, dict)
        ],
    }


def safe_source_map_path(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "path": redact_text(item.get("path", "-"), max_len=220),
        "count": parse_count(item.get("count")),
        "countries": safe_count_items(item.get("countries"), "country"),
        "cache_status": safe_count_items(item.get("cache_status"), "cache_status"),
        "user_agent_groups": safe_count_items(item.get("user_agent_groups"), "group"),
        "classification": redact_text(item.get("classification", "-"), max_len=120),
        "classification_reason": redact_text(item.get("classification_reason", "-"), max_len=360),
        "combined_rule_scope": redact_text(item.get("combined_rule_scope", "-"), max_len=120),
    }


def summarize_source_map_404(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    paths = value.get("top_map_404_paths") if isinstance(value.get("top_map_404_paths"), list) else []
    return {
        "status": redact_text(value.get("status", "-"), max_len=80),
        "interpretation": redact_text(value.get("interpretation", "-"), max_len=520),
        "status_policy": redact_text(value.get("status_policy", "-"), max_len=520),
        "map_404_total": parse_count(value.get("map_404_total")),
        "observed_map_404_detail_count": parse_count(value.get("observed_map_404_detail_count")),
        "detail_coverage_percent": value.get("detail_coverage_percent"),
        "unclassified_map_404_from_metric": parse_count(value.get("unclassified_map_404_from_metric")),
        "unknown_share_percent": value.get("unknown_share_percent"),
        "detail_completeness_status": redact_text(value.get("detail_completeness_status", "-"), max_len=120),
        "top_map_404_classification": safe_count_items(value.get("top_map_404_classification"), "classification", limit=8),
        "top_map_404_cache_status": safe_count_items(value.get("top_map_404_cache_status"), "cache_status", limit=6),
        "top_map_404_paths": [safe_source_map_path(item) for item in paths[:8] if isinstance(item, dict)],
    }


def summarize_ok_readiness(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    summary = value.get("summary") if isinstance(value.get("summary"), dict) else {}

    def safe_blockers(items: Any, key_name: str, limit: int = 8) -> List[Dict[str, Any]]:
        if not isinstance(items, list):
            return []
        rows: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    key_name: redact_text(item.get(key_name, item.get("key", "-")), max_len=180),
                    "label": redact_text(item.get("label", "-"), max_len=180),
                    "status": redact_text(item.get("status", "-"), max_len=80),
                    "value": item.get("value"),
                    "count": item.get("count"),
                    "reason": redact_text(item.get("reason", "-"), max_len=360),
                    "status_effect": redact_text(item.get("status_effect", "-"), max_len=120),
                    "remaining_stable_minutes_for_old_window": item.get("remaining_stable_minutes_for_old_window"),
                    "recommendation": redact_text(item.get("recommendation", "-"), max_len=360),
                }
            )
            if len(rows) >= limit:
                break
        return rows

    return {
        "status": redact_text(value.get("status", "-"), max_len=80),
        "policy": redact_text(value.get("policy", "-"), max_len=520),
        "summary": {
            "direct_status_blocker_count": parse_count(summary.get("direct_status_blocker_count")),
            "low_growth_blocker_count": parse_count(summary.get("low_growth_blocker_count")),
            "aggregate_detail_blocker_count": parse_count(summary.get("aggregate_detail_blocker_count")),
            "diagnostic_nonblocking_count": parse_count(summary.get("diagnostic_nonblocking_count")),
        },
        "direct_status_blockers": safe_blockers(value.get("direct_status_blockers"), "key"),
        "low_growth_blockers": safe_blockers(value.get("low_growth_blockers"), "key"),
        "aggregate_detail_blockers": safe_blockers(value.get("aggregate_detail_blockers"), "key"),
        "diagnostic_nonblocking_findings": safe_blockers(value.get("diagnostic_nonblocking_findings"), "signal_id"),
    }


def summarize_website(data: Optional[Dict[str, Any]], path: Path, error: Optional[str], exists: bool) -> Dict[str, Any]:
    if data is None:
        return {
            "present": False,
            "path": str(path),
            "exists": exists,
            "error": safe_text(error),
            "overall_status": STATUS_UNKNOWN,
            "correlation_status": CORRELATION_UNKNOWN,
        }

    metrics = data.get("metrics") if isinstance(data.get("metrics"), list) else []
    recommendations = data.get("recommendations") if isinstance(data.get("recommendations"), list) else []
    findings = data.get("correlation_findings") if isinstance(data.get("correlation_findings"), list) else []
    v2_findings = data.get("correlation_v2_findings") if isinstance(data.get("correlation_v2_findings"), list) else []
    return {
        "present": True,
        "path": str(path),
        "generated_at_utc": safe_text(data.get("generated_at_utc")),
        "mode": safe_text(data.get("mode")),
        "overall_status": normalize_status(data.get("overall_status")),
        "correlation_status": normalize_correlation(data.get("correlation_status")),
        "operational_interpretation": safe_text(data.get("operational_interpretation")),
        "metric_counts": status_counts([item for item in metrics if isinstance(item, dict)]),
        "non_ok_metrics": non_ok_items([item for item in metrics if isinstance(item, dict)]),
        "recommendation_count": len(recommendations),
        "correlation_finding_count": len(findings),
        "correlation_v2_finding_count": len(v2_findings),
        "correlation_v2_findings": sorted_v2_findings([item for item in v2_findings if isinstance(item, dict)]),
        "origin_pressure_breakdown": summarize_origin_pressure(data.get("origin_pressure_breakdown")),
        "source_map_404_breakdown": summarize_source_map_404(data.get("source_map_404_breakdown")),
        "ok_readiness": summarize_ok_readiness(data.get("ok_readiness")),
        "rolling_window_context": data.get("rolling_window_context") if isinstance(data.get("rolling_window_context"), dict) else {},
        "monitor_attempt_context": data.get("monitor_attempt_context") if isinstance(data.get("monitor_attempt_context"), dict) else {},
    }


def summarize_local(data: Optional[Dict[str, Any]], path: Path, error: Optional[str], exists: bool) -> Dict[str, Any]:
    if data is None:
        return {
            "present": False,
            "path": str(path),
            "exists": exists,
            "error": safe_text(error),
            "overall_status": STATUS_UNKNOWN,
        }

    findings = []
    for key in ("findings", "checks", "metrics", "recommendations"):
        value = data.get(key)
        if isinstance(value, list):
            findings.extend(item for item in value if isinstance(item, dict))
    observations = data.get("observations") if isinstance(data.get("observations"), list) else []

    return {
        "present": True,
        "path": str(path),
        "generated_at_utc": safe_text(data.get("generated_at_utc") or data.get("generated_at")),
        "overall_status": normalize_status(data.get("overall_status")),
        "finding_count": len(findings),
        "finding_counts": status_counts(findings),
        "non_ok_findings": non_ok_items(findings),
        "observation_count": len(observations),
        "observations": [safe_item(item, preferred_label="title") for item in observations[:8] if isinstance(item, dict)],
    }


def infer_private_pc_last_known_confirmation() -> Dict[str, Any]:
    for path in PRIVATE_PC_CONFIRMATION_DOCS:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lowered = text.casefold()
        has_private_context = "private" in lowered or "privater" in lowered
        has_ok_status = "overall_status=ok" in lowered or "overall status ok" in lowered
        has_no_findings = "keine findings" in lowered or "findings: none" in lowered
        if has_private_context and has_ok_status:
            return {
                "status": STATUS_OK,
                "source": str(path),
                "detail": "Existing project documentation records the private PC local agent as OK.",
                "findings_none": has_no_findings,
            }
    return {"status": STATUS_UNKNOWN, "source": None, "detail": "No local confirmation evidence found in project docs."}


def summarize_private_pc(data: Optional[Dict[str, Any]], path: Path, error: Optional[str], exists: bool) -> Dict[str, Any]:
    if data is not None:
        summary = summarize_local(data, path, error, exists)
        summary.update(
            {
                "maintained_locally": False,
                "last_known_local_confirmation": summary.get("overall_status"),
                "status_basis": "private_pc_report",
            }
        )
        return summary

    confirmation = infer_private_pc_last_known_confirmation()
    return {
        "present": False,
        "path": str(path),
        "exists": exists,
        "error": safe_text(error),
        "overall_status": STATUS_UNKNOWN,
        "maintained_locally": True,
        "last_known_local_confirmation": confirmation.get("status"),
        "last_known_local_confirmation_source": confirmation.get("source"),
        "status_basis": "project_documentation" if confirmation.get("status") == STATUS_OK else "missing_report",
        "note": (
            "Private PC status is maintained locally. No private PC report is present on Hetzner, "
            "so current private PC status is not guessed."
        ),
        "password_push_required": False,
    }


def safe_sourcemap_candidate(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "map_path": redact_text(item.get("map_path", "-"), max_len=240),
        "reference_path": redact_text(item.get("reference_path", "-"), max_len=240),
        "count": parse_count(item.get("count")),
        "classification": redact_text(item.get("classification", "-"), max_len=120),
        "auto_apply_eligible": bool(item.get("auto_apply_eligible")),
        "policy": redact_text(item.get("policy", "-"), max_len=240),
    }


def safe_sourcemap_action(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action_id": redact_text(item.get("action_id", "skip"), max_len=120),
        "map_path": redact_text(item.get("map_path", "-"), max_len=240),
        "reference_path": redact_text(item.get("reference_path", "-"), max_len=240),
        "count": parse_count(item.get("count")),
        "reason": redact_text(item.get("reason") or item.get("operation") or "-", max_len=360),
        "backup_path": redact_text(item.get("backup_path", "-"), max_len=240),
        "remote_verification": item.get("remote_verification"),
    }


def summarize_sourcemap_prevention(
    data: Optional[Dict[str, Any]],
    path: Path,
    error: Optional[str],
    exists: bool,
) -> Dict[str, Any]:
    if data is None:
        return {
            "present": False,
            "path": str(path),
            "exists": exists,
            "error": safe_text(error),
            "status": STATUS_UNKNOWN,
            "candidate_count": 0,
            "planned_count": 0,
            "applied_count": 0,
            "skipped_count": 0,
            "safe_to_auto_apply": False,
            "requires_operator_review": True,
            "rollback_hint_path": None,
        }

    candidates = data.get("candidates") if isinstance(data.get("candidates"), list) else []
    planned = data.get("planned_actions") if isinstance(data.get("planned_actions"), list) else []
    applied = data.get("applied_actions") if isinstance(data.get("applied_actions"), list) else []
    skipped = data.get("skipped_actions") if isinstance(data.get("skipped_actions"), list) else []
    stale = data.get("stale_candidates") if isinstance(data.get("stale_candidates"), list) else []
    metric = data.get("map_404_metric") if isinstance(data.get("map_404_metric"), dict) else {}

    return {
        "present": True,
        "path": str(path),
        "generated_at_utc": safe_text(data.get("generated_at_utc")),
        "mode": safe_text(data.get("mode")),
        "status": normalize_status(data.get("status")),
        "map_404_status": normalize_status(metric.get("status")),
        "map_404_value": parse_count(metric.get("value")),
        "candidate_count": parse_count(data.get("candidate_count")) or len(candidates),
        "planned_count": len(planned),
        "applied_count": len(applied),
        "skipped_count": len(skipped),
        "already_remediated_count": parse_count(data.get("already_remediated_count")) or len(stale),
        "active_wpo_actions_count": parse_count(data.get("active_wpo_actions_count")),
        "historical_window_remainder_count": parse_count(data.get("historical_window_remainder_count")),
        "safe_to_auto_apply": bool(data.get("safe_to_auto_apply")),
        "global_safe_to_auto_apply": bool(data.get("global_safe_to_auto_apply", data.get("safe_to_auto_apply"))),
        "wpo_minify_safe_to_apply": bool(data.get("wpo_minify_safe_to_apply")),
        "core_requires_review": bool(data.get("core_requires_review")),
        "auto_apply_scope": data.get("auto_apply_scope") if isinstance(data.get("auto_apply_scope"), dict) else {},
        "requires_operator_review": bool(data.get("requires_operator_review")),
        "rollback_hint_path": redact_text(data.get("rollback_hint_path"), max_len=240),
        "candidates": [safe_sourcemap_candidate(item) for item in candidates[:8] if isinstance(item, dict)],
        "stale_candidates": [safe_sourcemap_candidate(item) for item in stale[:8] if isinstance(item, dict)],
        "planned_actions": [safe_sourcemap_action(item) for item in planned[:8] if isinstance(item, dict)],
        "applied_actions": [safe_sourcemap_action(item) for item in applied[:8] if isinstance(item, dict)],
        "skipped_actions": [safe_sourcemap_action(item) for item in skipped[:8] if isinstance(item, dict)],
    }


def summarize_ai_radio_timeout(
    data: Optional[Dict[str, Any]],
    path: Path,
    error: Optional[str],
    exists: bool,
) -> Dict[str, Any]:
    if data is None:
        return {
            "present": False,
            "path": str(path),
            "exists": exists,
            "error": safe_text(error),
            "status": STATUS_UNKNOWN,
            "safe_to_auto_apply": False,
            "requires_operator_review": True,
        }

    top = data.get("top_timeout_endpoint") if isinstance(data.get("top_timeout_endpoint"), dict) else {}
    cloudflare = data.get("cloudflare_summary") if isinstance(data.get("cloudflare_summary"), dict) else {}
    findings = data.get("classification") if isinstance(data.get("classification"), list) else []
    remediation = data.get("microcache_remediation") if isinstance(data.get("microcache_remediation"), dict) else {}
    rolling = data.get("rolling_window_status") if isinstance(data.get("rolling_window_status"), dict) else {}
    return {
        "present": True,
        "path": str(path),
        "generated_at_utc": safe_text(data.get("generated_at_utc")),
        "status": normalize_status(data.get("status")),
        "top_timeout_endpoint": {
            "host": redact_text(top.get("host", "-"), max_len=180),
            "path": redact_text(top.get("path", "-"), max_len=220),
            "count": parse_count(top.get("count")),
            "statuses": safe_count_items(top.get("statuses"), "status", limit=4),
            "cache_status": safe_count_items(top.get("cache_status"), "cache_status", limit=4),
        },
        "nowplaying_is_primary_driver": bool(data.get("nowplaying_is_primary_driver")),
        "suggested_prevention": redact_text(data.get("suggested_prevention", "-"), max_len=420),
        "safe_to_auto_apply": bool(data.get("safe_to_auto_apply")),
        "requires_operator_review": bool(data.get("requires_operator_review")),
        "microcache_remediation": {
            "present": bool(remediation.get("present")),
            "microcache_deployed": bool(remediation.get("microcache_deployed")),
            "deployed_on_host": redact_text(remediation.get("deployed_on_host"), max_len=120),
            "origin_ip": redact_text(remediation.get("origin_ip"), max_len=80),
            "endpoint": redact_text(remediation.get("endpoint"), max_len=220),
            "local_validation": redact_text(remediation.get("local_validation"), max_len=120),
            "cache_header": redact_text(remediation.get("cache_header"), max_len=120),
            "nginx_cache_ttl_seconds": parse_count(remediation.get("nginx_cache_ttl_seconds")),
            "stale_on_error": bool(remediation.get("stale_on_error")),
            "cloudflare_change": bool(remediation.get("cloudflare_change")),
            "waf_change": bool(remediation.get("waf_change")),
            "expected_effect": redact_text(remediation.get("expected_effect"), max_len=240),
            "status_note": redact_text(remediation.get("status_note"), max_len=360),
            "rolling_window_remainder_hint": redact_text(remediation.get("rolling_window_remainder_hint"), max_len=360),
            "next_action": redact_text(remediation.get("next_action"), max_len=300),
        },
        "rolling_window_status": {
            "present": bool(rolling.get("present")),
            "status": redact_text(rolling.get("status"), max_len=120),
            "interpretation": redact_text(rolling.get("interpretation"), max_len=420),
            "latest_5xx_delta": rolling.get("latest_5xx_delta"),
            "latest_5xx_delta_low": bool(rolling.get("latest_5xx_delta_low")),
            "low_growth_limit": parse_count(rolling.get("low_growth_limit")),
            "max_recent_5xx_delta": rolling.get("max_recent_5xx_delta"),
            "stable_minutes": rolling.get("stable_minutes"),
            "remaining_stable_minutes_for_old_window": rolling.get("remaining_stable_minutes_for_old_window"),
            "stable_since_utc": redact_text(rolling.get("stable_since_utc"), max_len=120),
            "stable_since_reason": redact_text(rolling.get("stable_since_reason"), max_len=160),
        },
        "next_action": redact_text(data.get("next_action"), max_len=300),
        "total_504": parse_count(cloudflare.get("total_504")),
        "likely_cloudflare_timeout": parse_count(cloudflare.get("likely_cloudflare_timeout")),
        "nowplaying_504": parse_count(cloudflare.get("nowplaying_504")),
        "nowplaying_504_share_percent": cloudflare.get("nowplaying_504_share_percent"),
        "ai_radio_5xx_share_percent": cloudflare.get("ai_radio_5xx_share_percent"),
        "findings": [
            {
                "signal_id": redact_text(item.get("signal_id", "-"), max_len=120),
                "status": normalize_signal_status(item.get("status")),
                "count": parse_count(item.get("count")),
                "recommendation": redact_text(item.get("recommendation", "-"), max_len=360),
            }
            for item in findings[:8]
            if isinstance(item, dict)
        ],
    }


def recursive_safe_texts(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)):
                continue
            yield str(key)
            yield from recursive_safe_texts(item)
    elif isinstance(value, list):
        for item in value:
            yield from recursive_safe_texts(item)
    elif isinstance(value, (str, int, float, bool)):
        yield str(value)


def local_has_ufw_read_issue(local_data: Optional[Dict[str, Any]]) -> bool:
    if not local_data:
        return False
    joined = " ".join(recursive_safe_texts(local_data)).lower()
    return "ufw" in joined and any(
        marker in joined
        for marker in ("leserecht", "read-only", "read only", "permission", "berechtigung", "zugriff")
    )


CANONICAL_HEADER_FIELDS = (
    "overall_status",
    "website_status",
    "website_correlation_status",
    "local_status",
    "runtime_status",
    "runtime_stage",
    "autonomy_level",
    "monitoring_enabled",
    "timer_active",
    "timer_enabled",
    "scheduler_status",
    "low_live_enabled",
    "medium_live_enabled",
    "high_live_enabled",
    "production_apply_lock",
    "emergency_stop",
    "breach",
    "circuit_breaker_status",
    "rollback_status",
    "write_canary_status",
    "promotion_status",
    "owner_priority",
    "total_5xx",
    "http_504",
    "http_503",
    "http_522",
    "http_526",
    "nowplaying_504",
    "nowplaying_classification",
    "wp_users_me_504",
    "wp_users_me_classification",
    "source_map_404",
    "source_map_status",
    "rolling_window_status",
    "current_snapshot_id",
    "current_growth",
)


def load_canonical_truth_snapshot() -> Dict[str, Any]:
    """Phase 10.21: the canonical snapshot is the only source of current runtime truth.

    The master timer runs independently of the production pipeline, so a stale
    persisted snapshot is re-resolved in memory rather than reported as current.
    """
    snapshot = canonical_truth.load_or_resolve()
    return snapshot if isinstance(snapshot, dict) else {}


def build_canonical_header(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Flat current-truth header. Missing values stay UNKNOWN — never a legacy value."""
    canonical = snapshot.get("canonical") if isinstance(snapshot.get("canonical"), dict) else {}
    header: Dict[str, Any] = {
        "canonical_truth_status": snapshot.get("status", "NOT_AVAILABLE"),
        "canonical_generated_at": snapshot.get("generated_at_utc"),
        "missing_fields": snapshot.get("missing_fields", []),
    }
    for field in CANONICAL_HEADER_FIELDS:
        block = canonical.get(field)
        if isinstance(block, dict) and block.get("resolution") == "RESOLVED":
            header[field] = block.get("value")
            header[f"{field}__source"] = block.get("source")
            header[f"{field}__freshness"] = block.get("freshness")
        else:
            header[field] = None
            header[f"{field}__source"] = None
            header[f"{field}__freshness"] = canonical_truth.MISSING
    priority = canonical.get("owner_priority") if isinstance(canonical.get("owner_priority"), dict) else {}
    header["owner_priority_rank"] = priority.get("rank")
    header["owner_priority_reason"] = priority.get("rank_reason")
    header["owner_priority_suppressed"] = priority.get("suppressed_lower_priorities", [])
    header["legacy_seo_checklist_allowed"] = priority.get("legacy_seo_checklist_allowed", False)
    return header


def canonical_truth_summary(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if not snapshot:
        return {"present": False, "status": "NOT_AVAILABLE"}
    counts = snapshot.get("counts", {}) if isinstance(snapshot.get("counts"), dict) else {}
    return {
        "present": True,
        "status": snapshot.get("status"),
        "generated_at_utc": snapshot.get("generated_at_utc"),
        "schema_version": snapshot.get("schema_version"),
        "missing_fields": snapshot.get("missing_fields", []),
        "resolved_fields": counts.get("resolved_fields"),
        "unresolved_fields": counts.get("unresolved_fields"),
        "current_sources": counts.get("current_sources"),
        "stale_excluded_sources": counts.get("stale_excluded_sources"),
        "precedence": snapshot.get("precedence", []),
    }


def legacy_supersession_summary(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    legacy = snapshot.get("legacy_supersession") if isinstance(snapshot.get("legacy_supersession"), dict) else {}
    if not legacy:
        return {"present": False}
    return {
        "present": True,
        "status": legacy.get("status"),
        "counts": legacy.get("counts", {}),
        "legacy_modules": legacy.get("legacy_modules", []),
        "superseded_field_claims": legacy.get("superseded_field_claims", []),
        "conflicting_field_claims": legacy.get("conflicting_field_claims", []),
        "retention": legacy.get("retention"),
    }


def canonical_cell(header: Dict[str, Any], field: str) -> Any:
    """Value for an executive table cell; None renders as UNKNOWN, never as legacy."""
    value = header.get(field)
    return canonical_truth.UNKNOWN if value is None else value


def compute_overall_master_status(
    website_status: str,
    website_present: bool,
    hetzner_local_status: str,
    hetzner_local_present: bool,
    private_pc_status: str,
    private_pc_present: bool,
) -> str:
    statuses = [
        website_status if website_present else STATUS_UNKNOWN,
        hetzner_local_status if hetzner_local_present else STATUS_UNKNOWN,
    ]
    if private_pc_present:
        statuses.append(private_pc_status)
    if STATUS_CRITICAL in statuses:
        return STATUS_CRITICAL
    if STATUS_WARNING in statuses:
        return STATUS_WARNING
    if STATUS_UNKNOWN in statuses:
        return STATUS_UNKNOWN
    if statuses and all(status == STATUS_OK for status in statuses):
        return STATUS_OK
    return STATUS_UNKNOWN


def compute_action_status(
    website_status: str,
    website_correlation_status: str,
    hetzner_local_status: str,
    private_pc_status: str,
    website_present: bool,
    hetzner_local_present: bool,
    private_pc_present: bool,
) -> str:
    if not website_present and not hetzner_local_present and not private_pc_present:
        return ACTION_UNKNOWN
    if website_correlation_status == CORRELATION_ACTION_CANDIDATE:
        return ACTION_APPLY_CANDIDATE
    if hetzner_local_status == STATUS_CRITICAL or (private_pc_present and private_pc_status == STATUS_CRITICAL):
        return ACTION_LOCAL_ATTENTION
    if website_status == STATUS_CRITICAL and website_correlation_status == CORRELATION_WATCH:
        return ACTION_WATCH_ONLY
    if website_status == STATUS_CRITICAL:
        return ACTION_WARNING_REVIEW
    if STATUS_WARNING in {website_status, hetzner_local_status} or (
        private_pc_present and private_pc_status == STATUS_WARNING
    ):
        return ACTION_WARNING_REVIEW
    if (
        not website_present
        or not hetzner_local_present
        or website_status == STATUS_UNKNOWN
        or hetzner_local_status == STATUS_UNKNOWN
        or (private_pc_present and private_pc_status == STATUS_UNKNOWN)
    ):
        return ACTION_UNKNOWN
    if website_status == STATUS_OK and hetzner_local_status == STATUS_OK and (
        not private_pc_present or private_pc_status == STATUS_OK
    ):
        return ACTION_OK
    return ACTION_UNKNOWN


def build_recommendations(
    website_status: str,
    website_correlation_status: str,
    hetzner_local_status: str,
    hetzner_local_present: bool,
    hetzner_local_data: Optional[Dict[str, Any]],
    website_summary: Dict[str, Any],
    private_pc_summary: Dict[str, Any],
) -> List[str]:
    recommendations: List[str] = []

    if not website_summary.get("present"):
        recommendations.append("Website Sentinel Report fehlt oder ist nicht lesbar; Master darf daraus kein OK ableiten.")
    if not hetzner_local_present:
        recommendations.append("Hetzner Local Agent Report fehlt oder Push ist noch nicht eingerichtet.")
    if hetzner_local_status == STATUS_WARNING and local_has_ufw_read_issue(hetzner_local_data):
        recommendations.append(
            "Hetzner Local Agent läuft; UFW-Leserecht kann später über read-only Helper gelöst werden."
        )
    if website_status == STATUS_CRITICAL and website_correlation_status == CORRELATION_WATCH:
        recommendations.append("Website kritisch beobachtet, aber keine bestätigte Origin-Krise.")
    if website_status == STATUS_CRITICAL and website_correlation_status not in {
        CORRELATION_WATCH,
        CORRELATION_ACTION_CANDIDATE,
    }:
        recommendations.append(
            "Website 24h-Metriken bleiben kritisch; Rolling-Window-Kontext und 5xx-Rohdiagnose weiter beobachten."
        )
    ok_readiness = website_summary.get("ok_readiness")
    if website_status != STATUS_OK and isinstance(ok_readiness, dict) and ok_readiness:
        summary = ok_readiness.get("summary") if isinstance(ok_readiness.get("summary"), dict) else {}
        recommendations.append(
            "OK-Readiness trennt direkte Statusblocker von Diagnose: "
            f"direct={parse_count(summary.get('direct_status_blocker_count'))}, "
            f"low_growth={parse_count(summary.get('low_growth_blocker_count'))}, "
            f"aggregate_detail={parse_count(summary.get('aggregate_detail_blocker_count'))}, "
            f"diagnostic_only_v2={parse_count(summary.get('diagnostic_nonblocking_count'))}."
        )

    # Check for origin timeout issues that block OK readiness
    detail_blockers = ok_readiness.get("aggregate_detail_blockers", [])
    has_timeout_issue = any(b.get("key") == "origin_5xx_aggregate_detail_gap" for b in detail_blockers)
    if not has_timeout_issue:
        # Also check correlation findings for likely_cloudflare_timeout
        findings_v2 = website_summary.get("correlation_v2_findings", [])
        if isinstance(findings_v2, list):
            for finding in findings_v2:
                if finding.get("signal_id") == "likely_cloudflare_timeout":
                    has_timeout_issue = True
                    break
    if has_timeout_issue:
        recommendations.append("Origin timeout diagnostics required before OK readiness.")

    origin_pressure = website_summary.get("origin_pressure_breakdown")
    if website_status == STATUS_CRITICAL and isinstance(origin_pressure, dict) and origin_pressure:
        total_5xx = parse_count(origin_pressure.get("status_24h_total_5xx"))
        unknown_5xx = parse_count(origin_pressure.get("unclassified_5xx_from_status_aggregate"))
        coverage = origin_pressure.get("detail_coverage_percent")
        coverage_text = f"{coverage}%" if coverage is not None else "unknown"
        request_shapes = (
            origin_pressure.get("top_5xx_request_shapes")
            if isinstance(origin_pressure.get("top_5xx_request_shapes"), list)
            else []
        )
        actor_signals = (
            origin_pressure.get("top_5xx_actor_signals")
            if isinstance(origin_pressure.get("top_5xx_actor_signals"), list)
            else []
        )
        failure_modes = (
            origin_pressure.get("top_5xx_failure_modes")
            if isinstance(origin_pressure.get("top_5xx_failure_modes"), list)
            else []
        )
        status_inclusive_classifications = (
            origin_pressure.get("top_5xx_status_inclusive_classification")
            if isinstance(origin_pressure.get("top_5xx_status_inclusive_classification"), list)
            else []
        )
        if total_5xx and unknown_5xx:
            recommendations.append(
                "Website bleibt CRITICAL: status-24h zeigt "
                f"{total_5xx} 5xx; {unknown_5xx} davon sind nur aggregiert/unknown und nicht OK-faehig "
                f"(Detail-Coverage {coverage_text})."
            )
            status_gap = (
                origin_pressure.get("status_detail_gap")
                if isinstance(origin_pressure.get("status_detail_gap"), list)
                else []
            )
            gap_drivers = []
            for item in status_gap:
                if not isinstance(item, dict):
                    continue
                gap_count = parse_count(item.get("unclassified_count"))
                if gap_count <= 0:
                    continue
                gap_drivers.append(
                    f"{safe_text(item.get('status'))}={gap_count} "
                    f"({safe_text(item.get('status_only_classification'))})"
                )
            if gap_drivers:
                recommendations.append(
                    "5xx-Unknown-Rest ist statusweise sichtbar, aber nicht pfad/cache-klassifiziert: "
                    + ", ".join(gap_drivers[:3])
                    + "."
                )
        elif total_5xx:
            recommendations.append(
                f"Website bleibt CRITICAL: 5xx-Origin-Diagnose zeigt weiterhin {total_5xx} 5xx im 24h-Fenster."
            )
        if request_shapes or actor_signals or failure_modes:
            shape_text = md_count_items(request_shapes, "request_shape", limit=3)
            actor_text = md_count_items(actor_signals, "actor_signal", limit=3)
            mode_text = md_count_items(failure_modes, "failure_mode", limit=3)
            recommendations.append(
                "5xx-Diagnose trennt Pfad-Shape, Actor-Signal und Failure-Mode: "
                f"Shapes {shape_text}; Actors {actor_text}; Modes {mode_text}."
            )
        if status_inclusive_classifications:
            inclusive_text = md_count_items(status_inclusive_classifications, "classification", limit=3)
            recommendations.append(
                "Status-inclusive 5xx-Diagnose ordnet den aggregate-only Rest konservativ ein: "
                f"{inclusive_text}; weiterhin nicht OK-faehig ohne Pfad-/Cache-Detail oder 24h-low-growth."
            )
    source_map_404 = website_summary.get("source_map_404_breakdown")
    if website_status == STATUS_CRITICAL and isinstance(source_map_404, dict) and source_map_404:
        map_404_total = parse_count(source_map_404.get("map_404_total"))
        classifications = (
            source_map_404.get("top_map_404_classification")
            if isinstance(source_map_404.get("top_map_404_classification"), list)
            else []
        )
        drivers = []
        for item in classifications[:3]:
            if not isinstance(item, dict):
                continue
            drivers.append(f"{safe_text(item.get('classification'))}={safe_text(item.get('count'))}")
        if map_404_total:
            driver_text = ", ".join(drivers) if drivers else "keine Detailklassifikation"
            recommendations.append(
                "Website ist wegen .map-404 erst mit 24h-low-growth-Evidenz OK-faehig: "
                f"{map_404_total} Treffer; Treiber: {driver_text}."
            )
    monitor_context = website_summary.get("monitor_attempt_context")
    if isinstance(monitor_context, dict) and monitor_context.get("status") == "STALE_SUCCESS_NEWER_FAILED_ATTEMPTS":
        recommendations.append(
            "Neuere Cloudflare-Monitor-Laeufe sind fehlgeschlagen; Website-Status basiert auf letztem erfolgreichen Snapshot."
        )
    rolling_context = website_summary.get("rolling_window_context")
    if website_status == STATUS_CRITICAL and isinstance(rolling_context, dict):
        history = rolling_context.get("history") if isinstance(rolling_context.get("history"), dict) else {}
        blockers = history.get("old_window_blockers") if isinstance(history.get("old_window_blockers"), list) else []
        if blockers:
            blocker_labels = []
            remaining_values = []
            for blocker in blockers:
                if not isinstance(blocker, dict):
                    continue
                label = safe_text(blocker.get("label"), default="unknown")
                reason = safe_text(blocker.get("reason"), default="unknown")
                blocker_labels.append(f"{label} ({reason})")
                remaining = blocker.get("remaining_stable_minutes_for_old_window")
                if isinstance(remaining, (int, float)):
                    remaining_values.append(float(remaining))
            if blocker_labels:
                remaining_text = (
                    f"; max remaining {round(max(remaining_values), 2)} minutes"
                    if remaining_values
                    else ""
                )
                recommendations.append(
                    "Website nicht OK-faehig wegen fehlender 24h-low-growth-Evidenz: "
                    + ", ".join(blocker_labels[:3])
                    + remaining_text
                    + "."
                )
    if website_correlation_status == CORRELATION_ACTION_CANDIDATE:
        recommendations.append("Cloudflare apply-safe nur nach manueller Prüfung und Korrelation starten.")
    if hetzner_local_status == STATUS_CRITICAL:
        recommendations.append("Hetzner lokales System prüfen; keine automatische Remote-Aktion.")
    if private_pc_summary.get("maintained_locally") and not private_pc_summary.get("present"):
        recommendations.append(
            "Private PC status is maintained locally; kein Passwort-Push oder Remote-Zwang ableiten."
        )

    if not recommendations:
        recommendations.append("Keine unmittelbare defensive Aktion empfohlen.")

    deduped: List[str] = []
    for recommendation in recommendations:
        if recommendation not in deduped:
            deduped.append(recommendation)
    return deduped


def build_report(
    website_json: Path,
    local_json: Path,
    private_pc_json: Path,
    sourcemap_json: Path,
    ai_radio_timeout_json: Path,
    out_md: Path,
    out_json: Path,
    history_path: Path,
    autonomy_policy_json: Path = DEFAULT_AUTONOMY_POLICY_JSON,
    seo_optimizer_json: Path = DEFAULT_SEO_OPTIMIZER_JSON,
    editorial_review_json: Path = DEFAULT_EDITORIAL_REVIEW_JSON,
    microcache_status_json: Path = DEFAULT_MICROCACHE_STATUS_JSON,
    perf_audit_json: Path = DEFAULT_PERF_AUDIT_JSON,
    roadmap_json: Path = DEFAULT_ROADMAP_JSON,
    approval_queue_json: Path = DEFAULT_APPROVAL_QUEUE_JSON,
    owner_cli_report_json: Path = DEFAULT_OWNER_CLI_REPORT_JSON,
    draft_execution_plan_json: Path = DEFAULT_DRAFT_EXECUTION_PLAN_JSON,
    owner_review_pack_json: Path = DEFAULT_OWNER_REVIEW_PACK_JSON,
    manual_apply_checklist_json: Path = DEFAULT_MANUAL_APPLY_CHECKLIST_JSON,
    manual_completion_tracker_json: Path = DEFAULT_MANUAL_COMPLETION_TRACKER_JSON,
    post_manual_validation_json: Path = DEFAULT_POST_MANUAL_VALIDATION_JSON,
    owner_daily_action_summary_json: Path = DEFAULT_OWNER_DAILY_ACTION_SUMMARY_JSON,
    safe_apply_registry_json: Path = DEFAULT_SAFE_APPLY_REGISTRY_JSON,
    safe_apply_guard_json: Path = DEFAULT_SAFE_APPLY_GUARD_JSON,
    safe_apply_scope_json: Path = DEFAULT_SAFE_APPLY_SCOPE_JSON,
    safe_apply_dry_run_json: Path = DEFAULT_SAFE_APPLY_DRY_RUN_JSON,
    safe_apply_preflight_json: Path = DEFAULT_SAFE_APPLY_PREFLIGHT_JSON,
    autonomy_runtime_lock_json: Path = DEFAULT_AUTONOMY_RUNTIME_LOCK_JSON,
    safe_draft_autonomy_runner_json: Path = DEFAULT_SAFE_DRAFT_AUTONOMY_RUNNER_JSON,
    safe_draft_autonomy_verifier_json: Path = DEFAULT_SAFE_DRAFT_AUTONOMY_VERIFIER_JSON,
    safe_draft_autonomy_scheduler_plan_json: Path = DEFAULT_SAFE_DRAFT_AUTONOMY_SCHEDULER_PLAN_JSON,
    safe_draft_autonomy_timer_draft_json: Path = DEFAULT_SAFE_DRAFT_AUTONOMY_TIMER_DRAFT_JSON,
    safe_draft_autonomy_timer_install_review_json: Path = DEFAULT_SAFE_DRAFT_AUTONOMY_TIMER_INSTALL_REVIEW_JSON,
    owner_manual_timer_install_packet_json: Path = DEFAULT_OWNER_MANUAL_TIMER_INSTALL_PACKET_JSON,
    owner_timer_install_decision_gate_json: Path = DEFAULT_OWNER_TIMER_INSTALL_DECISION_GATE_JSON,
    manual_timer_install_command_preview_json: Path = DEFAULT_MANUAL_TIMER_INSTALL_COMMAND_PREVIEW_JSON,
    owner_timer_install_evidence_pack_json: Path = DEFAULT_OWNER_TIMER_INSTALL_EVIDENCE_PACK_JSON,
    safe_draft_autonomy_final_safety_json: Path = DEFAULT_SAFE_DRAFT_AUTONOMY_FINAL_SAFETY_JSON,
    manual_evidence_review_dashboard_json: Path = DEFAULT_MANUAL_EVIDENCE_REVIEW_DASHBOARD_JSON,
    manual_evidence_review_completion_tracker_json: Path = DEFAULT_MANUAL_EVIDENCE_REVIEW_COMPLETION_TRACKER_JSON,
    manual_evidence_review_completion_gate_json: Path = DEFAULT_MANUAL_EVIDENCE_REVIEW_COMPLETION_GATE_JSON,
    owner_evidence_review_console_json: Path = DEFAULT_OWNER_EVIDENCE_REVIEW_CONSOLE_JSON,
    final_owner_decision_snapshot_json: Path = DEFAULT_FINAL_OWNER_DECISION_SNAPSHOT_JSON,
    master_critical_cause_snapshot_json: Path = DEFAULT_MASTER_CRITICAL_CAUSE_SNAPSHOT_JSON,
    rolling_window_decay_observer_json: Path = DEFAULT_ROLLING_WINDOW_DECAY_OBSERVER_JSON,
    low_growth_readiness_timeline_json: Path = DEFAULT_LOW_GROWTH_READINESS_TIMELINE_JSON,
    manual_website_recheck_gate_json: Path = DEFAULT_MANUAL_WEBSITE_RECHECK_GATE_JSON,
    low_risk_autonomy_readiness_gate_json: Path = DEFAULT_LOW_RISK_AUTONOMY_READINESS_GATE_JSON,
    low_risk_policy_boundary_draft_json: Path = DEFAULT_LOW_RISK_POLICY_BOUNDARY_DRAFT_JSON,
    low_risk_policy_owner_review_tracker_json: Path = DEFAULT_LOW_RISK_POLICY_OWNER_REVIEW_TRACKER_JSON,
    low_risk_policy_review_completion_gate_json: Path = DEFAULT_LOW_RISK_POLICY_REVIEW_COMPLETION_GATE_JSON,
    low_risk_autonomy_final_safety_seal_json: Path = DEFAULT_LOW_RISK_AUTONOMY_FINAL_SAFETY_SEAL_JSON,
    safe_end_summary_json: Path = DEFAULT_SAFE_END_SUMMARY_JSON,
    safe_end_archive_snapshot_json: Path = DEFAULT_SAFE_END_ARCHIVE_SNAPSHOT_JSON,
    safe_end_archive_integrity_verifier_json: Path = DEFAULT_SAFE_END_ARCHIVE_INTEGRITY_VERIFIER_JSON,
    concrete_seo_performance_optimizer_json: Path = DEFAULT_CONCRETE_SEO_PERFORMANCE_OPTIMIZER_JSON,
    safe_sftp_seo_apply_lane_json: Path = DEFAULT_SAFE_SFTP_SEO_APPLY_LANE_JSON,
) -> Dict[str, Any]:
    generated_at = utc_now()
    website_data, website_error, website_exists = read_json(website_json)
    local_data, local_error, local_exists = read_json(local_json)
    private_pc_data, private_pc_error, private_pc_exists = read_json(private_pc_json)
    sourcemap_data, sourcemap_error, sourcemap_exists = read_json(sourcemap_json)
    ai_radio_data, ai_radio_error, ai_radio_exists = read_json(ai_radio_timeout_json)
    autonomy_data, autonomy_error, autonomy_exists = read_json(autonomy_policy_json)
    seo_data, seo_error, seo_exists = read_json(seo_optimizer_json)
    editorial_data, editorial_error, editorial_exists = read_json(editorial_review_json)
    microcache_data, microcache_error, microcache_exists = read_json(microcache_status_json)
    perf_audit_data, perf_audit_error, perf_audit_exists = read_json(perf_audit_json)
    roadmap_data, roadmap_error, roadmap_exists = read_json(roadmap_json)
    approval_queue_data, approval_queue_error, approval_queue_exists = read_json(approval_queue_json)
    owner_cli_data, owner_cli_error, owner_cli_exists = read_json(owner_cli_report_json)
    draft_execution_data, draft_execution_error, draft_execution_exists = read_json(draft_execution_plan_json)
    owner_review_pack_data, owner_review_pack_error, owner_review_pack_exists = read_json(owner_review_pack_json)
    manual_apply_checklist_data, manual_apply_checklist_error, manual_apply_checklist_exists = read_json(manual_apply_checklist_json)
    manual_completion_tracker_data, manual_completion_tracker_error, manual_completion_tracker_exists = read_json(manual_completion_tracker_json)
    post_manual_validation_data, post_manual_validation_error, post_manual_validation_exists = read_json(post_manual_validation_json)
    owner_daily_action_data, owner_daily_action_error, owner_daily_action_exists = read_json(owner_daily_action_summary_json)
    safe_apply_registry_data, safe_apply_registry_error, safe_apply_registry_exists = read_json(safe_apply_registry_json)
    safe_apply_guard_data, safe_apply_guard_error, safe_apply_guard_exists = read_json(safe_apply_guard_json)
    safe_apply_scope_data, safe_apply_scope_error, safe_apply_scope_exists = read_json(safe_apply_scope_json)
    safe_apply_dry_run_data, safe_apply_dry_run_error, safe_apply_dry_run_exists = read_json(safe_apply_dry_run_json)
    safe_apply_preflight_data, safe_apply_preflight_error, safe_apply_preflight_exists = read_json(safe_apply_preflight_json)
    autonomy_runtime_lock_data, autonomy_runtime_lock_error, autonomy_runtime_lock_exists = read_json(autonomy_runtime_lock_json)
    safe_draft_runner_data, safe_draft_runner_error, safe_draft_runner_exists = read_json(safe_draft_autonomy_runner_json)
    safe_draft_verifier_data, safe_draft_verifier_error, safe_draft_verifier_exists = read_json(safe_draft_autonomy_verifier_json)
    safe_draft_scheduler_data, safe_draft_scheduler_error, safe_draft_scheduler_exists = read_json(safe_draft_autonomy_scheduler_plan_json)
    safe_draft_timer_data, safe_draft_timer_error, safe_draft_timer_exists = read_json(safe_draft_autonomy_timer_draft_json)
    safe_draft_timer_review_data, safe_draft_timer_review_error, safe_draft_timer_review_exists = read_json(safe_draft_autonomy_timer_install_review_json)
    owner_manual_timer_packet_data, owner_manual_timer_packet_error, owner_manual_timer_packet_exists = read_json(owner_manual_timer_install_packet_json)
    owner_timer_decision_data, owner_timer_decision_error, owner_timer_decision_exists = read_json(owner_timer_install_decision_gate_json)
    manual_timer_preview_data, manual_timer_preview_error, manual_timer_preview_exists = read_json(manual_timer_install_command_preview_json)
    owner_timer_evidence_data, owner_timer_evidence_error, owner_timer_evidence_exists = read_json(owner_timer_install_evidence_pack_json)
    final_safety_data, final_safety_error, final_safety_exists = read_json(safe_draft_autonomy_final_safety_json)
    manual_evidence_dashboard_data, manual_evidence_dashboard_error, manual_evidence_dashboard_exists = read_json(manual_evidence_review_dashboard_json)
    manual_evidence_completion_data, manual_evidence_completion_error, manual_evidence_completion_exists = read_json(manual_evidence_review_completion_tracker_json)
    manual_evidence_gate_data, manual_evidence_gate_error, manual_evidence_gate_exists = read_json(manual_evidence_review_completion_gate_json)
    owner_evidence_console_data, owner_evidence_console_error, owner_evidence_console_exists = read_json(owner_evidence_review_console_json)
    final_owner_snapshot_data, final_owner_snapshot_error, final_owner_snapshot_exists = read_json(final_owner_decision_snapshot_json)
    master_critical_cause_data, master_critical_cause_error, master_critical_cause_exists = read_json(master_critical_cause_snapshot_json)
    rolling_window_decay_data, rolling_window_decay_error, rolling_window_decay_exists = read_json(rolling_window_decay_observer_json)
    low_growth_timeline_data, low_growth_timeline_error, low_growth_timeline_exists = read_json(low_growth_readiness_timeline_json)
    manual_recheck_gate_data, manual_recheck_gate_error, manual_recheck_gate_exists = read_json(manual_website_recheck_gate_json)
    low_risk_readiness_gate_data, low_risk_readiness_gate_error, low_risk_readiness_gate_exists = read_json(low_risk_autonomy_readiness_gate_json)
    low_risk_policy_boundary_data, low_risk_policy_boundary_error, low_risk_policy_boundary_exists = read_json(low_risk_policy_boundary_draft_json)
    low_risk_owner_review_data, low_risk_owner_review_error, low_risk_owner_review_exists = read_json(low_risk_policy_owner_review_tracker_json)
    low_risk_completion_gate_data, low_risk_completion_gate_error, low_risk_completion_gate_exists = read_json(low_risk_policy_review_completion_gate_json)
    low_risk_final_seal_data, low_risk_final_seal_error, low_risk_final_seal_exists = read_json(low_risk_autonomy_final_safety_seal_json)
    safe_end_data, safe_end_error, safe_end_exists = read_json(safe_end_summary_json)
    safe_end_archive_data, safe_end_archive_error, safe_end_archive_exists = read_json(safe_end_archive_snapshot_json)
    safe_end_integrity_data, safe_end_integrity_error, safe_end_integrity_exists = read_json(safe_end_archive_integrity_verifier_json)
    concrete_optimizer_data, concrete_optimizer_error, concrete_optimizer_exists = read_json(concrete_seo_performance_optimizer_json)
    safe_sftp_lane_data, safe_sftp_lane_error, safe_sftp_lane_exists = read_json(safe_sftp_seo_apply_lane_json)
    production_pipeline_data, production_pipeline_error, production_pipeline_exists = read_json(DEFAULT_PRODUCTION_PIPELINE_JSON)
    nowplaying_recovery_data, nowplaying_recovery_error, nowplaying_recovery_exists = read_json(DEFAULT_NOWPLAYING_RECOVERY_JSON)
    canonical_truth_snapshot = load_canonical_truth_snapshot()
    canonical_header = build_canonical_header(canonical_truth_snapshot)

    # Optional self-comparison: read the previous master report (if any) before
    # it is overwritten. Informational only; never affects current status.
    previous_master_data, _, previous_master_exists = read_json(out_json)

    website_summary = summarize_website(website_data, website_json, website_error, website_exists)
    hetzner_local_summary = summarize_local(local_data, local_json, local_error, local_exists)
    private_pc_summary = summarize_private_pc(private_pc_data, private_pc_json, private_pc_error, private_pc_exists)
    sourcemap_summary = summarize_sourcemap_prevention(
        sourcemap_data,
        sourcemap_json,
        sourcemap_error,
        sourcemap_exists,
    )
    ai_radio_summary = summarize_ai_radio_timeout(
        ai_radio_data,
        ai_radio_timeout_json,
        ai_radio_error,
        ai_radio_exists,
    )

    website_present = bool(website_summary["present"])
    hetzner_local_present = bool(hetzner_local_summary["present"])
    private_pc_present = bool(private_pc_summary["present"])
    website_status = normalize_status(website_summary.get("overall_status"))
    website_correlation_status = normalize_correlation(website_summary.get("correlation_status"))
    hetzner_local_status = normalize_status(hetzner_local_summary.get("overall_status"))
    private_pc_status = normalize_status(private_pc_summary.get("overall_status"))

    overall_master_status = compute_overall_master_status(
        website_status,
        website_present,
        hetzner_local_status,
        hetzner_local_present,
        private_pc_status,
        private_pc_present,
    )
    action_status = compute_action_status(
        website_status,
        website_correlation_status,
        hetzner_local_status,
        private_pc_status,
        website_present,
        hetzner_local_present,
        private_pc_present,
    )
    recommendations = build_recommendations(
        website_status,
        website_correlation_status,
        hetzner_local_status,
        hetzner_local_present,
        local_data,
        website_summary,
        private_pc_summary,
    )
    if sourcemap_summary.get("present"):
        if sourcemap_summary.get("safe_to_auto_apply"):
            recommendations.append(
                "SourceMap Prevention: reine WPO-Minify-Kandidaten sind fuer explizites apply-safe vorbereitet."
            )
        if sourcemap_summary.get("requires_operator_review"):
            recommendations.append(
                "SourceMap Prevention: nicht-WPO- oder gemischte .map-Kandidaten bleiben review-only."
            )
        if (
            parse_count(sourcemap_summary.get("already_remediated_count")) > 0
            and parse_count(sourcemap_summary.get("active_wpo_actions_count")) == 0
        ):
            recommendations.append(
                "WPO-Minify SourceMap references already absent; remaining .map hits likely 24h/browser-cache remainder."
            )
    if ai_radio_summary.get("present"):
        top = ai_radio_summary.get("top_timeout_endpoint") if isinstance(ai_radio_summary.get("top_timeout_endpoint"), dict) else {}
        remediation = ai_radio_summary.get("microcache_remediation") if isinstance(ai_radio_summary.get("microcache_remediation"), dict) else {}
        if remediation.get("microcache_deployed"):
            recommendations.append(
                "NowPlaying Microcache is deployed and HIT-confirmed on origin; remaining 504s are evaluated "
                "through 24h rolling window. Next action: observe 24h, not new WAF rule."
            )
        else:
            recommendations.append(
                "AI-Radio 504-Diagnose: Top endpoint "
                f"{safe_text(top.get('host'))}{safe_text(top.get('path'))}="
                f"{safe_text(top.get('count'))}; suggested prevention: "
                f"{safe_text(ai_radio_summary.get('suggested_prevention'))}"
            )
    autonomy_summary = summarize_autonomy_policy(
        autonomy_data,
        autonomy_policy_json,
        autonomy_error,
        autonomy_exists,
    )
    if not autonomy_summary.get("present"):
        recommendations.append(
            "Autonomy Policy Layer report fehlt; run sentinel_autonomy_policy.py "
            "fuer current_autonomy_level / policy-only Status."
        )
    elif autonomy_summary.get("policy_breach"):
        # Safe case never degrades the master; only a real breach escalates.
        action_status = escalate_action_status_for_autonomy(action_status)
        if overall_master_status == STATUS_OK:
            overall_master_status = STATUS_WARNING
        recommendations.append(
            "Autonomy Policy Layer meldet eine Policy-Verletzung "
            "(policy_only=false, HIGH allowed_now=true oder apply_status != "
            "not_applied ohne approved gate); manueller Review erforderlich."
        )
    else:
        recommendations.append(
            "Legacy Autonomy Policy Layer (superseded) ist policy-only; HIGH blockiert, "
            f"apply_status {safe_text(autonomy_summary.get('apply_status_summary'))} "
            f"auf {safe_text(autonomy_summary.get('current_autonomy_level'))}."
        )

    seo_summary = summarize_seo_safe_optimizer(
        seo_data,
        seo_optimizer_json,
        seo_error,
        seo_exists,
        editorial_data,
        editorial_exists,
    )
    performance_summary = summarize_performance_safe_improvement(
        ai_radio_summary,
        sourcemap_summary,
        website_summary,
        microcache_data,
        microcache_exists,
        perf_audit_data if isinstance(perf_audit_data, dict) else None,
        bool(perf_audit_exists and not perf_audit_error and isinstance(perf_audit_data, dict)),
    )
    roadmap_summary = summarize_roadmap(
        roadmap_data,
        roadmap_json,
        roadmap_error,
        roadmap_exists,
    )
    approval_queue_summary = summarize_approval_queue(
        approval_queue_data,
        approval_queue_json,
        approval_queue_error,
        approval_queue_exists,
    )
    owner_cli_summary = summarize_owner_cli(
        owner_cli_data,
        owner_cli_report_json,
        owner_cli_error,
        owner_cli_exists,
    )
    draft_execution_summary = summarize_draft_execution_planner(
        draft_execution_data,
        draft_execution_plan_json,
        draft_execution_error,
        draft_execution_exists,
    )
    owner_review_pack_summary = summarize_owner_review_pack(
        owner_review_pack_data,
        owner_review_pack_json,
        owner_review_pack_error,
        owner_review_pack_exists,
    )
    manual_apply_checklist_summary = summarize_manual_apply_checklist(
        manual_apply_checklist_data,
        manual_apply_checklist_json,
        manual_apply_checklist_error,
        manual_apply_checklist_exists,
    )
    manual_completion_tracker_summary = summarize_manual_completion_tracker(
        manual_completion_tracker_data,
        manual_completion_tracker_json,
        manual_completion_tracker_error,
        manual_completion_tracker_exists,
    )
    post_manual_validation_summary = summarize_post_manual_validation(
        post_manual_validation_data,
        post_manual_validation_json,
        post_manual_validation_error,
        post_manual_validation_exists,
    )
    owner_daily_action_summary = summarize_owner_daily_action_summary(
        owner_daily_action_data,
        owner_daily_action_summary_json,
        owner_daily_action_error,
        owner_daily_action_exists,
    )
    safe_apply_registry_summary = summarize_safe_apply_candidate_registry(
        safe_apply_registry_data,
        safe_apply_registry_json,
        safe_apply_registry_error,
        safe_apply_registry_exists,
    )
    safe_apply_guard_summary = summarize_safe_apply_guard_check(
        safe_apply_guard_data,
        safe_apply_guard_json,
        safe_apply_guard_error,
        safe_apply_guard_exists,
    )
    safe_apply_scope_summary = summarize_safe_apply_scope_manager(
        safe_apply_scope_data,
        safe_apply_scope_json,
        safe_apply_scope_error,
        safe_apply_scope_exists,
    )
    safe_apply_dry_run_summary = summarize_safe_apply_dry_run_planner(
        safe_apply_dry_run_data,
        safe_apply_dry_run_json,
        safe_apply_dry_run_error,
        safe_apply_dry_run_exists,
    )
    safe_apply_preflight_summary = summarize_safe_apply_preflight_validator(
        safe_apply_preflight_data,
        safe_apply_preflight_json,
        safe_apply_preflight_error,
        safe_apply_preflight_exists,
    )
    autonomy_runtime_lock_summary = summarize_autonomy_runtime_lock(
        autonomy_runtime_lock_data,
        autonomy_runtime_lock_json,
        autonomy_runtime_lock_error,
        autonomy_runtime_lock_exists,
    )
    safe_draft_runner_summary = summarize_safe_draft_autonomy_runner(
        safe_draft_runner_data,
        safe_draft_autonomy_runner_json,
        safe_draft_runner_error,
        safe_draft_runner_exists,
    )
    safe_draft_verifier_summary = summarize_safe_draft_autonomy_verifier(
        safe_draft_verifier_data,
        safe_draft_autonomy_verifier_json,
        safe_draft_verifier_error,
        safe_draft_verifier_exists,
    )
    safe_draft_scheduler_summary = summarize_safe_draft_autonomy_scheduler_plan(
        safe_draft_scheduler_data,
        safe_draft_autonomy_scheduler_plan_json,
        safe_draft_scheduler_error,
        safe_draft_scheduler_exists,
    )
    safe_draft_timer_summary = summarize_safe_draft_autonomy_timer_draft(
        safe_draft_timer_data,
        safe_draft_autonomy_timer_draft_json,
        safe_draft_timer_error,
        safe_draft_timer_exists,
    )
    safe_draft_timer_review_summary = summarize_safe_draft_autonomy_timer_install_review(
        safe_draft_timer_review_data,
        safe_draft_autonomy_timer_install_review_json,
        safe_draft_timer_review_error,
        safe_draft_timer_review_exists,
    )
    owner_manual_timer_packet_summary = summarize_owner_manual_timer_install_packet(
        owner_manual_timer_packet_data,
        owner_manual_timer_install_packet_json,
        owner_manual_timer_packet_error,
        owner_manual_timer_packet_exists,
    )
    owner_timer_decision_summary = summarize_owner_timer_install_decision_gate(
        owner_timer_decision_data,
        owner_timer_install_decision_gate_json,
        owner_timer_decision_error,
        owner_timer_decision_exists,
    )
    manual_timer_preview_summary = summarize_manual_timer_install_command_preview(
        manual_timer_preview_data,
        manual_timer_install_command_preview_json,
        manual_timer_preview_error,
        manual_timer_preview_exists,
    )
    owner_timer_evidence_summary = summarize_owner_timer_install_evidence_pack(
        owner_timer_evidence_data,
        owner_timer_install_evidence_pack_json,
        owner_timer_evidence_error,
        owner_timer_evidence_exists,
    )
    final_safety_summary = summarize_safe_draft_autonomy_final_safety(
        final_safety_data,
        safe_draft_autonomy_final_safety_json,
        final_safety_error,
        final_safety_exists,
    )
    manual_evidence_dashboard_summary = summarize_manual_evidence_review_dashboard(
        manual_evidence_dashboard_data,
        manual_evidence_review_dashboard_json,
        manual_evidence_dashboard_error,
        manual_evidence_dashboard_exists,
    )
    manual_evidence_completion_summary = summarize_manual_evidence_review_completion_tracker(
        manual_evidence_completion_data,
        manual_evidence_review_completion_tracker_json,
        manual_evidence_completion_error,
        manual_evidence_completion_exists,
    )
    manual_evidence_gate_summary = summarize_manual_evidence_review_completion_gate(
        manual_evidence_gate_data,
        manual_evidence_review_completion_gate_json,
        manual_evidence_gate_error,
        manual_evidence_gate_exists,
    )
    owner_evidence_console_summary = summarize_owner_evidence_review_console(
        owner_evidence_console_data,
        owner_evidence_review_console_json,
        owner_evidence_console_error,
        owner_evidence_console_exists,
    )
    final_owner_snapshot_summary = summarize_final_owner_decision_snapshot(
        final_owner_snapshot_data,
        final_owner_decision_snapshot_json,
        final_owner_snapshot_error,
        final_owner_snapshot_exists,
    )
    master_critical_cause_summary = summarize_master_critical_cause_snapshot(
        master_critical_cause_data,
        master_critical_cause_snapshot_json,
        master_critical_cause_error,
        master_critical_cause_exists,
    )
    rolling_window_decay_summary = summarize_rolling_window_decay_observer(
        rolling_window_decay_data,
        rolling_window_decay_observer_json,
        rolling_window_decay_error,
        rolling_window_decay_exists,
    )
    low_growth_timeline_summary = summarize_low_growth_readiness_timeline(
        low_growth_timeline_data,
        low_growth_readiness_timeline_json,
        low_growth_timeline_error,
        low_growth_timeline_exists,
    )
    manual_recheck_gate_summary = summarize_manual_website_recheck_gate(
        manual_recheck_gate_data,
        manual_website_recheck_gate_json,
        manual_recheck_gate_error,
        manual_recheck_gate_exists,
    )
    low_risk_readiness_gate_summary = summarize_low_risk_autonomy_readiness_gate(
        low_risk_readiness_gate_data,
        low_risk_autonomy_readiness_gate_json,
        low_risk_readiness_gate_error,
        low_risk_readiness_gate_exists,
    )
    low_risk_policy_boundary_summary = summarize_low_risk_policy_boundary_draft(
        low_risk_policy_boundary_data,
        low_risk_policy_boundary_draft_json,
        low_risk_policy_boundary_error,
        low_risk_policy_boundary_exists,
    )
    low_risk_owner_review_summary = summarize_low_risk_policy_owner_review_tracker(
        low_risk_owner_review_data,
        low_risk_policy_owner_review_tracker_json,
        low_risk_owner_review_error,
        low_risk_owner_review_exists,
    )
    low_risk_completion_gate_summary = summarize_low_risk_policy_review_completion_gate(
        low_risk_completion_gate_data,
        low_risk_policy_review_completion_gate_json,
        low_risk_completion_gate_error,
        low_risk_completion_gate_exists,
    )
    low_risk_final_seal_summary = summarize_low_risk_autonomy_final_safety_seal(
        low_risk_final_seal_data,
        low_risk_autonomy_final_safety_seal_json,
        low_risk_final_seal_error,
        low_risk_final_seal_exists,
    )
    safe_end_summary = summarize_safe_end_summary(
        safe_end_data,
        safe_end_summary_json,
        safe_end_error,
        safe_end_exists,
    )
    safe_end_archive_summary = summarize_safe_end_archive_snapshot(
        safe_end_archive_data,
        safe_end_archive_snapshot_json,
        safe_end_archive_error,
        safe_end_archive_exists,
    )
    safe_end_integrity_summary = summarize_safe_end_archive_integrity_verifier(
        safe_end_integrity_data,
        safe_end_archive_integrity_verifier_json,
        safe_end_integrity_error,
        safe_end_integrity_exists,
    )
    concrete_optimizer_summary = summarize_concrete_seo_performance_optimizer(
        concrete_optimizer_data,
        concrete_seo_performance_optimizer_json,
        concrete_optimizer_error,
        concrete_optimizer_exists,
    )
    safe_sftp_lane_summary = summarize_safe_sftp_seo_apply_lane(
        safe_sftp_lane_data,
        safe_sftp_seo_apply_lane_json,
        safe_sftp_lane_error,
        safe_sftp_lane_exists,
    )

    # SEO / Performance are draft-only and read-only: they NEVER worsen the
    # master status. Only a real autonomy policy breach (handled above) may
    # escalate the action status.
    if seo_summary.get("present"):
        recommendations.append(
            f"SEO Safe Optimizer: highest_risk={safe_text(seo_summary.get('highest_risk'))}, "
            "draft/review-only, keine Live-SEO-Aenderung."
        )
    else:
        recommendations.append(
            "SEO Safe Optimizer report fehlt; run sentinel_seo_safe_optimizer.py fuer Draft-Status."
        )
    if performance_summary.get("present"):
        recommendations.append(
            "Performance Safe Improvement: read-only Empfehlungen; "
            f"origin_5xx={safe_text(performance_summary.get('origin_5xx_status'))}, "
            f"nowplaying_cache={safe_text(performance_summary.get('ai_radio_nowplaying_cache_status'))}."
        )
    if roadmap_summary.get("present"):
        recommendations.append(
            "Safe Improvement Roadmap: review-only; "
            f"next_safe={roadmap_summary.get('roadmap_next_safe_count')}, "
            f"owner_review={roadmap_summary.get('roadmap_owner_review_count')}, "
            f"blocked_high={roadmap_summary.get('roadmap_blocked_high_count')}, "
            f"monitor_only={roadmap_summary.get('roadmap_monitor_only_count')}."
        )
    if approval_queue_summary.get("present"):
        if approval_queue_summary.get("queue_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Owner Approval Queue meldet einen Breach (HIGH nicht blockiert oder "
                "apply_status != not_applied); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Owner Approval Queue: review-only; "
                f"pending={approval_queue_summary.get('pending_owner_review_count')}, "
                f"draft_only={approval_queue_summary.get('approved_for_draft_only_count')}, "
                f"blocked_high={approval_queue_summary.get('blocked_high_risk_count')}."
            )
    if owner_cli_summary.get("present"):
        if owner_cli_summary.get("queue_policy_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Owner Approval CLI meldet einen Policy-Breach (HIGH approved oder "
                "apply_status != not_applied); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Owner Approval CLI: letzte Aktion "
                f"{safe_text(owner_cli_summary.get('last_owner_action'))} "
                f"(allowed={owner_cli_summary.get('last_owner_action_allowed')}, "
                f"{safe_text(owner_cli_summary.get('last_owner_action_status_change'))})."
            )
    if draft_execution_summary.get("present"):
        if draft_execution_summary.get("planner_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Draft Execution Planner meldet einen Breach (HIGH included oder "
                "apply_status != not_applied); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Draft Execution Planner: manual draft-only; "
                f"items={draft_execution_summary.get('execution_items_count')}, "
                f"excluded={draft_execution_summary.get('excluded_items_count')}, "
                f"ready_for_manual_copy={draft_execution_summary.get('ready_for_manual_copy_count')}, "
                "apply_status all_not_applied."
            )
    else:
        recommendations.append(
            "Draft Execution Planner report fehlt; run sentinel_draft_execution_planner.py "
            "fuer approved_for_draft_only Ausfuehrungsplaene."
        )
    if owner_review_pack_summary.get("present"):
        if owner_review_pack_summary.get("review_pack_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Owner Review Pack meldet einen Breach (HIGH/MEDIUM ready_for_copy oder "
                "apply_status != not_applied); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Owner Review Pack: manual copy/review only; "
                f"review_items={owner_review_pack_summary.get('review_items_count')}, "
                f"ready_for_copy={owner_review_pack_summary.get('ready_for_copy_count')}, "
                f"excluded={owner_review_pack_summary.get('excluded_count')}, "
                "apply_status all_not_applied."
            )
    else:
        recommendations.append(
            "Owner Review Pack report fehlt; run sentinel_owner_review_pack.py "
            "fuer Owner-Copy-Paste-Unterlagen."
        )
    if manual_apply_checklist_summary.get("present"):
        if manual_apply_checklist_summary.get("checklist_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Manual Apply Checklist meldet einen Breach (productive_change=true, "
                "HIGH/MEDIUM included oder apply_status != not_applied); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Manual Apply Checklist: manual owner steps only; "
                f"items={manual_apply_checklist_summary.get('checklist_items_count')}, "
                f"ready_for_review={manual_apply_checklist_summary.get('ready_for_manual_apply_review_count')}, "
                f"excluded={manual_apply_checklist_summary.get('excluded_count')}, "
                "apply_status all_not_applied."
            )
    else:
        recommendations.append(
            "Manual Apply Checklist report fehlt; run sentinel_manual_apply_checklist.py "
            "fuer manuelle Owner-Pruefschritte."
        )
    if manual_completion_tracker_summary.get("present"):
        if manual_completion_tracker_summary.get("completion_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Manual Completion Tracker meldet einen Breach (apply_status != not_applied, "
                "HIGH/MEDIUM completed oder productive_change=true); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Manual Completion Tracker: owner progress only; "
                f"completed={manual_completion_tracker_summary.get('completed_count')}, "
                f"in_progress={manual_completion_tracker_summary.get('in_progress_count')}, "
                f"needs_review={manual_completion_tracker_summary.get('needs_review_count')}, "
                f"unchecked={manual_completion_tracker_summary.get('unchecked_count')}; "
                "apply_status all_not_applied."
            )
    else:
        recommendations.append(
            "Manual Completion Tracker report fehlt; run sentinel_manual_completion_tracker.py list "
            "fuer Owner-Fortschrittsstatus."
        )
    if post_manual_validation_summary.get("present"):
        if post_manual_validation_summary.get("safety_violation"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Post-Manual Validation meldet eine Safety-Verletzung "
                "(HIGH/MEDIUM Checklist, apply_status != not_applied, productive_change, "
                "Network oder Apply-Funktion); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Post-Manual Validation: lokale Snapshots/Reports geprueft; "
                f"status={safe_text(post_manual_validation_summary.get('status'))}, "
                f"seo={safe_text(post_manual_validation_summary.get('seo_validation_status'))}, "
                f"performance={safe_text(post_manual_validation_summary.get('performance_validation_status'))}, "
                f"safety={safe_text(post_manual_validation_summary.get('safety_validation_status'))}."
            )
    else:
        recommendations.append(
            "Post-Manual Validation report fehlt; run sentinel_post_manual_validation.py "
            "nach manuellen Owner-Aenderungen."
        )
    if owner_daily_action_summary.get("present"):
        if owner_daily_action_summary.get("summary_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Owner Daily Action Summary meldet Safety-, Completion- oder Autonomy-Breach; "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Legacy Owner Daily Action Summary (superseded): "
                f"owner_status={safe_text(owner_daily_action_summary.get('owner_status'))}, "
                f"next={safe_text(owner_daily_action_summary.get('recommended_next_owner_action'))}"
            )
    else:
        recommendations.append(
            "Owner Daily Action Summary report fehlt; run sentinel_owner_daily_action_summary.py "
            "fuer Owner-Tagesuebersicht und Autonomy-Readiness."
        )
    if safe_apply_registry_summary.get("present"):
        if safe_apply_registry_summary.get("registry_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Apply Candidate Registry meldet einen Registry-Breach "
                "(HIGH/MEDIUM registered, verbotener candidate_type oder apply_status != not_applied); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Safe Apply Candidate Registry: registry-only, kein Apply; "
                f"draft_only={safe_apply_registry_summary.get('registered_draft_only_count')}, "
                f"validation_only={safe_apply_registry_summary.get('registered_validation_only_count')}, "
                f"missing_guards={safe_apply_registry_summary.get('not_registered_missing_guards_count')}, "
                f"blocked={safe_apply_registry_summary.get('blocked_not_allowed_count')}."
            )
    else:
        recommendations.append(
            "Safe Apply Candidate Registry report fehlt; run sentinel_safe_apply_candidate_registry.py "
            "fuer die spaetere Allowlist-Vorbereitung."
        )
    if safe_apply_guard_summary.get("present"):
        if safe_apply_guard_summary.get("guard_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Apply Guard Check meldet einen Guard-Breach "
                "(apply_status != not_applied, HIGH future-autonomous oder verbotener Live-Write ready); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Safe Apply Guard Check: kein Apply; "
                f"ready_draft={safe_apply_guard_summary.get('guards_ready_draft_only_count')}, "
                f"missing={safe_apply_guard_summary.get('guards_missing_for_autonomy_count')}, "
                f"blocked={safe_apply_guard_summary.get('guards_blocked_not_allowed_count')}, "
                f"monitor={safe_apply_guard_summary.get('guards_monitor_only_count')}."
            )
    else:
        recommendations.append(
            "Safe Apply Guard Check report fehlt; run sentinel_safe_apply_guard_checker.py "
            "fuer Guard-Bereitschaft der Registry."
        )
    if safe_apply_scope_summary.get("present"):
        if safe_apply_scope_summary.get("scope_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Apply Scope Manager meldet einen Scope-Breach "
                "(HIGH/MEDIUM in allowed scope, verbotener candidate_type/Pfad oder apply_status != not_applied); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Safe Apply Scope Manager: allowlist-only, kein Apply; "
                f"draft_only={safe_apply_scope_summary.get('scope_allowed_draft_only_count')}, "
                f"validation_only={safe_apply_scope_summary.get('scope_allowed_validation_only_count')}, "
                f"missing_guards={safe_apply_scope_summary.get('scope_not_allowed_missing_guards_count')}, "
                f"blocked={safe_apply_scope_summary.get('scope_blocked_high_risk_count')}."
            )
    else:
        recommendations.append(
            "Safe Apply Scope Manager report fehlt; run sentinel_safe_apply_scope_manager.py "
            "fuer die Scope-/Allowlist-Konfiguration."
        )
    if safe_apply_dry_run_summary.get("present"):
        if safe_apply_dry_run_summary.get("dry_run_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Apply Dry-Run Planner meldet einen Dry-Run-Breach "
                "(HIGH/MEDIUM ready, can_execute_now, Netzwerk/API/Login, verbotener Pfad "
                "oder apply_status != not_applied); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Safe Apply Dry-Run Planner: dry-run-only, kein Apply; "
                f"ready_draft={safe_apply_dry_run_summary.get('dry_run_ready_draft_only_count')}, "
                f"ready_validation={safe_apply_dry_run_summary.get('dry_run_ready_validation_only_count')}, "
                f"missing_guards={safe_apply_dry_run_summary.get('dry_run_not_ready_missing_guards_count')}, "
                f"blocked={safe_apply_dry_run_summary.get('dry_run_blocked_high_risk_count')}."
            )
    else:
        recommendations.append(
            "Safe Apply Dry-Run Planner report fehlt; run sentinel_safe_apply_dry_run_planner.py "
            "fuer den Dry-Run-Plan."
        )
    if safe_apply_preflight_summary.get("present"):
        if safe_apply_preflight_summary.get("preflight_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Apply Preflight Validator meldet einen Preflight-Breach "
                "(can_execute_now, apply_status != not_applied, HIGH/MEDIUM ready, Live-Apply-Funktion, "
                "Netzwerk/API/Login oder verbotener Pfad); manueller Review erforderlich."
            )
        else:
            global_missing = safe_apply_preflight_summary.get("global_missing_requirements") or []
            missing_note = (
                f" global_missing={len(global_missing)}" if isinstance(global_missing, list) and global_missing else ""
            )
            recommendations.append(
                "Safe Apply Preflight Validator: preflight-only, kein Apply; "
                f"ready_draft={safe_apply_preflight_summary.get('preflight_ready_draft_only_count')}, "
                f"ready_validation={safe_apply_preflight_summary.get('preflight_ready_validation_only_count')}, "
                f"not_ready={safe_apply_preflight_summary.get('preflight_not_ready_count')}, "
                f"blocked={safe_apply_preflight_summary.get('preflight_blocked_count')}.{missing_note}"
            )
    else:
        recommendations.append(
            "Safe Apply Preflight Validator report fehlt; run sentinel_safe_apply_preflight_validator.py "
            "fuer die Preflight-Validierung."
        )
    if autonomy_runtime_lock_summary.get("present"):
        if autonomy_runtime_lock_summary.get("runtime_lock_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Autonomy Runtime Lock meldet einen Runtime-Lock-Breach "
                "(live_apply_enabled, owner_disable_switch=false, blocked mode in allowed_modes "
                "oder unsicherer emergency_stop); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Autonomy Runtime Lock: owner-kontrolliert, kein Apply; "
                f"autonomy_enabled={autonomy_runtime_lock_summary.get('autonomy_enabled')}, "
                f"draft_only={autonomy_runtime_lock_summary.get('draft_only_enabled')}, "
                f"live_apply={autonomy_runtime_lock_summary.get('live_apply_enabled')}, "
                f"emergency_stop={autonomy_runtime_lock_summary.get('emergency_stop')}."
            )
    else:
        recommendations.append(
            "Autonomy Runtime Lock report fehlt; run sentinel_autonomy_runtime_lock.py status "
            "fuer den Owner-Runtime-Lock."
        )
    if safe_draft_runner_summary.get("present"):
        if safe_draft_runner_summary.get("runner_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Draft Autonomy Runner meldet einen Runner-Breach "
                "(live_apply, productive_change, apply_status != not_applied, HIGH/MEDIUM executed, "
                "verbotene Aktion, Schreibpfad ausserhalb der Allowlist, Netzwerk/API/Login oder Lauf trotz "
                "emergency_stop); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Safe Draft Autonomy Runner: draft-/validation-only, kein Live-Apply; "
                f"status={safe_draft_runner_summary.get('runner_status')}, "
                f"executed_draft={safe_draft_runner_summary.get('executed_draft_only_count')}, "
                f"executed_validation={safe_draft_runner_summary.get('executed_validation_only_count')}, "
                f"skipped={safe_draft_runner_summary.get('skipped_count')}."
            )
    else:
        recommendations.append(
            "Safe Draft Autonomy Runner report fehlt; run sentinel_safe_draft_autonomy_runner.py "
            "fuer den Draft-only-Autonomie-Lauf."
        )

    if safe_draft_verifier_summary.get("present"):
        if safe_draft_verifier_summary.get("verifier_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Draft Autonomy Verifier meldet einen Verifier-Breach "
                "(Output ausserhalb der Allowlist, Secret-Muster, ungueltiges JSON, live_apply, "
                "productive_change, apply_status != not_applied, verbotener Pfad oder Netzwerk/API/Login); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Safe Draft Autonomy Verifier: read-only Verifikation, kein Live-Apply; "
                f"status={safe_draft_verifier_summary.get('verifier_status')}, "
                f"safe_outputs={safe_draft_verifier_summary.get('verified_safe_outputs_count')}, "
                f"missing={safe_draft_verifier_summary.get('missing_outputs_count')}, "
                f"invalid_json={safe_draft_verifier_summary.get('invalid_json_count')}, "
                f"forbidden={safe_draft_verifier_summary.get('forbidden_path_count')}."
            )
    else:
        recommendations.append(
            "Safe Draft Autonomy Verifier report fehlt; run sentinel_safe_draft_autonomy_verifier.py "
            "fuer die Verifikation der Runner-Ausgaben."
        )

    if safe_draft_scheduler_summary.get("present"):
        if safe_draft_scheduler_summary.get("scheduler_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Draft Autonomy Scheduler Plan meldet einen Scheduler-Breach "
                "(can_install_timer_now, timer_installation_status != not_installed, verbotenes/Live-Apply/"
                "Netzwerk-Command, can_execute_live, apply_status != not_applied oder systemd/crontab-Schreibpfad); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Legacy Safe Draft Autonomy Scheduler Plan (superseded): review-only, kein Timer installiert, kein Live-Apply; "
                f"status={safe_draft_scheduler_summary.get('scheduler_status')}, "
                f"frequency={safe_draft_scheduler_summary.get('planned_frequency')}, "
                f"timer={safe_draft_scheduler_summary.get('timer_installation_status')}, "
                f"can_install={safe_draft_scheduler_summary.get('can_install_timer_now')}."
            )
    else:
        recommendations.append(
            "Safe Draft Autonomy Scheduler Plan report fehlt; run sentinel_safe_draft_autonomy_scheduler_plan.py "
            "fuer den Review-Scheduler-Plan."
        )

    if safe_draft_timer_summary.get("present"):
        if safe_draft_timer_summary.get("timer_draft_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Draft Autonomy Timer Draft meldet einen Timer-Draft-Breach "
                "(echter systemd/cron-Schreibpfad, installierter Timer, can_install_timer_now, can_execute_live, "
                "live_apply, apply_status != not_applied, verbotenes/Netzwerk/Live-Apply-Command in ausfuehrbarer "
                "Position oder Secret-Environment); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Legacy Safe Draft Autonomy Timer Draft (superseded): review-only Drafts unter drafts/apply, kein Timer installiert, "
                "kein Live-Apply; "
                f"status={safe_draft_timer_summary.get('timer_draft_status')}, "
                f"timer={safe_draft_timer_summary.get('timer_installation_status')}, "
                f"service_draft={safe_draft_timer_summary.get('service_draft_written')}, "
                f"timer_draft={safe_draft_timer_summary.get('timer_draft_written')}."
            )
    else:
        recommendations.append(
            "Safe Draft Autonomy Timer Draft report fehlt; run sentinel_safe_draft_autonomy_timer_draft.py "
            "fuer das Timer-Unit-Draft-Pack."
        )

    if safe_draft_timer_review_summary.get("present"):
        if safe_draft_timer_review_summary.get("install_reviewer_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Draft Autonomy Timer Install Review meldet einen Install-Reviewer-Breach "
                "(echter systemd/cron-Schreibvorgang, installierter Timer, can_install_timer_now, can_execute_live, "
                "live_apply, apply_status != not_applied, aktive verbotene/Netzwerk/systemctl/Live-Apply-Zeile in einem "
                "Draft oder Secret-Environment); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Safe Draft Autonomy Timer Install Review: review-only Readiness-Bewertung, kein Timer installiert, "
                "kein Live-Apply; "
                f"status={safe_draft_timer_review_summary.get('install_review_status')}, "
                f"can_install={safe_draft_timer_review_summary.get('can_install_timer_now')}, "
                f"checks_passed={safe_draft_timer_review_summary.get('safe_checks_passed_count')}, "
                f"checks_failed={safe_draft_timer_review_summary.get('safe_checks_failed_count')}."
            )
    else:
        recommendations.append(
            "Safe Draft Autonomy Timer Install Review report fehlt; run "
            "sentinel_safe_draft_autonomy_timer_install_reviewer.py fuer die Install-Readiness-Bewertung."
        )

    if owner_manual_timer_packet_summary.get("present"):
        if owner_manual_timer_packet_summary.get("packet_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Owner Manual Timer Install Packet meldet einen Packet-Breach "
                "(install_allowed_now, can_install_timer_now, timer_installation_status, Live-Apply, "
                "echter systemd/cron/.sh-Output, verbotener Pfad, Secret-Output oder apply_status != not_applied); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Owner Manual Timer Install Packet: review-only, keine Installation, kein Live-Apply; "
                f"status={owner_manual_timer_packet_summary.get('packet_status')}, "
                f"install_allowed={owner_manual_timer_packet_summary.get('install_allowed_now')}, "
                f"can_install={owner_manual_timer_packet_summary.get('can_install_timer_now')}, "
                f"emergency_stop={owner_manual_timer_packet_summary.get('emergency_stop_active')}."
            )
    else:
        recommendations.append(
            "Owner Manual Timer Install Packet report fehlt; run "
            "sentinel_owner_manual_timer_install_packet.py fuer das Review-only Install Packet."
        )

    if owner_timer_decision_summary.get("present"):
        if owner_timer_decision_summary.get("decision_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Owner Timer Install Decision Gate meldet einen Decision-Breach "
                "(install_allowed_now, can_install_timer_now, systemd/crontab write, live_apply, "
                "can_execute_live, apply_status != not_applied, fehlende Acknowledgements oder verbotener Output); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Owner Timer Install Decision Gate: decision-only, keine Installation, kein Live-Apply; "
                f"decision={owner_timer_decision_summary.get('decision_status')}, "
                f"manual_allowed={owner_timer_decision_summary.get('manual_install_allowed')}, "
                f"install_allowed={owner_timer_decision_summary.get('install_allowed_now')}."
            )
    else:
        recommendations.append(
            "Owner Timer Install Decision Gate report fehlt; run "
            "sentinel_owner_timer_install_decision_gate.py status fuer den Owner-Entscheidungsstatus."
        )

    if manual_timer_preview_summary.get("present"):
        if manual_timer_preview_summary.get("preview_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Manual Timer Install Command Preview meldet einen Preview-Breach "
                "(install_allowed_now, can_install_timer_now, .sh/systemd/crontab Output, live_apply, "
                "can_execute_live, apply_status != not_applied, Secret-Output oder verbotener Pfad); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Manual Timer Install Command Preview: review-only Markdown/JSON, keine Installation; "
                f"status={manual_timer_preview_summary.get('preview_status')}, "
                f"install_allowed={manual_timer_preview_summary.get('install_allowed_now')}, "
                f"command_preview_written={manual_timer_preview_summary.get('command_preview_written')}."
            )
    else:
        recommendations.append(
            "Manual Timer Install Command Preview report fehlt; run "
            "sentinel_manual_timer_install_command_preview.py fuer die Review-only Kommandovorschau."
        )

    if owner_timer_evidence_summary.get("present"):
        if owner_timer_evidence_summary.get("evidence_pack_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Owner Timer Install Evidence Pack meldet einen Evidence-Pack-Breach "
                "(install_allowed_now, can_install_timer_now, .sh/systemd/crontab Output, live_apply, "
                "can_execute_live, apply_status != not_applied, Secret-Output oder verbotener Pfad); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Owner Timer Install Evidence Pack: review-only Nachweis-Templates, keine Installation; "
                f"status={owner_timer_evidence_summary.get('evidence_pack_status')}, "
                f"install_allowed={owner_timer_evidence_summary.get('install_allowed_now')}, "
                f"template_written={owner_timer_evidence_summary.get('evidence_template_written')}."
            )
    else:
        recommendations.append(
            "Owner Timer Install Evidence Pack report fehlt; run "
            "sentinel_owner_timer_install_evidence_pack.py fuer die Evidence-/Nachweis-Templates."
        )

    if final_safety_summary.get("present"):
        if final_safety_summary.get("final_safety_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe Draft Autonomy Final Safety Report meldet einen Final-Safety-Breach "
                "(Install-/Live-Apply-Flag, Phase-Breach, verbotener Output, Netzwerk/API/Login oder apply_status != not_applied); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Safe Draft Autonomy Final Safety Report: "
                f"status={final_safety_summary.get('final_safety_status')}, "
                f"breaches={final_safety_summary.get('total_breach_count')}, "
                f"live_apply={final_safety_summary.get('live_apply_allowed')}, "
                f"next={final_safety_summary.get('final_recommended_owner_action')}."
            )
    else:
        recommendations.append(
            "Safe Draft Autonomy Final Safety Report fehlt; run "
            "sentinel_safe_draft_autonomy_final_safety_report.py fuer die finale Konsolidierung."
        )

    if manual_evidence_dashboard_summary.get("present"):
        if manual_evidence_dashboard_summary.get("dashboard_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Manual Evidence Review Dashboard meldet einen Dashboard-Breach "
                "(Live-/Install-Flag, upstream Breach, systemd/crontab write, Netzwerk/API/Login oder apply_status != not_applied); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Manual Evidence Review Dashboard: owner-review-only, keine Installation; "
                f"status={manual_evidence_dashboard_summary.get('dashboard_status')}, "
                f"breaches={manual_evidence_dashboard_summary.get('total_breaches')}, "
                f"install_allowed={manual_evidence_dashboard_summary.get('install_allowed_now')}."
            )
    else:
        recommendations.append(
            "Manual Evidence Review Dashboard fehlt; run "
            "sentinel_manual_evidence_review_dashboard.py fuer das Owner-Dashboard."
        )

    if manual_evidence_completion_summary.get("present"):
        if manual_evidence_completion_summary.get("tracker_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Manual Evidence Review Completion Tracker meldet einen Tracker-Breach "
                "(Live-/Install-Flag, systemd/crontab write, apply_status != not_applied oder Secret-/Write-Safety-Verletzung); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Manual Evidence Review Completion Tracker: owner progress only, keine Installation; "
                f"status={manual_evidence_completion_summary.get('tracker_status')}, "
                f"reviewed={manual_evidence_completion_summary.get('reviewed_count')}/"
                f"{manual_evidence_completion_summary.get('total_items')}, "
                f"blocked={manual_evidence_completion_summary.get('blocked_count')}."
            )
    else:
        recommendations.append(
            "Manual Evidence Review Completion Tracker fehlt; run "
            "sentinel_manual_evidence_review_completion_tracker.py list fuer den Owner-Review-Fortschritt."
        )

    if manual_evidence_gate_summary.get("present"):
        if manual_evidence_gate_summary.get("gate_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Manual Evidence Review Completion Gate meldet einen Gate-Breach "
                "(Live-/Install-Flag, upstream Breach, systemd/crontab write, apply_status != not_applied oder Secret-/Write-Safety-Verletzung); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Manual Evidence Review Completion Gate: Entscheidungsvorlage ohne Installation; "
                f"status={manual_evidence_gate_summary.get('gate_status')}, "
                f"reviewed={manual_evidence_gate_summary.get('reviewed_count')}/"
                f"{manual_evidence_gate_summary.get('total_items')}, "
                f"breach={manual_evidence_gate_summary.get('gate_breach')}."
            )
    else:
        recommendations.append(
            "Manual Evidence Review Completion Gate fehlt; run "
            "sentinel_manual_evidence_review_completion_gate.py fuer die Owner-Entscheidungsvorlage."
        )

    if owner_evidence_console_summary.get("present"):
        if owner_evidence_console_summary.get("console_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Owner Evidence Review Console meldet einen Console-Breach "
                "(unsicherer Suggested Command, Live-/Install-Flag, upstream Gate-Breach, systemd/crontab write oder Secret-/Write-Safety-Verletzung); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Owner Evidence Review Console: lokale Review-Konsole ohne Installation; "
                f"status={owner_evidence_console_summary.get('console_status')}, "
                f"open={owner_evidence_console_summary.get('open_items_count')}, "
                f"next={owner_evidence_console_summary.get('next_recommended_item')}."
            )
    else:
        recommendations.append(
            "Owner Evidence Review Console fehlt; run "
            "sentinel_owner_evidence_review_console.py fuer die lokale Review-Konsole."
        )

    if final_owner_snapshot_summary.get("present"):
        if final_owner_snapshot_summary.get("snapshot_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Final Owner Decision Snapshot meldet einen Snapshot-Breach "
                "(Live-/Install-Flag, upstream Breach, timer installed, systemd/crontab write oder Secret-/Write-Safety-Verletzung); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Final Owner Decision Snapshot: Abschlussnachweis ohne Installation; "
                f"status={final_owner_snapshot_summary.get('snapshot_status')}, "
                f"review={final_owner_snapshot_summary.get('reviewed_count')}/"
                f"{final_owner_snapshot_summary.get('total_items')}, "
                f"breach={final_owner_snapshot_summary.get('snapshot_breach')}."
            )
    else:
        recommendations.append(
            "Final Owner Decision Snapshot fehlt; run "
            "sentinel_final_owner_decision_snapshot.py fuer den finalen Abschlussnachweis."
        )

    if master_critical_cause_summary.get("present"):
        if master_critical_cause_summary.get("snapshot_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Master Critical Cause Snapshot meldet einen Snapshot-Breach "
                "(Live-/Install-Flag, apply_status != not_applied, systemd/crontab write, Apply-Command oder Secret-/Write-Safety-Verletzung); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Master Critical Cause Snapshot: read-only Ursachenanalyse; "
                f"status={master_critical_cause_summary.get('critical_snapshot_status')}, "
                f"autonomy_cause={master_critical_cause_summary.get('critical_caused_by_autonomy')}, "
                f"website_cause={master_critical_cause_summary.get('critical_caused_by_website')}."
            )
    else:
        recommendations.append(
            "Master Critical Cause Snapshot fehlt; run "
            "sentinel_master_critical_cause_snapshot.py zur CRITICAL-Ursachentrennung."
        )

    if rolling_window_decay_summary.get("present"):
        if rolling_window_decay_summary.get("snapshot_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Rolling Window Decay Observer meldet einen Snapshot-Breach "
                "(Live-/Install-Flag, apply_status != not_applied, systemd/crontab write, Apply-Command oder Secret-/Write-Safety-Verletzung); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Rolling Window Decay Observer: read-only 24h-Fenster-Beobachtung; "
                f"status={rolling_window_decay_summary.get('decay_status')}, "
                f"trend={rolling_window_decay_summary.get('trend')}, "
                f"delta_5xx={rolling_window_decay_summary.get('delta_5xx')}."
            )
    else:
        recommendations.append(
            "Rolling Window Decay Observer fehlt; run "
            "sentinel_rolling_window_decay_observer.py zur read-only 24h-Fenster-Beobachtung."
        )

    if low_growth_timeline_summary.get("present"):
        if low_growth_timeline_summary.get("snapshot_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Low Growth Readiness Timeline meldet einen Snapshot-Breach "
                "(Live-/Install-Flag, apply_status != not_applied, systemd/crontab write, Apply-Command oder Secret-/Write-Safety-Verletzung); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Low Growth Readiness Timeline: read-only Entscheidungsvorlage; "
                f"status={low_growth_timeline_summary.get('timeline_status')}, "
                f"last_trend={low_growth_timeline_summary.get('last_trend')}, "
                f"consecutive_stable_or_decreasing={low_growth_timeline_summary.get('consecutive_stable_or_decreasing_points')}."
            )
    else:
        recommendations.append(
            "Low Growth Readiness Timeline fehlt; run "
            "sentinel_low_growth_readiness_timeline.py zur read-only Reife-Bewertung."
        )

    if manual_recheck_gate_summary.get("present"):
        if manual_recheck_gate_summary.get("gate_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Manual Website Recheck Gate meldet einen Gate-Breach "
                "(upstream Breach, Live-/Install-Flag, apply_status != not_applied, systemd/crontab write, Apply-Command oder Secret-/Write-Safety-Verletzung); "
                "manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "Manual Website Recheck Gate: read-only Entscheidungsvorlage; "
                f"status={manual_recheck_gate_summary.get('gate_status')}, "
                f"recommended={manual_recheck_gate_summary.get('manual_recheck_recommended')}, "
                f"last_trend={manual_recheck_gate_summary.get('last_trend')}."
            )
    else:
        recommendations.append(
            "Manual Website Recheck Gate fehlt; run "
            "sentinel_manual_website_recheck_gate.py zur read-only Recheck-Entscheidung."
        )

    if low_risk_readiness_gate_summary.get("present"):
        if low_risk_readiness_gate_summary.get("readiness_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Low-Risk Autonomy Readiness Gate meldet einen Readiness-Breach "
                "(low_risk_autonomy_allowed_now/live_apply/install/timer-Flag, apply_status != not_applied, "
                "systemd/crontab write, Apply-Command, upstream Breach oder Secret-/Write-Safety-Verletzung); "
                "manueller Review erforderlich, Autonomie bleibt deaktiviert."
            )
        else:
            recommendations.append(
                "Low-Risk Autonomy Readiness Gate: read-only Entscheidungsvorlage; "
                f"status={low_risk_readiness_gate_summary.get('readiness_status')}, "
                f"allowed_now={low_risk_readiness_gate_summary.get('low_risk_autonomy_allowed_now')}, "
                f"policy_draft_allowed={low_risk_readiness_gate_summary.get('low_risk_policy_draft_allowed')}."
            )
    else:
        recommendations.append(
            "Low-Risk Autonomy Readiness Gate fehlt; run "
            "sentinel_low_risk_autonomy_readiness_gate.py zur read-only Readiness-Entscheidung."
        )

    if low_risk_policy_boundary_summary.get("present"):
        if low_risk_policy_boundary_summary.get("policy_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "LOW-RISK Policy Boundary Draft meldet einen Policy-Breach "
                "(policy_activation_allowed/low_risk_autonomy_allowed_now/live_apply/install/timer-Flag, "
                "apply_status != not_applied, systemd/crontab write, Apply-Command, upstream Breach "
                "oder Secret-/Write-Safety-Verletzung); manueller Review erforderlich, Aktivierung bleibt gesperrt."
            )
        else:
            recommendations.append(
                "LOW-RISK Policy Boundary Draft: read-only Owner-Review-Entwurf; "
                f"status={low_risk_policy_boundary_summary.get('policy_status')}, "
                f"activation_allowed={low_risk_policy_boundary_summary.get('policy_activation_allowed')}, "
                f"draft_only={low_risk_policy_boundary_summary.get('low_risk_draft_only_count')}, "
                f"never_auto_apply={low_risk_policy_boundary_summary.get('high_never_auto_apply_count')}."
            )
    else:
        recommendations.append(
            "LOW-RISK Policy Boundary Draft fehlt; run "
            "sentinel_low_risk_policy_boundary_draft.py zum read-only Policy-Entwurf."
        )

    if low_risk_owner_review_summary.get("present"):
        if low_risk_owner_review_summary.get("tracker_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "LOW-RISK Policy Owner Review Tracker meldet einen Tracker-Breach "
                "(Aktivierungs-/Apply-/Install-Flag, apply_status != not_applied, systemd/crontab/Script, "
                "Secret-/Write-Safety-Verletzung oder upstream Breach); manueller Review erforderlich."
            )
        else:
            recommendations.append(
                "LOW-RISK Policy Owner Review: review-only Tracker; "
                f"status={low_risk_owner_review_summary.get('tracker_status')}, "
                f"reviewed={low_risk_owner_review_summary.get('reviewed_count')}/"
                f"{low_risk_owner_review_summary.get('total_required')}, "
                f"activation_allowed={low_risk_owner_review_summary.get('policy_activation_allowed')}."
            )
    else:
        recommendations.append(
            "LOW-RISK Policy Owner Review Tracker fehlt; run "
            "sentinel_low_risk_policy_owner_review_tracker.py fuer die Owner-Review-Checkliste."
        )

    if low_risk_completion_gate_summary.get("present"):
        if low_risk_completion_gate_summary.get("gate_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "LOW-RISK Policy Review Completion Gate meldet einen Gate-Breach; "
                "manueller Review erforderlich, Autonomie bleibt deaktiviert."
            )
        else:
            recommendations.append(
                "LOW-RISK Policy Review Completion Gate: read-only Gate; "
                f"status={low_risk_completion_gate_summary.get('gate_status')}, "
                f"reviewed={low_risk_completion_gate_summary.get('reviewed_count')}/"
                f"{low_risk_completion_gate_summary.get('total_required')}, "
                f"activation_allowed={low_risk_completion_gate_summary.get('policy_activation_allowed')}."
            )
    else:
        recommendations.append(
            "LOW-RISK Policy Review Completion Gate fehlt; run "
            "sentinel_low_risk_policy_review_completion_gate.py."
        )

    if low_risk_final_seal_summary.get("present"):
        if low_risk_final_seal_summary.get("seal_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "LOW-RISK Autonomy Final Safety Seal meldet einen Seal-Breach; "
                "nicht fortfahren, bevor der Breach geklaert ist."
            )
        else:
            recommendations.append(
                "LOW-RISK Autonomy Final Safety Seal: read-only Abschluss; "
                f"status={low_risk_final_seal_summary.get('seal_status')}, "
                f"review_completed={low_risk_final_seal_summary.get('review_completed')}, "
                f"live_apply={low_risk_final_seal_summary.get('live_apply')}."
            )
    else:
        recommendations.append(
            "LOW-RISK Autonomy Final Safety Seal fehlt; run "
            "sentinel_low_risk_autonomy_final_safety_seal.py."
        )

    if safe_end_summary.get("present"):
        if safe_end_summary.get("safe_end_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe End Summary meldet einen Breach; keine Aktivierung, keinen Install und keinen Apply ausfuehren."
            )
        else:
            recommendations.append(
                "Safe End Summary: sicherer gesperrter Endzustand, keine Aktivierung; "
                f"status={safe_end_summary.get('safe_end_status')}, "
                f"emergency_stop={safe_end_summary.get('emergency_stop_active')}, "
                f"live_apply={safe_end_summary.get('live_apply')}."
            )
    else:
        recommendations.append(
            "Safe End Summary fehlt; run sentinel_safe_end_summary.py. "
            "Phase 5.10 is a safe locked end state, not autonomy activation."
        )

    if safe_end_archive_summary.get("present"):
        if safe_end_archive_summary.get("archive_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe-End Archive Snapshot meldet einen Archive-Breach; "
                "Archiv nicht als final verwenden, bis Breach geklaert ist."
            )
        else:
            recommendations.append(
                "Safe-End Archive Snapshot: audit-only Archiv, keine Aktivierung/Installation/Restore; "
                f"status={safe_end_archive_summary.get('archive_status')}, "
                f"copied={safe_end_archive_summary.get('copied_file_count')}, "
                f"checksums={safe_end_archive_summary.get('checksum_count')}."
            )
    else:
        recommendations.append(
            "Safe-End Archive Snapshot fehlt; run sentinel_safe_end_archive_snapshot.py. "
            "Phase 5.11 archives the locked safe end state. It is not activation, not install, not restore."
        )

    if safe_end_integrity_summary.get("present"):
        if safe_end_integrity_summary.get("integrity_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe-End Archive Integrity Verifier meldet einen Integritaets-Breach; "
                "Archiv nicht verwenden, bis Mismatch/Forbidden/Breach geklaert ist."
            )
        else:
            recommendations.append(
                "Safe-End Archive Integrity: read-only geprueft, kein Restore/Install/Apply; "
                f"status={safe_end_integrity_summary.get('integrity_status')}, "
                f"verified={safe_end_integrity_summary.get('verified_checksum_count')}, "
                f"mismatch={safe_end_integrity_summary.get('checksum_mismatch_count')}."
            )
    else:
        recommendations.append(
            "Safe-End Archive Integrity Verifier fehlt; run sentinel_safe_end_archive_integrity_verifier.py. "
            "Phase 5.12 verifies the locked archive. It is not restore, not activation, not install."
        )

    if concrete_optimizer_summary.get("present"):
        if concrete_optimizer_summary.get("optimizer_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Concrete SEO/Performance Optimizer meldet einen Breach; "
                "Owner-Drafts nicht verwenden, bis der Breach geklaert ist."
            )
        else:
            recommendations.append(
                "Concrete SEO/Performance Pack: owner-review Drafts erstellt; "
                f"status={concrete_optimizer_summary.get('optimizer_status')}, "
                f"recommendations={concrete_optimizer_summary.get('total_recommendations')}, "
                f"copy_paste={concrete_optimizer_summary.get('copy_paste_owner_apply_count')}, "
                f"diagnostic={concrete_optimizer_summary.get('diagnostic_only_count')}."
            )
    else:
        recommendations.append(
            "Concrete SEO/Performance Optimizer fehlt; run "
            "sentinel_concrete_seo_performance_optimizer.py fuer konkrete Owner-Drafts."
        )

    if safe_sftp_lane_summary.get("present"):
        if safe_sftp_lane_summary.get("apply_breach"):
            action_status = escalate_action_status_for_autonomy(action_status)
            if overall_master_status == STATUS_OK:
                overall_master_status = STATUS_WARNING
            recommendations.append(
                "Safe SFTP SEO Apply Lane meldet einen Apply-Breach "
                "(Aenderung ausserhalb erlaubtem MU-Plugin-Ziel, >1 Live-Datei, .htaccess/wp-config/Theme/Plugin, "
                "Cloudflare/Nginx/systemd/crontab, DB-Write, Secret-Output, eval/base64/remote-include, "
                "Healthcheck+Rollback-Fehler oder Upload ohne Owner-Approval); sofort pruefen, kein weiterer Apply."
            )
        else:
            recommendations.append(
                "Safe SFTP SEO Apply Lane: gated JSON-LD MU-Plugin Lane; "
                f"status={safe_sftp_lane_summary.get('apply_lane_status')}, "
                f"mode={safe_sftp_lane_summary.get('mode')}, "
                f"uploaded={safe_sftp_lane_summary.get('uploaded')}, "
                f"healthcheck={safe_sftp_lane_summary.get('healthcheck_status')}, "
                f"changed_files={safe_sftp_lane_summary.get('changed_file_count')}. "
                "Dry-run/prepare only unless explicit owner approval exists."
            )
    else:
        recommendations.append(
            "Safe SFTP SEO Apply Lane fehlt; run sentinel_safe_sftp_seo_apply_lane.py dry-run "
            "(dry-run/prepare only; live apply needs explicit owner approval)."
        )

    deduped_recommendations: List[str] = []
    for recommendation in recommendations:
        if recommendation not in deduped_recommendations:
            deduped_recommendations.append(recommendation)
    recommendations = deduped_recommendations

    self_comparison = {"present": False}
    if previous_master_exists and isinstance(previous_master_data, dict):
        self_comparison = {
            "present": True,
            "previous_generated_at_utc": safe_text(previous_master_data.get("generated_at_utc")),
            "previous_overall_master_status": safe_text(previous_master_data.get("overall_master_status")),
            "previous_action_status": safe_text(previous_master_data.get("action_status")),
            "overall_status_changed": safe_text(previous_master_data.get("overall_master_status")) != overall_master_status,
        }

    challenge_diagnosis = read_challenge_diagnosis(DEFAULT_CHALLENGE_DIAGNOSIS_JSON)

    report = {
        "schema_version": "1.0",
        "generated_at_utc": generated_at,
        "overall_master_status": overall_master_status,
        "action_status": action_status,
        "website_status": website_status,
        "website_correlation_status": website_correlation_status,
        "hetzner_local_status": hetzner_local_status,
        "private_pc_local_status": private_pc_status,
        "private_pc_last_known_local_confirmation": private_pc_summary.get("last_known_local_confirmation"),
        "local_status": hetzner_local_status,
        "local_status_compatibility_note": "local_status is retained as a compatibility alias for hetzner_local_status.",
        "website_correlation_v2_findings": website_summary.get("correlation_v2_findings", []),
        "website_origin_pressure_breakdown": website_summary.get("origin_pressure_breakdown", {}),
        "website_source_map_404_breakdown": website_summary.get("source_map_404_breakdown", {}),
        "website_ok_readiness": website_summary.get("ok_readiness", {}),
        "cloudflare_challenge_diagnosis": challenge_diagnosis,
        "sourcemap_prevention_status": sourcemap_summary.get("status"),
        "sourcemap_prevention": sourcemap_summary,
        "ai_radio_timeout_status": ai_radio_summary.get("status"),
        "ai_radio_timeout_diagnosis": ai_radio_summary,
        "autonomy_policy_status": autonomy_summary.get("status"),
        "autonomy_policy": autonomy_summary,
        "seo_safe_optimizer_status": seo_summary.get("status"),
        "seo_safe_optimizer": seo_summary,
        "performance_safe_improvement_status": performance_summary.get("status"),
        "performance_safe_improvement": performance_summary,
        "safe_improvement_roadmap_status": roadmap_summary.get("status"),
        "safe_improvement_roadmap": roadmap_summary,
        "approval_queue_status": approval_queue_summary.get("status"),
        "approval_queue": approval_queue_summary,
        "owner_approval_cli_status": owner_cli_summary.get("status"),
        "owner_approval_cli": owner_cli_summary,
        "draft_execution_planner_status": draft_execution_summary.get("status"),
        "draft_execution_planner": draft_execution_summary,
        "owner_review_pack_status": owner_review_pack_summary.get("status"),
        "owner_review_pack": owner_review_pack_summary,
        "manual_apply_checklist_status": manual_apply_checklist_summary.get("status"),
        "manual_apply_checklist": manual_apply_checklist_summary,
        "manual_completion_tracker_status": manual_completion_tracker_summary.get("status"),
        "manual_completion_tracker": manual_completion_tracker_summary,
        "post_manual_validation_status": post_manual_validation_summary.get("status"),
        "post_manual_validation": post_manual_validation_summary,
        "owner_daily_action_summary_status": owner_daily_action_summary.get("status"),
        "owner_daily_action_summary": owner_daily_action_summary,
        "safe_apply_candidate_registry_status": safe_apply_registry_summary.get("status"),
        "safe_apply_candidate_registry": safe_apply_registry_summary,
        "safe_apply_guard_check_status": safe_apply_guard_summary.get("status"),
        "safe_apply_guard_check": safe_apply_guard_summary,
        "safe_apply_scope_manager_status": safe_apply_scope_summary.get("status"),
        "safe_apply_scope_manager": safe_apply_scope_summary,
        "safe_apply_dry_run_planner_status": safe_apply_dry_run_summary.get("status"),
        "safe_apply_dry_run_planner": safe_apply_dry_run_summary,
        "safe_apply_preflight_validator_status": safe_apply_preflight_summary.get("status"),
        "safe_apply_preflight_validator": safe_apply_preflight_summary,
        "autonomy_runtime_lock_status": autonomy_runtime_lock_summary.get("status"),
        "autonomy_runtime_lock": autonomy_runtime_lock_summary,
        "safe_draft_autonomy_runner_status": safe_draft_runner_summary.get("status"),
        "safe_draft_autonomy_runner": safe_draft_runner_summary,
        "safe_draft_autonomy_verifier_status": safe_draft_verifier_summary.get("status"),
        "safe_draft_autonomy_verifier": safe_draft_verifier_summary,
        "safe_draft_autonomy_scheduler_plan_status": safe_draft_scheduler_summary.get("status"),
        "safe_draft_autonomy_scheduler_plan": safe_draft_scheduler_summary,
        "safe_draft_autonomy_timer_draft_status": safe_draft_timer_summary.get("status"),
        "safe_draft_autonomy_timer_draft": safe_draft_timer_summary,
        "safe_draft_autonomy_timer_install_review_status": safe_draft_timer_review_summary.get("status"),
        "safe_draft_autonomy_timer_install_review": safe_draft_timer_review_summary,
        "owner_manual_timer_install_packet_status": owner_manual_timer_packet_summary.get("status"),
        "owner_manual_timer_install_packet": owner_manual_timer_packet_summary,
        "owner_timer_install_decision_gate_status": owner_timer_decision_summary.get("status"),
        "owner_timer_install_decision_gate": owner_timer_decision_summary,
        "manual_timer_install_command_preview_status": manual_timer_preview_summary.get("status"),
        "manual_timer_install_command_preview": manual_timer_preview_summary,
        "owner_timer_install_evidence_pack_status": owner_timer_evidence_summary.get("status"),
        "owner_timer_install_evidence_pack": owner_timer_evidence_summary,
        "safe_draft_autonomy_final_safety_status": final_safety_summary.get("status"),
        "safe_draft_autonomy_final_safety": final_safety_summary,
        "manual_evidence_review_dashboard_status": manual_evidence_dashboard_summary.get("status"),
        "manual_evidence_review_dashboard": manual_evidence_dashboard_summary,
        "manual_evidence_review_completion_tracker_status": manual_evidence_completion_summary.get("status"),
        "manual_evidence_review_completion_tracker": manual_evidence_completion_summary,
        "manual_evidence_review_completion_gate_status": manual_evidence_gate_summary.get("status"),
        "manual_evidence_review_completion_gate": manual_evidence_gate_summary,
        "owner_evidence_review_console_status": owner_evidence_console_summary.get("status"),
        "owner_evidence_review_console": owner_evidence_console_summary,
        "final_owner_decision_snapshot_status": final_owner_snapshot_summary.get("status"),
        "final_owner_decision_snapshot": final_owner_snapshot_summary,
        "master_critical_cause_snapshot_status": master_critical_cause_summary.get("status"),
        "master_critical_cause_snapshot": master_critical_cause_summary,
        "rolling_window_decay_observer_status": rolling_window_decay_summary.get("status"),
        "rolling_window_decay_observer": rolling_window_decay_summary,
        "low_growth_readiness_timeline_status": low_growth_timeline_summary.get("status"),
        "low_growth_readiness_timeline": low_growth_timeline_summary,
        "manual_website_recheck_gate_status": manual_recheck_gate_summary.get("status"),
        "manual_website_recheck_gate": manual_recheck_gate_summary,
        "low_risk_autonomy_readiness_gate_status": low_risk_readiness_gate_summary.get("status"),
        "low_risk_autonomy_readiness_gate": low_risk_readiness_gate_summary,
        "low_risk_policy_boundary_draft_status": low_risk_policy_boundary_summary.get("status"),
        "low_risk_policy_boundary_draft": low_risk_policy_boundary_summary,
        "low_risk_policy_owner_review_tracker_status": low_risk_owner_review_summary.get("status"),
        "low_risk_policy_owner_review_tracker": low_risk_owner_review_summary,
        "low_risk_policy_review_completion_gate_status": low_risk_completion_gate_summary.get("status"),
        "low_risk_policy_review_completion_gate": low_risk_completion_gate_summary,
        "low_risk_autonomy_final_safety_seal_status": low_risk_final_seal_summary.get("status"),
        "low_risk_autonomy_final_safety_seal": low_risk_final_seal_summary,
        "safe_end_summary_status": safe_end_summary.get("status"),
        "safe_end_summary": safe_end_summary,
        "safe_end_archive_snapshot_status": safe_end_archive_summary.get("status"),
        "safe_end_archive_snapshot": safe_end_archive_summary,
        "safe_end_archive_integrity_verifier_status": safe_end_integrity_summary.get("status"),
        "safe_end_archive_integrity_verifier": safe_end_integrity_summary,
        "concrete_seo_performance_optimizer_status": concrete_optimizer_summary.get("status"),
        "concrete_seo_performance_optimizer": concrete_optimizer_summary,
        "safe_sftp_seo_apply_lane_status": safe_sftp_lane_summary.get("status"),
        "safe_sftp_seo_apply_lane": safe_sftp_lane_summary,
        "production_pipeline_status": production_pipeline_data.get("status") if production_pipeline_exists and isinstance(production_pipeline_data, dict) else "NOT_AVAILABLE",
        "production_pipeline": production_pipeline_data if production_pipeline_exists and isinstance(production_pipeline_data, dict) else {"present": False},
        "nowplaying_recovery_status": nowplaying_recovery_data.get("status") if nowplaying_recovery_exists and isinstance(nowplaying_recovery_data, dict) else "NOT_AVAILABLE",
        "nowplaying_recovery": nowplaying_recovery_data if nowplaying_recovery_exists and isinstance(nowplaying_recovery_data, dict) else {"present": False},
        "canonical_truth_status": canonical_truth_snapshot.get("status", "NOT_AVAILABLE"),
        "canonical_truth": canonical_truth_summary(canonical_truth_snapshot),
        "canonical_header": canonical_header,
        "legacy_supersession": legacy_supersession_summary(canonical_truth_snapshot),
        "self_comparison": self_comparison,
        "sources": {
            "website": website_summary,
            "hetzner_local": hetzner_local_summary,
            "local": hetzner_local_summary,
            "private_pc_local": private_pc_summary,
            "sourcemap_prevention": sourcemap_summary,
            "ai_radio_timeout": ai_radio_summary,
        },
        "recommendations": recommendations,
        "outputs": {
            "markdown": str(out_md),
            "json": str(out_json),
            "history": str(history_path),
        },
        "safety": {
            "defensive_reports_only": True,
            "network_access": False,
            "cloudflare_mutations": False,
            "external_scans": False,
            "credential_collection": False,
            "secrets_in_report": False,
        },
    }
    return report


def md_status(value: Any) -> str:
    return f"`{safe_text(value)}`"


def md_list(values: Any, limit: int = 4) -> str:
    if not isinstance(values, list) or not values:
        return "-"
    items = [safe_text(item).replace("|", "\\|") for item in values[:limit]]
    if len(values) > limit:
        items.append("...")
    return ", ".join(items)


def render_website_correlation_v2(findings: Any) -> List[str]:
    lines = ["## Website Correlation Layer v2", ""]
    if not isinstance(findings, list) or not findings:
        lines.extend(["- Keine Correlation-v2-Findings im Website-Report vorhanden.", ""])
        return lines

    lines.extend(
        [
            "| Signal | Status | Count | Paths | User-Agents | Countries | Empfehlung |",
            "|---|---|---:|---|---|---|---|",
        ]
    )
    for item in findings[:8]:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| `{safe_text(item.get('signal_id'))}` | `{safe_text(item.get('status'))}` | "
            f"{safe_text(item.get('count'))} | {md_list(item.get('paths'))} | "
            f"{md_list(item.get('user_agents'), limit=3)} | {md_list(item.get('countries'))} | "
            f"{safe_text(item.get('recommendation')).replace('|', '\\|')} |"
        )
    lines.append("")
    return lines


def md_count_items(values: Any, key: str, limit: int = 4) -> str:
    if not isinstance(values, list) or not values:
        return "-"
    items: List[str] = []
    for item in values[:limit]:
        if not isinstance(item, dict):
            continue
        items.append(f"{safe_text(item.get(key), '-')}: {safe_text(item.get('count'), '0')}")
    return md_list(items, limit=limit)


def render_website_origin_pressure(origin: Any) -> List[str]:
    lines = ["## Website 5xx Origin Pressure Breakdown", ""]
    if not isinstance(origin, dict) or not origin:
        lines.extend(["- Keine 5xx-Origin-Diagnose im Website-Report vorhanden.", ""])
        return lines

    lines.extend(
        [
            f"- Status: `{safe_text(origin.get('status'))}`",
            f"- Interpretation: {safe_text(origin.get('interpretation'))}",
            f"- Policy: {safe_text(origin.get('status_policy'))}",
            f"- 5xx aus status-24h: `{safe_text(origin.get('status_24h_total_5xx'))}`",
            f"- Detaillierte 5xx-Zeilen: `{safe_text(origin.get('observed_5xx_detail_count'))}`",
            f"- Detail Coverage: `{safe_text(origin.get('detail_coverage_percent'))}%`",
            f"- Nur aggregiert/unknown: `{safe_text(origin.get('unclassified_5xx_from_status_aggregate'))}` "
            f"(`{safe_text(origin.get('unknown_share_percent'))}%`)",
            f"- Detail Completeness: `{safe_text(origin.get('detail_completeness_status'))}`",
            f"- Diagnostic Gap: {safe_text(origin.get('diagnostic_gap'))}",
            f"- Status-inclusive Scope: {safe_text(origin.get('status_inclusive_classification_scope'))}",
            f"- Cache Interpretation: {safe_text(origin.get('cache_status_interpretation'))}",
            "",
            "### Classification",
            "",
        ]
    )
    classifications = origin.get("top_5xx_classification")
    if isinstance(classifications, list) and classifications:
        lines.extend(["| Classification | Count |", "|---|---:|"])
        for item in classifications:
            if not isinstance(item, dict):
                continue
            lines.append(f"| `{safe_text(item.get('classification'))}` | {safe_text(item.get('count'))} |")
        lines.append("")
    else:
        lines.extend(["- Keine Classification-Daten vorhanden.", ""])

    status_inclusive = origin.get("top_5xx_status_inclusive_classification")
    lines.extend(["### Status-inclusive Classification", ""])
    if isinstance(status_inclusive, list) and status_inclusive:
        lines.extend(["| Classification | Count |", "|---|---:|"])
        for item in status_inclusive:
            if not isinstance(item, dict):
                continue
            lines.append(f"| `{safe_text(item.get('classification'))}` | {safe_text(item.get('count'))} |")
        lines.append("")
    else:
        lines.extend(["- Keine status-inclusive Classification-Daten vorhanden.", ""])

    lines.extend(
        [
            "### Aggregates",
            "",
            f"- Status Codes: {md_count_items(origin.get('top_5xx_status_codes'), 'status', limit=6)}",
            f"- Countries: {md_count_items(origin.get('top_5xx_countries'), 'country', limit=6)}",
            f"- Cache Status: {md_count_items(origin.get('top_5xx_cache_status'), 'cache_status', limit=6)}",
            f"- UA-Gruppen: {md_count_items(origin.get('top_5xx_user_agent_groups'), 'group', limit=6)}",
            f"- Status-only Gap Classification: "
            f"{md_count_items(origin.get('status_only_gap_classification'), 'classification', limit=6)}",
            f"- Status-inclusive Classification: "
            f"{md_count_items(origin.get('top_5xx_status_inclusive_classification'), 'classification', limit=6)}",
            f"- Request Shapes: {md_count_items(origin.get('top_5xx_request_shapes'), 'request_shape', limit=6)}",
            f"- Actor Signals: {md_count_items(origin.get('top_5xx_actor_signals'), 'actor_signal', limit=6)}",
            f"- Failure Modes: {md_count_items(origin.get('top_5xx_failure_modes'), 'failure_mode', limit=6)}",
            "",
        ]
    )

    status_gap = origin.get("status_detail_gap")
    if isinstance(status_gap, list) and status_gap:
        lines.extend(
            [
                "### 5xx Detail Gap By Status",
                "",
                "| Status | status-24h | Detailed | Aggregate-only | Coverage | Status-only Classification |",
                "|---:|---:|---:|---:|---:|---|",
            ]
        )
        for item in status_gap[:8]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {safe_text(item.get('status'))} | {safe_text(item.get('status_24h_count'))} | "
                f"{safe_text(item.get('detailed_count'))} | {safe_text(item.get('unclassified_count'))} | "
                f"{safe_text(item.get('detail_coverage_percent'))}% | "
                f"`{safe_text(item.get('status_only_classification'))}` |"
            )
        lines.append("")

    paths = origin.get("top_5xx_paths")
    if isinstance(paths, list) and paths:
        lines.extend(
            [
                "### Top 5xx Paths",
                "",
                "| Count | Path | Status | Cache | UA-Gruppen | Request Shape | Actor Signal | Failure Mode | Classification | Sentinel Combined |",
                "|---:|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for item in paths[:8]:
            if not isinstance(item, dict):
                continue
            combined = (
                f"{safe_text(item.get('combined_rule_scope'))}; "
                f"actual={str(bool(item.get('actual_5xx_traffic_covered_by_combined_rule'))).lower()}"
            )
            lines.append(
                f"| {safe_text(item.get('count'))} | {safe_text(item.get('path')).replace('|', '\\|')} | "
                f"{md_count_items(item.get('statuses'), 'status')} | "
                f"{md_count_items(item.get('cache_status'), 'cache_status')} | "
                f"{md_count_items(item.get('user_agent_groups'), 'group')} | "
                f"`{safe_text(item.get('request_shape'))}` | "
                f"`{safe_text(item.get('actor_signal'))}` | "
                f"`{safe_text(item.get('failure_mode'))}` | "
                f"`{safe_text(item.get('classification'))}` | {safe_text(combined)} |"
            )
        lines.append("")

    coverage = origin.get("sentinel_combined_rule_coverage")
    if isinstance(coverage, list) and coverage:
        lines.extend(
            [
                "### Sentinel Combined Rule Coverage",
                "",
                "| Path | Count | Scope | Actual 5xx Covered | Reason |",
                "|---|---:|---|---:|---|",
            ]
        )
        for item in coverage[:8]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {safe_text(item.get('path')).replace('|', '\\|')} | {safe_text(item.get('count'))} | "
                f"{safe_text(item.get('combined_rule_scope'))} | "
                f"{str(bool(item.get('actual_5xx_traffic_covered_by_combined_rule'))).lower()} | "
                f"{safe_text(item.get('reason')).replace('|', '\\|')} |"
            )
        lines.append("")
    return lines


def render_website_source_map_404(breakdown: Any) -> List[str]:
    lines = ["## Website Source Map 404 Breakdown", ""]
    if not isinstance(breakdown, dict) or not breakdown:
        lines.extend(["- Keine Source-Map-404-Diagnose im Website-Report vorhanden.", ""])
        return lines

    lines.extend(
        [
            f"- Status: `{safe_text(breakdown.get('status'))}`",
            f"- Interpretation: {safe_text(breakdown.get('interpretation'))}",
            f"- Policy: {safe_text(breakdown.get('status_policy'))}",
            f"- 404 auf .map: `{safe_text(breakdown.get('map_404_total'))}`",
            f"- Detaillierte .map-404-Zeilen: `{safe_text(breakdown.get('observed_map_404_detail_count'))}`",
            f"- Detail Coverage: `{safe_text(breakdown.get('detail_coverage_percent'))}%`",
            f"- Nur aggregiert/unknown: `{safe_text(breakdown.get('unclassified_map_404_from_metric'))}` "
            f"(`{safe_text(breakdown.get('unknown_share_percent'))}%`)",
            f"- Detail Completeness: `{safe_text(breakdown.get('detail_completeness_status'))}`",
            "",
            "### Source Map Classification",
            "",
        ]
    )

    classifications = breakdown.get("top_map_404_classification")
    if isinstance(classifications, list) and classifications:
        lines.extend(["| Classification | Count |", "|---|---:|"])
        for item in classifications:
            if not isinstance(item, dict):
                continue
            lines.append(f"| `{safe_text(item.get('classification'))}` | {safe_text(item.get('count'))} |")
        lines.append("")
    else:
        lines.extend(["- Keine Source-Map-Classification-Daten vorhanden.", ""])

    paths = breakdown.get("top_map_404_paths")
    if isinstance(paths, list) and paths:
        lines.extend(
            [
                "### Top Source Map 404 Paths",
                "",
                "| Count | Path | Country | Cache | UA-Gruppen | Classification | Sentinel Combined |",
                "|---:|---|---|---|---|---|---|",
            ]
        )
        for item in paths[:8]:
            if not isinstance(item, dict):
                continue
            path = safe_text(item.get("path")).replace("|", "\\|")
            lines.append(
                f"| {safe_text(item.get('count'))} | {path} | "
                f"{md_count_items(item.get('countries'), 'country')} | "
                f"{md_count_items(item.get('cache_status'), 'cache_status')} | "
                f"{md_count_items(item.get('user_agent_groups'), 'group')} | "
                f"`{safe_text(item.get('classification'))}` | "
                f"{safe_text(item.get('combined_rule_scope'))} |"
            )
        lines.append("")

    return lines


def render_website_ok_readiness(readiness: Any) -> List[str]:
    lines = ["## Website OK Readiness", ""]
    if not isinstance(readiness, dict) or not readiness:
        lines.extend(["- Keine OK-Readiness-Diagnose im Website-Report vorhanden.", ""])
        return lines
    summary = readiness.get("summary") if isinstance(readiness.get("summary"), dict) else {}
    lines.extend(
        [
            f"- Status: `{safe_text(readiness.get('status'))}`",
            f"- Policy: {safe_text(readiness.get('policy'))}",
            f"- Direct Status Blockers: `{safe_text(summary.get('direct_status_blocker_count'))}`",
            f"- Low-Growth Blockers: `{safe_text(summary.get('low_growth_blocker_count'))}`",
            f"- Aggregate Detail Blockers: `{safe_text(summary.get('aggregate_detail_blocker_count'))}`",
            f"- Diagnostic-only v2 Findings: `{safe_text(summary.get('diagnostic_nonblocking_count'))}`",
            "",
        ]
    )

    direct = readiness.get("direct_status_blockers")
    if isinstance(direct, list) and direct:
        lines.extend(["### Direct Status Blockers", "", "| Metrik | Status | Wert | Effect | Reason |", "|---|---|---:|---|---|"])
        for item in direct[:8]:
            if not isinstance(item, dict):
                continue
            label = item.get("label") or item.get("key") or "-"
            lines.append(
                f"| {safe_text(label)} | `{safe_text(item.get('status'))}` | {safe_text(item.get('value'))} | "
                f"{safe_text(item.get('status_effect'))} | {safe_text(item.get('reason'))} |"
            )
        lines.append("")

    aggregate = readiness.get("aggregate_detail_blockers")
    if isinstance(aggregate, list) and aggregate:
        lines.extend(["### Aggregate Detail Blockers", "", "| Key | Status | Wert | Effect | Reason |", "|---|---|---:|---|---|"])
        for item in aggregate[:8]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {safe_text(item.get('key'))} | `{safe_text(item.get('status'))}` | "
                f"{safe_text(item.get('value'))} | {safe_text(item.get('status_effect'))} | "
                f"{safe_text(item.get('reason'))} |"
            )
        lines.append("")

    diagnostic = readiness.get("diagnostic_nonblocking_findings")
    if isinstance(diagnostic, list) and diagnostic:
        lines.extend(
            [
                "### Diagnostic-only v2 Findings",
                "",
                "| Signal | Status | Count | Effect | Recommendation |",
                "|---|---|---:|---|---|",
            ]
        )
        for item in diagnostic[:8]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {safe_text(item.get('signal_id'))} | `{safe_text(item.get('status'))}` | "
                f"{safe_text(item.get('count'))} | {safe_text(item.get('status_effect'))} | "
                f"{safe_text(item.get('recommendation'))} |"
            )
        lines.append("")
    return lines


def render_source_detail(title: str, source: Dict[str, Any]) -> List[str]:
    lines = [f"## {title}", ""]
    if not source.get("present"):
        lines.append(f"- Status: `{STATUS_UNKNOWN}`")
        lines.append(f"- Pfad: `{safe_text(source.get('path'))}`")
        lines.append(f"- Hinweis: {safe_text(source.get('error'))}")
        lines.append("")
        return lines

    if title.startswith("Website"):
        lines.extend(
            [
                f"- Generated: `{safe_text(source.get('generated_at_utc'))}`",
                f"- Mode: `{safe_text(source.get('mode'))}`",
                f"- Operational Interpretation: {safe_text(source.get('operational_interpretation'))}",
                f"- Recommendation Count: `{safe_text(source.get('recommendation_count'))}`",
                f"- Correlation Findings: `{safe_text(source.get('correlation_finding_count'))}`",
                f"- Correlation v2 Findings: `{safe_text(source.get('correlation_v2_finding_count'))}`",
                "",
            ]
        )
        non_ok = source.get("non_ok_metrics") if isinstance(source.get("non_ok_metrics"), list) else []
        if non_ok:
            lines.extend(["### Auffaellige Website-Metriken", "", "| Metrik | Status | Wert | Empfehlung |", "|---|---|---:|---|"])
            for item in non_ok:
                label = item.get("label") or item.get("metric") or item.get("key") or "-"
                lines.append(
                    f"| {safe_text(label)} | `{safe_text(item.get('status'))}` | "
                    f"{safe_text(item.get('value'))} | {safe_text(item.get('recommendation'))} |"
                )
            lines.append("")
        lines.extend(render_website_correlation_v2(source.get("correlation_v2_findings")))
        lines.extend(render_website_origin_pressure(source.get("origin_pressure_breakdown")))
        lines.extend(render_website_source_map_404(source.get("source_map_404_breakdown")))
        lines.extend(render_website_ok_readiness(source.get("ok_readiness")))
        rolling = source.get("rolling_window_context") if isinstance(source.get("rolling_window_context"), dict) else {}
        if rolling:
            comparison = rolling.get("comparison") if isinstance(rolling.get("comparison"), dict) else {}
            history = rolling.get("history") if isinstance(rolling.get("history"), dict) else {}
            lines.extend(
                [
                    "### Rolling Window Context",
                    "",
                    f"- Status: `{safe_text(rolling.get('status'))}`",
                    f"- Interpretation: {safe_text(rolling.get('interpretation'))}",
                    f"- Previous Snapshot: `{safe_text(comparison.get('previous_generated_at_utc'))}`",
                    f"- Current Snapshot: `{safe_text(comparison.get('current_generated_at_utc'))}`",
                    f"- Minutes Between: `{safe_text(comparison.get('minutes_between'))}`",
                    f"- Multi-Snapshot Stability: `{safe_text(history.get('status'))}`",
                    f"- Successful Snapshots: `{safe_text(history.get('successful_snapshot_count'))}`",
                    f"- Old-Window Required Stable Minutes: `{safe_text(history.get('old_window_required_stable_minutes'))}`",
                    "",
                ]
            )
            blockers = history.get("old_window_blockers") if isinstance(history.get("old_window_blockers"), list) else []
            if blockers:
                lines.extend(
                    [
                        "#### OK Blockers",
                        "",
                        "| Metrik | Reason | Latest Delta | Max Recent Delta | Stable Since | Stable Minutes | Remaining Minutes |",
                        "|---|---|---:|---:|---|---:|---:|",
                    ]
                )
                for item in blockers[:8]:
                    if not isinstance(item, dict):
                        continue
                    latest_delta = safe_text(item.get("latest_delta"))
                    if item.get("latest_delta_comparable") is False:
                        if item.get("previous_monitor_limit") is not None or item.get("current_monitor_limit") is not None:
                            detail = (
                                f"{safe_text(item.get('delta_comparability_reason'))}: "
                                f"{safe_text(item.get('previous_monitor_limit'))}->"
                                f"{safe_text(item.get('current_monitor_limit'))}"
                            )
                        else:
                            detail = (
                                f"{safe_text(item.get('delta_comparability_reason'))}: "
                                f"{safe_text(item.get('previous_raw_group_count'))}->"
                                f"{safe_text(item.get('current_raw_group_count'))}"
                            )
                        latest_delta = (
                            f"{latest_delta} ({detail})"
                        )
                    lines.append(
                        f"| {safe_text(item.get('label'))} | {safe_text(item.get('reason'))} | "
                        f"{latest_delta} | {safe_text(item.get('max_recent_delta'))} | "
                        f"{safe_text(item.get('stable_since_utc'))} "
                        f"({safe_text(item.get('stable_since_reason'))}) | "
                        f"{safe_text(item.get('stable_minutes'))} | "
                        f"{safe_text(item.get('remaining_stable_minutes_for_old_window'))} |"
                    )
                lines.append("")
        monitor_context = (
            source.get("monitor_attempt_context") if isinstance(source.get("monitor_attempt_context"), dict) else {}
        )
        if monitor_context:
            evaluated = (
                monitor_context.get("evaluated_run")
                if isinstance(monitor_context.get("evaluated_run"), dict)
                else {}
            )
            newest = (
                monitor_context.get("newest_attempt")
                if isinstance(monitor_context.get("newest_attempt"), dict)
                else {}
            )
            lines.extend(
                [
                    "### Monitor Attempt Context",
                    "",
                    f"- Status: `{safe_text(monitor_context.get('status'))}`",
                    f"- Interpretation: {safe_text(monitor_context.get('interpretation'))}",
                    f"- Evaluated Run: `{safe_text(evaluated.get('run_id'))}` (`{safe_text(evaluated.get('status'))}`)",
                    f"- Newest Attempt: `{safe_text(newest.get('run_id'))}` (`{safe_text(newest.get('status'))}`)",
                    f"- Newer Failed Attempts: `{safe_text(monitor_context.get('newer_failed_attempt_count'))}`",
                    "",
                ]
            )
    else:
        lines.extend(
            [
                f"- Generated: `{safe_text(source.get('generated_at_utc'))}`",
                f"- Finding Count: `{safe_text(source.get('finding_count'))}`",
                f"- Informational Observations: `{safe_text(source.get('observation_count', 0))}`",
                "",
            ]
        )
        non_ok = source.get("non_ok_findings") if isinstance(source.get("non_ok_findings"), list) else []
        if non_ok:
            lines.extend(["### Auffaellige lokale Befunde", "", "| Befund | Status | Detail | Empfehlung |", "|---|---|---|---|"])
            for item in non_ok:
                label = item.get("title") or item.get("label") or item.get("name") or item.get("metric") or item.get("key") or "-"
                detail = item.get("detail") or item.get("value") or "-"
                lines.append(
                    f"| {safe_text(label)} | `{safe_text(item.get('status'))}` | "
                    f"{safe_text(detail)} | {safe_text(item.get('recommendation'))} |"
                )
            lines.append("")
        observations = source.get("observations") if isinstance(source.get("observations"), list) else []
        if observations:
            lines.extend(["### Informational Observations", "", "| Observation | Status | Detail |", "|---|---|---|"])
            for item in observations[:8]:
                label = item.get("title") or item.get("label") or item.get("category") or "-"
                detail = item.get("detail") or item.get("recommendation") or "-"
                lines.append(f"| {safe_text(label)} | `{safe_text(item.get('status'))}` | {safe_text(detail)} |")
            lines.append("")
    return lines


def render_private_pc_detail(source: Dict[str, Any]) -> List[str]:
    lines = ["## Private PC Local", ""]
    if source.get("present"):
        lines.extend(render_source_detail("Private PC Local Agent", source)[2:])
        return lines

    lines.extend(
        [
            f"- Current Status: `{STATUS_UNKNOWN}`",
            f"- Report Present On Hetzner: `{safe_text(source.get('present'))}`",
            f"- Maintained Locally: `{safe_text(source.get('maintained_locally'))}`",
            f"- Last Known Local Confirmation: `{safe_text(source.get('last_known_local_confirmation'))}`",
            f"- Confirmation Source: `{safe_text(source.get('last_known_local_confirmation_source'))}`",
            f"- Note: {safe_text(source.get('note'))}",
            f"- Password Push Required: `{safe_text(source.get('password_push_required'))}`",
            "",
        ]
    )
    return lines


def render_sourcemap_prevention(source: Dict[str, Any]) -> List[str]:
    lines = ["## SourceMap Prevention", ""]
    if not source.get("present"):
        lines.extend(
            [
                f"- Status: `{STATUS_UNKNOWN}`",
                f"- Pfad: `{safe_text(source.get('path'))}`",
                f"- Hinweis: {safe_text(source.get('error'))}",
                "",
            ]
        )
        return lines

    lines.extend(
        [
            f"- Generated: `{safe_text(source.get('generated_at_utc'))}`",
            f"- Mode: `{safe_text(source.get('mode'))}`",
            f"- Status: `{safe_text(source.get('status'))}`",
            f"- .map-404: `{safe_text(source.get('map_404_value'))}` (`{safe_text(source.get('map_404_status'))}`)",
            f"- Candidates: `{safe_text(source.get('candidate_count'))}`",
            f"- Planned / Applied / Skipped: `{safe_text(source.get('planned_count'))}` / "
            f"`{safe_text(source.get('applied_count'))}` / `{safe_text(source.get('skipped_count'))}`",
            f"- Active WPO Actions: `{safe_text(source.get('active_wpo_actions_count'))}`",
            f"- Already Remediated WPO: `{safe_text(source.get('already_remediated_count'))}`",
            f"- Historical Window Remainder Hits: `{safe_text(source.get('historical_window_remainder_count'))}`",
            f"- Global Safe to Auto Apply: `{str(bool(source.get('global_safe_to_auto_apply'))).lower()}`",
            f"- WPO-Minify Safe to Apply: `{str(bool(source.get('wpo_minify_safe_to_apply'))).lower()}`",
            f"- Core Requires Review: `{str(bool(source.get('core_requires_review'))).lower()}`",
            f"- Requires Operator Review: `{str(bool(source.get('requires_operator_review'))).lower()}`",
            f"- Last Rollback Path: `{safe_text(source.get('rollback_hint_path'))}`",
            "",
        ]
    )

    candidates = source.get("candidates") if isinstance(source.get("candidates"), list) else []
    if candidates:
        lines.extend(
            [
                "### SourceMap Candidates",
                "",
                "| Count | Classification | Auto Apply | Map Path | Reference Path | Policy |",
                "|---:|---|---:|---|---|---|",
            ]
        )
        for item in candidates[:8]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {safe_text(item.get('count'))} | `{safe_text(item.get('classification'))}` | "
                f"`{str(bool(item.get('auto_apply_eligible'))).lower()}` | "
                f"{safe_text(item.get('map_path')).replace('|', '\\|')} | "
                f"{safe_text(item.get('reference_path')).replace('|', '\\|')} | "
                f"{safe_text(item.get('policy')).replace('|', '\\|')} |"
            )
        lines.append("")

    stale = source.get("stale_candidates") if isinstance(source.get("stale_candidates"), list) else []
    if stale:
        lines.extend(
            [
                "### Stale / Already Remediated WPO-Minify",
                "",
                "| Count | Classification | Map Path | Reference Path |",
                "|---:|---|---|---|",
            ]
        )
        for item in stale[:8]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {safe_text(item.get('count'))} | `{safe_text(item.get('classification'))}` | "
                f"{safe_text(item.get('map_path')).replace('|', '\\|')} | "
                f"{safe_text(item.get('reference_path')).replace('|', '\\|')} |"
            )
        lines.append("")

    def render_actions(title: str, actions: Any) -> None:
        if not isinstance(actions, list) or not actions:
            return
        lines.extend([f"### {title}", "", "| Action | Count | Reference | Reason |", "|---|---:|---|---|"])
        for item in actions[:8]:
            if not isinstance(item, dict):
                continue
            reason = safe_text(item.get("reason")).replace("|", "\\|")
            lines.append(
                f"| `{safe_text(item.get('action_id'))}` | {safe_text(item.get('count'))} | "
                f"{safe_text(item.get('reference_path')).replace('|', '\\|')} | {reason} |"
            )
        lines.append("")

    render_actions("Planned SourceMap Actions", source.get("planned_actions"))
    render_actions("Applied SourceMap Actions", source.get("applied_actions"))
    render_actions("Skipped SourceMap Actions", source.get("skipped_actions"))
    return lines


def render_ai_radio_timeout(source: Dict[str, Any]) -> List[str]:
    lines = ["## AI-Radio API Timeout Diagnosis", ""]
    if not source.get("present"):
        lines.extend(
            [
                f"- Status: `{STATUS_UNKNOWN}`",
                f"- Pfad: `{safe_text(source.get('path'))}`",
                f"- Hinweis: {safe_text(source.get('error'))}",
                "",
            ]
        )
        return lines

    top = source.get("top_timeout_endpoint") if isinstance(source.get("top_timeout_endpoint"), dict) else {}
    remediation = source.get("microcache_remediation") if isinstance(source.get("microcache_remediation"), dict) else {}
    rolling = source.get("rolling_window_status") if isinstance(source.get("rolling_window_status"), dict) else {}
    lines.extend(
        [
            f"- Generated: `{safe_text(source.get('generated_at_utc'))}`",
            f"- Status: `{safe_text(source.get('status'))}`",
            f"- Top Timeout Endpoint: `{safe_text(top.get('host'))}{safe_text(top.get('path'))}` "
            f"(`{safe_text(top.get('count'))}`)",
            f"- /api/nowplaying Primary Driver: `{str(bool(source.get('nowplaying_is_primary_driver'))).lower()}`",
            f"- 504 Total: `{safe_text(source.get('total_504'))}`",
            f"- 24h NowPlaying 504 Count: `{safe_text(source.get('nowplaying_504'))}`",
            f"- likely_cloudflare_timeout: `{safe_text(source.get('likely_cloudflare_timeout'))}`",
            f"- NowPlaying 504 Share: `{safe_text(source.get('nowplaying_504_share_percent'))}%`",
            f"- AI-Radio 5xx Share: `{safe_text(source.get('ai_radio_5xx_share_percent'))}%`",
            f"- Remediation Deployed: `{str(bool(remediation.get('microcache_deployed'))).lower()}`",
            f"- Local Validation: `{safe_text(remediation.get('local_validation'))}`",
            f"- Latest 5xx Delta: `{safe_text(rolling.get('latest_5xx_delta'))}`",
            f"- Rolling-Window Status: `{safe_text(rolling.get('status'))}`",
            f"- Suggested Prevention: {safe_text(source.get('suggested_prevention'))}",
            f"- Next Action: {safe_text(source.get('next_action') or remediation.get('next_action'))}",
            f"- Safe to Auto Apply: `{str(bool(source.get('safe_to_auto_apply'))).lower()}`",
            f"- Requires Operator Review: `{str(bool(source.get('requires_operator_review'))).lower()}`",
            "",
        ]
    )
    if remediation.get("microcache_deployed"):
        lines.extend(
            [
                "### NowPlaying Microcache Remediation",
                "",
                "- NowPlaying Microcache is deployed and HIT-confirmed on origin; remaining 504s are evaluated through 24h rolling window.",
                f"- Deployed Host: `{safe_text(remediation.get('deployed_on_host'))}`",
                f"- Origin IP: `{safe_text(remediation.get('origin_ip'))}`",
                f"- Endpoint: `{safe_text(remediation.get('endpoint'))}`",
                f"- Cache Header: `{safe_text(remediation.get('cache_header'))}`",
                f"- Nginx Cache TTL Seconds: `{safe_text(remediation.get('nginx_cache_ttl_seconds'))}`",
                f"- Stale On Error: `{str(bool(remediation.get('stale_on_error'))).lower()}`",
                f"- Cloudflare Change: `{str(bool(remediation.get('cloudflare_change'))).lower()}`",
                f"- WAF Change: `{str(bool(remediation.get('waf_change'))).lower()}`",
                f"- Expected Effect: {safe_text(remediation.get('expected_effect'))}",
                f"- Rolling-Window Note: {safe_text(remediation.get('rolling_window_remainder_hint'))}",
                "",
                "### AI-Radio Rolling-Window Status",
                "",
                f"- Latest 5xx Delta: `{safe_text(rolling.get('latest_5xx_delta'))}`",
                f"- Latest 5xx Delta Low: `{str(bool(rolling.get('latest_5xx_delta_low'))).lower()}`",
                f"- Stable Minutes: `{safe_text(rolling.get('stable_minutes'))}`",
                f"- Remaining Stable Minutes For Old Window: `{safe_text(rolling.get('remaining_stable_minutes_for_old_window'))}`",
                f"- Interpretation: {safe_text(rolling.get('interpretation'))}",
                "",
            ]
        )
    findings = source.get("findings") if isinstance(source.get("findings"), list) else []
    if findings:
        lines.extend(["### Timeout Findings", "", "| Signal | Status | Count | Empfehlung |", "|---|---|---:|---|"])
        for item in findings:
            if not isinstance(item, dict):
                continue
            recommendation = safe_text(item.get("recommendation")).replace("|", "\\|")
            lines.append(
                f"| `{safe_text(item.get('signal_id'))}` | `{safe_text(item.get('status'))}` | "
                f"{safe_text(item.get('count'))} | {recommendation} |"
            )
        lines.append("")
    return lines


def render_cloudflare_challenge_diagnosis(diagnosis: Optional[Dict[str, Any]]) -> List[str]:
    if not diagnosis:
        return []
    lines = [
        "## Cloudflare Challenge Diagnosis",
        "",
    ]
    if not diagnosis.get("present"):
        lines.append(f"- Diagnosis report not available: `{safe_text(diagnosis.get('error'))}`")
        lines.append("")
        return lines

    verdict = diagnosis.get("verdict")
    confidence = diagnosis.get("confidence")
    botfight_share = diagnosis.get("botfight_share_percent")
    sentinel_assessment = diagnosis.get("sentineldefense_assessment")
    top_rec = diagnosis.get("top_recommendation")

    lines.append(f"- **Verdict:** `{safe_text(verdict)}` (confidence: {safe_text(confidence)})")
    lines.append(f"- **Bot Fight Mode share:** {safe_text(botfight_share)}% of security actions")
    lines.append(f"- **SentinelDefense assessment:** {safe_text(sentinel_assessment)}")
    if top_rec:
        lines.append(f"- **Top recommendation:** {safe_text(top_rec)}")
    lines.append("")
    lines.append(
        "**Note:** Global 403/curl challenge is caused by Cloudflare Bot Fight Mode, "
        "not SentinelDefense. Real browsers likely pass through."
    )
    lines.append("")
    return lines


def render_autonomy_policy(autonomy: Dict[str, Any]) -> List[str]:
    lines = ["## Autonomy & Improvement Policy (Legacy / Superseded)", ""]
    if not autonomy or not autonomy.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_autonomy_policy.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(autonomy.get('status'))}",
            f"- Current autonomy level: {md_status(autonomy.get('current_autonomy_level'))}",
            f"- Policy-only: {md_status(autonomy.get('policy_only'))}",
            f"- Apply-status summary: {md_status(autonomy.get('apply_status_summary'))}",
            f"- Evaluated actions: {md_status(autonomy.get('evaluated_actions_count'))}",
            f"- Allowed now (draft/policy-only): {md_status(autonomy.get('allowed_now_count'))}",
            f"- Blocked: {md_status(autonomy.get('blocked_count'))}",
            f"- Owner approval required: {md_status(autonomy.get('owner_approval_required_count'))}",
            f"- HIGH-risk (always blocked): {md_status(autonomy.get('high_risk_count'))}",
            f"- HIGH-risk allowed now (must be 0): {md_status(autonomy.get('high_risk_allowed_now_count'))}",
            f"- Last audit timestamp: {md_status(autonomy.get('last_audit_timestamp'))}",
            "",
        ]
    )
    if autonomy.get("policy_breach"):
        lines.append(
            "- **Policy breach detected** — action status escalated to at least "
            "`WARNING_REVIEW`; manual review required."
        )
        lines.append("")
    return lines


def render_seo_safe_optimizer(seo: Dict[str, Any]) -> List[str]:
    lines = ["## SEO Safe Optimizer Status", ""]
    if not seo or not seo.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_seo_safe_optimizer.py`",
                "",
            ]
        )
        return lines
    editorial = seo.get("editorial_review_summary", {}) if isinstance(seo.get("editorial_review_summary"), dict) else {}
    if editorial.get("present") is False:
        editorial_text = "not available"
    else:
        editorial_text = (
            f"apply_status={safe_text(editorial.get('apply_status'))}, "
            f"proposals={parse_count(editorial.get('proposal_count'))}, "
            f"improve={parse_count(editorial.get('improve_count'))}, "
            f"review_only={parse_count(editorial.get('review_only_count'))}, "
            f"high_risk={parse_count(editorial.get('high_risk_count'))}, "
            f"all_not_applied={editorial.get('all_not_applied')}"
        )
    lines.extend(
        [
            f"- Status: {md_status(seo.get('status'))}",
            f"- Highest risk: {md_status(seo.get('highest_risk'))}",
            f"- Title: {md_status(seo.get('title_status'))}",
            f"- Meta description: {md_status(seo.get('meta_description_status'))}",
            f"- Canonical: {md_status(seo.get('canonical_status'))}",
            f"- Open Graph: {md_status(seo.get('open_graph_status'))}",
            f"- Twitter Cards: {md_status(seo.get('twitter_cards_status'))}",
            f"- Schema (JSON-LD): {md_status(seo.get('schema_status'))}",
            f"- robots.txt: {md_status(seo.get('robots_status'))}",
            f"- Sitemap: {md_status(seo.get('sitemap_status'))}",
            f"- Editorial review: {editorial_text}",
            f"- Improved drafts available: {md_status(seo.get('improved_drafts_available'))}",
            "",
            "**Next safe SEO steps:**",
            "",
        ]
    )
    steps = seo.get("next_safe_seo_steps") if isinstance(seo.get("next_safe_seo_steps"), list) else []
    if steps:
        for step in steps:
            lines.append(f"- {safe_text(step)}")
    else:
        lines.append("- Keine SEO-Schritte verfuegbar.")
    lines.append("")
    return lines


def render_performance_safe_improvement(perf: Dict[str, Any]) -> List[str]:
    lines = ["## Performance Safe Improvement Status", ""]
    if not perf or not perf.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Keine lokalen Performance-/Cache-Reports verfuegbar; read-only.",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(perf.get('status'))} (read-only)",
            f"- Cache status: {md_status(perf.get('cache_status'))}",
            f"- Image optimization: {md_status(perf.get('image_optimization_status'))}",
            f"- Lazy loading: {md_status(perf.get('lazy_loading_status'))}",
            f"- External embed risk: {md_status(perf.get('external_embed_risk'))}",
            f"- AI-Radio NowPlaying cache: {md_status(perf.get('ai_radio_nowplaying_cache_status'))}",
            f"- AI-Radio local validation: {md_status(perf.get('ai_radio_local_validation'))}",
            f"- Source map status: {md_status(perf.get('source_map_status'))}",
            f"- Origin 5xx status: {md_status(perf.get('origin_5xx_status'))}",
            "",
            "**Next safe performance steps:**",
            "",
        ]
    )
    steps = perf.get("next_safe_performance_steps") if isinstance(perf.get("next_safe_performance_steps"), list) else []
    if steps:
        for step in steps:
            lines.append(f"- {safe_text(step)}")
    else:
        lines.append("- Keine Performance-Schritte verfuegbar.")
    lines.append("")
    return lines


def render_safe_improvement_roadmap(roadmap: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Improvement Roadmap", ""]
    if not roadmap or not roadmap.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_improvement_roadmap.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(roadmap.get('status'))} (review-only)",
            f"- Next safe drafts: {md_status(roadmap.get('roadmap_next_safe_count'))}",
            f"- Owner review required: {md_status(roadmap.get('roadmap_owner_review_count'))}",
            f"- Blocked high risk: {md_status(roadmap.get('roadmap_blocked_high_count'))}",
            f"- Monitor only: {md_status(roadmap.get('roadmap_monitor_only_count'))}",
            "",
            "**Top 5 next safe steps:**",
            "",
        ]
    )
    steps = roadmap.get("top_5_next_safe_steps") if isinstance(roadmap.get("top_5_next_safe_steps"), list) else []
    if steps:
        for entry in steps:
            lines.append(f"- `{safe_text(entry.get('roadmap_id'))}`: {safe_text(entry.get('suggested_next_step'))}")
    else:
        lines.append("- (none)")
    lines.append("")
    return lines


def render_approval_queue(queue: Dict[str, Any]) -> List[str]:
    lines = ["## Owner Approval Queue", ""]
    if not queue or not queue.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_owner_approval_queue.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(queue.get('status'))} (review-only)",
            f"- Pending owner review: {md_status(queue.get('pending_owner_review_count'))}",
            f"- Approved for draft only: {md_status(queue.get('approved_for_draft_only_count'))}",
            f"- Monitor only: {md_status(queue.get('monitor_only_count'))}",
            f"- Blocked high risk: {md_status(queue.get('blocked_high_risk_count'))}",
            f"- Queue breach: {md_status(queue.get('queue_breach'))}",
            f"- Reconcile enabled: {md_status(queue.get('reconcile_enabled'))} "
            f"(preserved={md_status(queue.get('preserved_decisions_count'))}, "
            f"stale={md_status(queue.get('stale_items_count'))}, "
            f"security_overrides={md_status(queue.get('security_overrides_count'))})",
            "",
            "**Top pending items:**",
            "",
        ]
    )
    top = queue.get("top_pending_items") if isinstance(queue.get("top_pending_items"), list) else []
    if top:
        for entry in top:
            lines.append(
                f"- `{safe_text(entry.get('queue_id'))}` "
                f"[{safe_text(entry.get('impact_area'))}/{safe_text(entry.get('risk_classification'))}]: "
                f"{safe_text(entry.get('title'))}"
            )
    else:
        lines.append("- (none)")
    lines.append("")
    return lines


def render_owner_cli(cli: Dict[str, Any]) -> List[str]:
    lines = ["## Owner Approval CLI (last action)", ""]
    if not cli or not cli.get("present"):
        lines.extend(["- Status: `NOT_AVAILABLE`", ""])
        return lines
    lines.extend(
        [
            f"- Last owner action: `{md_status(cli.get('last_owner_action'))}`",
            f"- Allowed: {md_status(cli.get('last_owner_action_allowed'))}",
            f"- Queue id: `{md_status(cli.get('last_owner_action_queue_id'))}`",
            f"- Status change: `{md_status(cli.get('last_owner_action_status_change'))}`",
            f"- Queue policy breach: {md_status(cli.get('queue_policy_breach'))}",
            "",
        ]
    )
    return lines


def render_draft_execution_planner(planner: Dict[str, Any]) -> List[str]:
    lines = ["## Draft Execution Planner", ""]
    if not planner or not planner.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_draft_execution_planner.py`",
                "",
            ]
        )
        return lines
    apply_summary = planner.get("apply_status_summary") if isinstance(planner.get("apply_status_summary"), dict) else {}
    draft_types = planner.get("draft_types") if isinstance(planner.get("draft_types"), list) else []
    lines.extend(
        [
            f"- Status: {md_status(planner.get('status'))} (manual draft-only)",
            f"- Execution items: {md_status(planner.get('execution_items_count'))}",
            f"- Excluded items: {md_status(planner.get('excluded_items_count'))}",
            f"- Ready for manual copy: {md_status(planner.get('ready_for_manual_copy_count'))}",
            f"- Planner breach: {md_status(planner.get('planner_breach'))}",
            f"- Apply status all_not_applied: {md_status(apply_summary.get('all_not_applied'))}",
            f"- Apply status other count: {md_status(apply_summary.get('other_apply_status_count'))}",
            f"- HIGH included count: {md_status(planner.get('high_included_count'))}",
            "",
        ]
    )
    if draft_types:
        lines.append("**Draft types:**")
        lines.append("")
        for draft_type in draft_types:
            lines.append(f"- `{safe_text(draft_type)}`")
        lines.append("")
    return lines


def render_owner_review_pack(pack: Dict[str, Any]) -> List[str]:
    lines = ["## Owner Review Pack", ""]
    if not pack or not pack.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_owner_review_pack.py`",
                "",
            ]
        )
        return lines
    apply_summary = pack.get("apply_status_summary") if isinstance(pack.get("apply_status_summary"), dict) else {}
    sections = pack.get("sections") if isinstance(pack.get("sections"), list) else []
    lines.extend(
        [
            f"- Status: {md_status(pack.get('status'))} (manual owner review only)",
            f"- Review items: {md_status(pack.get('review_items_count'))}",
            f"- Ready for owner review: {md_status(pack.get('ready_for_owner_review_count'))}",
            f"- Ready for copy: {md_status(pack.get('ready_for_copy_count'))}",
            f"- Excluded: {md_status(pack.get('excluded_count'))}",
            f"- Review pack breach: {md_status(pack.get('review_pack_breach'))}",
            f"- Apply status all_not_applied: {md_status(apply_summary.get('all_not_applied'))}",
            f"- Apply status other count: {md_status(apply_summary.get('other_apply_status_count'))}",
            f"- HIGH/MEDIUM ready count: {md_status(pack.get('high_or_medium_ready_count'))}",
            "",
        ]
    )
    if sections:
        lines.append("**Sections:**")
        lines.append("")
        for section in sections:
            lines.append(f"- `{safe_text(section)}`")
        lines.append("")
    return lines


def render_manual_apply_checklist(checklist: Dict[str, Any]) -> List[str]:
    lines = ["## Manual Apply Checklist", ""]
    if not checklist or not checklist.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_manual_apply_checklist.py`",
                "",
            ]
        )
        return lines
    apply_summary = checklist.get("apply_status_summary") if isinstance(checklist.get("apply_status_summary"), dict) else {}
    sections = checklist.get("sections") if isinstance(checklist.get("sections"), list) else []
    lines.extend(
        [
            f"- Status: {md_status(checklist.get('status'))} (manual checklist only)",
            f"- Checklist items: {md_status(checklist.get('checklist_items_count'))}",
            f"- Ready for manual apply review: {md_status(checklist.get('ready_for_manual_apply_review_count'))}",
            f"- Excluded: {md_status(checklist.get('excluded_count'))}",
            f"- Checklist breach: {md_status(checklist.get('checklist_breach'))}",
            f"- Apply status all_not_applied: {md_status(apply_summary.get('all_not_applied'))}",
            f"- Apply status other count: {md_status(apply_summary.get('other_apply_status_count'))}",
            f"- HIGH/MEDIUM included count: {md_status(checklist.get('high_medium_included_count'))}",
            f"- Productive change: {md_status(checklist.get('productive_change'))}",
            "",
        ]
    )
    if sections:
        lines.append("**Sections:**")
        lines.append("")
        for section in sections:
            lines.append(f"- `{safe_text(section)}`")
        lines.append("")
    return lines


def render_manual_completion_tracker(tracker: Dict[str, Any]) -> List[str]:
    lines = ["## Manual Completion Tracker", ""]
    if not tracker or not tracker.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_manual_completion_tracker.py list`",
                "",
            ]
        )
        return lines
    apply_summary = tracker.get("apply_status_summary") if isinstance(tracker.get("apply_status_summary"), dict) else {}
    last_action = tracker.get("last_owner_completion_action") if isinstance(tracker.get("last_owner_completion_action"), dict) else {}
    lines.extend(
        [
            f"- Status: {md_status(tracker.get('status'))} (owner progress only)",
            f"- Checklist items: {md_status(tracker.get('checklist_items_count'))}",
            f"- Completed: {md_status(tracker.get('completed_count'))}",
            f"- In progress: {md_status(tracker.get('in_progress_count'))}",
            f"- Needs review: {md_status(tracker.get('needs_review_count'))}",
            f"- Skipped: {md_status(tracker.get('skipped_count'))}",
            f"- Unchecked: {md_status(tracker.get('unchecked_count'))}",
            f"- Completion breach: {md_status(tracker.get('completion_breach'))}",
            f"- HIGH/MEDIUM completed count: {md_status(tracker.get('high_medium_completed_count'))}",
            f"- Apply status all_not_applied: {md_status(apply_summary.get('all_not_applied'))}",
            f"- Apply status other count: {md_status(apply_summary.get('other_apply_status_count'))}",
            f"- Productive change: {md_status(tracker.get('productive_change'))}",
            "",
        ]
    )
    if last_action:
        lines.extend(
            [
                "**Last owner completion action:**",
                "",
                f"- Command: `{safe_text(last_action.get('command'))}`",
                f"- Checklist ID: `{safe_text(last_action.get('checklist_id'))}`",
                f"- Timestamp: `{safe_text(last_action.get('timestamp_utc'))}`",
                "",
            ]
        )
    return lines


def render_post_manual_validation(validation: Dict[str, Any]) -> List[str]:
    lines = ["## Post-Manual Validation", ""]
    if not validation or not validation.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_post_manual_validation.py` nach manuellen Owner-Aenderungen",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Validation status: {md_status(validation.get('status'))}",
            f"- SEO validation status: {md_status(validation.get('seo_validation_status'))}",
            f"- Performance validation status: {md_status(validation.get('performance_validation_status'))}",
            f"- Safety validation status: {md_status(validation.get('safety_validation_status'))}",
            f"- Checklist items: {md_status(validation.get('checklist_items_count'))}",
            f"- Validation warnings: {md_status(validation.get('validation_warning_count'))}",
            f"- Validation available: {md_status(validation.get('validation_available'))}",
            f"- Safety violation: {md_status(validation.get('safety_violation'))}",
            f"- Productive change: {md_status(validation.get('productive_change'))}",
            f"- No network default: {md_status(validation.get('no_network_default'))}",
            f"- No apply function: {md_status(validation.get('no_apply_function'))}",
            "",
        ]
    )
    next_steps = validation.get("next_owner_steps") if isinstance(validation.get("next_owner_steps"), list) else []
    if next_steps:
        lines.append("**Next owner steps:**")
        lines.append("")
        for step in next_steps[:8]:
            lines.append(f"- {safe_text(step)}")
        lines.append("")
    return lines


def render_owner_daily_action_summary(owner: Dict[str, Any]) -> List[str]:
    lines = ["## Owner Daily Action Summary (Legacy / Superseded)", ""]
    if not owner or not owner.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_owner_daily_action_summary.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Owner status: {md_status(owner.get('owner_status'))}",
            f"- Recommended next owner action: {md_status(owner.get('recommended_next_owner_action'))}",
            f"- Open manual items: {md_status(owner.get('open_manual_items'))}",
            f"- Completed manual items: {md_status(owner.get('completed_manual_items'))}",
            f"- In progress manual items: {md_status(owner.get('in_progress_manual_items'))}",
            f"- Needs review items: {md_status(owner.get('needs_review_items'))}",
            f"- Skipped items: {md_status(owner.get('skipped_items'))}",
            f"- Blocked high-risk items: {md_status(owner.get('blocked_high_risk_items'))}",
            f"- Summary breach: {md_status(owner.get('summary_breach'))}",
            "",
        ]
    )
    return lines


def render_autonomous_improvement_readiness(owner: Dict[str, Any]) -> List[str]:
    lines = ["## Autonomous Improvement Readiness", ""]
    if not owner or not owner.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_owner_daily_action_summary.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Draft-only ready: {md_status(owner.get('autonomy_ready_draft_only_count'))}",
            f"- Ready after owner approval: {md_status(owner.get('ready_after_owner_approval_count'))}",
            f"- Not ready, missing guards: {md_status(owner.get('not_ready_missing_guards_count'))}",
            f"- Blocked high-risk: {md_status(owner.get('blocked_high_risk_count'))}",
            f"- Monitor-only: {md_status(owner.get('monitor_only_count'))}",
            f"- Next safe autonomy build step: {md_status(owner.get('next_safe_autonomy_build_step'))}",
            "",
        ]
    )
    return lines


def render_safe_apply_candidate_registry(registry: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Apply Candidate Registry", ""]
    if not registry or not registry.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_apply_candidate_registry.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(registry.get('status'))}",
            f"- Candidate count: {md_status(registry.get('candidate_count'))}",
            f"- Registered draft-only: {md_status(registry.get('registered_draft_only_count'))}",
            f"- Registered validation-only: {md_status(registry.get('registered_validation_only_count'))}",
            f"- Not registered, missing guards: {md_status(registry.get('not_registered_missing_guards_count'))}",
            f"- Blocked not allowed: {md_status(registry.get('blocked_not_allowed_count'))}",
            f"- Monitor-only: {md_status(registry.get('monitor_only_count'))}",
            f"- Registry breach: {md_status(registry.get('registry_breach'))}",
            "",
        ]
    )
    return lines


def render_safe_apply_guard_check(guard: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Apply Guard Check", ""]
    if not guard or not guard.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_apply_guard_checker.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(guard.get('status'))}",
            f"- Candidate count: {md_status(guard.get('candidate_count'))}",
            f"- Guards ready draft-only: {md_status(guard.get('guards_ready_draft_only_count'))}",
            f"- Guards ready validation-only: {md_status(guard.get('guards_ready_validation_only_count'))}",
            f"- Guards missing for autonomy: {md_status(guard.get('guards_missing_for_autonomy_count'))}",
            f"- Guards blocked not allowed: {md_status(guard.get('guards_blocked_not_allowed_count'))}",
            f"- Guards monitor-only: {md_status(guard.get('guards_monitor_only_count'))}",
            f"- Guard breach: {md_status(guard.get('guard_breach'))}",
            "",
        ]
    )
    return lines


def render_safe_apply_scope_manager(scope: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Apply Scope Allowlist", ""]
    if not scope or not scope.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_apply_scope_manager.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(scope.get('status'))}",
            f"- Candidate count: {md_status(scope.get('candidate_count'))}",
            f"- Scope allowed draft-only: {md_status(scope.get('scope_allowed_draft_only_count'))}",
            f"- Scope allowed validation-only: {md_status(scope.get('scope_allowed_validation_only_count'))}",
            f"- Scope not allowed (missing guards): {md_status(scope.get('scope_not_allowed_missing_guards_count'))}",
            f"- Scope blocked (high risk): {md_status(scope.get('scope_blocked_high_risk_count'))}",
            f"- Scope monitor-only: {md_status(scope.get('scope_monitor_only_count'))}",
            f"- Scope breach: {md_status(scope.get('scope_breach'))}",
            "",
        ]
    )
    return lines


def render_safe_apply_dry_run_planner(dry_run: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Apply Dry-Run Plan", ""]
    if not dry_run or not dry_run.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_apply_dry_run_planner.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(dry_run.get('status'))}",
            f"- Candidate count: {md_status(dry_run.get('candidate_count'))}",
            f"- Dry-run ready draft-only: {md_status(dry_run.get('dry_run_ready_draft_only_count'))}",
            f"- Dry-run ready validation-only: {md_status(dry_run.get('dry_run_ready_validation_only_count'))}",
            f"- Dry-run not ready (missing guards): {md_status(dry_run.get('dry_run_not_ready_missing_guards_count'))}",
            f"- Dry-run blocked (high risk): {md_status(dry_run.get('dry_run_blocked_high_risk_count'))}",
            f"- Dry-run monitor-only: {md_status(dry_run.get('dry_run_monitor_only_count'))}",
            f"- Dry-run breach: {md_status(dry_run.get('dry_run_breach'))}",
            "",
        ]
    )
    return lines


def render_safe_apply_preflight_validator(preflight: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Apply Preflight Validation", ""]
    if not preflight or not preflight.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_apply_preflight_validator.py`",
                "",
            ]
        )
        return lines
    global_missing = preflight.get("global_missing_requirements")
    lines.extend(
        [
            f"- Status: {md_status(preflight.get('status'))}",
            f"- Candidate count: {md_status(preflight.get('candidate_count'))}",
            f"- Preflight ready draft-only: {md_status(preflight.get('preflight_ready_draft_only_count'))}",
            f"- Preflight ready validation-only: {md_status(preflight.get('preflight_ready_validation_only_count'))}",
            f"- Preflight not ready: {md_status(preflight.get('preflight_not_ready_count'))}",
            f"- Preflight blocked: {md_status(preflight.get('preflight_blocked_count'))}",
            f"- Preflight monitor-only: {md_status(preflight.get('preflight_monitor_only_count'))}",
            f"- Preflight breach: {md_status(preflight.get('preflight_breach'))}",
            f"- Global missing requirements: {md_list(global_missing) if isinstance(global_missing, list) else md_status(global_missing)}",
            "",
        ]
    )
    return lines


def render_autonomy_runtime_lock(lock: Dict[str, Any]) -> List[str]:
    lines = ["## Autonomy Runtime Lock (Legacy / Superseded)", ""]
    if not lock or not lock.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_autonomy_runtime_lock.py status`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(lock.get('status'))}",
            f"- Autonomy enabled: {md_status(lock.get('autonomy_enabled'))}",
            f"- Draft-only enabled: {md_status(lock.get('draft_only_enabled'))}",
            f"- Validation-only enabled: {md_status(lock.get('validation_only_enabled'))}",
            f"- Live apply enabled: {md_status(lock.get('live_apply_enabled'))}",
            f"- Owner disable switch: {md_status(lock.get('owner_disable_switch'))}",
            f"- Emergency stop: {md_status(lock.get('emergency_stop'))}",
            f"- Max autonomy level: {md_status(lock.get('max_autonomy_level'))}",
            f"- Allowed modes: {md_list(lock.get('allowed_modes'))}",
            f"- Runtime lock breach: {md_status(lock.get('runtime_lock_breach'))}",
            "",
        ]
    )
    return lines


def render_safe_draft_autonomy_runner(runner: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Draft Autonomy Runner", ""]
    if not runner or not runner.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_draft_autonomy_runner.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(runner.get('status'))}",
            f"- Runner status: {md_status(runner.get('runner_status'))}",
            f"- Executed draft-only: {md_status(runner.get('executed_draft_only_count'))}",
            f"- Executed validation-only: {md_status(runner.get('executed_validation_only_count'))}",
            f"- Skipped: {md_status(runner.get('skipped_count'))}",
            f"- Blocked by runtime lock: {md_status(runner.get('blocked_by_runtime_lock_count'))}",
            f"- Blocked by emergency stop: {md_status(runner.get('blocked_by_emergency_stop_count'))}",
            f"- Live apply: {md_status(runner.get('live_apply'))}",
            f"- Runner breach: {md_status(runner.get('runner_breach'))}",
            "",
        ]
    )
    return lines


def render_safe_draft_autonomy_verifier(verifier: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Draft Autonomy Verifier", ""]
    if not verifier or not verifier.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_draft_autonomy_verifier.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(verifier.get('status'))}",
            f"- Verifier status: {md_status(verifier.get('verifier_status'))}",
            f"- Last runner status: {md_status(verifier.get('last_runner_status'))}",
            f"- Verified safe outputs: {md_status(verifier.get('verified_safe_outputs_count'))}",
            f"- Missing outputs: {md_status(verifier.get('missing_outputs_count'))}",
            f"- Invalid JSON: {md_status(verifier.get('invalid_json_count'))}",
            f"- Forbidden path: {md_status(verifier.get('forbidden_path_count'))}",
            f"- Secret pattern: {md_status(verifier.get('secret_pattern_count'))}",
            f"- Verifier breach: {md_status(verifier.get('verifier_breach'))}",
            "",
        ]
    )
    return lines


def render_safe_draft_autonomy_scheduler_plan(plan: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Draft Autonomy Scheduler Plan (Legacy / Superseded)", ""]
    if not plan or not plan.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_draft_autonomy_scheduler_plan.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(plan.get('status'))}",
            f"- Scheduler status: {md_status(plan.get('scheduler_status'))}",
            f"- Planned frequency: {md_status(plan.get('planned_frequency'))}",
            f"- Planned sequence steps: {md_status(plan.get('planned_sequence_count'))}",
            f"- Timer installation status: {md_status(plan.get('timer_installation_status'))}",
            f"- Can install timer now: {md_status(plan.get('can_install_timer_now'))}",
            f"- Can execute live: {md_status(plan.get('can_execute_live'))}",
            f"- Owner review required: {md_status(plan.get('owner_review_required'))}",
            f"- Scheduler breach: {md_status(plan.get('scheduler_breach'))}",
            f"- Blocked reason: {md_status(plan.get('blocked_reason'))}",
            "",
        ]
    )
    return lines


def render_safe_draft_autonomy_timer_draft(timer: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Draft Autonomy Timer Draft (Legacy / Superseded)", ""]
    if not timer or not timer.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_draft_autonomy_timer_draft.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(timer.get('status'))}",
            f"- Timer draft status: {md_status(timer.get('timer_draft_status'))}",
            f"- Timer installation status: {md_status(timer.get('timer_installation_status'))}",
            f"- Service draft written: {md_status(timer.get('service_draft_written'))}",
            f"- Timer draft written: {md_status(timer.get('timer_draft_written'))}",
            f"- Install review written: {md_status(timer.get('install_review_written'))}",
            f"- Rollback review written: {md_status(timer.get('rollback_review_written'))}",
            f"- systemd file written: {md_status(timer.get('systemd_file_written'))}",
            f"- crontab file written: {md_status(timer.get('crontab_file_written'))}",
            f"- Can install timer now: {md_status(timer.get('can_install_timer_now'))}",
            f"- Owner review required: {md_status(timer.get('owner_review_required'))}",
            f"- Timer draft breach: {md_status(timer.get('timer_draft_breach'))}",
            f"- Blocked reason: {md_status(timer.get('blocked_reason'))}",
            "",
        ]
    )
    return lines


def render_safe_draft_autonomy_timer_install_review(review: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Draft Autonomy Timer Install Review (Legacy / Superseded)", ""]
    if not review or not review.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_draft_autonomy_timer_install_reviewer.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(review.get('status'))}",
            f"- Install review status: {md_status(review.get('install_review_status'))}",
            f"- Timer installation status: {md_status(review.get('timer_installation_status'))}",
            f"- Can install timer now: {md_status(review.get('can_install_timer_now'))}",
            f"- Service draft safe: {md_status(review.get('service_draft_safe'))}",
            f"- Timer draft safe: {md_status(review.get('timer_draft_safe'))}",
            f"- Install review safe: {md_status(review.get('install_review_safe'))}",
            f"- Rollback review safe: {md_status(review.get('rollback_review_safe'))}",
            f"- Safe checks passed: {md_status(review.get('safe_checks_passed_count'))}",
            f"- Safe checks failed: {md_status(review.get('safe_checks_failed_count'))}",
            f"- Owner review required: {md_status(review.get('owner_review_required'))}",
            f"- Install reviewer breach: {md_status(review.get('install_reviewer_breach'))}",
            f"- Blocked reason: {md_status(review.get('blocked_reason'))}",
            "",
        ]
    )
    return lines


def render_owner_manual_timer_install_packet(packet: Dict[str, Any]) -> List[str]:
    lines = ["## Owner Manual Timer Install Packet (Legacy / Superseded)", ""]
    if not packet or not packet.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_owner_manual_timer_install_packet.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(packet.get('status'))}",
            f"- Packet status: {md_status(packet.get('packet_status'))}",
            f"- Owner review required: {md_status(packet.get('owner_review_required'))}",
            f"- Install allowed now: {md_status(packet.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(packet.get('can_install_timer_now'))}",
            f"- Timer installation status: {md_status(packet.get('timer_installation_status'))}",
            f"- Emergency stop active: {md_status(packet.get('emergency_stop_active'))}",
            f"- Install review status: {md_status(packet.get('install_review_status'))}",
            f"- Safe checks passed: {md_status(packet.get('safe_checks_passed_count'))}",
            f"- Safe checks failed: {md_status(packet.get('safe_checks_failed_count'))}",
            f"- Packet breach: {md_status(packet.get('packet_breach'))}",
            f"- Blocked reason: {md_status(packet.get('blocked_reason'))}",
            "",
        ]
    )
    return lines


def render_owner_timer_install_decision_gate(decision: Dict[str, Any]) -> List[str]:
    lines = ["## Owner Timer Install Decision Gate", ""]
    if not decision or not decision.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_owner_timer_install_decision_gate.py status`",
                "",
            ]
        )
        return lines
    last_action = decision.get("last_owner_decision_action") if isinstance(decision.get("last_owner_decision_action"), dict) else {}
    lines.extend(
        [
            f"- Status: {md_status(decision.get('status'))}",
            f"- Gate status: {md_status(decision.get('gate_status'))}",
            f"- Decision status: {md_status(decision.get('decision_status'))}",
            f"- Manual install allowed: {md_status(decision.get('manual_install_allowed'))}",
            f"- Install allowed now: {md_status(decision.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(decision.get('can_install_timer_now'))}",
            f"- Emergency stop active: {md_status(decision.get('emergency_stop_active'))}",
            f"- Acknowledged no live apply: {md_status(decision.get('owner_acknowledged_no_live_apply'))}",
            f"- Acknowledged manual only: {md_status(decision.get('owner_acknowledged_manual_only'))}",
            f"- Acknowledged rollback: {md_status(decision.get('owner_acknowledged_rollback'))}",
            f"- Acknowledged emergency stop: {md_status(decision.get('owner_acknowledged_emergency_stop'))}",
            f"- Last owner decision action: {md_status(last_action.get('command'))}",
            f"- Decision breach: {md_status(decision.get('decision_breach'))}",
            f"- Blocked reason: {md_status(decision.get('blocked_reason'))}",
            "",
        ]
    )
    return lines


def render_manual_timer_install_command_preview(preview: Dict[str, Any]) -> List[str]:
    lines = ["## Manual Timer Install Command Preview", ""]
    if not preview or not preview.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_manual_timer_install_command_preview.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(preview.get('status'))}",
            f"- Preview status: {md_status(preview.get('preview_status'))}",
            f"- Decision status: {md_status(preview.get('decision_status'))}",
            f"- Manual install allowed: {md_status(preview.get('manual_install_allowed'))}",
            f"- Install allowed now: {md_status(preview.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(preview.get('can_install_timer_now'))}",
            f"- Emergency stop active: {md_status(preview.get('emergency_stop_active'))}",
            f"- Command preview written: {md_status(preview.get('command_preview_written'))}",
            f"- Shell script generated: {md_status(preview.get('shell_script_generated'))}",
            f"- systemd file written: {md_status(preview.get('systemd_file_written'))}",
            f"- crontab file written: {md_status(preview.get('crontab_file_written'))}",
            f"- Live apply: {md_status(preview.get('live_apply'))}",
            f"- Can execute live: {md_status(preview.get('can_execute_live'))}",
            f"- Apply status: {md_status(preview.get('apply_status'))}",
            f"- Preview breach: {md_status(preview.get('preview_breach'))}",
            f"- Blocked reason: {md_status(preview.get('blocked_reason'))}",
            "",
        ]
    )
    return lines


def render_owner_timer_install_evidence_pack(evidence: Dict[str, Any]) -> List[str]:
    lines = ["## Owner Timer Install Evidence Pack", ""]
    if not evidence or not evidence.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_owner_timer_install_evidence_pack.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Status: {md_status(evidence.get('status'))}",
            f"- Evidence pack status: {md_status(evidence.get('evidence_pack_status'))}",
            f"- Decision status: {md_status(evidence.get('decision_status'))}",
            f"- Preview status: {md_status(evidence.get('preview_status'))}",
            f"- Manual install allowed: {md_status(evidence.get('manual_install_allowed'))}",
            f"- Install allowed now: {md_status(evidence.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(evidence.get('can_install_timer_now'))}",
            f"- Emergency stop active: {md_status(evidence.get('emergency_stop_active'))}",
            f"- Evidence template written: {md_status(evidence.get('evidence_template_written'))}",
            f"- Shell script generated: {md_status(evidence.get('shell_script_generated'))}",
            f"- systemd file written: {md_status(evidence.get('systemd_file_written'))}",
            f"- crontab file written: {md_status(evidence.get('crontab_file_written'))}",
            f"- Live apply: {md_status(evidence.get('live_apply'))}",
            f"- Can execute live: {md_status(evidence.get('can_execute_live'))}",
            f"- Apply status: {md_status(evidence.get('apply_status'))}",
            f"- Evidence pack breach: {md_status(evidence.get('evidence_pack_breach'))}",
            f"- Blocked reason: {md_status(evidence.get('blocked_reason'))}",
            "",
        ]
    )
    return lines


def render_safe_draft_autonomy_final_safety(final: Dict[str, Any]) -> List[str]:
    lines = ["## Safe Draft Autonomy Final Safety", ""]
    if not final or not final.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_draft_autonomy_final_safety_report.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Final safety status: {md_status(final.get('final_safety_status'))}",
            f"- Draft-only autonomy ready: {md_status(final.get('draft_only_autonomy_ready'))}",
            f"- Draft-only runner verified: {md_status(final.get('draft_only_runner_verified'))}",
            f"- Timer installation ready for owner review: {md_status(final.get('timer_installation_ready_for_owner_review'))}",
            f"- Timer installation allowed now: {md_status(final.get('timer_installation_allowed_now'))}",
            f"- Live apply allowed: {md_status(final.get('live_apply_allowed'))}",
            f"- Emergency stop active: {md_status(final.get('emergency_stop_active'))}",
            f"- Total breaches: {md_status(final.get('total_breach_count'))}",
            f"- Total phases: {md_status(final.get('total_phase_count'))}",
            f"- Safe phases: {md_status(final.get('safe_phase_count'))}",
            f"- Blocked phases: {md_status(final.get('blocked_phase_count'))}",
            f"- Final safety breach: {md_status(final.get('final_safety_breach'))}",
            f"- Final recommended owner action: {md_status(final.get('final_recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_manual_evidence_review_dashboard(dashboard: Dict[str, Any]) -> List[str]:
    lines = ["## Manual Evidence Review Dashboard (Legacy / Superseded)", ""]
    if not dashboard or not dashboard.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_manual_evidence_review_dashboard.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Dashboard status: {md_status(dashboard.get('dashboard_status'))}",
            f"- Emergency stop active: {md_status(dashboard.get('emergency_stop_active'))}",
            f"- Total breaches: {md_status(dashboard.get('total_breaches'))}",
            f"- Safe chain count: {md_status(dashboard.get('safe_chain_count'))}",
            f"- Blocked chain count: {md_status(dashboard.get('blocked_chain_count'))}",
            f"- Evidence docs available/missing: {md_status(dashboard.get('evidence_docs_available_count'))} / {md_status(dashboard.get('evidence_docs_missing_count'))}",
            f"- Timer installation status: {md_status(dashboard.get('timer_installation_status'))}",
            f"- Install allowed now: {md_status(dashboard.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(dashboard.get('can_install_timer_now'))}",
            f"- Live apply allowed: {md_status(dashboard.get('live_apply_allowed'))}",
            f"- Open owner evidence items: {md_status(dashboard.get('open_owner_evidence_items_count'))}",
            f"- Dashboard breach: {md_status(dashboard.get('dashboard_breach'))}",
            f"- Next safe step: {md_status(dashboard.get('next_safe_step'))}",
            "",
        ]
    )
    return lines


def render_manual_evidence_review_completion_tracker(tracker: Dict[str, Any]) -> List[str]:
    lines = ["## Manual Evidence Review Completion Tracker", ""]
    if not tracker or not tracker.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_manual_evidence_review_completion_tracker.py list`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Tracker status: {md_status(tracker.get('tracker_status'))}",
            f"- Reviewed: {md_status(tracker.get('reviewed_count'))} / {md_status(tracker.get('total_items'))}",
            f"- Unchecked: {md_status(tracker.get('unchecked_count'))}",
            f"- Needs work: {md_status(tracker.get('needs_work_count'))}",
            f"- Blocked: {md_status(tracker.get('blocked_count'))}",
            f"- Skipped: {md_status(tracker.get('skipped_count'))}",
            f"- Completion percent: {md_status(tracker.get('completion_percent'))}",
            f"- Emergency stop active: {md_status(tracker.get('emergency_stop_active'))}",
            f"- Install allowed now: {md_status(tracker.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(tracker.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(tracker.get('live_apply'))}",
            f"- Tracker breach: {md_status(tracker.get('tracker_breach'))}",
            f"- Next owner action: {md_status(tracker.get('next_owner_action'))}",
            "",
        ]
    )
    return lines


def render_manual_evidence_review_completion_gate(gate: Dict[str, Any]) -> List[str]:
    lines = ["## Manual Evidence Review Completion Gate", ""]
    if not gate or not gate.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_manual_evidence_review_completion_gate.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Gate status: {md_status(gate.get('gate_status'))}",
            f"- Reviewed: {md_status(gate.get('reviewed_count'))} / {md_status(gate.get('total_items'))}",
            f"- Completion percent: {md_status(gate.get('completion_percent'))}",
            f"- All required reviewed: {md_status(gate.get('all_required_reviewed'))}",
            f"- Unchecked: {md_status(gate.get('unchecked_count'))}",
            f"- Needs work: {md_status(gate.get('needs_work_count'))}",
            f"- Blocked: {md_status(gate.get('blocked_count'))}",
            f"- Emergency stop active: {md_status(gate.get('emergency_stop_active'))}",
            f"- Install allowed now: {md_status(gate.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(gate.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(gate.get('live_apply'))}",
            f"- Gate breach: {md_status(gate.get('gate_breach'))}",
            f"- Next owner action: {md_status(gate.get('next_owner_action'))}",
            f"- Reason: {md_status(gate.get('reason'))}",
            "",
        ]
    )
    return lines


def render_owner_evidence_review_console(console: Dict[str, Any]) -> List[str]:
    lines = ["## Owner Evidence Review Console", ""]
    if not console or not console.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_owner_evidence_review_console.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Console status: {md_status(console.get('console_status'))}",
            f"- Reviewed: {md_status(console.get('reviewed_count'))} / {md_status(console.get('total_items'))}",
            f"- Open items: {md_status(console.get('open_items_count'))}",
            f"- Unchecked: {md_status(console.get('unchecked_count'))}",
            f"- Needs work: {md_status(console.get('needs_work_count'))}",
            f"- Blocked: {md_status(console.get('blocked_count'))}",
            f"- Emergency stop active: {md_status(console.get('emergency_stop_active'))}",
            f"- Install allowed now: {md_status(console.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(console.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(console.get('live_apply'))}",
            f"- Next recommended item: {md_status(console.get('next_recommended_item'))}",
            f"- Console breach: {md_status(console.get('console_breach'))}",
            f"- Next owner action: {md_status(console.get('next_owner_action'))}",
            "",
        ]
    )
    return lines


def render_final_owner_decision_snapshot(snapshot: Dict[str, Any]) -> List[str]:
    lines = ["## Final Owner Decision Snapshot (Legacy / Superseded)", ""]
    if not snapshot or not snapshot.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_final_owner_decision_snapshot.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Snapshot status: {md_status(snapshot.get('snapshot_status'))}",
            f"- Review completed: {md_status(snapshot.get('review_completed'))}",
            f"- Reviewed: {md_status(snapshot.get('reviewed_count'))} / {md_status(snapshot.get('total_items'))}",
            f"- Completion percent: {md_status(snapshot.get('completion_percent'))}",
            f"- Emergency stop active: {md_status(snapshot.get('emergency_stop_active'))}",
            f"- Install allowed now: {md_status(snapshot.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(snapshot.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(snapshot.get('live_apply'))}",
            f"- Timer installation status: {md_status(snapshot.get('timer_installation_status'))}",
            f"- Total breaches: {md_status(snapshot.get('total_breaches'))}",
            f"- Owner decision required for any install: {md_status(snapshot.get('owner_decision_required_for_any_install'))}",
            f"- Snapshot breach: {md_status(snapshot.get('snapshot_breach'))}",
            f"- Recommended owner action: {md_status(snapshot.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_master_critical_cause_snapshot(snapshot: Dict[str, Any]) -> List[str]:
    lines = ["## Master Critical Cause Snapshot", ""]
    if not snapshot or not snapshot.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_master_critical_cause_snapshot.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Critical snapshot status: {md_status(snapshot.get('critical_snapshot_status'))}",
            f"- Master status: {md_status(snapshot.get('master_status'))}",
            f"- Action status: {md_status(snapshot.get('action_status'))}",
            f"- Critical caused by autonomy: {md_status(snapshot.get('critical_caused_by_autonomy'))}",
            f"- Critical caused by website: {md_status(snapshot.get('critical_caused_by_website'))}",
            f"- Critical caused by rolling window: {md_status(snapshot.get('critical_caused_by_rolling_window'))}",
            f"- Critical caused by SourceMap: {md_status(snapshot.get('critical_caused_by_sourcemap'))}",
            f"- Autonomy total breaches: {md_status(snapshot.get('autonomy_total_breaches'))}",
            f"- Final owner snapshot breach: {md_status(snapshot.get('final_owner_snapshot_breach'))}",
            f"- Emergency stop active: {md_status(snapshot.get('emergency_stop_active'))}",
            f"- Install allowed now: {md_status(snapshot.get('install_allowed_now'))}",
            f"- Live apply: {md_status(snapshot.get('live_apply'))}",
            f"- Snapshot breach: {md_status(snapshot.get('snapshot_breach'))}",
            f"- Recommended owner action: {md_status(snapshot.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_rolling_window_decay_observer(observer: Dict[str, Any]) -> List[str]:
    lines = ["## Rolling Window Decay Observer", ""]
    if not observer or not observer.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_rolling_window_decay_observer.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Decay status: {md_status(observer.get('decay_status'))}",
            f"- Trend: {md_status(observer.get('trend'))}",
            f"- Master status: {md_status(observer.get('master_status'))}",
            f"- Website critical: {md_status(observer.get('website_critical'))}",
            f"- Autonomy cause: {md_status(observer.get('autonomy_cause'))}",
            f"- Website cause: {md_status(observer.get('website_cause'))}",
            f"- Rolling-window cause: {md_status(observer.get('rolling_window_cause'))}",
            f"- SourceMap warning: {md_status(observer.get('sourcemap_warning'))}",
            f"- Current 5xx total: {md_status(observer.get('current_5xx_total'))}",
            f"- Previous 5xx total: {md_status(observer.get('previous_5xx_total'))}",
            f"- Delta 5xx: {md_status(observer.get('delta_5xx'))}",
            f"- Current 504 total: {md_status(observer.get('current_504_total'))}",
            f"- Previous 504 total: {md_status(observer.get('previous_504_total'))}",
            f"- Delta 504: {md_status(observer.get('delta_504'))}",
            f"- Current SourceMap 404 total: {md_status(observer.get('current_sourcemap_404_total'))}",
            f"- Delta SourceMap 404: {md_status(observer.get('delta_sourcemap_404'))}",
            f"- History points: {md_status(observer.get('history_points'))}",
            f"- Observation required: {md_status(observer.get('observation_required'))}",
            f"- Snapshot breach: {md_status(observer.get('snapshot_breach'))}",
            f"- Recommended owner action: {md_status(observer.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_low_growth_readiness_timeline(timeline: Dict[str, Any]) -> List[str]:
    lines = ["## Low Growth Readiness Timeline", ""]
    if not timeline or not timeline.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_low_growth_readiness_timeline.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Timeline status: {md_status(timeline.get('timeline_status'))}",
            f"- Total points: {md_status(timeline.get('total_points'))}",
            f"- Increasing points: {md_status(timeline.get('increasing_points'))}",
            f"- Stable points: {md_status(timeline.get('stable_points'))}",
            f"- Decreasing points: {md_status(timeline.get('decreasing_points'))}",
            f"- Last trend: {md_status(timeline.get('last_trend'))}",
            f"- Consecutive stable or decreasing points: {md_status(timeline.get('consecutive_stable_or_decreasing_points'))}",
            f"- Latest 5xx total: {md_status(timeline.get('latest_5xx_total'))}",
            f"- Latest 504 total: {md_status(timeline.get('latest_504_total'))}",
            f"- Latest delta 5xx: {md_status(timeline.get('latest_delta_5xx'))}",
            f"- Latest delta 504: {md_status(timeline.get('latest_delta_504'))}",
            f"- Readiness level: {md_status(timeline.get('readiness_level'))}",
            f"- Manual recheck recommended: {md_status(timeline.get('manual_recheck_recommended'))}",
            f"- Observation required: {md_status(timeline.get('observation_required'))}",
            f"- Snapshot breach: {md_status(timeline.get('snapshot_breach'))}",
            f"- Recommended owner action: {md_status(timeline.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_manual_website_recheck_gate(gate: Dict[str, Any]) -> List[str]:
    lines = ["## Manual Website Recheck Gate", ""]
    if not gate or not gate.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_manual_website_recheck_gate.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Gate status: {md_status(gate.get('gate_status'))}",
            f"- Manual recheck recommended: {md_status(gate.get('manual_recheck_recommended'))}",
            f"- Timeline status: {md_status(gate.get('timeline_status'))}",
            f"- Decay status: {md_status(gate.get('decay_status'))}",
            f"- Last trend: {md_status(gate.get('last_trend'))}",
            f"- Consecutive stable/decreasing points: {md_status(gate.get('consecutive_stable_or_decreasing_points'))}",
            f"- Total points: {md_status(gate.get('total_points'))}",
            f"- Latest 5xx total: {md_status(gate.get('latest_5xx_total'))}",
            f"- Latest 504 total: {md_status(gate.get('latest_504_total'))}",
            f"- Latest delta 5xx: {md_status(gate.get('latest_delta_5xx'))}",
            f"- Latest delta 504: {md_status(gate.get('latest_delta_504'))}",
            f"- Master status: {md_status(gate.get('master_status'))}",
            f"- Critical caused by website: {md_status(gate.get('critical_caused_by_website'))}",
            f"- Critical caused by autonomy: {md_status(gate.get('critical_caused_by_autonomy'))}",
            f"- Emergency stop active: {md_status(gate.get('emergency_stop_active'))}",
            f"- Gate breach: {md_status(gate.get('gate_breach'))}",
            f"- Recommended owner action: {md_status(gate.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_low_risk_autonomy_readiness_gate(gate: Dict[str, Any]) -> List[str]:
    lines = ["## Low-Risk Autonomy Readiness Gate", ""]
    if not gate or not gate.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_low_risk_autonomy_readiness_gate.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Readiness status: {md_status(gate.get('readiness_status'))}",
            f"- LOW-RISK autonomy allowed now: {md_status(gate.get('low_risk_autonomy_allowed_now'))}",
            f"- LOW-RISK policy draft allowed: {md_status(gate.get('low_risk_policy_draft_allowed'))}",
            f"- Owner policy review required: {md_status(gate.get('owner_policy_review_required'))}",
            f"- Manual recheck recommended: {md_status(gate.get('manual_recheck_recommended'))}",
            f"- Manual recheck gate status: {md_status(gate.get('manual_recheck_gate_status'))}",
            f"- Timeline status: {md_status(gate.get('timeline_status'))}",
            f"- Decay status: {md_status(gate.get('decay_status'))}",
            f"- Consecutive stable/decreasing points: {md_status(gate.get('consecutive_stable_or_decreasing_points'))}",
            f"- Emergency stop active: {md_status(gate.get('emergency_stop_active'))}",
            f"- Autonomy total breaches: {md_status(gate.get('autonomy_total_breaches'))}",
            f"- Final owner snapshot breach: {md_status(gate.get('final_owner_snapshot_breach'))}",
            f"- Readiness breach: {md_status(gate.get('readiness_breach'))}",
            f"- Recommended owner action: {md_status(gate.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_low_risk_policy_boundary_draft(policy: Dict[str, Any]) -> List[str]:
    lines = ["## LOW-RISK Policy Boundary Draft", ""]
    if not policy or not policy.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_low_risk_policy_boundary_draft.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Policy status: {md_status(policy.get('policy_status'))}",
            f"- Emergency stop active: {md_status(policy.get('emergency_stop_active'))}",
            f"- Owner policy review required: {md_status(policy.get('owner_policy_review_required'))}",
            f"- Policy activation allowed: {md_status(policy.get('policy_activation_allowed'))}",
            f"- LOW-RISK autonomy allowed now: {md_status(policy.get('low_risk_autonomy_allowed_now'))}",
            f"- LOW-RISK draft-only count: {md_status(policy.get('low_risk_draft_only_count'))}",
            f"- LOW-RISK review-only count: {md_status(policy.get('low_risk_review_only_count'))}",
            f"- LOW-RISK potential-future-apply count: {md_status(policy.get('low_risk_potential_future_apply_count'))}",
            f"- MEDIUM owner-approval-required count: {md_status(policy.get('medium_owner_approval_required_count'))}",
            f"- HIGH never-auto-apply count: {md_status(policy.get('high_never_auto_apply_count'))}",
            f"- FORBIDDEN count: {md_status(policy.get('forbidden_count'))}",
            f"- Policy breach: {md_status(policy.get('policy_breach'))}",
            f"- Recommended owner action: {md_status(policy.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_low_risk_policy_owner_review_tracker(tracker: Dict[str, Any]) -> List[str]:
    lines = ["## LOW-RISK Policy Owner Review", ""]
    if not tracker or not tracker.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_low_risk_policy_owner_review_tracker.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Tracker status: {md_status(tracker.get('tracker_status'))}",
            f"- Reviewed: {md_status(tracker.get('reviewed_count'))} / {md_status(tracker.get('total_required'))}",
            f"- Unchecked: {md_status(tracker.get('unchecked_count'))}",
            f"- Needs work: {md_status(tracker.get('needs_work_count'))}",
            f"- Completion percent: {md_status(tracker.get('completion_percent'))}",
            f"- All required reviewed: {md_status(tracker.get('all_required_reviewed'))}",
            f"- Emergency stop active: {md_status(tracker.get('emergency_stop_active'))}",
            f"- LOW-RISK autonomy allowed now: {md_status(tracker.get('low_risk_autonomy_allowed_now'))}",
            f"- Policy activation allowed: {md_status(tracker.get('policy_activation_allowed'))}",
            f"- Install allowed now: {md_status(tracker.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(tracker.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(tracker.get('live_apply'))}",
            f"- Apply status: {md_status(tracker.get('apply_status'))}",
            f"- Tracker breach: {md_status(tracker.get('tracker_breach'))}",
            f"- Recommended owner action: {md_status(tracker.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_low_risk_policy_review_completion_gate(gate: Dict[str, Any]) -> List[str]:
    lines = ["## LOW-RISK Policy Review Completion", ""]
    if not gate or not gate.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_low_risk_policy_review_completion_gate.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Gate status: {md_status(gate.get('gate_status'))}",
            f"- Tracker status: {md_status(gate.get('tracker_status'))}",
            f"- Reviewed: {md_status(gate.get('reviewed_count'))} / {md_status(gate.get('total_required'))}",
            f"- Completion percent: {md_status(gate.get('completion_percent'))}",
            f"- All required reviewed: {md_status(gate.get('all_required_reviewed'))}",
            f"- Emergency stop active: {md_status(gate.get('emergency_stop_active'))}",
            f"- LOW-RISK autonomy allowed now: {md_status(gate.get('low_risk_autonomy_allowed_now'))}",
            f"- Policy activation allowed: {md_status(gate.get('policy_activation_allowed'))}",
            f"- Install allowed now: {md_status(gate.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(gate.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(gate.get('live_apply'))}",
            f"- Apply status: {md_status(gate.get('apply_status'))}",
            f"- Gate breach: {md_status(gate.get('gate_breach'))}",
            f"- Recommended owner action: {md_status(gate.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_low_risk_autonomy_final_safety_seal(seal: Dict[str, Any]) -> List[str]:
    lines = ["## LOW-RISK Autonomy Final Safety Seal", ""]
    if not seal or not seal.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_low_risk_autonomy_final_safety_seal.py`",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Seal status: {md_status(seal.get('seal_status'))}",
            f"- Review completed: {md_status(seal.get('review_completed'))}",
            f"- Reviewed: {md_status(seal.get('reviewed_count'))} / {md_status(seal.get('total_required'))}",
            f"- Emergency stop active: {md_status(seal.get('emergency_stop_active'))}",
            f"- LOW-RISK autonomy allowed now: {md_status(seal.get('low_risk_autonomy_allowed_now'))}",
            f"- Policy activation allowed: {md_status(seal.get('policy_activation_allowed'))}",
            f"- Install allowed now: {md_status(seal.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(seal.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(seal.get('live_apply'))}",
            f"- Apply status: {md_status(seal.get('apply_status'))}",
            f"- Total breaches: {md_status(seal.get('total_breaches'))}",
            f"- Seal breach: {md_status(seal.get('seal_breach'))}",
            f"- Recommended owner action: {md_status(seal.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_safe_end_summary(safe_end: Dict[str, Any]) -> List[str]:
    lines = ["## Safe End Summary", ""]
    if not safe_end or not safe_end.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_end_summary.py`",
                "- Hinweis: Phase 5.10 is a safe locked end state, not autonomy activation.",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Safe end status: {md_status(safe_end.get('safe_end_status'))}",
            f"- Evidence review complete: {md_status(safe_end.get('evidence_review_complete'))}",
            f"- Final owner snapshot complete: {md_status(safe_end.get('final_owner_snapshot_complete'))}",
            f"- Website recheck recommended: {md_status(safe_end.get('website_recheck_recommended'))}",
            f"- LOW-RISK policy review complete: {md_status(safe_end.get('low_risk_policy_review_complete'))}",
            f"- LOW-RISK final seal complete: {md_status(safe_end.get('low_risk_final_seal_complete'))}",
            f"- Emergency stop active: {md_status(safe_end.get('emergency_stop_active'))}",
            f"- LOW-RISK autonomy allowed now: {md_status(safe_end.get('low_risk_autonomy_allowed_now'))}",
            f"- Policy activation allowed: {md_status(safe_end.get('policy_activation_allowed'))}",
            f"- Install allowed now: {md_status(safe_end.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(safe_end.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(safe_end.get('live_apply'))}",
            f"- Apply status: {md_status(safe_end.get('apply_status'))}",
            f"- Total breaches: {md_status(safe_end.get('total_breaches'))}",
            f"- Safe end breach: {md_status(safe_end.get('safe_end_breach'))}",
            f"- Recommended owner action: {md_status(safe_end.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_safe_end_archive_snapshot(archive: Dict[str, Any]) -> List[str]:
    lines = ["## Safe-End Archive Snapshot", ""]
    if not archive or not archive.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_end_archive_snapshot.py`",
                "- Hinweis: Phase 5.11 archives the locked safe end state. It is not activation, not install, not restore.",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Archive status: {md_status(archive.get('archive_status'))}",
            f"- Archive path: {md_status(archive.get('archive_path'))}",
            f"- Copied file count: {md_status(archive.get('copied_file_count'))}",
            f"- Checksum count: {md_status(archive.get('checksum_count'))}",
            f"- Safe end status: {md_status(archive.get('safe_end_status'))}",
            f"- Emergency stop active: {md_status(archive.get('emergency_stop_active'))}",
            f"- LOW-RISK autonomy allowed now: {md_status(archive.get('low_risk_autonomy_allowed_now'))}",
            f"- Policy activation allowed: {md_status(archive.get('policy_activation_allowed'))}",
            f"- Install allowed now: {md_status(archive.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(archive.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(archive.get('live_apply'))}",
            f"- Apply status: {md_status(archive.get('apply_status'))}",
            f"- Total breaches: {md_status(archive.get('total_breaches'))}",
            f"- Archive breach: {md_status(archive.get('archive_breach'))}",
            f"- Recommended owner action: {md_status(archive.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_safe_end_archive_integrity_verifier(integrity: Dict[str, Any]) -> List[str]:
    lines = ["## Safe-End Archive Integrity Verifier", ""]
    if not integrity or not integrity.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_end_archive_integrity_verifier.py`",
                "- Hinweis: Phase 5.12 verifies the locked archive. It is not restore, not activation, not install.",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Integrity status: {md_status(integrity.get('integrity_status'))}",
            f"- Latest archive path: {md_status(integrity.get('latest_archive_path'))}",
            f"- Manifest file count: {md_status(integrity.get('manifest_file_count'))}",
            f"- Checksum file count: {md_status(integrity.get('checksum_file_count'))}",
            f"- Verified checksum count: {md_status(integrity.get('verified_checksum_count'))}",
            f"- Missing file count: {md_status(integrity.get('missing_file_count'))}",
            f"- Checksum mismatch count: {md_status(integrity.get('checksum_mismatch_count'))}",
            f"- Forbidden artifact count: {md_status(integrity.get('forbidden_artifact_count'))}",
            f"- Restore executed: {md_status(integrity.get('restore_executed'))}",
            f"- Safe end status: {md_status(integrity.get('safe_end_status'))}",
            f"- Archive status: {md_status(integrity.get('archive_status'))}",
            f"- Emergency stop active: {md_status(integrity.get('emergency_stop_active'))}",
            f"- LOW-RISK autonomy allowed now: {md_status(integrity.get('low_risk_autonomy_allowed_now'))}",
            f"- Policy activation allowed: {md_status(integrity.get('policy_activation_allowed'))}",
            f"- Install allowed now: {md_status(integrity.get('install_allowed_now'))}",
            f"- Can install timer now: {md_status(integrity.get('can_install_timer_now'))}",
            f"- Live apply: {md_status(integrity.get('live_apply'))}",
            f"- Apply status: {md_status(integrity.get('apply_status'))}",
            f"- Integrity breach: {md_status(integrity.get('integrity_breach'))}",
            f"- Recommended owner action: {md_status(integrity.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_safe_sftp_seo_apply_lane(lane: Dict[str, Any]) -> List[str]:
    lines = ["## Safe SFTP SEO Apply Lane (Level 1)", ""]
    if not lane or not lane.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_safe_sftp_seo_apply_lane.py dry-run`",
                "- Hinweis: Dry-run/prepare only unless explicit owner approval exists. No uncontrolled live apply.",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Apply lane status: {md_status(lane.get('apply_lane_status'))}",
            f"- Mode: {md_status(lane.get('mode'))}",
            f"- Target file: {md_status(lane.get('target_file'))}",
            f"- Uploaded: {md_status(lane.get('uploaded'))}",
            f"- Healthcheck status: {md_status(lane.get('healthcheck_status'))}",
            f"- Rollback status: {md_status(lane.get('rollback_status'))}",
            f"- Changed file count: {md_status(lane.get('changed_file_count'))}",
            f"- Allowed target only: {md_status(lane.get('allowed_target_only'))}",
            f"- Live apply: {md_status(lane.get('live_apply'))}",
            f"- Apply status: {md_status(lane.get('apply_status'))}",
            f"- Apply breach: {md_status(lane.get('apply_breach'))}",
            f"- Recommended owner action: {md_status(lane.get('recommended_owner_action'))}",
            "",
        ]
    )
    return lines


def render_concrete_seo_performance_optimizer(optimizer: Dict[str, Any]) -> List[str]:
    lines = ["## Concrete SEO & Performance Optimizer", ""]
    if not optimizer or not optimizer.get("present"):
        lines.extend(
            [
                "- Status: `NOT_AVAILABLE`",
                "- Empfehlung: `run sentinel_concrete_seo_performance_optimizer.py`",
                "- Hinweis: Phase 6.0 erzeugt konkrete Owner-Drafts, aber keinen Live-Apply.",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            f"- Optimizer status: {md_status(optimizer.get('optimizer_status'))}",
            f"- SEO pack created: {md_status(optimizer.get('seo_pack_created'))}",
            f"- Performance pack created: {md_status(optimizer.get('performance_pack_created'))}",
            f"- WordPress copy/paste pack created: {md_status(optimizer.get('wordpress_copy_paste_pack_created'))}",
            f"- JSON-LD pack created: {md_status(optimizer.get('jsonld_pack_created'))}",
            f"- Internal linking pack created: {md_status(optimizer.get('internal_linking_pack_created'))}",
            f"- Image pack created: {md_status(optimizer.get('image_pack_created'))}",
            f"- Origin 5xx pack created: {md_status(optimizer.get('origin_5xx_pack_created'))}",
            f"- Total recommendations: {md_status(optimizer.get('total_recommendations'))}",
            f"- Copy/Paste owner apply count: {md_status(optimizer.get('copy_paste_owner_apply_count'))}",
            f"- Owner review required count: {md_status(optimizer.get('owner_review_required_count'))}",
            f"- Diagnostic only count: {md_status(optimizer.get('diagnostic_only_count'))}",
            f"- Do not apply automatically count: {md_status(optimizer.get('do_not_apply_automatically_count'))}",
            f"- Live apply: {md_status(optimizer.get('live_apply'))}",
            f"- Install allowed now: {md_status(optimizer.get('install_allowed_now'))}",
            f"- Policy activation allowed: {md_status(optimizer.get('policy_activation_allowed'))}",
            f"- Apply status: {md_status(optimizer.get('apply_status'))}",
            f"- Optimizer breach: {md_status(optimizer.get('optimizer_breach'))}",
            "",
        ]
    )
    return lines


def render_canonical_runtime_section(
    header: Dict[str, Any], summary: Dict[str, Any]
) -> List[str]:
    """Runtime section with per-field provenance; no Level-1 data may appear here."""
    lines = [
        "## Runtime Status (Canonical)",
        "",
        f"- Canonical truth status: {md_status(summary.get('status', 'NOT_AVAILABLE'))}",
        f"- Canonical snapshot: {md_status(header.get('canonical_generated_at'))}",
        f"- Resolved fields: {md_status(summary.get('resolved_fields'))}, "
        f"unresolved: {md_status(summary.get('unresolved_fields'))}",
        "",
        "| Field | Value | Source | Freshness |",
        "|---|---|---|---|",
    ]
    for field in (
        "autonomy_level",
        "runtime_stage",
        "runtime_status",
        "monitoring_enabled",
        "timer_active",
        "timer_enabled",
        "scheduler_status",
        "low_live_enabled",
        "medium_live_enabled",
        "high_live_enabled",
        "production_apply_lock",
        "circuit_breaker_status",
        "rollback_status",
        "write_canary_status",
        "promotion_status",
        "emergency_stop",
        "breach",
        "owner_priority",
    ):
        lines.append(
            f"| `{field}` | {md_status(canonical_cell(header, field))} | "
            f"{md_status(header.get(f'{field}__source'))} | "
            f"{md_status(header.get(f'{field}__freshness'))} |"
        )
    lines.extend([
        "",
        "- Legacy Level-1 data never appears in this section.",
        f"- Owner priority rank: {md_status(header.get('owner_priority_rank'))}",
        f"- Suppressed lower priorities: "
        f"{md_status(', '.join(header.get('owner_priority_suppressed', [])) or 'none')}",
        f"- Legacy SEO checklist may lead: {md_status(header.get('legacy_seo_checklist_allowed'))}",
        "",
    ])
    return lines


def render_legacy_historical_modules(legacy: Dict[str, Any]) -> List[str]:
    """Historical modules stay visible, explicitly labelled and without effect."""
    lines = ["## Legacy / Historical Modules", ""]
    if not legacy.get("present"):
        lines.extend([
            "- No legacy supersession snapshot is available (run `sentinel_canonical_truth.py --resolve`).",
            "",
        ])
        return lines
    counts = legacy.get("counts", {}) if isinstance(legacy.get("counts"), dict) else {}
    lines.extend([
        f"- Status: {md_status(legacy.get('status'))}",
        f"- Retention: {safe_text(legacy.get('retention'))}",
        f"- Legacy modules: {md_status(counts.get('legacy_modules'))}, "
        f"superseded field claims: {md_status(counts.get('superseded'))}, "
        f"conflicts neutralized: {md_status(counts.get('conflicts_neutralized'))}",
        "",
        "| Legacy module | Generated | Freshness | Superseded by | Operational effect |",
        "|---|---|---|---|---|",
    ])
    for row in legacy.get("legacy_modules", []):
        superseded_by = ", ".join(row.get("superseded_by", [])) or "-"
        lines.append(
            f"| {md_status(row.get('legacy_source'))} | {md_status(row.get('generated_at'))} | "
            f"{md_status(row.get('freshness'))} | {md_status(superseded_by)} | `false` |"
        )
    claims = legacy.get("superseded_field_claims", [])
    if claims:
        lines.extend([
            "",
            "| Canonical field | Legacy value | Canonical value | Freshness | Operational effect |",
            "|---|---|---|---|---|",
        ])
        for row in claims:
            legacy_value = row.get("legacy_value")
            canonical_value = row.get("canonical_value")
            if isinstance(legacy_value, (dict, list)):
                legacy_value = type(legacy_value).__name__
            if isinstance(canonical_value, (dict, list)):
                canonical_value = type(canonical_value).__name__
            lines.append(
                f"| {md_status(row.get('canonical_field'))} | {md_status(legacy_value)} | "
                f"{md_status(canonical_value)} | {md_status(row.get('freshness'))} | `false` |"
            )
    lines.extend([
        "",
        "- Historical components, reports and state files are never deleted.",
        "- A legacy value never overwrites a current runtime field, owner priority, systemd "
        "state, emergency stop state, autonomy level or website metric.",
        "",
    ])
    return lines


def render_markdown(report: Dict[str, Any]) -> str:
    website = report["sources"]["website"]
    hetzner_local = report["sources"]["hetzner_local"]
    private_pc_local = report["sources"]["private_pc_local"]
    sourcemap_prevention = report["sources"].get("sourcemap_prevention", {})
    ai_radio_timeout = report["sources"].get("ai_radio_timeout", {})
    autonomy_policy = report.get("autonomy_policy", {}) if isinstance(report.get("autonomy_policy"), dict) else {}
    draft_execution_planner = report.get("draft_execution_planner", {}) if isinstance(report.get("draft_execution_planner"), dict) else {}
    owner_review_pack = report.get("owner_review_pack", {}) if isinstance(report.get("owner_review_pack"), dict) else {}
    manual_apply_checklist = report.get("manual_apply_checklist", {}) if isinstance(report.get("manual_apply_checklist"), dict) else {}
    manual_completion_tracker = report.get("manual_completion_tracker", {}) if isinstance(report.get("manual_completion_tracker"), dict) else {}
    post_manual_validation = report.get("post_manual_validation", {}) if isinstance(report.get("post_manual_validation"), dict) else {}
    owner_daily_action_summary = report.get("owner_daily_action_summary", {}) if isinstance(report.get("owner_daily_action_summary"), dict) else {}
    safe_apply_registry = report.get("safe_apply_candidate_registry", {}) if isinstance(report.get("safe_apply_candidate_registry"), dict) else {}
    safe_apply_guard = report.get("safe_apply_guard_check", {}) if isinstance(report.get("safe_apply_guard_check"), dict) else {}
    safe_apply_scope = report.get("safe_apply_scope_manager", {}) if isinstance(report.get("safe_apply_scope_manager"), dict) else {}
    safe_apply_dry_run = report.get("safe_apply_dry_run_planner", {}) if isinstance(report.get("safe_apply_dry_run_planner"), dict) else {}
    safe_apply_preflight = report.get("safe_apply_preflight_validator", {}) if isinstance(report.get("safe_apply_preflight_validator"), dict) else {}
    autonomy_runtime_lock = report.get("autonomy_runtime_lock", {}) if isinstance(report.get("autonomy_runtime_lock"), dict) else {}
    safe_draft_runner = report.get("safe_draft_autonomy_runner", {}) if isinstance(report.get("safe_draft_autonomy_runner"), dict) else {}
    safe_draft_verifier = report.get("safe_draft_autonomy_verifier", {}) if isinstance(report.get("safe_draft_autonomy_verifier"), dict) else {}
    safe_draft_scheduler = report.get("safe_draft_autonomy_scheduler_plan", {}) if isinstance(report.get("safe_draft_autonomy_scheduler_plan"), dict) else {}
    safe_draft_timer = report.get("safe_draft_autonomy_timer_draft", {}) if isinstance(report.get("safe_draft_autonomy_timer_draft"), dict) else {}
    safe_draft_timer_review = report.get("safe_draft_autonomy_timer_install_review", {}) if isinstance(report.get("safe_draft_autonomy_timer_install_review"), dict) else {}
    owner_manual_timer_packet = report.get("owner_manual_timer_install_packet", {}) if isinstance(report.get("owner_manual_timer_install_packet"), dict) else {}
    owner_timer_decision = report.get("owner_timer_install_decision_gate", {}) if isinstance(report.get("owner_timer_install_decision_gate"), dict) else {}
    manual_timer_preview = report.get("manual_timer_install_command_preview", {}) if isinstance(report.get("manual_timer_install_command_preview"), dict) else {}
    owner_timer_evidence = report.get("owner_timer_install_evidence_pack", {}) if isinstance(report.get("owner_timer_install_evidence_pack"), dict) else {}
    final_safety = report.get("safe_draft_autonomy_final_safety", {}) if isinstance(report.get("safe_draft_autonomy_final_safety"), dict) else {}
    manual_evidence_dashboard = report.get("manual_evidence_review_dashboard", {}) if isinstance(report.get("manual_evidence_review_dashboard"), dict) else {}
    manual_evidence_completion = report.get("manual_evidence_review_completion_tracker", {}) if isinstance(report.get("manual_evidence_review_completion_tracker"), dict) else {}
    manual_evidence_gate = report.get("manual_evidence_review_completion_gate", {}) if isinstance(report.get("manual_evidence_review_completion_gate"), dict) else {}
    owner_evidence_console = report.get("owner_evidence_review_console", {}) if isinstance(report.get("owner_evidence_review_console"), dict) else {}
    final_owner_snapshot = report.get("final_owner_decision_snapshot", {}) if isinstance(report.get("final_owner_decision_snapshot"), dict) else {}
    master_critical_cause = report.get("master_critical_cause_snapshot", {}) if isinstance(report.get("master_critical_cause_snapshot"), dict) else {}
    rolling_window_decay = report.get("rolling_window_decay_observer", {}) if isinstance(report.get("rolling_window_decay_observer"), dict) else {}
    low_growth_timeline = report.get("low_growth_readiness_timeline", {}) if isinstance(report.get("low_growth_readiness_timeline"), dict) else {}
    manual_recheck_gate = report.get("manual_website_recheck_gate", {}) if isinstance(report.get("manual_website_recheck_gate"), dict) else {}
    low_risk_readiness_gate = report.get("low_risk_autonomy_readiness_gate", {}) if isinstance(report.get("low_risk_autonomy_readiness_gate"), dict) else {}
    low_risk_policy_boundary = report.get("low_risk_policy_boundary_draft", {}) if isinstance(report.get("low_risk_policy_boundary_draft"), dict) else {}
    low_risk_owner_review = report.get("low_risk_policy_owner_review_tracker", {}) if isinstance(report.get("low_risk_policy_owner_review_tracker"), dict) else {}
    low_risk_completion_gate = report.get("low_risk_policy_review_completion_gate", {}) if isinstance(report.get("low_risk_policy_review_completion_gate"), dict) else {}
    low_risk_final_seal = report.get("low_risk_autonomy_final_safety_seal", {}) if isinstance(report.get("low_risk_autonomy_final_safety_seal"), dict) else {}
    safe_end = report.get("safe_end_summary", {}) if isinstance(report.get("safe_end_summary"), dict) else {}
    safe_end_archive = report.get("safe_end_archive_snapshot", {}) if isinstance(report.get("safe_end_archive_snapshot"), dict) else {}
    safe_end_integrity = report.get("safe_end_archive_integrity_verifier", {}) if isinstance(report.get("safe_end_archive_integrity_verifier"), dict) else {}
    concrete_optimizer = report.get("concrete_seo_performance_optimizer", {}) if isinstance(report.get("concrete_seo_performance_optimizer"), dict) else {}
    safe_sftp_lane = report.get("safe_sftp_seo_apply_lane", {}) if isinstance(report.get("safe_sftp_seo_apply_lane"), dict) else {}
    canonical_header = report.get("canonical_header", {}) if isinstance(report.get("canonical_header"), dict) else {}
    canonical_summary = report.get("canonical_truth", {}) if isinstance(report.get("canonical_truth"), dict) else {}
    legacy_supersession = report.get("legacy_supersession", {}) if isinstance(report.get("legacy_supersession"), dict) else {}

    def canonical_row(field: str) -> str:
        return md_status(canonical_cell(canonical_header, field))

    lines = [
        "# Sentinel Master Report",
        "",
        f"**Generated:** `{safe_text(report.get('generated_at_utc'))}` UTC",
        "",
        "## Canonical Runtime Truth (Phase 10.21)",
        "",
        f"- Canonical Truth Status: {md_status(report.get('canonical_truth_status'))}",
        f"- Canonical Snapshot: {md_status(canonical_header.get('canonical_generated_at'))}",
        f"- Runtime Level: {canonical_row('autonomy_level')}",
        f"- Runtime Stage: {canonical_row('runtime_stage')}",
        f"- Runtime Health: {canonical_row('runtime_status')}",
        f"- 24/7 Monitoring: {canonical_row('monitoring_enabled')}",
        f"- systemd Timer Active: {canonical_row('timer_active')}",
        f"- Scheduler: {canonical_row('scheduler_status')}",
        f"- LOW_LIVE: {canonical_row('low_live_enabled')}",
        f"- MEDIUM: {canonical_row('medium_live_enabled')}",
        f"- HIGH: {canonical_row('high_live_enabled')}",
        f"- Production Apply Lock: {canonical_row('production_apply_lock')}",
        f"- Circuit Breaker: {canonical_row('circuit_breaker_status')}",
        f"- Rollback: {canonical_row('rollback_status')}",
        f"- Write Canary: {canonical_row('write_canary_status')}",
        f"- Promotion: {canonical_row('promotion_status')}",
        f"- Emergency Stop: {canonical_row('emergency_stop')}",
        f"- Breach: {canonical_row('breach')}",
        f"- Owner Priority: {canonical_row('owner_priority')}",
        f"- Owner Priority Rank: {md_status(canonical_header.get('owner_priority_rank'))}",
        f"- Owner Priority Reason: {safe_text(canonical_header.get('owner_priority_reason'))}",
        "",
        "Legacy Level-1 modules never provide these values. Historical results are listed "
        "separately under `Legacy / Historical Modules`.",
        "",
    ]
    if canonical_header.get("missing_fields"):
        lines.extend([
            f"- Canonical Truth Incomplete, missing fields: "
            f"`{', '.join(canonical_header['missing_fields'])}`",
            "- No legacy value is substituted for a missing current value.",
            "",
        ])
    lines.extend([
        "## Master-Bewertung",
        "",
        "| Signal | Status |",
        "|---|---|",
        f"| Website Status | {md_status(report.get('website_status'))} |",
        f"| Website Correlation Status | {md_status(report.get('website_correlation_status'))} |",
        f"| Hetzner Local Status | {md_status(report.get('hetzner_local_status'))} |",
        f"| Private PC Local Status | {md_status(report.get('private_pc_local_status'))} |",
        f"| Private PC Last Known Local Confirmation | {md_status(report.get('private_pc_last_known_local_confirmation'))} |",
        f"| Canonical Runtime Level | {canonical_row('autonomy_level')} |",
        f"| Canonical Runtime Stage | {canonical_row('runtime_stage')} |",
        f"| Canonical Monitoring Enabled | {canonical_row('monitoring_enabled')} |",
        f"| Canonical systemd Timer Active | {canonical_row('timer_active')} |",
        f"| Canonical Scheduler Status | {canonical_row('scheduler_status')} |",
        f"| Canonical LOW_LIVE Enabled | {canonical_row('low_live_enabled')} |",
        f"| Canonical Production Apply Lock | {canonical_row('production_apply_lock')} |",
        f"| Canonical Emergency Stop | {canonical_row('emergency_stop')} |",
        f"| Canonical Breach | {canonical_row('breach')} |",
        f"| Canonical Write Canary | {canonical_row('write_canary_status')} |",
        f"| Canonical Promotion | {canonical_row('promotion_status')} |",
        f"| Canonical Owner Priority | {canonical_row('owner_priority')} |",
        f"| Canonical Total 5xx (24h) | {canonical_row('total_5xx')} |",
        f"| Canonical NowPlaying 504 (24h) | {canonical_row('nowplaying_504')} |",
        f"| Canonical NowPlaying Classification | {canonical_row('nowplaying_classification')} |",
        f"| Canonical /wp-json users/me 504 (24h) | {canonical_row('wp_users_me_504')} |",
        f"| Canonical /wp-json users/me Classification | {canonical_row('wp_users_me_classification')} |",
        f"| Canonical SourceMap 404 (24h) | {canonical_row('source_map_404')} |",
        f"| Canonical SourceMap Status | {canonical_row('source_map_status')} |",
        f"| Canonical Rolling Window | {canonical_row('rolling_window_status')} |",
        f"| Legacy SourceMap Prevention Status (superseded) | {md_status(report.get('sourcemap_prevention_status'))} |",
        f"| SourceMap Global Safe to Auto Apply | {md_status(sourcemap_prevention.get('global_safe_to_auto_apply'))} |",
        f"| SourceMap WPO-Minify Safe to Apply | {md_status(sourcemap_prevention.get('wpo_minify_safe_to_apply'))} |",
        f"| SourceMap Requires Operator Review | {md_status(sourcemap_prevention.get('requires_operator_review'))} |",
        f"| Legacy AI-Radio Timeout Status (superseded) | {md_status(report.get('ai_radio_timeout_status'))} |",
        f"| AI-Radio Microcache Deployed | {md_status(ai_radio_timeout.get('microcache_remediation', {}).get('microcache_deployed'))} |",
        f"| AI-Radio Latest 5xx Delta | {md_status(ai_radio_timeout.get('rolling_window_status', {}).get('latest_5xx_delta'))} |",
        f"| AI-Radio Safe to Auto Apply | {md_status(ai_radio_timeout.get('safe_to_auto_apply'))} |",
        f"| AI-Radio Requires Operator Review | {md_status(ai_radio_timeout.get('requires_operator_review'))} |",
        f"| Autonomy Policy Status | {md_status(report.get('autonomy_policy_status'))} |",
        f"| Legacy Autonomy Level (superseded) | {md_status(autonomy_policy.get('current_autonomy_level'))} |",
        f"| Autonomy Policy-Only | {md_status(autonomy_policy.get('policy_only'))} |",
        f"| Draft Execution Planner Status | {md_status(report.get('draft_execution_planner_status'))} |",
        f"| Draft Execution Items | {md_status(draft_execution_planner.get('execution_items_count'))} |",
        f"| Owner Review Pack Status | {md_status(report.get('owner_review_pack_status'))} |",
        f"| Owner Review Pack Ready for Copy | {md_status(owner_review_pack.get('ready_for_copy_count'))} |",
        f"| Manual Apply Checklist Status | {md_status(report.get('manual_apply_checklist_status'))} |",
        f"| Manual Checklist Items | {md_status(manual_apply_checklist.get('checklist_items_count'))} |",
        f"| Manual Completion Tracker Status | {md_status(report.get('manual_completion_tracker_status'))} |",
        f"| Manual Completion Completed | {md_status(manual_completion_tracker.get('completed_count'))} |",
        f"| Manual Completion Needs Review | {md_status(manual_completion_tracker.get('needs_review_count'))} |",
        f"| Post-Manual Validation Status | {md_status(report.get('post_manual_validation_status'))} |",
        f"| Post-Manual Validation Warnings | {md_status(post_manual_validation.get('validation_warning_count'))} |",
        f"| Owner Daily Action Status | {md_status(owner_daily_action_summary.get('owner_status'))} |",
        f"| Legacy Owner Next Action (superseded) | {md_status(owner_daily_action_summary.get('recommended_next_owner_action'))} |",
        f"| Safe Apply Registry Status | {md_status(report.get('safe_apply_candidate_registry_status'))} |",
        f"| Safe Apply Registry Draft-only | {md_status(safe_apply_registry.get('registered_draft_only_count'))} |",
        f"| Safe Apply Registry Breach | {md_status(safe_apply_registry.get('registry_breach'))} |",
        f"| Safe Apply Guard Status | {md_status(report.get('safe_apply_guard_check_status'))} |",
        f"| Safe Apply Guards Ready Draft-only | {md_status(safe_apply_guard.get('guards_ready_draft_only_count'))} |",
        f"| Safe Apply Guard Breach | {md_status(safe_apply_guard.get('guard_breach'))} |",
        f"| Safe Apply Scope Status | {md_status(report.get('safe_apply_scope_manager_status'))} |",
        f"| Safe Apply Scope Allowed Draft-only | {md_status(safe_apply_scope.get('scope_allowed_draft_only_count'))} |",
        f"| Safe Apply Scope Allowed Validation-only | {md_status(safe_apply_scope.get('scope_allowed_validation_only_count'))} |",
        f"| Safe Apply Scope Breach | {md_status(safe_apply_scope.get('scope_breach'))} |",
        f"| Safe Apply Dry-Run Status | {md_status(report.get('safe_apply_dry_run_planner_status'))} |",
        f"| Safe Apply Dry-Run Ready Draft-only | {md_status(safe_apply_dry_run.get('dry_run_ready_draft_only_count'))} |",
        f"| Safe Apply Dry-Run Ready Validation-only | {md_status(safe_apply_dry_run.get('dry_run_ready_validation_only_count'))} |",
        f"| Safe Apply Dry-Run Breach | {md_status(safe_apply_dry_run.get('dry_run_breach'))} |",
        f"| Safe Apply Preflight Status | {md_status(report.get('safe_apply_preflight_validator_status'))} |",
        f"| Safe Apply Preflight Ready Draft-only | {md_status(safe_apply_preflight.get('preflight_ready_draft_only_count'))} |",
        f"| Safe Apply Preflight Not Ready | {md_status(safe_apply_preflight.get('preflight_not_ready_count'))} |",
        f"| Safe Apply Preflight Breach | {md_status(safe_apply_preflight.get('preflight_breach'))} |",
        f"| Autonomy Runtime Lock Status | {md_status(report.get('autonomy_runtime_lock_status'))} |",
        f"| Autonomy Runtime Lock Live Apply | {md_status(autonomy_runtime_lock.get('live_apply_enabled'))} |",
        f"| Legacy Autonomy Runtime Lock Emergency Stop (superseded) | {md_status(autonomy_runtime_lock.get('emergency_stop'))} |",
        f"| Autonomy Runtime Lock Breach | {md_status(autonomy_runtime_lock.get('runtime_lock_breach'))} |",
        f"| Safe Draft Runner Status | {md_status(report.get('safe_draft_autonomy_runner_status'))} |",
        f"| Safe Draft Runner Executed Draft-only | {md_status(safe_draft_runner.get('executed_draft_only_count'))} |",
        f"| Safe Draft Runner Live Apply | {md_status(safe_draft_runner.get('live_apply'))} |",
        f"| Safe Draft Runner Breach | {md_status(safe_draft_runner.get('runner_breach'))} |",
        f"| Safe Draft Verifier Status | {md_status(report.get('safe_draft_autonomy_verifier_status'))} |",
        f"| Safe Draft Verifier Safe Outputs | {md_status(safe_draft_verifier.get('verified_safe_outputs_count'))} |",
        f"| Safe Draft Verifier Forbidden Path | {md_status(safe_draft_verifier.get('forbidden_path_count'))} |",
        f"| Safe Draft Verifier Breach | {md_status(safe_draft_verifier.get('verifier_breach'))} |",
        f"| Safe Draft Scheduler Plan Status | {md_status(report.get('safe_draft_autonomy_scheduler_plan_status'))} |",
        f"| Legacy Safe Draft Scheduler Timer Install (superseded) | {md_status(safe_draft_scheduler.get('timer_installation_status'))} |",
        f"| Safe Draft Scheduler Can Install Now | {md_status(safe_draft_scheduler.get('can_install_timer_now'))} |",
        f"| Safe Draft Scheduler Breach | {md_status(safe_draft_scheduler.get('scheduler_breach'))} |",
        f"| Safe Draft Timer Draft Status | {md_status(report.get('safe_draft_autonomy_timer_draft_status'))} |",
        f"| Legacy Safe Draft Timer Installation (superseded) | {md_status(safe_draft_timer.get('timer_installation_status'))} |",
        f"| Safe Draft Timer systemd Written | {md_status(safe_draft_timer.get('systemd_file_written'))} |",
        f"| Safe Draft Timer Breach | {md_status(safe_draft_timer.get('timer_draft_breach'))} |",
        f"| Safe Draft Timer Install Review Status | {md_status(report.get('safe_draft_autonomy_timer_install_review_status'))} |",
        f"| Safe Draft Timer Install Can Install Now | {md_status(safe_draft_timer_review.get('can_install_timer_now'))} |",
        f"| Safe Draft Timer Install Checks Failed | {md_status(safe_draft_timer_review.get('safe_checks_failed_count'))} |",
        f"| Safe Draft Timer Install Breach | {md_status(safe_draft_timer_review.get('install_reviewer_breach'))} |",
        f"| Owner Manual Timer Packet Status | {md_status(owner_manual_timer_packet.get('packet_status'))} |",
        f"| Owner Manual Timer Install Allowed | {md_status(owner_manual_timer_packet.get('install_allowed_now'))} |",
        f"| Owner Manual Timer Can Install Now | {md_status(owner_manual_timer_packet.get('can_install_timer_now'))} |",
        f"| Owner Manual Timer Packet Breach | {md_status(owner_manual_timer_packet.get('packet_breach'))} |",
        f"| Owner Timer Install Decision Status | {md_status(owner_timer_decision.get('decision_status'))} |",
        f"| Owner Timer Manual Install Allowed | {md_status(owner_timer_decision.get('manual_install_allowed'))} |",
        f"| Owner Timer Install Allowed Now | {md_status(owner_timer_decision.get('install_allowed_now'))} |",
        f"| Owner Timer Can Install Now | {md_status(owner_timer_decision.get('can_install_timer_now'))} |",
        f"| Owner Timer Decision Breach | {md_status(owner_timer_decision.get('decision_breach'))} |",
        f"| Manual Timer Command Preview Status | {md_status(manual_timer_preview.get('preview_status'))} |",
        f"| Manual Timer Command Preview Written | {md_status(manual_timer_preview.get('command_preview_written'))} |",
        f"| Manual Timer Command Preview Install Allowed | {md_status(manual_timer_preview.get('install_allowed_now'))} |",
        f"| Manual Timer Command Preview Can Install | {md_status(manual_timer_preview.get('can_install_timer_now'))} |",
        f"| Manual Timer Command Preview Breach | {md_status(manual_timer_preview.get('preview_breach'))} |",
        f"| Owner Timer Evidence Pack Status | {md_status(owner_timer_evidence.get('evidence_pack_status'))} |",
        f"| Owner Timer Evidence Template Written | {md_status(owner_timer_evidence.get('evidence_template_written'))} |",
        f"| Owner Timer Evidence Install Allowed | {md_status(owner_timer_evidence.get('install_allowed_now'))} |",
        f"| Owner Timer Evidence Can Install | {md_status(owner_timer_evidence.get('can_install_timer_now'))} |",
        f"| Owner Timer Evidence Pack Breach | {md_status(owner_timer_evidence.get('evidence_pack_breach'))} |",
        f"| Safe Draft Final Safety Status | {md_status(final_safety.get('final_safety_status'))} |",
        f"| Safe Draft Final Draft-only Ready | {md_status(final_safety.get('draft_only_autonomy_ready'))} |",
        f"| Safe Draft Final Timer Install Allowed | {md_status(final_safety.get('timer_installation_allowed_now'))} |",
        f"| Safe Draft Final Live Apply Allowed | {md_status(final_safety.get('live_apply_allowed'))} |",
        f"| Safe Draft Final Breaches | {md_status(final_safety.get('total_breach_count'))} |",
        f"| Safe Draft Final Breach | {md_status(final_safety.get('final_safety_breach'))} |",
        f"| Manual Evidence Dashboard Status | {md_status(manual_evidence_dashboard.get('dashboard_status'))} |",
        f"| Legacy Manual Evidence Dashboard Emergency Stop (superseded) | {md_status(manual_evidence_dashboard.get('emergency_stop_active'))} |",
        f"| Manual Evidence Dashboard Breaches | {md_status(manual_evidence_dashboard.get('total_breaches'))} |",
        f"| Manual Evidence Dashboard Install Allowed | {md_status(manual_evidence_dashboard.get('install_allowed_now'))} |",
        f"| Manual Evidence Dashboard Can Install | {md_status(manual_evidence_dashboard.get('can_install_timer_now'))} |",
        f"| Manual Evidence Dashboard Breach | {md_status(manual_evidence_dashboard.get('dashboard_breach'))} |",
        f"| Evidence Review Completion Status | {md_status(manual_evidence_completion.get('tracker_status'))} |",
        f"| Evidence Review Completion Reviewed | {md_status(manual_evidence_completion.get('reviewed_count'))} / {md_status(manual_evidence_completion.get('total_items'))} |",
        f"| Evidence Review Completion Blocked | {md_status(manual_evidence_completion.get('blocked_count'))} |",
        f"| Evidence Review Completion Percent | {md_status(manual_evidence_completion.get('completion_percent'))} |",
        f"| Evidence Review Completion Breach | {md_status(manual_evidence_completion.get('tracker_breach'))} |",
        f"| Evidence Review Gate Status | {md_status(manual_evidence_gate.get('gate_status'))} |",
        f"| Evidence Review Gate Reviewed | {md_status(manual_evidence_gate.get('reviewed_count'))} / {md_status(manual_evidence_gate.get('total_items'))} |",
        f"| Evidence Review Gate Complete | {md_status(manual_evidence_gate.get('all_required_reviewed'))} |",
        f"| Evidence Review Gate Percent | {md_status(manual_evidence_gate.get('completion_percent'))} |",
        f"| Evidence Review Gate Breach | {md_status(manual_evidence_gate.get('gate_breach'))} |",
        f"| Owner Review Console Status | {md_status(owner_evidence_console.get('console_status'))} |",
        f"| Owner Review Console Open Items | {md_status(owner_evidence_console.get('open_items_count'))} |",
        f"| Owner Review Console Next Item | {md_status(owner_evidence_console.get('next_recommended_item'))} |",
        f"| Owner Review Console Breach | {md_status(owner_evidence_console.get('console_breach'))} |",
        f"| Final Owner Snapshot Status | {md_status(final_owner_snapshot.get('snapshot_status'))} |",
        f"| Final Owner Snapshot Review | {md_status(final_owner_snapshot.get('reviewed_count'))} / {md_status(final_owner_snapshot.get('total_items'))} |",
        f"| Legacy Final Owner Snapshot Emergency Stop (superseded) | {md_status(final_owner_snapshot.get('emergency_stop_active'))} |",
        f"| Final Owner Snapshot Install Allowed | {md_status(final_owner_snapshot.get('install_allowed_now'))} |",
        f"| Final Owner Snapshot Breach | {md_status(final_owner_snapshot.get('snapshot_breach'))} |",
        f"| Master Critical Cause Status | {md_status(master_critical_cause.get('critical_snapshot_status'))} |",
        f"| Master Critical Autonomy Cause | {md_status(master_critical_cause.get('critical_caused_by_autonomy'))} |",
        f"| Master Critical Website Cause | {md_status(master_critical_cause.get('critical_caused_by_website'))} |",
        f"| Master Critical Autonomy Breaches | {md_status(master_critical_cause.get('autonomy_total_breaches'))} |",
        f"| Master Critical Cause Breach | {md_status(master_critical_cause.get('snapshot_breach'))} |",
        f"| Rolling Window Decay Status | {md_status(rolling_window_decay.get('decay_status'))} |",
        f"| Rolling Window Trend | {md_status(rolling_window_decay.get('trend'))} |",
        f"| Rolling Window Delta 5xx | {md_status(rolling_window_decay.get('delta_5xx'))} |",
        f"| Rolling Window Delta 504 | {md_status(rolling_window_decay.get('delta_504'))} |",
        f"| Rolling Window Observation Required | {md_status(rolling_window_decay.get('observation_required'))} |",
        f"| Rolling Window Decay Breach | {md_status(rolling_window_decay.get('snapshot_breach'))} |",
        f"| Low Growth Timeline Status | {md_status(low_growth_timeline.get('timeline_status'))} |",
        f"| Low Growth Last Trend | {md_status(low_growth_timeline.get('last_trend'))} |",
        f"| Low Growth Consecutive Stable/Decreasing | {md_status(low_growth_timeline.get('consecutive_stable_or_decreasing_points'))} |",
        f"| Low Growth Manual Recheck Recommended | {md_status(low_growth_timeline.get('manual_recheck_recommended'))} |",
        f"| Low Growth Timeline Breach | {md_status(low_growth_timeline.get('snapshot_breach'))} |",
        f"| Manual Website Recheck Gate Status | {md_status(manual_recheck_gate.get('gate_status'))} |",
        f"| Manual Website Recheck Recommended | {md_status(manual_recheck_gate.get('manual_recheck_recommended'))} |",
        f"| Manual Website Recheck Last Trend | {md_status(manual_recheck_gate.get('last_trend'))} |",
        f"| Manual Website Recheck Stable/Decreasing | {md_status(manual_recheck_gate.get('consecutive_stable_or_decreasing_points'))} |",
        f"| Manual Website Recheck Gate Breach | {md_status(manual_recheck_gate.get('gate_breach'))} |",
        f"| Low-Risk Autonomy Readiness Status | {md_status(low_risk_readiness_gate.get('readiness_status'))} |",
        f"| Low-Risk Autonomy Allowed Now | {md_status(low_risk_readiness_gate.get('low_risk_autonomy_allowed_now'))} |",
        f"| Low-Risk Policy Draft Allowed | {md_status(low_risk_readiness_gate.get('low_risk_policy_draft_allowed'))} |",
        f"| Low-Risk Owner Policy Review Required | {md_status(low_risk_readiness_gate.get('owner_policy_review_required'))} |",
        f"| Low-Risk Autonomy Readiness Breach | {md_status(low_risk_readiness_gate.get('readiness_breach'))} |",
        f"| LOW-RISK Policy Boundary Status | {md_status(low_risk_policy_boundary.get('policy_status'))} |",
        f"| LOW-RISK Policy Activation Allowed | {md_status(low_risk_policy_boundary.get('policy_activation_allowed'))} |",
        f"| LOW-RISK Policy Draft-Only Count | {md_status(low_risk_policy_boundary.get('low_risk_draft_only_count'))} |",
        f"| LOW-RISK Policy Never-Auto-Apply Count | {md_status(low_risk_policy_boundary.get('high_never_auto_apply_count'))} |",
        f"| LOW-RISK Policy Boundary Breach | {md_status(low_risk_policy_boundary.get('policy_breach'))} |",
        f"| LOW-RISK Policy Owner Review Status | {md_status(low_risk_owner_review.get('tracker_status'))} |",
        f"| LOW-RISK Policy Owner Review Progress | {md_status(low_risk_owner_review.get('reviewed_count'))} / {md_status(low_risk_owner_review.get('total_required'))} |",
        f"| LOW-RISK Policy Owner Review Breach | {md_status(low_risk_owner_review.get('tracker_breach'))} |",
        f"| Policy Review Completion Status | {md_status(low_risk_completion_gate.get('gate_status'))} |",
        f"| Policy Review Completion Percent | {md_status(low_risk_completion_gate.get('completion_percent'))} |",
        f"| Policy Review Completion Breach | {md_status(low_risk_completion_gate.get('gate_breach'))} |",
        f"| Final Safety Seal Status | {md_status(low_risk_final_seal.get('seal_status'))} |",
        f"| Final Safety Seal Review Complete | {md_status(low_risk_final_seal.get('review_completed'))} |",
        f"| Final Safety Seal Breach | {md_status(low_risk_final_seal.get('seal_breach'))} |",
        f"| Safe End Status | {md_status(safe_end.get('safe_end_status'))} |",
        f"| Legacy Safe End Emergency Stop (superseded) | {md_status(safe_end.get('emergency_stop_active'))} |",
        f"| Safe End Live Apply | {md_status(safe_end.get('live_apply'))} |",
        f"| Safe End Install Allowed | {md_status(safe_end.get('install_allowed_now'))} |",
        f"| Safe End Breach | {md_status(safe_end.get('safe_end_breach'))} |",
        f"| Safe-End Archive Status | {md_status(safe_end_archive.get('archive_status'))} |",
        f"| Safe-End Archive Copied Files | {md_status(safe_end_archive.get('copied_file_count'))} |",
        f"| Safe-End Archive Checksums | {md_status(safe_end_archive.get('checksum_count'))} |",
        f"| Safe-End Archive Breach | {md_status(safe_end_archive.get('archive_breach'))} |",
        f"| Safe-End Archive Integrity Status | {md_status(safe_end_integrity.get('integrity_status'))} |",
        f"| Safe-End Archive Integrity Verified | {md_status(safe_end_integrity.get('verified_checksum_count'))} |",
        f"| Safe-End Archive Integrity Mismatch | {md_status(safe_end_integrity.get('checksum_mismatch_count'))} |",
        f"| Safe-End Archive Integrity Forbidden | {md_status(safe_end_integrity.get('forbidden_artifact_count'))} |",
        f"| Safe-End Archive Integrity Breach | {md_status(safe_end_integrity.get('integrity_breach'))} |",
        f"| Concrete SEO/Performance Status | {md_status(concrete_optimizer.get('optimizer_status'))} |",
        f"| Concrete SEO/Performance Recommendations | {md_status(concrete_optimizer.get('total_recommendations'))} |",
        f"| Concrete SEO/Performance Copy/Paste | {md_status(concrete_optimizer.get('copy_paste_owner_apply_count'))} |",
        f"| Concrete SEO/Performance Diagnostic | {md_status(concrete_optimizer.get('diagnostic_only_count'))} |",
        f"| Concrete SEO/Performance Breach | {md_status(concrete_optimizer.get('optimizer_breach'))} |",
        f"| Safe SFTP SEO Apply Lane Status | {md_status(safe_sftp_lane.get('apply_lane_status'))} |",
        f"| Safe SFTP SEO Apply Mode | {md_status(safe_sftp_lane.get('mode'))} |",
        f"| Safe SFTP SEO Apply Uploaded | {md_status(safe_sftp_lane.get('uploaded'))} |",
        f"| Safe SFTP SEO Apply Changed Files | {md_status(safe_sftp_lane.get('changed_file_count'))} |",
        f"| Safe SFTP SEO Apply Breach | {md_status(safe_sftp_lane.get('apply_breach'))} |",
        f"| Overall Master Status | {md_status(report.get('overall_master_status'))} |",
        f"| Action Status | {md_status(report.get('action_status'))} |",
        "",
        "## Empfehlungen",
        "",
    ])
    for recommendation in report.get("recommendations", []):
        lines.append(f"- {safe_text(recommendation)}")
    lines.append("")

    lines.extend(render_canonical_runtime_section(canonical_header, canonical_summary))
    lines.extend(render_legacy_historical_modules(legacy_supersession))

    lines.extend(render_source_detail("Website Sentinel", website))
    lines.extend(render_source_detail("Hetzner Local Agent", hetzner_local))
    lines.extend(render_private_pc_detail(private_pc_local))
    lines.extend(render_sourcemap_prevention(sourcemap_prevention))
    lines.extend(render_ai_radio_timeout(ai_radio_timeout))
    lines.extend(render_cloudflare_challenge_diagnosis(report.get("cloudflare_challenge_diagnosis")))
    lines.extend(render_autonomy_policy(autonomy_policy))
    lines.extend(render_seo_safe_optimizer(report.get("seo_safe_optimizer", {}) if isinstance(report.get("seo_safe_optimizer"), dict) else {}))
    lines.extend(render_performance_safe_improvement(report.get("performance_safe_improvement", {}) if isinstance(report.get("performance_safe_improvement"), dict) else {}))
    lines.extend(render_safe_improvement_roadmap(report.get("safe_improvement_roadmap", {}) if isinstance(report.get("safe_improvement_roadmap"), dict) else {}))
    lines.extend(render_approval_queue(report.get("approval_queue", {}) if isinstance(report.get("approval_queue"), dict) else {}))
    lines.extend(render_owner_cli(report.get("owner_approval_cli", {}) if isinstance(report.get("owner_approval_cli"), dict) else {}))
    lines.extend(render_draft_execution_planner(report.get("draft_execution_planner", {}) if isinstance(report.get("draft_execution_planner"), dict) else {}))
    lines.extend(render_owner_review_pack(report.get("owner_review_pack", {}) if isinstance(report.get("owner_review_pack"), dict) else {}))
    lines.extend(render_manual_apply_checklist(report.get("manual_apply_checklist", {}) if isinstance(report.get("manual_apply_checklist"), dict) else {}))
    lines.extend(render_manual_completion_tracker(report.get("manual_completion_tracker", {}) if isinstance(report.get("manual_completion_tracker"), dict) else {}))
    lines.extend(render_post_manual_validation(report.get("post_manual_validation", {}) if isinstance(report.get("post_manual_validation"), dict) else {}))
    lines.extend(render_owner_daily_action_summary(report.get("owner_daily_action_summary", {}) if isinstance(report.get("owner_daily_action_summary"), dict) else {}))
    lines.extend(render_autonomous_improvement_readiness(report.get("owner_daily_action_summary", {}) if isinstance(report.get("owner_daily_action_summary"), dict) else {}))
    lines.extend(render_safe_apply_candidate_registry(report.get("safe_apply_candidate_registry", {}) if isinstance(report.get("safe_apply_candidate_registry"), dict) else {}))
    lines.extend(render_safe_apply_guard_check(report.get("safe_apply_guard_check", {}) if isinstance(report.get("safe_apply_guard_check"), dict) else {}))
    lines.extend(render_safe_apply_scope_manager(report.get("safe_apply_scope_manager", {}) if isinstance(report.get("safe_apply_scope_manager"), dict) else {}))
    lines.extend(render_safe_apply_dry_run_planner(report.get("safe_apply_dry_run_planner", {}) if isinstance(report.get("safe_apply_dry_run_planner"), dict) else {}))
    lines.extend(render_safe_apply_preflight_validator(report.get("safe_apply_preflight_validator", {}) if isinstance(report.get("safe_apply_preflight_validator"), dict) else {}))
    lines.extend(render_autonomy_runtime_lock(report.get("autonomy_runtime_lock", {}) if isinstance(report.get("autonomy_runtime_lock"), dict) else {}))
    lines.extend(render_safe_draft_autonomy_runner(report.get("safe_draft_autonomy_runner", {}) if isinstance(report.get("safe_draft_autonomy_runner"), dict) else {}))
    lines.extend(render_safe_draft_autonomy_verifier(report.get("safe_draft_autonomy_verifier", {}) if isinstance(report.get("safe_draft_autonomy_verifier"), dict) else {}))
    lines.extend(render_safe_draft_autonomy_scheduler_plan(report.get("safe_draft_autonomy_scheduler_plan", {}) if isinstance(report.get("safe_draft_autonomy_scheduler_plan"), dict) else {}))
    lines.extend(render_safe_draft_autonomy_timer_draft(report.get("safe_draft_autonomy_timer_draft", {}) if isinstance(report.get("safe_draft_autonomy_timer_draft"), dict) else {}))
    lines.extend(render_safe_draft_autonomy_timer_install_review(report.get("safe_draft_autonomy_timer_install_review", {}) if isinstance(report.get("safe_draft_autonomy_timer_install_review"), dict) else {}))
    lines.extend(render_owner_manual_timer_install_packet(report.get("owner_manual_timer_install_packet", {}) if isinstance(report.get("owner_manual_timer_install_packet"), dict) else {}))
    lines.extend(render_owner_timer_install_decision_gate(report.get("owner_timer_install_decision_gate", {}) if isinstance(report.get("owner_timer_install_decision_gate"), dict) else {}))
    lines.extend(render_manual_timer_install_command_preview(report.get("manual_timer_install_command_preview", {}) if isinstance(report.get("manual_timer_install_command_preview"), dict) else {}))
    lines.extend(render_owner_timer_install_evidence_pack(report.get("owner_timer_install_evidence_pack", {}) if isinstance(report.get("owner_timer_install_evidence_pack"), dict) else {}))
    lines.extend(render_safe_draft_autonomy_final_safety(report.get("safe_draft_autonomy_final_safety", {}) if isinstance(report.get("safe_draft_autonomy_final_safety"), dict) else {}))
    lines.extend(render_manual_evidence_review_dashboard(report.get("manual_evidence_review_dashboard", {}) if isinstance(report.get("manual_evidence_review_dashboard"), dict) else {}))
    lines.extend(render_manual_evidence_review_completion_tracker(report.get("manual_evidence_review_completion_tracker", {}) if isinstance(report.get("manual_evidence_review_completion_tracker"), dict) else {}))
    lines.extend(render_manual_evidence_review_completion_gate(report.get("manual_evidence_review_completion_gate", {}) if isinstance(report.get("manual_evidence_review_completion_gate"), dict) else {}))
    lines.extend(render_owner_evidence_review_console(report.get("owner_evidence_review_console", {}) if isinstance(report.get("owner_evidence_review_console"), dict) else {}))
    lines.extend(render_final_owner_decision_snapshot(report.get("final_owner_decision_snapshot", {}) if isinstance(report.get("final_owner_decision_snapshot"), dict) else {}))
    lines.extend(render_master_critical_cause_snapshot(report.get("master_critical_cause_snapshot", {}) if isinstance(report.get("master_critical_cause_snapshot"), dict) else {}))
    lines.extend(render_rolling_window_decay_observer(report.get("rolling_window_decay_observer", {}) if isinstance(report.get("rolling_window_decay_observer"), dict) else {}))
    lines.extend(render_low_growth_readiness_timeline(report.get("low_growth_readiness_timeline", {}) if isinstance(report.get("low_growth_readiness_timeline"), dict) else {}))
    lines.extend(render_manual_website_recheck_gate(report.get("manual_website_recheck_gate", {}) if isinstance(report.get("manual_website_recheck_gate"), dict) else {}))
    lines.extend(render_low_risk_autonomy_readiness_gate(report.get("low_risk_autonomy_readiness_gate", {}) if isinstance(report.get("low_risk_autonomy_readiness_gate"), dict) else {}))
    lines.extend(render_low_risk_policy_boundary_draft(report.get("low_risk_policy_boundary_draft", {}) if isinstance(report.get("low_risk_policy_boundary_draft"), dict) else {}))
    lines.extend(render_low_risk_policy_owner_review_tracker(report.get("low_risk_policy_owner_review_tracker", {}) if isinstance(report.get("low_risk_policy_owner_review_tracker"), dict) else {}))
    lines.extend(render_low_risk_policy_review_completion_gate(report.get("low_risk_policy_review_completion_gate", {}) if isinstance(report.get("low_risk_policy_review_completion_gate"), dict) else {}))
    lines.extend(render_low_risk_autonomy_final_safety_seal(report.get("low_risk_autonomy_final_safety_seal", {}) if isinstance(report.get("low_risk_autonomy_final_safety_seal"), dict) else {}))
    lines.extend(render_safe_end_summary(report.get("safe_end_summary", {}) if isinstance(report.get("safe_end_summary"), dict) else {}))
    lines.extend(render_safe_end_archive_snapshot(report.get("safe_end_archive_snapshot", {}) if isinstance(report.get("safe_end_archive_snapshot"), dict) else {}))
    lines.extend(render_safe_end_archive_integrity_verifier(report.get("safe_end_archive_integrity_verifier", {}) if isinstance(report.get("safe_end_archive_integrity_verifier"), dict) else {}))
    lines.extend(render_concrete_seo_performance_optimizer(report.get("concrete_seo_performance_optimizer", {}) if isinstance(report.get("concrete_seo_performance_optimizer"), dict) else {}))
    lines.extend(render_safe_sftp_seo_apply_lane(report.get("safe_sftp_seo_apply_lane", {}) if isinstance(report.get("safe_sftp_seo_apply_lane"), dict) else {}))

    # Production Pipeline and NowPlaying Recovery (Phase 10.20)
    pipeline = report.get("production_pipeline") if isinstance(report.get("production_pipeline"), dict) else {}
    nowplaying = report.get("nowplaying_recovery") if isinstance(report.get("nowplaying_recovery"), dict) else {}
    lines.extend([
        "## Production Pipeline (Phase 10.20)",
        "",
        f"- Pipeline status: `{md_status(pipeline.get('status'))}`",
        f"- Owner priority: `{md_status(pipeline.get('owner_priority', {}).get('selected_priority'))}`",
        f"- Runtime level: `{md_status(pipeline.get('runtime', {}).get('autonomy_level'))}`",
        f"- Timer active: `{str(pipeline.get('runtime', {}).get('systemd_timer_active', False)).lower()}`",
        f"- LOW_LIVE enabled: `{str(pipeline.get('runtime', {}).get('low_live_apply_enabled', False)).lower()}`",
        f"- Emergency stop: `{str(pipeline.get('runtime', {}).get('emergency_stop', True)).lower()}`",
        f"- Breach: `{str(pipeline.get('runtime', {}).get('breach', False)).lower()}`",
        "",
        "## NowPlaying Recovery (Phase 10.20)",
        "",
        f"- Recovery status: `{md_status(nowplaying.get('status'))}`",
        f"- Classification: `{md_status(nowplaying.get('classification', {}).get('classification'))}`",
        f"- Automatic repair allowed: `{str(nowplaying.get('classification', {}).get('automatic_repair_allowed', False)).lower()}`",
        f"- Repair applied: `{str(nowplaying.get('repair_applied', False)).lower()}`",
        "",
    ])

    lines.extend(
        [
            "## Sicherheitsgrenzen",
            "",
            "- Nur defensive Reports.",
            "- Keine Angriffe, keine Gegenmassnahmen, keine Scans fremder Systeme.",
            "- Keine Credential-Sammlung.",
            "- Keine Secrets in Master-Reports oder Logs.",
            "- Keine Cloudflare-Regeln werden geaendert.",
            "- Autonomy Policy Layer ist policy-only/dry-run; keine Apply-Funktion, apply_status bleibt not_applied.",
            "- SEO Safe Optimizer, Performance Safe Improvement, Draft Execution Planner, Owner Review Pack, Manual Apply Checklist, Manual Completion Tracker und Post-Manual Validation sind read-only/draft-only und veraendern den Master-Status nicht, ausser bei echter Safety-Verletzung.",
            "- Dieses Skript liest lokale Dateien und schreibt lokale Report-Dateien.",
            "",
            "## Outputs",
            "",
            f"- Markdown: `{safe_text(report['outputs'].get('markdown'))}`",
            f"- JSON: `{safe_text(report['outputs'].get('json'))}`",
            f"- History: `{safe_text(report['outputs'].get('history'))}`",
            "",
        ]
    )
    return "\n".join(lines)


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_history(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "generated_at_utc": report.get("generated_at_utc"),
        "overall_master_status": report.get("overall_master_status"),
        "action_status": report.get("action_status"),
        "website_status": report.get("website_status"),
        "website_correlation_status": report.get("website_correlation_status"),
        "hetzner_local_status": report.get("hetzner_local_status"),
        "private_pc_local_status": report.get("private_pc_local_status"),
        "private_pc_last_known_local_confirmation": report.get("private_pc_last_known_local_confirmation"),
        "local_status": report.get("local_status"),
        "sourcemap_prevention_status": report.get("sourcemap_prevention_status"),
        "sourcemap_safe_to_auto_apply": report.get("sourcemap_prevention", {}).get("safe_to_auto_apply"),
        "sourcemap_global_safe_to_auto_apply": report.get("sourcemap_prevention", {}).get("global_safe_to_auto_apply"),
        "sourcemap_wpo_minify_safe_to_apply": report.get("sourcemap_prevention", {}).get("wpo_minify_safe_to_apply"),
        "sourcemap_core_requires_review": report.get("sourcemap_prevention", {}).get("core_requires_review"),
        "sourcemap_requires_operator_review": report.get("sourcemap_prevention", {}).get("requires_operator_review"),
        "ai_radio_timeout_status": report.get("ai_radio_timeout_status"),
        "ai_radio_top_timeout_endpoint": report.get("ai_radio_timeout_diagnosis", {}).get("top_timeout_endpoint"),
        "ai_radio_suggested_prevention": report.get("ai_radio_timeout_diagnosis", {}).get("suggested_prevention"),
        "ai_radio_microcache_deployed": report.get("ai_radio_timeout_diagnosis", {}).get("microcache_remediation", {}).get("microcache_deployed"),
        "ai_radio_latest_5xx_delta": report.get("ai_radio_timeout_diagnosis", {}).get("rolling_window_status", {}).get("latest_5xx_delta"),
        "ai_radio_next_action": report.get("ai_radio_timeout_diagnosis", {}).get("next_action"),
        "ai_radio_safe_to_auto_apply": report.get("ai_radio_timeout_diagnosis", {}).get("safe_to_auto_apply"),
        "ai_radio_requires_operator_review": report.get("ai_radio_timeout_diagnosis", {}).get("requires_operator_review"),
        "autonomy_policy_status": report.get("autonomy_policy_status"),
        "autonomy_current_level": report.get("autonomy_policy", {}).get("current_autonomy_level"),
        "autonomy_policy_only": report.get("autonomy_policy", {}).get("policy_only"),
        "autonomy_policy_breach": report.get("autonomy_policy", {}).get("policy_breach"),
        "autonomy_high_risk_allowed_now_count": report.get("autonomy_policy", {}).get("high_risk_allowed_now_count"),
        "autonomy_apply_status_summary": report.get("autonomy_policy", {}).get("apply_status_summary"),
        "autonomy_last_audit_timestamp": report.get("autonomy_policy", {}).get("last_audit_timestamp"),
        "seo_safe_optimizer_status": report.get("seo_safe_optimizer_status"),
        "seo_highest_risk": report.get("seo_safe_optimizer", {}).get("highest_risk"),
        "seo_improved_drafts_available": report.get("seo_safe_optimizer", {}).get("improved_drafts_available"),
        "performance_safe_improvement_status": report.get("performance_safe_improvement_status"),
        "performance_origin_5xx_status": report.get("performance_safe_improvement", {}).get("origin_5xx_status"),
        "performance_ai_radio_nowplaying_cache_status": report.get("performance_safe_improvement", {}).get("ai_radio_nowplaying_cache_status"),
        "roadmap_status": report.get("safe_improvement_roadmap_status"),
        "roadmap_next_safe_count": report.get("safe_improvement_roadmap", {}).get("roadmap_next_safe_count"),
        "roadmap_owner_review_count": report.get("safe_improvement_roadmap", {}).get("roadmap_owner_review_count"),
        "roadmap_blocked_high_count": report.get("safe_improvement_roadmap", {}).get("roadmap_blocked_high_count"),
        "roadmap_monitor_only_count": report.get("safe_improvement_roadmap", {}).get("roadmap_monitor_only_count"),
        "approval_queue_status": report.get("approval_queue_status"),
        "approval_queue_pending_count": report.get("approval_queue", {}).get("pending_owner_review_count"),
        "approval_queue_draft_only_count": report.get("approval_queue", {}).get("approved_for_draft_only_count"),
        "approval_queue_blocked_high_count": report.get("approval_queue", {}).get("blocked_high_risk_count"),
        "approval_queue_breach": report.get("approval_queue", {}).get("queue_breach"),
        "approval_queue_reconcile_enabled": report.get("approval_queue", {}).get("reconcile_enabled"),
        "approval_queue_preserved_decisions_count": report.get("approval_queue", {}).get("preserved_decisions_count"),
        "approval_queue_stale_items_count": report.get("approval_queue", {}).get("stale_items_count"),
        "approval_queue_security_overrides_count": report.get("approval_queue", {}).get("security_overrides_count"),
        "owner_approval_cli_status": report.get("owner_approval_cli_status"),
        "last_owner_action": report.get("owner_approval_cli", {}).get("last_owner_action"),
        "last_owner_action_allowed": report.get("owner_approval_cli", {}).get("last_owner_action_allowed"),
        "owner_cli_queue_policy_breach": report.get("owner_approval_cli", {}).get("queue_policy_breach"),
        "draft_execution_planner_status": report.get("draft_execution_planner_status"),
        "draft_execution_items_count": report.get("draft_execution_planner", {}).get("execution_items_count"),
        "draft_execution_excluded_items_count": report.get("draft_execution_planner", {}).get("excluded_items_count"),
        "draft_execution_ready_for_manual_copy_count": report.get("draft_execution_planner", {}).get("ready_for_manual_copy_count"),
        "draft_execution_apply_status_summary": report.get("draft_execution_planner", {}).get("apply_status_summary"),
        "draft_execution_planner_breach": report.get("draft_execution_planner", {}).get("planner_breach"),
        "owner_review_pack_status": report.get("owner_review_pack_status"),
        "owner_review_items_count": report.get("owner_review_pack", {}).get("review_items_count"),
        "owner_review_ready_for_owner_review_count": report.get("owner_review_pack", {}).get("ready_for_owner_review_count"),
        "owner_review_ready_for_copy_count": report.get("owner_review_pack", {}).get("ready_for_copy_count"),
        "owner_review_excluded_count": report.get("owner_review_pack", {}).get("excluded_count"),
        "owner_review_apply_status_summary": report.get("owner_review_pack", {}).get("apply_status_summary"),
        "owner_review_pack_breach": report.get("owner_review_pack", {}).get("review_pack_breach"),
        "manual_apply_checklist_status": report.get("manual_apply_checklist_status"),
        "manual_checklist_items_count": report.get("manual_apply_checklist", {}).get("checklist_items_count"),
        "manual_ready_for_manual_apply_review_count": report.get("manual_apply_checklist", {}).get("ready_for_manual_apply_review_count"),
        "manual_checklist_excluded_count": report.get("manual_apply_checklist", {}).get("excluded_count"),
        "manual_high_medium_included_count": report.get("manual_apply_checklist", {}).get("high_medium_included_count"),
        "manual_checklist_apply_status_summary": report.get("manual_apply_checklist", {}).get("apply_status_summary"),
        "manual_checklist_breach": report.get("manual_apply_checklist", {}).get("checklist_breach"),
        "manual_checklist_productive_change": report.get("manual_apply_checklist", {}).get("productive_change"),
        "manual_completion_tracker_status": report.get("manual_completion_tracker_status"),
        "manual_completion_completed_count": report.get("manual_completion_tracker", {}).get("completed_count"),
        "manual_completion_in_progress_count": report.get("manual_completion_tracker", {}).get("in_progress_count"),
        "manual_completion_needs_review_count": report.get("manual_completion_tracker", {}).get("needs_review_count"),
        "manual_completion_skipped_count": report.get("manual_completion_tracker", {}).get("skipped_count"),
        "manual_completion_unchecked_count": report.get("manual_completion_tracker", {}).get("unchecked_count"),
        "manual_completion_last_owner_action": report.get("manual_completion_tracker", {}).get("last_owner_completion_action"),
        "manual_completion_breach": report.get("manual_completion_tracker", {}).get("completion_breach"),
        "manual_completion_productive_change": report.get("manual_completion_tracker", {}).get("productive_change"),
        "post_manual_validation_status": report.get("post_manual_validation_status"),
        "post_manual_validation_seo_status": report.get("post_manual_validation", {}).get("seo_validation_status"),
        "post_manual_validation_performance_status": report.get("post_manual_validation", {}).get("performance_validation_status"),
        "post_manual_validation_safety_status": report.get("post_manual_validation", {}).get("safety_validation_status"),
        "post_manual_validation_checklist_items_count": report.get("post_manual_validation", {}).get("checklist_items_count"),
        "post_manual_validation_warning_count": report.get("post_manual_validation", {}).get("validation_warning_count"),
        "post_manual_validation_safety_violation": report.get("post_manual_validation", {}).get("safety_violation"),
        "post_manual_validation_productive_change": report.get("post_manual_validation", {}).get("productive_change"),
        "owner_daily_action_summary_status": report.get("owner_daily_action_summary_status"),
        "owner_status": report.get("owner_daily_action_summary", {}).get("owner_status"),
        "owner_recommended_next_action": report.get("owner_daily_action_summary", {}).get("recommended_next_owner_action"),
        "owner_open_manual_items": report.get("owner_daily_action_summary", {}).get("open_manual_items"),
        "owner_completed_manual_items": report.get("owner_daily_action_summary", {}).get("completed_manual_items"),
        "owner_needs_review_items": report.get("owner_daily_action_summary", {}).get("needs_review_items"),
        "owner_blocked_high_risk_items": report.get("owner_daily_action_summary", {}).get("blocked_high_risk_items"),
        "owner_summary_breach": report.get("owner_daily_action_summary", {}).get("summary_breach"),
        "autonomy_ready_draft_only_count": report.get("owner_daily_action_summary", {}).get("autonomy_ready_draft_only_count"),
        "autonomy_ready_after_owner_approval_count": report.get("owner_daily_action_summary", {}).get("ready_after_owner_approval_count"),
        "autonomy_not_ready_missing_guards_count": report.get("owner_daily_action_summary", {}).get("not_ready_missing_guards_count"),
        "autonomy_blocked_high_risk_count": report.get("owner_daily_action_summary", {}).get("blocked_high_risk_count"),
        "autonomy_monitor_only_count": report.get("owner_daily_action_summary", {}).get("monitor_only_count"),
        "next_safe_autonomy_build_step": report.get("owner_daily_action_summary", {}).get("next_safe_autonomy_build_step"),
        "safe_apply_registry_status": report.get("safe_apply_candidate_registry_status"),
        "safe_apply_registered_draft_only_count": report.get("safe_apply_candidate_registry", {}).get("registered_draft_only_count"),
        "safe_apply_registered_validation_only_count": report.get("safe_apply_candidate_registry", {}).get("registered_validation_only_count"),
        "safe_apply_not_registered_missing_guards_count": report.get("safe_apply_candidate_registry", {}).get("not_registered_missing_guards_count"),
        "safe_apply_blocked_not_allowed_count": report.get("safe_apply_candidate_registry", {}).get("blocked_not_allowed_count"),
        "safe_apply_monitor_only_count": report.get("safe_apply_candidate_registry", {}).get("monitor_only_count"),
        "safe_apply_registry_breach": report.get("safe_apply_candidate_registry", {}).get("registry_breach"),
        "safe_apply_guard_check_status": report.get("safe_apply_guard_check_status"),
        "safe_apply_guards_ready_draft_only_count": report.get("safe_apply_guard_check", {}).get("guards_ready_draft_only_count"),
        "safe_apply_guards_ready_validation_only_count": report.get("safe_apply_guard_check", {}).get("guards_ready_validation_only_count"),
        "safe_apply_guards_missing_for_autonomy_count": report.get("safe_apply_guard_check", {}).get("guards_missing_for_autonomy_count"),
        "safe_apply_guards_blocked_not_allowed_count": report.get("safe_apply_guard_check", {}).get("guards_blocked_not_allowed_count"),
        "safe_apply_guards_monitor_only_count": report.get("safe_apply_guard_check", {}).get("guards_monitor_only_count"),
        "safe_apply_guard_breach": report.get("safe_apply_guard_check", {}).get("guard_breach"),
        "safe_apply_scope_manager_status": report.get("safe_apply_scope_manager_status"),
        "safe_apply_scope_allowed_draft_only_count": report.get("safe_apply_scope_manager", {}).get("scope_allowed_draft_only_count"),
        "safe_apply_scope_allowed_validation_only_count": report.get("safe_apply_scope_manager", {}).get("scope_allowed_validation_only_count"),
        "safe_apply_scope_not_allowed_missing_guards_count": report.get("safe_apply_scope_manager", {}).get("scope_not_allowed_missing_guards_count"),
        "safe_apply_scope_blocked_high_risk_count": report.get("safe_apply_scope_manager", {}).get("scope_blocked_high_risk_count"),
        "safe_apply_scope_monitor_only_count": report.get("safe_apply_scope_manager", {}).get("scope_monitor_only_count"),
        "safe_apply_scope_breach": report.get("safe_apply_scope_manager", {}).get("scope_breach"),
        "safe_apply_dry_run_planner_status": report.get("safe_apply_dry_run_planner_status"),
        "safe_apply_dry_run_ready_draft_only_count": report.get("safe_apply_dry_run_planner", {}).get("dry_run_ready_draft_only_count"),
        "safe_apply_dry_run_ready_validation_only_count": report.get("safe_apply_dry_run_planner", {}).get("dry_run_ready_validation_only_count"),
        "safe_apply_dry_run_not_ready_missing_guards_count": report.get("safe_apply_dry_run_planner", {}).get("dry_run_not_ready_missing_guards_count"),
        "safe_apply_dry_run_blocked_high_risk_count": report.get("safe_apply_dry_run_planner", {}).get("dry_run_blocked_high_risk_count"),
        "safe_apply_dry_run_monitor_only_count": report.get("safe_apply_dry_run_planner", {}).get("dry_run_monitor_only_count"),
        "safe_apply_dry_run_breach": report.get("safe_apply_dry_run_planner", {}).get("dry_run_breach"),
        "safe_apply_preflight_validator_status": report.get("safe_apply_preflight_validator_status"),
        "safe_apply_preflight_ready_draft_only_count": report.get("safe_apply_preflight_validator", {}).get("preflight_ready_draft_only_count"),
        "safe_apply_preflight_ready_validation_only_count": report.get("safe_apply_preflight_validator", {}).get("preflight_ready_validation_only_count"),
        "safe_apply_preflight_not_ready_count": report.get("safe_apply_preflight_validator", {}).get("preflight_not_ready_count"),
        "safe_apply_preflight_blocked_count": report.get("safe_apply_preflight_validator", {}).get("preflight_blocked_count"),
        "safe_apply_preflight_monitor_only_count": report.get("safe_apply_preflight_validator", {}).get("preflight_monitor_only_count"),
        "safe_apply_preflight_breach": report.get("safe_apply_preflight_validator", {}).get("preflight_breach"),
        "autonomy_runtime_lock_status": report.get("autonomy_runtime_lock_status"),
        "autonomy_runtime_lock_autonomy_enabled": report.get("autonomy_runtime_lock", {}).get("autonomy_enabled"),
        "autonomy_runtime_lock_draft_only_enabled": report.get("autonomy_runtime_lock", {}).get("draft_only_enabled"),
        "autonomy_runtime_lock_validation_only_enabled": report.get("autonomy_runtime_lock", {}).get("validation_only_enabled"),
        "autonomy_runtime_lock_live_apply_enabled": report.get("autonomy_runtime_lock", {}).get("live_apply_enabled"),
        "autonomy_runtime_lock_emergency_stop": report.get("autonomy_runtime_lock", {}).get("emergency_stop"),
        "autonomy_runtime_lock_breach": report.get("autonomy_runtime_lock", {}).get("runtime_lock_breach"),
        "safe_draft_autonomy_runner_status": report.get("safe_draft_autonomy_runner_status"),
        "safe_draft_runner_status": report.get("safe_draft_autonomy_runner", {}).get("runner_status"),
        "safe_draft_runner_executed_draft_only_count": report.get("safe_draft_autonomy_runner", {}).get("executed_draft_only_count"),
        "safe_draft_runner_executed_validation_only_count": report.get("safe_draft_autonomy_runner", {}).get("executed_validation_only_count"),
        "safe_draft_runner_skipped_count": report.get("safe_draft_autonomy_runner", {}).get("skipped_count"),
        "safe_draft_runner_blocked_by_runtime_lock_count": report.get("safe_draft_autonomy_runner", {}).get("blocked_by_runtime_lock_count"),
        "safe_draft_runner_blocked_by_emergency_stop_count": report.get("safe_draft_autonomy_runner", {}).get("blocked_by_emergency_stop_count"),
        "safe_draft_runner_breach": report.get("safe_draft_autonomy_runner", {}).get("runner_breach"),
        "safe_draft_autonomy_verifier_status": report.get("safe_draft_autonomy_verifier_status"),
        "safe_draft_verifier_status": report.get("safe_draft_autonomy_verifier", {}).get("verifier_status"),
        "safe_draft_verifier_verified_safe_outputs_count": report.get("safe_draft_autonomy_verifier", {}).get("verified_safe_outputs_count"),
        "safe_draft_verifier_missing_outputs_count": report.get("safe_draft_autonomy_verifier", {}).get("missing_outputs_count"),
        "safe_draft_verifier_invalid_json_count": report.get("safe_draft_autonomy_verifier", {}).get("invalid_json_count"),
        "safe_draft_verifier_forbidden_path_count": report.get("safe_draft_autonomy_verifier", {}).get("forbidden_path_count"),
        "safe_draft_verifier_secret_pattern_count": report.get("safe_draft_autonomy_verifier", {}).get("secret_pattern_count"),
        "safe_draft_verifier_breach": report.get("safe_draft_autonomy_verifier", {}).get("verifier_breach"),
        "safe_draft_autonomy_scheduler_plan_status": report.get("safe_draft_autonomy_scheduler_plan_status"),
        "safe_draft_scheduler_status": report.get("safe_draft_autonomy_scheduler_plan", {}).get("scheduler_status"),
        "safe_draft_scheduler_planned_frequency": report.get("safe_draft_autonomy_scheduler_plan", {}).get("planned_frequency"),
        "safe_draft_scheduler_timer_installation_status": report.get("safe_draft_autonomy_scheduler_plan", {}).get("timer_installation_status"),
        "safe_draft_scheduler_can_install_timer_now": report.get("safe_draft_autonomy_scheduler_plan", {}).get("can_install_timer_now"),
        "safe_draft_scheduler_owner_review_required": report.get("safe_draft_autonomy_scheduler_plan", {}).get("owner_review_required"),
        "safe_draft_scheduler_breach": report.get("safe_draft_autonomy_scheduler_plan", {}).get("scheduler_breach"),
        "safe_draft_autonomy_timer_draft_status": report.get("safe_draft_autonomy_timer_draft_status"),
        "safe_draft_timer_draft_status": report.get("safe_draft_autonomy_timer_draft", {}).get("timer_draft_status"),
        "safe_draft_timer_installation_status": report.get("safe_draft_autonomy_timer_draft", {}).get("timer_installation_status"),
        "safe_draft_timer_service_draft_written": report.get("safe_draft_autonomy_timer_draft", {}).get("service_draft_written"),
        "safe_draft_timer_timer_draft_written": report.get("safe_draft_autonomy_timer_draft", {}).get("timer_draft_written"),
        "safe_draft_timer_systemd_file_written": report.get("safe_draft_autonomy_timer_draft", {}).get("systemd_file_written"),
        "safe_draft_timer_can_install_timer_now": report.get("safe_draft_autonomy_timer_draft", {}).get("can_install_timer_now"),
        "safe_draft_timer_breach": report.get("safe_draft_autonomy_timer_draft", {}).get("timer_draft_breach"),
        "safe_draft_autonomy_timer_install_review_status": report.get("safe_draft_autonomy_timer_install_review_status"),
        "safe_draft_timer_install_review_status": report.get("safe_draft_autonomy_timer_install_review", {}).get("install_review_status"),
        "safe_draft_timer_install_can_install_timer_now": report.get("safe_draft_autonomy_timer_install_review", {}).get("can_install_timer_now"),
        "safe_draft_timer_install_checks_passed_count": report.get("safe_draft_autonomy_timer_install_review", {}).get("safe_checks_passed_count"),
        "safe_draft_timer_install_checks_failed_count": report.get("safe_draft_autonomy_timer_install_review", {}).get("safe_checks_failed_count"),
        "safe_draft_timer_install_breach": report.get("safe_draft_autonomy_timer_install_review", {}).get("install_reviewer_breach"),
        "owner_manual_timer_install_packet_status": report.get("owner_manual_timer_install_packet_status"),
        "owner_manual_timer_packet_status": report.get("owner_manual_timer_install_packet", {}).get("packet_status"),
        "owner_manual_timer_install_allowed_now": report.get("owner_manual_timer_install_packet", {}).get("install_allowed_now"),
        "owner_manual_timer_can_install_timer_now": report.get("owner_manual_timer_install_packet", {}).get("can_install_timer_now"),
        "owner_manual_timer_emergency_stop_active": report.get("owner_manual_timer_install_packet", {}).get("emergency_stop_active"),
        "owner_manual_timer_packet_breach": report.get("owner_manual_timer_install_packet", {}).get("packet_breach"),
        "owner_timer_install_decision_gate_status": report.get("owner_timer_install_decision_gate_status"),
        "owner_timer_install_decision_status": report.get("owner_timer_install_decision_gate", {}).get("decision_status"),
        "owner_timer_manual_install_allowed": report.get("owner_timer_install_decision_gate", {}).get("manual_install_allowed"),
        "owner_timer_install_allowed_now": report.get("owner_timer_install_decision_gate", {}).get("install_allowed_now"),
        "owner_timer_can_install_timer_now": report.get("owner_timer_install_decision_gate", {}).get("can_install_timer_now"),
        "owner_timer_decision_breach": report.get("owner_timer_install_decision_gate", {}).get("decision_breach"),
        "manual_timer_install_command_preview_status": report.get("manual_timer_install_command_preview_status"),
        "manual_timer_preview_status": report.get("manual_timer_install_command_preview", {}).get("preview_status"),
        "manual_timer_preview_manual_install_allowed": report.get("manual_timer_install_command_preview", {}).get("manual_install_allowed"),
        "manual_timer_preview_install_allowed_now": report.get("manual_timer_install_command_preview", {}).get("install_allowed_now"),
        "manual_timer_preview_can_install_timer_now": report.get("manual_timer_install_command_preview", {}).get("can_install_timer_now"),
        "manual_timer_preview_command_preview_written": report.get("manual_timer_install_command_preview", {}).get("command_preview_written"),
        "manual_timer_preview_breach": report.get("manual_timer_install_command_preview", {}).get("preview_breach"),
        "owner_timer_install_evidence_pack_status": report.get("owner_timer_install_evidence_pack_status"),
        "owner_timer_evidence_pack_status": report.get("owner_timer_install_evidence_pack", {}).get("evidence_pack_status"),
        "owner_timer_evidence_manual_install_allowed": report.get("owner_timer_install_evidence_pack", {}).get("manual_install_allowed"),
        "owner_timer_evidence_install_allowed_now": report.get("owner_timer_install_evidence_pack", {}).get("install_allowed_now"),
        "owner_timer_evidence_can_install_timer_now": report.get("owner_timer_install_evidence_pack", {}).get("can_install_timer_now"),
        "owner_timer_evidence_template_written": report.get("owner_timer_install_evidence_pack", {}).get("evidence_template_written"),
        "owner_timer_evidence_pack_breach": report.get("owner_timer_install_evidence_pack", {}).get("evidence_pack_breach"),
        "safe_draft_autonomy_final_safety_status": report.get("safe_draft_autonomy_final_safety_status"),
        "safe_draft_final_safety_status": report.get("safe_draft_autonomy_final_safety", {}).get("final_safety_status"),
        "safe_draft_final_draft_only_autonomy_ready": report.get("safe_draft_autonomy_final_safety", {}).get("draft_only_autonomy_ready"),
        "safe_draft_final_timer_installation_allowed_now": report.get("safe_draft_autonomy_final_safety", {}).get("timer_installation_allowed_now"),
        "safe_draft_final_live_apply_allowed": report.get("safe_draft_autonomy_final_safety", {}).get("live_apply_allowed"),
        "safe_draft_final_emergency_stop_active": report.get("safe_draft_autonomy_final_safety", {}).get("emergency_stop_active"),
        "safe_draft_final_total_breach_count": report.get("safe_draft_autonomy_final_safety", {}).get("total_breach_count"),
        "safe_draft_final_safety_breach": report.get("safe_draft_autonomy_final_safety", {}).get("final_safety_breach"),
        "manual_evidence_review_dashboard_status": report.get("manual_evidence_review_dashboard_status"),
        "manual_evidence_dashboard_status": report.get("manual_evidence_review_dashboard", {}).get("dashboard_status"),
        "manual_evidence_dashboard_emergency_stop_active": report.get("manual_evidence_review_dashboard", {}).get("emergency_stop_active"),
        "manual_evidence_dashboard_total_breaches": report.get("manual_evidence_review_dashboard", {}).get("total_breaches"),
        "manual_evidence_dashboard_install_allowed_now": report.get("manual_evidence_review_dashboard", {}).get("install_allowed_now"),
        "manual_evidence_dashboard_can_install_timer_now": report.get("manual_evidence_review_dashboard", {}).get("can_install_timer_now"),
        "manual_evidence_dashboard_breach": report.get("manual_evidence_review_dashboard", {}).get("dashboard_breach"),
        "manual_evidence_review_completion_tracker_status": report.get("manual_evidence_review_completion_tracker_status"),
        "manual_evidence_completion_tracker_status": report.get("manual_evidence_review_completion_tracker", {}).get("tracker_status"),
        "manual_evidence_completion_reviewed_count": report.get("manual_evidence_review_completion_tracker", {}).get("reviewed_count"),
        "manual_evidence_completion_unchecked_count": report.get("manual_evidence_review_completion_tracker", {}).get("unchecked_count"),
        "manual_evidence_completion_needs_work_count": report.get("manual_evidence_review_completion_tracker", {}).get("needs_work_count"),
        "manual_evidence_completion_blocked_count": report.get("manual_evidence_review_completion_tracker", {}).get("blocked_count"),
        "manual_evidence_completion_skipped_count": report.get("manual_evidence_review_completion_tracker", {}).get("skipped_count"),
        "manual_evidence_completion_percent": report.get("manual_evidence_review_completion_tracker", {}).get("completion_percent"),
        "manual_evidence_completion_breach": report.get("manual_evidence_review_completion_tracker", {}).get("tracker_breach"),
        "manual_evidence_review_completion_gate_status": report.get("manual_evidence_review_completion_gate_status"),
        "manual_evidence_gate_status": report.get("manual_evidence_review_completion_gate", {}).get("gate_status"),
        "manual_evidence_gate_reviewed_count": report.get("manual_evidence_review_completion_gate", {}).get("reviewed_count"),
        "manual_evidence_gate_total_items": report.get("manual_evidence_review_completion_gate", {}).get("total_items"),
        "manual_evidence_gate_completion_percent": report.get("manual_evidence_review_completion_gate", {}).get("completion_percent"),
        "manual_evidence_gate_all_required_reviewed": report.get("manual_evidence_review_completion_gate", {}).get("all_required_reviewed"),
        "manual_evidence_gate_breach": report.get("manual_evidence_review_completion_gate", {}).get("gate_breach"),
        "owner_evidence_review_console_status": report.get("owner_evidence_review_console_status"),
        "owner_evidence_console_status": report.get("owner_evidence_review_console", {}).get("console_status"),
        "owner_evidence_console_reviewed_count": report.get("owner_evidence_review_console", {}).get("reviewed_count"),
        "owner_evidence_console_total_items": report.get("owner_evidence_review_console", {}).get("total_items"),
        "owner_evidence_console_open_items_count": report.get("owner_evidence_review_console", {}).get("open_items_count"),
        "owner_evidence_console_next_recommended_item": report.get("owner_evidence_review_console", {}).get("next_recommended_item"),
        "owner_evidence_console_breach": report.get("owner_evidence_review_console", {}).get("console_breach"),
        "final_owner_decision_snapshot_status": report.get("final_owner_decision_snapshot_status"),
        "final_owner_snapshot_status": report.get("final_owner_decision_snapshot", {}).get("snapshot_status"),
        "final_owner_snapshot_review_completed": report.get("final_owner_decision_snapshot", {}).get("review_completed"),
        "final_owner_snapshot_reviewed_count": report.get("final_owner_decision_snapshot", {}).get("reviewed_count"),
        "final_owner_snapshot_total_items": report.get("final_owner_decision_snapshot", {}).get("total_items"),
        "final_owner_snapshot_emergency_stop_active": report.get("final_owner_decision_snapshot", {}).get("emergency_stop_active"),
        "final_owner_snapshot_install_allowed_now": report.get("final_owner_decision_snapshot", {}).get("install_allowed_now"),
        "final_owner_snapshot_breach": report.get("final_owner_decision_snapshot", {}).get("snapshot_breach"),
        "master_critical_cause_snapshot_status": report.get("master_critical_cause_snapshot_status"),
        "master_critical_cause_status": report.get("master_critical_cause_snapshot", {}).get("critical_snapshot_status"),
        "master_critical_cause_autonomy": report.get("master_critical_cause_snapshot", {}).get("critical_caused_by_autonomy"),
        "master_critical_cause_website": report.get("master_critical_cause_snapshot", {}).get("critical_caused_by_website"),
        "master_critical_cause_rolling_window": report.get("master_critical_cause_snapshot", {}).get("critical_caused_by_rolling_window"),
        "master_critical_cause_sourcemap": report.get("master_critical_cause_snapshot", {}).get("critical_caused_by_sourcemap"),
        "master_critical_cause_autonomy_total_breaches": report.get("master_critical_cause_snapshot", {}).get("autonomy_total_breaches"),
        "master_critical_cause_breach": report.get("master_critical_cause_snapshot", {}).get("snapshot_breach"),
        "rolling_window_decay_observer_status": report.get("rolling_window_decay_observer_status"),
        "rolling_window_decay_status": report.get("rolling_window_decay_observer", {}).get("decay_status"),
        "rolling_window_decay_trend": report.get("rolling_window_decay_observer", {}).get("trend"),
        "rolling_window_decay_delta_5xx": report.get("rolling_window_decay_observer", {}).get("delta_5xx"),
        "rolling_window_decay_delta_504": report.get("rolling_window_decay_observer", {}).get("delta_504"),
        "rolling_window_decay_observation_required": report.get("rolling_window_decay_observer", {}).get("observation_required"),
        "rolling_window_decay_breach": report.get("rolling_window_decay_observer", {}).get("snapshot_breach"),
        "low_growth_readiness_timeline_status": report.get("low_growth_readiness_timeline_status"),
        "low_growth_timeline_status": report.get("low_growth_readiness_timeline", {}).get("timeline_status"),
        "low_growth_timeline_total_points": report.get("low_growth_readiness_timeline", {}).get("total_points"),
        "low_growth_timeline_last_trend": report.get("low_growth_readiness_timeline", {}).get("last_trend"),
        "low_growth_timeline_consecutive_stable_or_decreasing": report.get("low_growth_readiness_timeline", {}).get("consecutive_stable_or_decreasing_points"),
        "low_growth_timeline_manual_recheck_recommended": report.get("low_growth_readiness_timeline", {}).get("manual_recheck_recommended"),
        "low_growth_timeline_breach": report.get("low_growth_readiness_timeline", {}).get("snapshot_breach"),
        "manual_website_recheck_gate_status": report.get("manual_website_recheck_gate_status"),
        "manual_website_recheck_gate_gate_status": report.get("manual_website_recheck_gate", {}).get("gate_status"),
        "manual_website_recheck_recommended": report.get("manual_website_recheck_gate", {}).get("manual_recheck_recommended"),
        "manual_website_recheck_last_trend": report.get("manual_website_recheck_gate", {}).get("last_trend"),
        "manual_website_recheck_consecutive_stable_or_decreasing": report.get("manual_website_recheck_gate", {}).get("consecutive_stable_or_decreasing_points"),
        "manual_website_recheck_gate_breach": report.get("manual_website_recheck_gate", {}).get("gate_breach"),
        "low_risk_autonomy_readiness_gate_status": report.get("low_risk_autonomy_readiness_gate_status"),
        "low_risk_autonomy_readiness_status": report.get("low_risk_autonomy_readiness_gate", {}).get("readiness_status"),
        "low_risk_autonomy_allowed_now": report.get("low_risk_autonomy_readiness_gate", {}).get("low_risk_autonomy_allowed_now"),
        "low_risk_policy_draft_allowed": report.get("low_risk_autonomy_readiness_gate", {}).get("low_risk_policy_draft_allowed"),
        "low_risk_owner_policy_review_required": report.get("low_risk_autonomy_readiness_gate", {}).get("owner_policy_review_required"),
        "low_risk_autonomy_readiness_breach": report.get("low_risk_autonomy_readiness_gate", {}).get("readiness_breach"),
        "low_risk_policy_boundary_draft_status": report.get("low_risk_policy_boundary_draft_status"),
        "low_risk_policy_boundary_status": report.get("low_risk_policy_boundary_draft", {}).get("policy_status"),
        "low_risk_policy_activation_allowed": report.get("low_risk_policy_boundary_draft", {}).get("policy_activation_allowed"),
        "low_risk_policy_owner_review_required": report.get("low_risk_policy_boundary_draft", {}).get("owner_policy_review_required"),
        "low_risk_policy_draft_only_count": report.get("low_risk_policy_boundary_draft", {}).get("low_risk_draft_only_count"),
        "low_risk_policy_high_never_auto_apply_count": report.get("low_risk_policy_boundary_draft", {}).get("high_never_auto_apply_count"),
        "low_risk_policy_boundary_breach": report.get("low_risk_policy_boundary_draft", {}).get("policy_breach"),
        "low_risk_policy_owner_review_tracker_status": report.get("low_risk_policy_owner_review_tracker_status"),
        "low_risk_policy_owner_review_status": report.get("low_risk_policy_owner_review_tracker", {}).get("tracker_status"),
        "low_risk_policy_owner_review_reviewed_count": report.get("low_risk_policy_owner_review_tracker", {}).get("reviewed_count"),
        "low_risk_policy_owner_review_total_required": report.get("low_risk_policy_owner_review_tracker", {}).get("total_required"),
        "low_risk_policy_owner_review_breach": report.get("low_risk_policy_owner_review_tracker", {}).get("tracker_breach"),
        "low_risk_policy_review_completion_gate_status": report.get("low_risk_policy_review_completion_gate_status"),
        "low_risk_policy_review_completion_status": report.get("low_risk_policy_review_completion_gate", {}).get("gate_status"),
        "low_risk_policy_review_completion_percent": report.get("low_risk_policy_review_completion_gate", {}).get("completion_percent"),
        "low_risk_policy_review_completion_breach": report.get("low_risk_policy_review_completion_gate", {}).get("gate_breach"),
        "low_risk_autonomy_final_safety_seal_status": report.get("low_risk_autonomy_final_safety_seal_status"),
        "low_risk_autonomy_final_seal_status": report.get("low_risk_autonomy_final_safety_seal", {}).get("seal_status"),
        "low_risk_autonomy_final_seal_review_completed": report.get("low_risk_autonomy_final_safety_seal", {}).get("review_completed"),
        "low_risk_autonomy_final_seal_breach": report.get("low_risk_autonomy_final_safety_seal", {}).get("seal_breach"),
        "safe_end_summary_status": report.get("safe_end_summary_status"),
        "safe_end_status": report.get("safe_end_summary", {}).get("safe_end_status"),
        "safe_end_low_risk_policy_review_complete": report.get("safe_end_summary", {}).get("low_risk_policy_review_complete"),
        "safe_end_low_risk_final_seal_complete": report.get("safe_end_summary", {}).get("low_risk_final_seal_complete"),
        "safe_end_emergency_stop_active": report.get("safe_end_summary", {}).get("emergency_stop_active"),
        "safe_end_live_apply": report.get("safe_end_summary", {}).get("live_apply"),
        "safe_end_install_allowed_now": report.get("safe_end_summary", {}).get("install_allowed_now"),
        "safe_end_breach": report.get("safe_end_summary", {}).get("safe_end_breach"),
        "safe_end_archive_snapshot_status": report.get("safe_end_archive_snapshot_status"),
        "safe_end_archive_status": report.get("safe_end_archive_snapshot", {}).get("archive_status"),
        "safe_end_archive_copied_file_count": report.get("safe_end_archive_snapshot", {}).get("copied_file_count"),
        "safe_end_archive_checksum_count": report.get("safe_end_archive_snapshot", {}).get("checksum_count"),
        "safe_end_archive_breach": report.get("safe_end_archive_snapshot", {}).get("archive_breach"),
        "safe_end_archive_integrity_verifier_status": report.get("safe_end_archive_integrity_verifier_status"),
        "safe_end_archive_integrity_status": report.get("safe_end_archive_integrity_verifier", {}).get("integrity_status"),
        "safe_end_archive_integrity_verified_checksum_count": report.get("safe_end_archive_integrity_verifier", {}).get("verified_checksum_count"),
        "safe_end_archive_integrity_checksum_mismatch_count": report.get("safe_end_archive_integrity_verifier", {}).get("checksum_mismatch_count"),
        "safe_end_archive_integrity_forbidden_artifact_count": report.get("safe_end_archive_integrity_verifier", {}).get("forbidden_artifact_count"),
        "safe_end_archive_integrity_breach": report.get("safe_end_archive_integrity_verifier", {}).get("integrity_breach"),
        "concrete_seo_performance_optimizer_status": report.get("concrete_seo_performance_optimizer_status"),
        "concrete_optimizer_total_recommendations": report.get("concrete_seo_performance_optimizer", {}).get("total_recommendations"),
        "concrete_optimizer_copy_paste_owner_apply_count": report.get("concrete_seo_performance_optimizer", {}).get("copy_paste_owner_apply_count"),
        "concrete_optimizer_diagnostic_only_count": report.get("concrete_seo_performance_optimizer", {}).get("diagnostic_only_count"),
        "concrete_optimizer_breach": report.get("concrete_seo_performance_optimizer", {}).get("optimizer_breach"),
        "safe_sftp_seo_apply_lane_status": report.get("safe_sftp_seo_apply_lane_status"),
        "safe_sftp_seo_apply_mode": report.get("safe_sftp_seo_apply_lane", {}).get("mode"),
        "safe_sftp_seo_apply_uploaded": report.get("safe_sftp_seo_apply_lane", {}).get("uploaded"),
        "safe_sftp_seo_apply_healthcheck_status": report.get("safe_sftp_seo_apply_lane", {}).get("healthcheck_status"),
        "safe_sftp_seo_apply_changed_file_count": report.get("safe_sftp_seo_apply_lane", {}).get("changed_file_count"),
        "safe_sftp_seo_apply_live_apply": report.get("safe_sftp_seo_apply_lane", {}).get("live_apply"),
        "safe_sftp_seo_apply_breach": report.get("safe_sftp_seo_apply_lane", {}).get("apply_breach"),
        "recommendations": report.get("recommendations", []),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Sentinel master report.")
    parser.add_argument("--website-json", type=Path, default=DEFAULT_WEBSITE_JSON)
    parser.add_argument("--local-json", type=Path, default=DEFAULT_LOCAL_JSON)
    parser.add_argument("--private-pc-json", type=Path, default=DEFAULT_PRIVATE_PC_JSON)
    parser.add_argument("--sourcemap-json", type=Path, default=DEFAULT_SOURCEMAP_JSON)
    parser.add_argument("--ai-radio-timeout-json", type=Path, default=DEFAULT_AI_RADIO_TIMEOUT_JSON)
    parser.add_argument("--autonomy-policy-json", type=Path, default=DEFAULT_AUTONOMY_POLICY_JSON)
    parser.add_argument("--seo-optimizer-json", type=Path, default=DEFAULT_SEO_OPTIMIZER_JSON)
    parser.add_argument("--editorial-review-json", type=Path, default=DEFAULT_EDITORIAL_REVIEW_JSON)
    parser.add_argument("--microcache-status-json", type=Path, default=DEFAULT_MICROCACHE_STATUS_JSON)
    parser.add_argument("--perf-audit-json", type=Path, default=DEFAULT_PERF_AUDIT_JSON)
    parser.add_argument("--roadmap-json", type=Path, default=DEFAULT_ROADMAP_JSON)
    parser.add_argument("--approval-queue-json", type=Path, default=DEFAULT_APPROVAL_QUEUE_JSON)
    parser.add_argument("--owner-cli-report-json", type=Path, default=DEFAULT_OWNER_CLI_REPORT_JSON)
    parser.add_argument("--draft-execution-plan-json", type=Path, default=DEFAULT_DRAFT_EXECUTION_PLAN_JSON)
    parser.add_argument("--owner-review-pack-json", type=Path, default=DEFAULT_OWNER_REVIEW_PACK_JSON)
    parser.add_argument("--manual-apply-checklist-json", type=Path, default=DEFAULT_MANUAL_APPLY_CHECKLIST_JSON)
    parser.add_argument("--manual-completion-tracker-json", type=Path, default=DEFAULT_MANUAL_COMPLETION_TRACKER_JSON)
    parser.add_argument("--post-manual-validation-json", type=Path, default=DEFAULT_POST_MANUAL_VALIDATION_JSON)
    parser.add_argument("--owner-daily-action-summary-json", type=Path, default=DEFAULT_OWNER_DAILY_ACTION_SUMMARY_JSON)
    parser.add_argument("--safe-apply-registry-json", type=Path, default=DEFAULT_SAFE_APPLY_REGISTRY_JSON)
    parser.add_argument("--safe-apply-guard-json", type=Path, default=DEFAULT_SAFE_APPLY_GUARD_JSON)
    parser.add_argument("--safe-apply-scope-json", type=Path, default=DEFAULT_SAFE_APPLY_SCOPE_JSON)
    parser.add_argument("--safe-apply-dry-run-json", type=Path, default=DEFAULT_SAFE_APPLY_DRY_RUN_JSON)
    parser.add_argument("--safe-apply-preflight-json", type=Path, default=DEFAULT_SAFE_APPLY_PREFLIGHT_JSON)
    parser.add_argument("--autonomy-runtime-lock-json", type=Path, default=DEFAULT_AUTONOMY_RUNTIME_LOCK_JSON)
    parser.add_argument("--safe-draft-autonomy-runner-json", type=Path, default=DEFAULT_SAFE_DRAFT_AUTONOMY_RUNNER_JSON)
    parser.add_argument("--safe-draft-autonomy-verifier-json", type=Path, default=DEFAULT_SAFE_DRAFT_AUTONOMY_VERIFIER_JSON)
    parser.add_argument("--safe-draft-autonomy-scheduler-plan-json", type=Path, default=DEFAULT_SAFE_DRAFT_AUTONOMY_SCHEDULER_PLAN_JSON)
    parser.add_argument("--safe-draft-autonomy-timer-draft-json", type=Path, default=DEFAULT_SAFE_DRAFT_AUTONOMY_TIMER_DRAFT_JSON)
    parser.add_argument("--safe-draft-autonomy-timer-install-review-json", type=Path, default=DEFAULT_SAFE_DRAFT_AUTONOMY_TIMER_INSTALL_REVIEW_JSON)
    parser.add_argument("--owner-manual-timer-install-packet-json", type=Path, default=DEFAULT_OWNER_MANUAL_TIMER_INSTALL_PACKET_JSON)
    parser.add_argument("--owner-timer-install-decision-gate-json", type=Path, default=DEFAULT_OWNER_TIMER_INSTALL_DECISION_GATE_JSON)
    parser.add_argument("--manual-timer-install-command-preview-json", type=Path, default=DEFAULT_MANUAL_TIMER_INSTALL_COMMAND_PREVIEW_JSON)
    parser.add_argument("--owner-timer-install-evidence-pack-json", type=Path, default=DEFAULT_OWNER_TIMER_INSTALL_EVIDENCE_PACK_JSON)
    parser.add_argument("--safe-draft-autonomy-final-safety-json", type=Path, default=DEFAULT_SAFE_DRAFT_AUTONOMY_FINAL_SAFETY_JSON)
    parser.add_argument("--manual-evidence-review-dashboard-json", type=Path, default=DEFAULT_MANUAL_EVIDENCE_REVIEW_DASHBOARD_JSON)
    parser.add_argument("--manual-evidence-review-completion-tracker-json", type=Path, default=DEFAULT_MANUAL_EVIDENCE_REVIEW_COMPLETION_TRACKER_JSON)
    parser.add_argument("--manual-evidence-review-completion-gate-json", type=Path, default=DEFAULT_MANUAL_EVIDENCE_REVIEW_COMPLETION_GATE_JSON)
    parser.add_argument("--owner-evidence-review-console-json", type=Path, default=DEFAULT_OWNER_EVIDENCE_REVIEW_CONSOLE_JSON)
    parser.add_argument("--final-owner-decision-snapshot-json", type=Path, default=DEFAULT_FINAL_OWNER_DECISION_SNAPSHOT_JSON)
    parser.add_argument("--master-critical-cause-snapshot-json", type=Path, default=DEFAULT_MASTER_CRITICAL_CAUSE_SNAPSHOT_JSON)
    parser.add_argument("--rolling-window-decay-observer-json", type=Path, default=DEFAULT_ROLLING_WINDOW_DECAY_OBSERVER_JSON)
    parser.add_argument("--low-growth-readiness-timeline-json", type=Path, default=DEFAULT_LOW_GROWTH_READINESS_TIMELINE_JSON)
    parser.add_argument("--manual-website-recheck-gate-json", type=Path, default=DEFAULT_MANUAL_WEBSITE_RECHECK_GATE_JSON)
    parser.add_argument("--low-risk-autonomy-readiness-gate-json", type=Path, default=DEFAULT_LOW_RISK_AUTONOMY_READINESS_GATE_JSON)
    parser.add_argument("--low-risk-policy-boundary-draft-json", type=Path, default=DEFAULT_LOW_RISK_POLICY_BOUNDARY_DRAFT_JSON)
    parser.add_argument("--low-risk-policy-owner-review-tracker-json", type=Path, default=DEFAULT_LOW_RISK_POLICY_OWNER_REVIEW_TRACKER_JSON)
    parser.add_argument("--low-risk-policy-review-completion-gate-json", type=Path, default=DEFAULT_LOW_RISK_POLICY_REVIEW_COMPLETION_GATE_JSON)
    parser.add_argument("--low-risk-autonomy-final-safety-seal-json", type=Path, default=DEFAULT_LOW_RISK_AUTONOMY_FINAL_SAFETY_SEAL_JSON)
    parser.add_argument("--safe-end-summary-json", type=Path, default=DEFAULT_SAFE_END_SUMMARY_JSON)
    parser.add_argument("--safe-end-archive-snapshot-json", type=Path, default=DEFAULT_SAFE_END_ARCHIVE_SNAPSHOT_JSON)
    parser.add_argument("--safe-end-archive-integrity-verifier-json", type=Path, default=DEFAULT_SAFE_END_ARCHIVE_INTEGRITY_VERIFIER_JSON)
    parser.add_argument("--concrete-seo-performance-optimizer-json", type=Path, default=DEFAULT_CONCRETE_SEO_PERFORMANCE_OPTIMIZER_JSON)
    parser.add_argument("--safe-sftp-seo-apply-lane-json", type=Path, default=DEFAULT_SAFE_SFTP_SEO_APPLY_LANE_JSON)
    parser.add_argument("--production-pipeline-json", type=Path, default=DEFAULT_PRODUCTION_PIPELINE_JSON)
    parser.add_argument("--nowplaying-recovery-json", type=Path, default=DEFAULT_NOWPLAYING_RECOVERY_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--history", type=Path, default=DEFAULT_HISTORY)
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    report = build_report(
        args.website_json,
        args.local_json,
        args.private_pc_json,
        args.sourcemap_json,
        args.ai_radio_timeout_json,
        args.out_md,
        args.out_json,
        args.history,
        args.autonomy_policy_json,
        args.seo_optimizer_json,
        args.editorial_review_json,
        args.microcache_status_json,
        args.perf_audit_json,
        args.roadmap_json,
        args.approval_queue_json,
        args.owner_cli_report_json,
        args.draft_execution_plan_json,
        args.owner_review_pack_json,
        args.manual_apply_checklist_json,
        args.manual_completion_tracker_json,
        args.post_manual_validation_json,
        args.owner_daily_action_summary_json,
        args.safe_apply_registry_json,
        args.safe_apply_guard_json,
        args.safe_apply_scope_json,
        args.safe_apply_dry_run_json,
        args.safe_apply_preflight_json,
        args.autonomy_runtime_lock_json,
        args.safe_draft_autonomy_runner_json,
        args.safe_draft_autonomy_verifier_json,
        args.safe_draft_autonomy_scheduler_plan_json,
        args.safe_draft_autonomy_timer_draft_json,
        args.safe_draft_autonomy_timer_install_review_json,
        args.owner_manual_timer_install_packet_json,
        args.owner_timer_install_decision_gate_json,
        args.manual_timer_install_command_preview_json,
        args.owner_timer_install_evidence_pack_json,
        args.safe_draft_autonomy_final_safety_json,
        args.manual_evidence_review_dashboard_json,
        args.manual_evidence_review_completion_tracker_json,
        args.manual_evidence_review_completion_gate_json,
        args.owner_evidence_review_console_json,
        args.final_owner_decision_snapshot_json,
        args.master_critical_cause_snapshot_json,
        args.rolling_window_decay_observer_json,
        args.low_growth_readiness_timeline_json,
        args.manual_website_recheck_gate_json,
        args.low_risk_autonomy_readiness_gate_json,
        args.low_risk_policy_boundary_draft_json,
        args.low_risk_policy_owner_review_tracker_json,
        args.low_risk_policy_review_completion_gate_json,
        args.low_risk_autonomy_final_safety_seal_json,
        args.safe_end_summary_json,
        args.safe_end_archive_snapshot_json,
        args.safe_end_archive_integrity_verifier_json,
        args.concrete_seo_performance_optimizer_json,
        args.safe_sftp_seo_apply_lane_json,
    )
    write_json_atomic(args.out_json, report)
    write_text_atomic(args.out_md, render_markdown(report))
    append_history(args.history, report)
    print(
        "Sentinel master report written: "
        f"{args.out_md} ({report['overall_master_status']}, action={report['action_status']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
