#!/usr/bin/env python3
"""Send the daily Sentinel master report via SMTP.

Configuration is read from /etc/sentinel-defense.env and can be overridden by
real environment variables. Secrets are never printed.
"""

from __future__ import annotations

import argparse
import os
import re
import smtplib
import ssl
import sys
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
import json

import sentinel_canonical_truth as canonical_truth


PROJECT_DIR = Path("/srv/sentinel-defense")

DEFAULT_ENV_FILE = Path("/etc/sentinel-defense.env")
DEFAULT_MASTER_MD = PROJECT_DIR / "reports/latest/sentinel-master-report.md"
DEFAULT_MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
DEFAULT_WEBSITE_MD = PROJECT_DIR / "reports/latest/sentinel-defense-report.md"

DEFAULT_SUBJECT = "Sentinel Daily Report"

WP_USERS_ME_PATH = "/wp-json/wp/v2/users/me"

ENV_KEYS = (
    "SENTINEL_MAIL_TO",
    "SENTINEL_MAIL_FROM",
    "SENTINEL_MAIL_SUBJECT",
    "SENTINEL_SMTP_HOST",
    "SENTINEL_SMTP_PORT",
    "SENTINEL_SMTP_USER",
    "SENTINEL_SMTP_PASSWORD",
    "SENTINEL_SMTP_STARTTLS",
)
REQUIRED_SEND_KEYS = (
    "SENTINEL_MAIL_TO",
    "SENTINEL_MAIL_FROM",
    "SENTINEL_SMTP_HOST",
    "SENTINEL_SMTP_PORT",
    "SENTINEL_SMTP_USER",
    "SENTINEL_SMTP_PASSWORD",
)

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|credential)"
    r"\s*[:=]\s*[^\s,;]+"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")


@dataclass(frozen=True)
class MailConfig:
    mail_to: str
    mail_from: str
    subject: str
    smtp_host: str
    smtp_port: Optional[int]
    smtp_user: str
    smtp_password: str
    starttls: bool

    @property
    def recipients(self) -> List[str]:
        return parse_recipients(self.mail_to)

    def missing_send_keys(self) -> List[str]:
        missing: List[str] = []
        if not self.mail_to:
            missing.append("SENTINEL_MAIL_TO")
        if not self.mail_from:
            missing.append("SENTINEL_MAIL_FROM")
        if not self.smtp_host:
            missing.append("SENTINEL_SMTP_HOST")
        if self.smtp_port is None:
            missing.append("SENTINEL_SMTP_PORT")
        if not self.smtp_user:
            missing.append("SENTINEL_SMTP_USER")
        if not self.smtp_password:
            missing.append("SENTINEL_SMTP_PASSWORD")
        if not self.recipients:
            missing.append("SENTINEL_MAIL_TO_VALID_RECIPIENT")
        return missing


def redact_text(value: Any) -> str:
    text = str(value)
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = BEARER_RE.sub("Bearer <redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    return text


def redact_known_values(value: Any, secrets: Iterable[str]) -> str:
    text = redact_text(value)
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "<redacted>")
    return text


def strip_inline_comment(value: str) -> str:
    for marker in (" #", "\t#"):
        index = value.find(marker)
        if index >= 0:
            return value[:index].rstrip()
    return value.strip()


def parse_env_value(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        quote = value[0]
        escaped = False
        chars: List[str] = []
        for char in value[1:]:
            if escaped:
                chars.append(char)
                escaped = False
                continue
            if quote == '"' and char == "\\":
                escaped = True
                continue
            if char == quote:
                return "".join(chars)
            chars.append(char)
        return "".join(chars)
    return strip_inline_comment(value)


def read_env_file(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    if not path.exists():
        return env
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"Env-Datei konnte nicht gelesen werden: {redact_text(exc)}", file=sys.stderr)
        return env

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].lstrip()
        if "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        env[key] = parse_env_value(raw_value)
    return env


def merged_env(env_file: Path) -> Dict[str, str]:
    file_env = read_env_file(env_file)
    env: Dict[str, str] = {}
    for key in ENV_KEYS:
        if key in file_env:
            env[key] = file_env[key]
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def parse_bool(value: str, default: bool = True) -> bool:
    if value == "":
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return default


def parse_port(value: str) -> Optional[int]:
    if not value:
        return None
    try:
        port = int(value)
    except ValueError:
        return None
    if 1 <= port <= 65535:
        return port
    return None


def config_from_env(env: Dict[str, str]) -> MailConfig:
    return MailConfig(
        mail_to=env.get("SENTINEL_MAIL_TO", "").strip(),
        mail_from=env.get("SENTINEL_MAIL_FROM", "").strip(),
        subject=env.get("SENTINEL_MAIL_SUBJECT", "").strip() or DEFAULT_SUBJECT,
        smtp_host=env.get("SENTINEL_SMTP_HOST", "").strip(),
        smtp_port=parse_port(env.get("SENTINEL_SMTP_PORT", "").strip()),
        smtp_user=env.get("SENTINEL_SMTP_USER", "").strip(),
        smtp_password=env.get("SENTINEL_SMTP_PASSWORD", ""),
        starttls=parse_bool(env.get("SENTINEL_SMTP_STARTTLS", ""), default=True),
    )


def parse_recipients(value: str) -> List[str]:
    recipients = [item.strip() for item in re.split(r"[,;\s]+", value) if item.strip()]
    return recipients


def read_text_or_note(path: Path, label: str) -> str:
    try:
        if path.exists():
            return path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"{label} konnte nicht gelesen werden: {redact_text(exc)}"
    return f"{label} fehlt: {path}"


def read_json_or_empty(path: Path) -> Dict[str, Any]:
    try:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(data, dict):
        return data
    return {}


def as_status(value: Any) -> str:
    return redact_text(value if value is not None else "UNKNOWN")


def load_canonical_truth() -> Dict[str, Any]:
    """Phase 10.21: the canonical snapshot is the only source of current truth.

    The mail timer runs independently of the production pipeline, so a stale
    persisted snapshot is re-resolved in memory instead of being mailed as current.
    """
    return canonical_truth.load_or_resolve()


def canonical_show(canonical: Dict[str, Any], field: str) -> str:
    """Render one canonical value; unresolved fields stay UNKNOWN, never legacy."""
    block = canonical.get(field)
    if not isinstance(block, dict):
        return "UNKNOWN"
    return redact_text(canonical_truth.show(block))


def build_subject(configured_subject: str, canonical_report: Dict[str, Any]) -> str:
    """Subject badge comes from canonical truth, never from a second status source."""
    subject = (configured_subject or DEFAULT_SUBJECT).strip()
    subject = re.sub(r"^\[[^\]]*\]\s*", "", subject).strip() or DEFAULT_SUBJECT
    canonical = canonical_report.get("canonical", {}) if isinstance(canonical_report, dict) else {}
    if canonical_report.get("status") != "CANONICAL_TRUTH_OK":
        badge = "CANONICAL_TRUTH_INCOMPLETE"
    else:
        badge = canonical_truth.show(canonical.get("overall_status", {}))
    return f"[{badge}] {subject}"


def build_legacy_section(canonical_report: Dict[str, Any]) -> List[str]:
    """Section 16: historical modules stay listed, labelled and without effect."""
    blocks = canonical_report.get("daily_summary_blocks", {}) if isinstance(canonical_report, dict) else {}
    if blocks.get("legacy_section"):
        return ["", "-----", ""] + list(blocks["legacy_section"])
    return [
        "",
        "-----",
        "",
        "Legacy / Historical Modules",
        "",
        "- no canonical legacy supersession snapshot available",
    ]


def build_summary(master_json_path: Path) -> str:
    data = read_json_or_empty(master_json_path)
    recommendations = data.get("recommendations")
    if not isinstance(recommendations, list):
        recommendations = []

    challenge_diagnosis = data.get("cloudflare_challenge_diagnosis", {})
    sourcemap = data.get("sourcemap_prevention")
    if not isinstance(sourcemap, dict):
        sourcemap = {}
    ai_radio = data.get("ai_radio_timeout_diagnosis")
    if not isinstance(ai_radio, dict):
        ai_radio = {}
    autonomy = data.get("autonomy_policy")
    if not isinstance(autonomy, dict):
        autonomy = {}
    seo = data.get("seo_safe_optimizer")
    if not isinstance(seo, dict):
        seo = {}
    performance = data.get("performance_safe_improvement")
    if not isinstance(performance, dict):
        performance = {}
    roadmap = data.get("safe_improvement_roadmap")
    if not isinstance(roadmap, dict):
        roadmap = {}
    approval_queue = data.get("approval_queue")
    if not isinstance(approval_queue, dict):
        approval_queue = {}
    owner_daily = data.get("owner_daily_action_summary")
    if not isinstance(owner_daily, dict):
        owner_daily = {}
    safe_apply_registry = data.get("safe_apply_candidate_registry")
    if not isinstance(safe_apply_registry, dict):
        safe_apply_registry = {}
    safe_apply_guard = data.get("safe_apply_guard_check")
    if not isinstance(safe_apply_guard, dict):
        safe_apply_guard = {}
    safe_apply_scope = data.get("safe_apply_scope_manager")
    if not isinstance(safe_apply_scope, dict):
        safe_apply_scope = {}
    safe_apply_dry_run = data.get("safe_apply_dry_run_planner")
    if not isinstance(safe_apply_dry_run, dict):
        safe_apply_dry_run = {}
    safe_apply_preflight = data.get("safe_apply_preflight_validator")
    if not isinstance(safe_apply_preflight, dict):
        safe_apply_preflight = {}
    autonomy_runtime_lock = data.get("autonomy_runtime_lock")
    if not isinstance(autonomy_runtime_lock, dict):
        autonomy_runtime_lock = {}
    safe_draft_runner = data.get("safe_draft_autonomy_runner")
    if not isinstance(safe_draft_runner, dict):
        safe_draft_runner = {}
    safe_draft_verifier = data.get("safe_draft_autonomy_verifier")
    if not isinstance(safe_draft_verifier, dict):
        safe_draft_verifier = {}
    safe_draft_scheduler = data.get("safe_draft_autonomy_scheduler_plan")
    if not isinstance(safe_draft_scheduler, dict):
        safe_draft_scheduler = {}
    safe_draft_timer = data.get("safe_draft_autonomy_timer_draft")
    if not isinstance(safe_draft_timer, dict):
        safe_draft_timer = {}
    safe_draft_timer_review = data.get("safe_draft_autonomy_timer_install_review")
    if not isinstance(safe_draft_timer_review, dict):
        safe_draft_timer_review = {}
    owner_manual_timer_packet = data.get("owner_manual_timer_install_packet")
    if not isinstance(owner_manual_timer_packet, dict):
        owner_manual_timer_packet = {}
    owner_timer_decision = data.get("owner_timer_install_decision_gate")
    if not isinstance(owner_timer_decision, dict):
        owner_timer_decision = {}
    manual_timer_preview = data.get("manual_timer_install_command_preview")
    if not isinstance(manual_timer_preview, dict):
        manual_timer_preview = {}
    owner_timer_evidence = data.get("owner_timer_install_evidence_pack")
    if not isinstance(owner_timer_evidence, dict):
        owner_timer_evidence = {}
    final_safety = data.get("safe_draft_autonomy_final_safety")
    if not isinstance(final_safety, dict):
        final_safety = {}
    manual_evidence_dashboard = data.get("manual_evidence_review_dashboard")
    if not isinstance(manual_evidence_dashboard, dict):
        manual_evidence_dashboard = {}
    manual_evidence_completion = data.get("manual_evidence_review_completion_tracker")
    if not isinstance(manual_evidence_completion, dict):
        manual_evidence_completion = {}
    manual_evidence_gate = data.get("manual_evidence_review_completion_gate")
    if not isinstance(manual_evidence_gate, dict):
        manual_evidence_gate = {}
    owner_evidence_console = data.get("owner_evidence_review_console")
    if not isinstance(owner_evidence_console, dict):
        owner_evidence_console = {}
    final_owner_snapshot = data.get("final_owner_decision_snapshot")
    if not isinstance(final_owner_snapshot, dict):
        final_owner_snapshot = {}
    master_critical_cause = data.get("master_critical_cause_snapshot")
    if not isinstance(master_critical_cause, dict):
        master_critical_cause = {}
    rolling_window_decay = data.get("rolling_window_decay_observer")
    if not isinstance(rolling_window_decay, dict):
        rolling_window_decay = {}
    low_growth_timeline = data.get("low_growth_readiness_timeline")
    if not isinstance(low_growth_timeline, dict):
        low_growth_timeline = {}
    manual_recheck_gate = data.get("manual_website_recheck_gate")
    if not isinstance(manual_recheck_gate, dict):
        manual_recheck_gate = {}
    low_risk_readiness_gate = data.get("low_risk_autonomy_readiness_gate")
    if not isinstance(low_risk_readiness_gate, dict):
        low_risk_readiness_gate = {}
    low_risk_policy_boundary = data.get("low_risk_policy_boundary_draft")
    if not isinstance(low_risk_policy_boundary, dict):
        low_risk_policy_boundary = {}
    low_risk_owner_review = data.get("low_risk_policy_owner_review_tracker")
    if not isinstance(low_risk_owner_review, dict):
        low_risk_owner_review = {}
    low_risk_completion_gate = data.get("low_risk_policy_review_completion_gate")
    if not isinstance(low_risk_completion_gate, dict):
        low_risk_completion_gate = {}
    low_risk_final_seal = data.get("low_risk_autonomy_final_safety_seal")
    if not isinstance(low_risk_final_seal, dict):
        low_risk_final_seal = {}
    safe_end = data.get("safe_end_summary")
    if not isinstance(safe_end, dict):
        safe_end = {}
    safe_end_archive = data.get("safe_end_archive_snapshot")
    if not isinstance(safe_end_archive, dict):
        safe_end_archive = {}
    safe_end_integrity = data.get("safe_end_archive_integrity_verifier")
    if not isinstance(safe_end_integrity, dict):
        safe_end_integrity = {}
    concrete_optimizer = data.get("concrete_seo_performance_optimizer")
    if not isinstance(concrete_optimizer, dict):
        concrete_optimizer = {}
    safe_sftp_lane = data.get("safe_sftp_seo_apply_lane")
    if not isinstance(safe_sftp_lane, dict):
        safe_sftp_lane = {}

    canonical_report = load_canonical_truth()
    canonical = canonical_report.get("canonical", {}) if isinstance(canonical_report, dict) else {}
    blocks = canonical_report.get("daily_summary_blocks", {}) if isinstance(canonical_report, dict) else {}

    # Phase 10.21: the executive header is the canonical header, verbatim. The
    # mailer assembles no runtime, website or priority value of its own.
    lines: List[str] = []
    if blocks.get("header"):
        lines.extend(blocks["header"])
        lines.extend(["", f"Action Status: {as_status(data.get('action_status'))}"])
    else:
        lines.extend([
            "Sentinel Daily Summary",
            "",
            f"Generated: {as_status(data.get('generated_at_utc'))}",
            "",
            "Canonical Truth:",
            "CANONICAL_TRUTH_INCOMPLETE",
            "",
            "No canonical daily header is available; run sentinel_canonical_truth.py --resolve.",
            "No legacy value is substituted for a missing current value.",
        ])

    if blocks.get("runtime_section"):
        lines.extend(["", "-----", ""])
        lines.extend(blocks["runtime_section"])
    if blocks.get("website_section"):
        lines.extend(["", "-----", ""])
        lines.extend(blocks["website_section"])
    if blocks.get("owner_priority_section"):
        lines.extend(["", "-----", ""])
        lines.extend(blocks["owner_priority_section"])

    lines.extend([
        "",
        "-----",
        "",
        "Cloudflare Challenge Note:",
    ])
    if challenge_diagnosis.get("present"):
        verdict = challenge_diagnosis.get("verdict", "unknown")
        botfight_share = challenge_diagnosis.get("botfight_share_percent", "?")
        lines.append(
            f"- Global 403/curl challenge is caused by Cloudflare Bot Fight Mode "
            f"({botfight_share}% of security actions), not SentinelDefense."
        )
        lines.append("- Real browsers likely pass through.")
    else:
        lines.append("- No Cloudflare challenge diagnosis available.")

    lines.extend([
        "",
        "SourceMap Prevention:",
        f"- Current SourceMap 404 (24h): {canonical_show(canonical, 'source_map_404')}",
        f"- Current SourceMap Status: {canonical_show(canonical, 'source_map_status')}",
        "- Legacy SourceMap Diagnostic (below): stale informational, no operational effect.",
    ])
    if sourcemap:
        lines.append(f"- Legacy status (superseded): {as_status(sourcemap.get('status'))}")
        lines.append(f"- Candidates: {as_status(sourcemap.get('candidate_count'))}")
        lines.append(
            "- Planned/Applied/Skipped: "
            f"{as_status(sourcemap.get('planned_count'))}/"
            f"{as_status(sourcemap.get('applied_count'))}/"
            f"{as_status(sourcemap.get('skipped_count'))}"
        )
        lines.append(f"- Active WPO actions: {as_status(sourcemap.get('active_wpo_actions_count'))}")
        lines.append(f"- Already remediated WPO: {as_status(sourcemap.get('already_remediated_count'))}")
        lines.append(f"- Historical window remainder hits: {as_status(sourcemap.get('historical_window_remainder_count'))}")
        if sourcemap.get("already_remediated_count") and not sourcemap.get("active_wpo_actions_count"):
            lines.append(
                "- WPO-Minify SourceMap references already absent; remaining .map hits likely 24h/browser-cache remainder."
            )
        lines.append(f"- Global safe to auto apply: {as_status(sourcemap.get('global_safe_to_auto_apply'))}")
        lines.append(f"- WPO-Minify safe to apply: {as_status(sourcemap.get('wpo_minify_safe_to_apply'))}")
        lines.append(f"- Core requires review: {as_status(sourcemap.get('core_requires_review'))}")
        lines.append(f"- Requires operator review: {as_status(sourcemap.get('requires_operator_review'))}")
        lines.append(f"- Rollback hint: {as_status(sourcemap.get('rollback_hint_path'))}")
    else:
        lines.append("- No SourceMap Prevention report available.")

    lines.extend([
        "",
        "AI-Radio / NowPlaying:",
        f"- Current NowPlaying 504: {canonical_show(canonical, 'nowplaying_504')}",
        f"- Recovery classification: {canonical_show(canonical, 'nowplaying_classification')}",
        f"- Automatic local repair: {canonical_show(canonical, 'nowplaying_automatic_repair_allowed')}",
        f"- Current {WP_USERS_ME_PATH} 504: {canonical_show(canonical, 'wp_users_me_504')}",
        f"- {WP_USERS_ME_PATH} classification: {canonical_show(canonical, 'wp_users_me_classification')}",
        "",
        "Legacy AI-Radio Timeout Diagnosis (superseded, informational only):",
    ])
    if ai_radio:
        top = ai_radio.get("top_timeout_endpoint") if isinstance(ai_radio.get("top_timeout_endpoint"), dict) else {}
        remediation = ai_radio.get("microcache_remediation") if isinstance(ai_radio.get("microcache_remediation"), dict) else {}
        rolling = ai_radio.get("rolling_window_status") if isinstance(ai_radio.get("rolling_window_status"), dict) else {}
        lines.append(f"- Status: {as_status(ai_radio.get('status'))}")
        lines.append(
            "- Top timeout endpoint: "
            f"{as_status(top.get('host'))}{as_status(top.get('path'))} "
            f"({as_status(top.get('count'))})"
        )
        lines.append(
            f"- Legacy 24h NowPlaying 504 count (superseded): {as_status(ai_radio.get('nowplaying_504'))}"
        )
        lines.append(f"- Remediation deployed: {as_status(remediation.get('microcache_deployed'))}")
        lines.append(f"- Local validation: {as_status(remediation.get('local_validation'))}")
        if remediation.get("microcache_deployed"):
            lines.append(
                "- NowPlaying Microcache is deployed and HIT-confirmed on origin; remaining 504s are evaluated through 24h rolling window."
            )
        lines.append(f"- Latest 5xx delta: {as_status(rolling.get('latest_5xx_delta'))}")
        lines.append(f"- Rolling-window status: {as_status(rolling.get('status'))}")
        lines.append(f"- Suggested prevention: {as_status(ai_radio.get('suggested_prevention'))}")
        lines.append(f"- Next action: {as_status(ai_radio.get('next_action') or remediation.get('next_action'))}")
        lines.append(f"- Safe to auto apply: {as_status(ai_radio.get('safe_to_auto_apply'))}")
        lines.append(f"- Requires operator review: {as_status(ai_radio.get('requires_operator_review'))}")
    else:
        lines.append("- No AI-Radio timeout diagnosis available.")

    lines.extend([
        "",
        "Legacy Autonomy Policy (superseded by canonical runtime):",
    ])
    if autonomy.get("present"):
        breach = " — POLICY BREACH, manual review" if autonomy.get("policy_breach") else ""
        policy_only_text = "policy-only" if autonomy.get("policy_only") else "NOT policy-only"
        high_blocked_text = (
            "HIGH blocked"
            if as_status(autonomy.get("high_risk_allowed_now_count")) in {"0", "-"}
            else "HIGH allowed_now!"
        )
        lines.append(
            f"- Legacy autonomy level (superseded, operational_effect=false): "
            f"{as_status(autonomy.get('current_autonomy_level'))}, "
            f"{policy_only_text}, {high_blocked_text}{breach}"
        )
        lines.append(
            f"- Canonical runtime level: {canonical_show(canonical, 'autonomy_level')}"
        )
    else:
        lines.append("- Legacy autonomy policy: NOT_AVAILABLE (historical module)")
    if seo.get("present"):
        lines.append(
            f"- SEO: {as_status(seo.get('highest_risk'))} risk drafts available, review-only"
        )
    else:
        lines.append("- SEO: NOT_AVAILABLE (run sentinel_seo_safe_optimizer.py)")
    if performance.get("present"):
        lines.append("- Performance: read-only recommendations only")
    else:
        lines.append("- Performance: NOT_AVAILABLE (read-only)")
    if roadmap.get("present"):
        lines.append(
            f"- Roadmap: next_safe={as_status(roadmap.get('roadmap_next_safe_count'))}, "
            f"owner_review={as_status(roadmap.get('roadmap_owner_review_count'))}, "
            f"blocked_high={as_status(roadmap.get('roadmap_blocked_high_count'))} (review-only)"
        )
    else:
        lines.append("- Roadmap: NOT_AVAILABLE (run sentinel_safe_improvement_roadmap.py)")
    if approval_queue.get("present"):
        lines.append(
            f"- Approval Queue: pending={as_status(approval_queue.get('pending_owner_review_count'))}, "
            f"draft_only={as_status(approval_queue.get('approved_for_draft_only_count'))}, "
            f"blocked_high={as_status(approval_queue.get('blocked_high_risk_count'))} (review-only, no auto-apply)"
        )
    else:
        lines.append("- Approval Queue: NOT_AVAILABLE (run sentinel_owner_approval_queue.py)")
    if owner_daily.get("present"):
        lines.append(
            f"- Legacy Owner Next Action (superseded): "
            f"{as_status(owner_daily.get('recommended_next_owner_action'))}"
        )
        lines.append(
            "- Autonomy Readiness: "
            f"draft_only={as_status(owner_daily.get('autonomy_ready_draft_only_count'))}, "
            f"not_ready={as_status(owner_daily.get('not_ready_missing_guards_count'))}, "
            f"blocked_high={as_status(owner_daily.get('blocked_high_risk_count'))}"
        )
    else:
        lines.append("- Legacy Owner Next Action (superseded): NOT_AVAILABLE (historical module)")
    if safe_apply_registry.get("present"):
        lines.append(
            "- Safe Apply Registry: "
            f"draft_only={as_status(safe_apply_registry.get('registered_draft_only_count'))}, "
            f"validation_only={as_status(safe_apply_registry.get('registered_validation_only_count'))}, "
            f"missing_guards={as_status(safe_apply_registry.get('not_registered_missing_guards_count'))}, "
            f"blocked={as_status(safe_apply_registry.get('blocked_not_allowed_count'))}"
        )
    else:
        lines.append("- Safe Apply Registry: NOT_AVAILABLE (run sentinel_safe_apply_candidate_registry.py)")
    if safe_apply_guard.get("present"):
        lines.append(
            "- Safe Apply Guards: "
            f"ready_draft={as_status(safe_apply_guard.get('guards_ready_draft_only_count'))}, "
            f"missing={as_status(safe_apply_guard.get('guards_missing_for_autonomy_count'))}, "
            f"blocked={as_status(safe_apply_guard.get('guards_blocked_not_allowed_count'))}, "
            f"breach={as_status(safe_apply_guard.get('guard_breach'))}"
        )
    else:
        lines.append("- Safe Apply Guards: NOT_AVAILABLE (run sentinel_safe_apply_guard_checker.py)")
    if safe_apply_scope.get("present"):
        lines.append(
            "- Safe Apply Scope: "
            f"draft_only={as_status(safe_apply_scope.get('scope_allowed_draft_only_count'))}, "
            f"validation_only={as_status(safe_apply_scope.get('scope_allowed_validation_only_count'))}, "
            f"blocked={as_status(safe_apply_scope.get('scope_blocked_high_risk_count'))}, "
            f"breach={as_status(safe_apply_scope.get('scope_breach'))}"
        )
    else:
        lines.append("- Safe Apply Scope: NOT_AVAILABLE (run sentinel_safe_apply_scope_manager.py)")
    if safe_apply_dry_run.get("present"):
        lines.append(
            "- Safe Apply Dry-Run: "
            f"ready_draft={as_status(safe_apply_dry_run.get('dry_run_ready_draft_only_count'))}, "
            f"ready_validation={as_status(safe_apply_dry_run.get('dry_run_ready_validation_only_count'))}, "
            f"blocked={as_status(safe_apply_dry_run.get('dry_run_blocked_high_risk_count'))}, "
            f"breach={as_status(safe_apply_dry_run.get('dry_run_breach'))}"
        )
    else:
        lines.append("- Safe Apply Dry-Run: NOT_AVAILABLE (run sentinel_safe_apply_dry_run_planner.py)")
    if safe_apply_preflight.get("present"):
        lines.append(
            "- Safe Apply Preflight: "
            f"ready_draft={as_status(safe_apply_preflight.get('preflight_ready_draft_only_count'))}, "
            f"not_ready={as_status(safe_apply_preflight.get('preflight_not_ready_count'))}, "
            f"blocked={as_status(safe_apply_preflight.get('preflight_blocked_count'))}, "
            f"breach={as_status(safe_apply_preflight.get('preflight_breach'))}"
        )
    else:
        lines.append("- Safe Apply Preflight: NOT_AVAILABLE (run sentinel_safe_apply_preflight_validator.py)")
    if autonomy_runtime_lock.get("present"):
        lines.append(
            "- Autonomy Runtime Lock: "
            f"draft_only={as_status(autonomy_runtime_lock.get('draft_only_enabled'))}, "
            f"live_apply={as_status(autonomy_runtime_lock.get('live_apply_enabled'))}, "
            f"emergency_stop={as_status(autonomy_runtime_lock.get('emergency_stop'))}, "
            f"breach={as_status(autonomy_runtime_lock.get('runtime_lock_breach'))}"
        )
    else:
        lines.append("- Autonomy Runtime Lock: NOT_AVAILABLE (run sentinel_autonomy_runtime_lock.py status)")
    if safe_draft_runner.get("present"):
        lines.append(
            "- Safe Draft Autonomy: "
            f"status={as_status(safe_draft_runner.get('runner_status'))}, "
            f"executed_draft={as_status(safe_draft_runner.get('executed_draft_only_count'))}, "
            f"skipped={as_status(safe_draft_runner.get('skipped_count'))}, "
            f"breach={as_status(safe_draft_runner.get('runner_breach'))}"
        )
    else:
        lines.append("- Safe Draft Autonomy: NOT_AVAILABLE (run sentinel_safe_draft_autonomy_runner.py)")
    if safe_draft_verifier.get("present"):
        lines.append(
            "- Draft Autonomy Verifier: "
            f"status={as_status(safe_draft_verifier.get('verifier_status'))}, "
            f"safe_outputs={as_status(safe_draft_verifier.get('verified_safe_outputs_count'))}, "
            f"breach={as_status(safe_draft_verifier.get('verifier_breach'))}"
        )
    else:
        lines.append("- Draft Autonomy Verifier: NOT_AVAILABLE (run sentinel_safe_draft_autonomy_verifier.py)")
    if safe_draft_scheduler.get("present"):
        lines.append(
            "- Legacy Draft Autonomy Scheduler Plan (superseded): "
            f"status={as_status(safe_draft_scheduler.get('scheduler_status'))}, "
            f"timer={as_status(safe_draft_scheduler.get('timer_installation_status'))}, "
            f"breach={as_status(safe_draft_scheduler.get('scheduler_breach'))}"
        )
    else:
        lines.append("- Legacy Draft Autonomy Scheduler Plan (superseded): NOT_AVAILABLE (historical module)")
    if safe_draft_timer.get("present"):
        lines.append(
            "- Legacy Draft Autonomy Timer Draft (superseded): "
            f"status={as_status(safe_draft_timer.get('timer_draft_status'))}, "
            f"installed={as_status(safe_draft_timer.get('timer_installation_status'))}, "
            f"breach={as_status(safe_draft_timer.get('timer_draft_breach'))}"
        )
    else:
        lines.append("- Legacy Draft Autonomy Timer Draft (superseded): NOT_AVAILABLE (historical module)")
    if safe_draft_timer_review.get("present"):
        lines.append(
            "- Timer Install Review: "
            f"status={as_status(safe_draft_timer_review.get('install_review_status'))}, "
            f"can_install={as_status(safe_draft_timer_review.get('can_install_timer_now'))}, "
            f"breach={as_status(safe_draft_timer_review.get('install_reviewer_breach'))}"
        )
    else:
        lines.append("- Timer Install Review: NOT_AVAILABLE (run sentinel_safe_draft_autonomy_timer_install_reviewer.py)")
    if owner_manual_timer_packet.get("present"):
        lines.append(
            "- Manual Timer Install Packet: "
            f"status={as_status(owner_manual_timer_packet.get('packet_status'))}, "
            f"install_allowed={as_status(owner_manual_timer_packet.get('install_allowed_now'))}, "
            f"breach={as_status(owner_manual_timer_packet.get('packet_breach'))}"
        )
    else:
        lines.append("- Manual Timer Install Packet: NOT_AVAILABLE (run sentinel_owner_manual_timer_install_packet.py)")
    if owner_timer_decision.get("present"):
        lines.append(
            "- Timer Install Decision: "
            f"status={as_status(owner_timer_decision.get('decision_status'))}, "
            f"manual_allowed={as_status(owner_timer_decision.get('manual_install_allowed'))}, "
            f"breach={as_status(owner_timer_decision.get('decision_breach'))}"
        )
    else:
        lines.append("- Timer Install Decision: NOT_AVAILABLE (run sentinel_owner_timer_install_decision_gate.py status)")
    if manual_timer_preview.get("present"):
        lines.append(
            "- Manual Timer Command Preview: "
            f"status={as_status(manual_timer_preview.get('preview_status'))}, "
            f"install_allowed={as_status(manual_timer_preview.get('install_allowed_now'))}, "
            f"breach={as_status(manual_timer_preview.get('preview_breach'))}"
        )
    else:
        lines.append("- Manual Timer Command Preview: NOT_AVAILABLE (run sentinel_manual_timer_install_command_preview.py)")
    if owner_timer_evidence.get("present"):
        lines.append(
            "- Timer Install Evidence Pack: "
            f"status={as_status(owner_timer_evidence.get('evidence_pack_status'))}, "
            f"install_allowed={as_status(owner_timer_evidence.get('install_allowed_now'))}, "
            f"breach={as_status(owner_timer_evidence.get('evidence_pack_breach'))}"
        )
    else:
        lines.append("- Timer Install Evidence Pack: NOT_AVAILABLE (run sentinel_owner_timer_install_evidence_pack.py)")
    if final_safety.get("present"):
        lines.append(
            "- Final Safe Draft Autonomy: "
            f"status={as_status(final_safety.get('final_safety_status'))}, "
            f"breaches={as_status(final_safety.get('total_breach_count'))}, "
            f"live_apply={as_status(final_safety.get('live_apply_allowed'))}"
        )
    else:
        lines.append("- Final Safe Draft Autonomy: NOT_AVAILABLE (run sentinel_safe_draft_autonomy_final_safety_report.py)")
    if manual_evidence_dashboard.get("present"):
        lines.append(
            "- Manual Evidence Dashboard: "
            f"status={as_status(manual_evidence_dashboard.get('dashboard_status'))}, "
            f"breaches={as_status(manual_evidence_dashboard.get('total_breaches'))}, "
            f"install_allowed={as_status(manual_evidence_dashboard.get('install_allowed_now'))}"
        )
    else:
        lines.append("- Manual Evidence Dashboard: NOT_AVAILABLE (run sentinel_manual_evidence_review_dashboard.py)")
    if manual_evidence_completion.get("present"):
        lines.append(
            "- Evidence Review Completion: "
            f"status={as_status(manual_evidence_completion.get('tracker_status'))}, "
            f"reviewed={as_status(manual_evidence_completion.get('reviewed_count'))}/"
            f"{as_status(manual_evidence_completion.get('total_items'))}, "
            f"breach={as_status(manual_evidence_completion.get('tracker_breach'))}"
        )
    else:
        lines.append("- Evidence Review Completion: NOT_AVAILABLE (run sentinel_manual_evidence_review_completion_tracker.py list)")
    if manual_evidence_gate.get("present"):
        lines.append(
            "- Evidence Review Gate: "
            f"status={as_status(manual_evidence_gate.get('gate_status'))}, "
            f"reviewed={as_status(manual_evidence_gate.get('reviewed_count'))}/"
            f"{as_status(manual_evidence_gate.get('total_items'))}, "
            f"breach={as_status(manual_evidence_gate.get('gate_breach'))}"
        )
    else:
        lines.append("- Evidence Review Gate: NOT_AVAILABLE (run sentinel_manual_evidence_review_completion_gate.py)")
    if owner_evidence_console.get("present"):
        lines.append(
            "- Owner Review Console: "
            f"status={as_status(owner_evidence_console.get('console_status'))}, "
            f"open={as_status(owner_evidence_console.get('open_items_count'))}, "
            f"breach={as_status(owner_evidence_console.get('console_breach'))}"
        )
    else:
        lines.append("- Owner Review Console: NOT_AVAILABLE (run sentinel_owner_evidence_review_console.py)")
    if final_owner_snapshot.get("present"):
        lines.append(
            "- Final Owner Snapshot: "
            f"status={as_status(final_owner_snapshot.get('snapshot_status'))}, "
            f"review={as_status(final_owner_snapshot.get('reviewed_count'))}/"
            f"{as_status(final_owner_snapshot.get('total_items'))}, "
            f"breach={as_status(final_owner_snapshot.get('snapshot_breach'))}"
        )
    else:
        lines.append("- Final Owner Snapshot: NOT_AVAILABLE (run sentinel_final_owner_decision_snapshot.py)")
    if master_critical_cause.get("present"):
        lines.append(
            "- Master Critical Cause: "
            f"status={as_status(master_critical_cause.get('critical_snapshot_status'))}, "
            f"autonomy_cause={as_status(master_critical_cause.get('critical_caused_by_autonomy'))}, "
            f"breach={as_status(master_critical_cause.get('snapshot_breach'))}"
        )
    else:
        lines.append("- Master Critical Cause: NOT_AVAILABLE (run sentinel_master_critical_cause_snapshot.py)")
    if rolling_window_decay.get("present"):
        lines.append(
            "- Rolling Window Decay: "
            f"status={as_status(rolling_window_decay.get('decay_status'))}, "
            f"trend={as_status(rolling_window_decay.get('trend'))}, "
            f"delta_5xx={as_status(rolling_window_decay.get('delta_5xx'))}, "
            f"breach={as_status(rolling_window_decay.get('snapshot_breach'))}"
        )
    else:
        lines.append("- Rolling Window Decay: NOT_AVAILABLE (run sentinel_rolling_window_decay_observer.py)")
    if low_growth_timeline.get("present"):
        lines.append(
            "- Low Growth Readiness: "
            f"status={as_status(low_growth_timeline.get('timeline_status'))}, "
            f"last_trend={as_status(low_growth_timeline.get('last_trend'))}, "
            f"consecutive_stable_or_decreasing={as_status(low_growth_timeline.get('consecutive_stable_or_decreasing_points'))}, "
            f"breach={as_status(low_growth_timeline.get('snapshot_breach'))}"
        )
    else:
        lines.append("- Low Growth Readiness: NOT_AVAILABLE (run sentinel_low_growth_readiness_timeline.py)")
    if manual_recheck_gate.get("present"):
        lines.append(
            "- Manual Website Recheck Gate: "
            f"status={as_status(manual_recheck_gate.get('gate_status'))}, "
            f"recommended={as_status(manual_recheck_gate.get('manual_recheck_recommended'))}, "
            f"breach={as_status(manual_recheck_gate.get('gate_breach'))}"
        )
    else:
        lines.append("- Manual Website Recheck Gate: NOT_AVAILABLE (run sentinel_manual_website_recheck_gate.py)")
    if low_risk_readiness_gate.get("present"):
        lines.append(
            "- Low-Risk Autonomy Readiness: "
            f"status={as_status(low_risk_readiness_gate.get('readiness_status'))}, "
            f"allowed_now={as_status(low_risk_readiness_gate.get('low_risk_autonomy_allowed_now'))}, "
            f"breach={as_status(low_risk_readiness_gate.get('readiness_breach'))}"
        )
    else:
        lines.append("- Low-Risk Autonomy Readiness: NOT_AVAILABLE (run sentinel_low_risk_autonomy_readiness_gate.py)")
    if low_risk_policy_boundary.get("present"):
        lines.append(
            "- LOW-RISK Policy Boundary: "
            f"status={as_status(low_risk_policy_boundary.get('policy_status'))}, "
            f"owner_review_required={as_status(low_risk_policy_boundary.get('owner_policy_review_required'))}, "
            f"breach={as_status(low_risk_policy_boundary.get('policy_breach'))}"
        )
    else:
        lines.append("- LOW-RISK Policy Boundary: NOT_AVAILABLE (run sentinel_low_risk_policy_boundary_draft.py)")
    if low_risk_owner_review.get("present"):
        lines.append(
            "- LOW-RISK Policy Owner Review: "
            f"status={as_status(low_risk_owner_review.get('tracker_status'))}, "
            f"reviewed={as_status(low_risk_owner_review.get('reviewed_count'))}/"
            f"{as_status(low_risk_owner_review.get('total_required'))}, "
            f"breach={as_status(low_risk_owner_review.get('tracker_breach'))}"
        )
    else:
        lines.append("- LOW-RISK Policy Owner Review: NOT_AVAILABLE (run sentinel_low_risk_policy_owner_review_tracker.py)")
    if low_risk_completion_gate.get("present"):
        lines.append(
            "- Policy Review Completion Gate: "
            f"status={as_status(low_risk_completion_gate.get('gate_status'))}, "
            f"reviewed={as_status(low_risk_completion_gate.get('reviewed_count'))}/"
            f"{as_status(low_risk_completion_gate.get('total_required'))}, "
            f"breach={as_status(low_risk_completion_gate.get('gate_breach'))}"
        )
    else:
        lines.append("- Policy Review Completion Gate: NOT_AVAILABLE (run sentinel_low_risk_policy_review_completion_gate.py)")
    if low_risk_final_seal.get("present"):
        lines.append(
            "- LOW-RISK Final Safety Seal: "
            f"status={as_status(low_risk_final_seal.get('seal_status'))}, "
            f"review_completed={as_status(low_risk_final_seal.get('review_completed'))}, "
            f"breach={as_status(low_risk_final_seal.get('seal_breach'))}"
        )
    else:
        lines.append("- LOW-RISK Final Safety Seal: NOT_AVAILABLE (run sentinel_low_risk_autonomy_final_safety_seal.py)")
    if safe_end.get("present"):
        lines.append(
            "- Safe End Summary: "
            f"status={as_status(safe_end.get('safe_end_status'))}, "
            f"breaches={as_status(safe_end.get('total_breaches'))}, "
            f"breach={as_status(safe_end.get('safe_end_breach'))}"
        )
    else:
        lines.append("- Safe End Summary: NOT_AVAILABLE (run sentinel_safe_end_summary.py)")
    if safe_end_archive.get("present"):
        lines.append(
            "- Safe-End Archive: "
            f"status={as_status(safe_end_archive.get('archive_status'))}, "
            f"copied={as_status(safe_end_archive.get('copied_file_count'))}, "
            f"breach={as_status(safe_end_archive.get('archive_breach'))}"
        )
    else:
        lines.append("- Safe-End Archive: NOT_AVAILABLE (run sentinel_safe_end_archive_snapshot.py)")
    if safe_end_integrity.get("present"):
        lines.append(
            "- Safe-End Archive Integrity: "
            f"status={as_status(safe_end_integrity.get('integrity_status'))}, "
            f"verified={as_status(safe_end_integrity.get('verified_checksum_count'))}, "
            f"mismatch={as_status(safe_end_integrity.get('checksum_mismatch_count'))}, "
            f"breach={as_status(safe_end_integrity.get('integrity_breach'))}"
        )
    else:
        lines.append("- Safe-End Archive Integrity: NOT_AVAILABLE (run sentinel_safe_end_archive_integrity_verifier.py)")
    if concrete_optimizer.get("present"):
        lines.append(
            "- Concrete SEO/Performance Pack: "
            f"status={as_status(concrete_optimizer.get('optimizer_status'))}, "
            f"recommendations={as_status(concrete_optimizer.get('total_recommendations'))}, "
            f"breach={as_status(concrete_optimizer.get('optimizer_breach'))}"
        )
    else:
        lines.append("- Concrete SEO/Performance Pack: NOT_AVAILABLE (run sentinel_concrete_seo_performance_optimizer.py)")
    if safe_sftp_lane.get("present"):
        lines.append(
            "- Safe SFTP SEO Apply: "
            f"status={as_status(safe_sftp_lane.get('apply_lane_status'))}, "
            f"uploaded={as_status(safe_sftp_lane.get('uploaded'))}, "
            f"healthcheck={as_status(safe_sftp_lane.get('healthcheck_status'))}, "
            f"breach={as_status(safe_sftp_lane.get('apply_breach'))}"
        )
    else:
        lines.append("- Safe SFTP SEO Apply: NOT_AVAILABLE (run sentinel_safe_sftp_seo_apply_lane.py dry-run)")

    lines.extend(build_legacy_section(canonical_report))

    lines.extend([
        "",
        "-----",
        "",
        "Recommendations:",
    ])
    if recommendations:
        for recommendation in recommendations[:8]:
            lines.append(f"- {redact_text(recommendation)}")
    else:
        lines.append("- Keine Master-Empfehlungen verfuegbar.")
    return "\n".join(lines)


def excerpt_markdown(markdown: str, max_lines: int = 80) -> str:
    lines = markdown.splitlines()
    if not lines:
        return ""
    selected = lines[:max_lines]
    if len(lines) > max_lines:
        selected.append("")
        selected.append("... Auszug gekuerzt ...")
    return "\n".join(selected)


def build_mail_body(master_md_path: Path, master_json_path: Path, website_md_path: Path) -> str:
    summary = build_summary(master_json_path)
    master_md = redact_text(read_text_or_note(master_md_path, "Sentinel Master Markdown Report"))

    parts = [
        summary,
        "",
        "----- Sentinel Master Markdown Report -----",
        "",
        master_md,
    ]

    if website_md_path.exists():
        website_md = redact_text(read_text_or_note(website_md_path, "Website Sentinel Markdown Report"))
        parts.extend(
            [
                "",
                "----- Website Sentinel Auszug -----",
                "",
                excerpt_markdown(website_md),
            ]
        )
    return "\n".join(parts)


def build_message(config: MailConfig, body: str, subject: Optional[str] = None) -> EmailMessage:
    message = EmailMessage()
    message["From"] = config.mail_from
    message["To"] = ", ".join(config.recipients)
    message["Subject"] = subject or config.subject
    message.set_content(body)
    return message


def send_mail(config: MailConfig, message: EmailMessage) -> None:
    if config.smtp_port is None:
        raise ValueError("SMTP port missing")
    context = ssl.create_default_context()
    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=30) as smtp:
        smtp.ehlo()
        if config.starttls:
            smtp.starttls(context=context)
            smtp.ehlo()
        smtp.login(config.smtp_user, config.smtp_password)
        smtp.send_message(message)


def print_dry_run(config: MailConfig, missing: Iterable[str]) -> None:
    print("Sentinel Daily Mailer Dry Run")
    print(f"Empfaenger: {config.mail_to or '<fehlt>'}")
    print(f"Sender: {config.mail_from or '<fehlt>'}")
    print(f"Host: {config.smtp_host or '<fehlt>'}")
    print(f"Port: {config.smtp_port if config.smtp_port is not None else '<fehlt/ungueltig>'}")
    print(f"STARTTLS: {'ja' if config.starttls else 'nein'}")
    print(f"Passwort vorhanden: {'ja' if bool(config.smtp_password) else 'nein'}")
    print(f"Betreff: {build_subject(config.subject, load_canonical_truth())}")
    missing_list = list(missing)
    if missing_list:
        print("Fehlende Pflichtwerte fuer --send: " + ", ".join(missing_list))
    print("Versand: nein (--dry-run)")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send the Sentinel daily report via SMTP.")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    parser.add_argument("--master-md", type=Path, default=DEFAULT_MASTER_MD)
    parser.add_argument("--master-json", type=Path, default=DEFAULT_MASTER_JSON)
    parser.add_argument("--website-md", type=Path, default=DEFAULT_WEBSITE_MD)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Print non-secret SMTP/report metadata only.")
    mode.add_argument("--send", action="store_true", help="Send the report email.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    config = config_from_env(merged_env(args.env_file))
    missing = config.missing_send_keys()

    if args.dry_run:
        print_dry_run(config, missing)
        return 0

    if missing:
        print(
            "Mailversand abgebrochen: fehlende SMTP/Mail-Konfiguration: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 2

    body = build_mail_body(args.master_md, args.master_json, args.website_md)
    subject = build_subject(config.subject, load_canonical_truth())
    message = build_message(config, body, subject)
    try:
        send_mail(config, message)
    except Exception as exc:  # noqa: BLE001 - keep CLI failure concise and redacted.
        safe_error = redact_known_values(exc, (config.smtp_password, config.smtp_user))
        print(f"Mailversand fehlgeschlagen: {safe_error}", file=sys.stderr)
        return 1

    print(f"Sentinel Daily Mail gesendet an {config.mail_to} via {config.smtp_host}:{config.smtp_port}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
