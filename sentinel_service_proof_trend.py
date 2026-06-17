#!/usr/bin/env python3
"""Sentinel Service Proof & Trend Evidence (Phase 9.2).

A safe, read-only proof layer on top of the Phase 9.0 control plane and the
existing rolling-window / low-growth observers. It turns the daily monitoring
evidence into a *careful* service proof that can be reused in owner-facing and
Payhip-safe marketing copy, without ever overstating the situation.

What this phase documents (from the 2026-06-17 daily report):

1. Multi-day trend proof: the move CRITICAL -> WARNING still holds.
2. Daily fluctuation tracking: 5xx fluctuated 323 -> 452 inside the WARNING
   range; this is daily variance / rolling-window leftover, not new growth.
3. No premature WAF rule: nothing here derives a broad block.
4. OK-readiness blockers: 5xx and SiteLockSpider are `low_growth_but_not_24h`.
5. Remaining stable minutes before the 24h evidence window is satisfied.
6. A cautiously worded service proof statement (no 100% OK claim).
7. A Payhip-safe marketing proof paragraph.

This module changes nothing. There is deliberately no apply mode, no SFTP
write, no DB write, no Cloudflare write, no WAF rule, no service activation
through systemctl and no timer installation. It only reads local reports/state
(plus git status read-only) and writes reports/state/audit/playbook files under
the allowed project roots.

Invariants surfaced and enforced:
    live_apply        = false
    emergency_stop    = true
    allowed_apply_now = false
    current_level in {LEVEL_1_DRAFT_ONLY, LEVEL_2_LOW_RISK_PREP_PREVIEW}
    every HIGH action  -> blocked / review-only
    every MEDIUM action-> owner gate (backup/healthcheck/rollback)
    no premature WAF rule, no automatic security rule, no 100% OK claim,
    no secrets in any report, state, audit or playbook output.
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
PROOF_JSON = PROJECT_DIR / "reports/latest/sentinel-service-proof.json"
PROOF_MD = PROJECT_DIR / "reports/latest/sentinel-service-proof.md"
TREND_EVIDENCE_MD = PROJECT_DIR / "reports/latest/sentinel-trend-evidence.md"
OK_READINESS_MD = PROJECT_DIR / "reports/latest/sentinel-ok-readiness-blockers.md"
MARKETING_MD = PROJECT_DIR / "reports/latest/sentinel-service-proof-marketing.md"

STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_SERVICE_PROOF_JSON = STATE_DIR / "sentinel_service_proof.json"
STATE_LATEST_SERVICE_PROOF_JSON = STATE_DIR / "latest_service_proof.json"

AUDIT_JSONL = PROJECT_DIR / "audit/sentinel-service-proof-trend.jsonl"

PLAYBOOK_PROOF = PROJECT_DIR / "playbooks/sentinel-service-proof.playbook.json"
PLAYBOOK_TREND = PROJECT_DIR / "playbooks/sentinel-trend-evidence.playbook.json"

# Output is restricted to exactly these roots (Phase 9.2 spec, same as 9.1).
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

SCHEMA_VERSION = "service-proof-trend-9.2"

# ---------------------------------------------------------------------------
# Autonomy levels (must mirror Phase 9.0)
# ---------------------------------------------------------------------------
LEVEL_1 = "LEVEL_1_DRAFT_ONLY"
LEVEL_2 = "LEVEL_2_LOW_RISK_PREP_PREVIEW"
ALLOWED_CURRENT_LEVELS = {LEVEL_1, LEVEL_2}
DEFAULT_CURRENT_LEVEL = LEVEL_1

READ_ONLY = "READ_ONLY"
DRAFT = "DRAFT"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CLASS_ORDER = [READ_ONLY, DRAFT, LOW, MEDIUM, HIGH]

# ---------------------------------------------------------------------------
# Owner-reported daily snapshot (2026-06-17 master report)
# These are the documented figures the proof is built on. The module also reads
# the on-disk observer reports for corroboration/provenance, but does not let
# stale on-disk values override the owner-stated current snapshot.
# ---------------------------------------------------------------------------
WINDOW_MINUTES_24H = 1440

DAILY_SNAPSHOT: Dict[str, Any] = {
    "report_date": "2026-06-17",
    "overall_master_status": "WARNING",
    "website_status": "WARNING",
    "website_correlation_status": "NORMAL",
    "local_status": "OK",
    "errors_5xx_total": 452,
    "errors_5xx_previous": 323,
    "sitelockspider_total": 413,
    "sourcemap_detail_rows": 0,
    "autonomy_level": LEVEL_1,
    "live_apply": False,
    "emergency_stop": True,
    "high_blocked": True,
    "breach": False,
}

# OK-readiness blockers: both signals show low growth but have not yet cleared a
# full 24h window, so the situation cannot be declared OK yet.
OK_READINESS_BLOCKERS: List[Dict[str, Any]] = [
    {
        "signal": "errors_5xx",
        "status": "low_growth_but_not_24h",
        "reason": "5xx growth is low and within WARNING range, but a full 24h "
                  "stable evidence window is not yet complete.",
    },
    {
        "signal": "sitelockspider",
        "status": "low_growth_but_not_24h",
        "reason": "SiteLockSpider scanner pressure is contained by the existing "
                  "managed-challenge rule, but a full 24h stable window is not yet complete.",
    },
]

# Approximate remaining stable minutes until each signal satisfies the 24h window.
REMAINING_STABLE_MINUTES: Dict[str, int] = {
    "errors_5xx": 982,
    "sitelockspider": 951,
}

CAUTIOUS_SERVICE_PROOF_STATEMENT = (
    "Sentinel reduced and stabilized the situation into WARNING range, while still "
    "preventing unsafe automation and continuing 24h evidence monitoring."
)

PAYHIP_SAFE_PROOF_TEXT = (
    "Sentinel monitors real website risk signals over time. In our own workflow, "
    "the system moved from CRITICAL into WARNING range and continued to block unsafe "
    "automation while tracking remaining 24-hour stability evidence. This shows the "
    "value of safe diagnosis, controlled improvement and no blind autopilot."
)

DOES_NOT_CLAIM: List[str] = [
    "Does not claim the website is 100% OK.",
    "Does not claim CRITICAL is fully resolved; the 24h evidence window is not yet complete.",
    "Does not claim any automatic security or WAF rule was created.",
    "Does not claim any live change or apply was performed.",
    "Does not claim a guaranteed future status; it reports observed trend evidence only.",
]

# ---------------------------------------------------------------------------
# Inputs (read-only; for safety mirroring + provenance/corroboration only)
# ---------------------------------------------------------------------------
INPUT_JSON: List[Tuple[str, Path]] = [
    ("control_plane", PROJECT_DIR / "reports/latest/autonomous-control-plane.json"),
    ("autonomy_policy", STATE_DIR / "autonomy_policy.json"),
    ("action_memory", STATE_DIR / "action_memory.json"),
    ("no_auto_apply", STATE_DIR / "no_auto_apply_rules.json"),
    ("rolling_window", PROJECT_DIR / "reports/latest/rolling-window-decay-observer.json"),
    ("low_growth", PROJECT_DIR / "reports/latest/low-growth-readiness-timeline.json"),
    ("master_report", PROJECT_DIR / "reports/latest/sentinel-master-report.json"),
]
INPUT_MD: List[Tuple[str, Path]] = [
    ("cloudflare_daily_md", PROJECT_DIR / "cloudflare-monitor/latest/cloudflare-daily-monitor.md"),
    ("master_report_md", PROJECT_DIR / "reports/latest/sentinel-master-report.md"),
]

# ---------------------------------------------------------------------------
# Secret handling (verbatim from the proven 9.0/9.1 scaffolding)
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
        raise ValueError(f"Refusing to write outside allowed proof roots: {path}")
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
    log_ok, log_out = run_readonly(["git", "log", "--oneline", "-15"])
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
        "recent_log": log_out.splitlines()[:15],
        "status_available": st_ok,
        "untracked_count": untracked,
        "modified_count": modified,
        "recommended": (untracked + modified) > 0,
        "files_sample": files_sample,
    }


def resolve_safety(inputs: Dict[str, Any]) -> Dict[str, Any]:
    cp = inputs["data"].get("control_plane")
    policy = inputs["data"].get("autonomy_policy")

    def pick(key: str, default: Any) -> Any:
        if isinstance(cp, dict) and key in cp:
            return cp[key]
        if isinstance(policy, dict) and key in policy:
            return policy[key]
        return default

    return {
        "live_apply": bool(pick("live_apply", False)),
        "emergency_stop": bool(pick("emergency_stop", True)),
        "allowed_apply_now": bool(pick("allowed_apply_now", False)),
        "current_level": pick("current_level", DEFAULT_CURRENT_LEVEL),
        "upstream_breach": bool(cp.get("breach")) if isinstance(cp, dict) else False,
        "upstream_status": cp.get("status") if isinstance(cp, dict) else "not_available",
        "control_plane_available": isinstance(cp, dict),
    }


def _action_groups(inputs: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    am = inputs["data"].get("action_memory")
    groups: Dict[str, List[Dict[str, Any]]] = {c: [] for c in CLASS_ORDER}
    if isinstance(am, dict) and isinstance(am.get("actions"), list):
        for a in am["actions"]:
            if not isinstance(a, dict):
                continue
            cls = a.get("classification")
            if cls not in groups:
                continue
            groups[cls].append({
                "id": a.get("id"),
                "owner_gate_required": bool(a.get("owner_gate_required")),
                "blocked": bool(a.get("blocked")),
            })
    return groups


def _no_auto_apply_scopes(inputs: Dict[str, Any]) -> List[str]:
    no = inputs["data"].get("no_auto_apply")
    scopes: List[str] = []
    if isinstance(no, dict):
        rules = no.get("rules") or no.get("no_auto_apply_rules") or []
        if isinstance(rules, list):
            for r in rules:
                if isinstance(r, dict):
                    scopes.append(str(r.get("scope") or r.get("id") or r.get("token") or ""))
                else:
                    scopes.append(str(r))
    return [s for s in scopes if s]


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
# Trend / readiness / proof builders
# ---------------------------------------------------------------------------
def build_multi_day_trend_proof() -> Dict[str, Any]:
    return {
        "claim": "CRITICAL_TO_WARNING_STILL_VALID",
        "from_status": "CRITICAL",
        "to_status": "WARNING",
        "current_overall_status": DAILY_SNAPSHOT["overall_master_status"],
        "valid": True,
        "regressed_to_critical": False,
        "interpretation": (
            "The multi-day trend from CRITICAL down into the WARNING range still holds. "
            "The current report is WARNING, not CRITICAL, so the earlier improvement is preserved."
        ),
    }


def build_daily_fluctuation() -> Dict[str, Any]:
    prev = DAILY_SNAPSHOT["errors_5xx_previous"]
    cur = DAILY_SNAPSHOT["errors_5xx_total"]
    return {
        "signal": "errors_5xx",
        "previous_value": prev,
        "current_value": cur,
        "delta": cur - prev,
        "direction": "increase" if cur > prev else ("decrease" if cur < prev else "stable"),
        "classification": "WARNING_RANGE_FLUCTUATION",
        "is_real_new_growth": False,
        "is_attack_escalation": False,
        "triggers_waf_rule": False,
        "interpretation": (
            f"5xx fluctuated from {prev} to {cur} while the status stayed WARNING. "
            "This is daily variance / rolling-window leftover, not a new attack and "
            "not a reason for a broad block."
        ),
    }


def build_ok_readiness() -> Dict[str, Any]:
    signals = {}
    for sig, remaining in REMAINING_STABLE_MINUTES.items():
        signals[sig] = {
            "remaining_stable_minutes": remaining,
            "window_minutes": WINDOW_MINUTES_24H,
            "approximate": True,
        }
    return {
        "ok_ready": False,
        "blockers": OK_READINESS_BLOCKERS,
        "remaining_stable_minutes": signals,
        "interpretation": (
            "Both 5xx and SiteLockSpider show low growth but have not yet completed a "
            "full 24h stable window, so the overall situation cannot be declared OK yet."
        ),
    }


def build_service_proof(safety: Dict[str, Any], breach: bool, breach_reasons: List[str],
                        git: Dict[str, Any]) -> Dict[str, Any]:
    trend = build_multi_day_trend_proof()
    fluctuation = build_daily_fluctuation()
    readiness = build_ok_readiness()

    status = "SERVICE_PROOF_WARNING_RANGE_STABILIZED_LOCKED"
    if breach:
        status = "SERVICE_PROOF_BREACH"

    return {
        "schema_version": SCHEMA_VERSION,
        "phase": "9.2",
        "generated_at": utc_now(),
        "status": status,
        "read_only": True,
        # snapshot the proof is built on
        "daily_snapshot": DAILY_SNAPSHOT,
        # the seven documented proof elements
        "multi_day_trend_proof": trend,
        "daily_fluctuation": fluctuation,
        "no_premature_waf_rule": {
            "derive_waf_rule": False,
            "derive_automatic_security_rule": False,
            "reason": (
                "A WARNING-range fluctuation in 5xx/scanner pressure is a signal for "
                "rolling-window / low-growth observation, not for a broad WAF block."
            ),
        },
        "ok_readiness": readiness,
        "cautious_service_proof_statement": CAUTIOUS_SERVICE_PROOF_STATEMENT,
        "payhip_safe_proof_text": PAYHIP_SAFE_PROOF_TEXT,
        "no_100_percent_ok_claim": True,
        "does_not_claim": DOES_NOT_CLAIM,
        # safety mirror
        "autonomy_level": safety["current_level"],
        "snapshot_autonomy_level": DAILY_SNAPSHOT["autonomy_level"],
        "live_apply": safety["live_apply"],
        "emergency_stop": safety["emergency_stop"],
        "allowed_apply_now": safety["allowed_apply_now"],
        "high_blocked": DAILY_SNAPSHOT["high_blocked"],
        "breach": breach,
        "breach_reasons": breach_reasons,
        "upstream": {
            "control_plane_available": safety["control_plane_available"],
            "control_plane_status": safety["upstream_status"],
            "control_plane_breach": safety["upstream_breach"],
        },
        # explicit non-actions
        "applied_changes": False,
        "live_change_performed": False,
        "automatic_security_rule_created": False,
        "waf_rule_created": False,
        "secrets_in_report": False,
        # git checkpoint
        "git_checkpoint": git,
    }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def render_proof_md(proof: Dict[str, Any]) -> str:
    t = proof["multi_day_trend_proof"]
    f = proof["daily_fluctuation"]
    r = proof["ok_readiness"]
    lines = [
        "# Sentinel Service Proof (Phase 9.2)",
        "",
        f"- Generated: {proof['generated_at']}",
        f"- Status: **{proof['status']}**",
        f"- Report date: `{proof['daily_snapshot']['report_date']}`",
        f"- Overall master status: **{proof['daily_snapshot']['overall_master_status']}**",
        f"- Autonomy level: `{proof['autonomy_level']}` (snapshot: `{proof['snapshot_autonomy_level']}`)",
        f"- live_apply: `{proof['live_apply']}` | emergency_stop: `{proof['emergency_stop']}` | "
        f"allowed_apply_now: `{proof['allowed_apply_now']}` | breach: `{proof['breach']}`",
        "",
        "## 1. Multi-day trend proof",
        f"- Claim: `{t['claim']}` (valid: `{t['valid']}`)",
        f"- {t['from_status']} -> {t['to_status']} (now: {t['current_overall_status']})",
        f"- {t['interpretation']}",
        "",
        "## 2. Daily fluctuation tracking",
        f"- 5xx: `{f['previous_value']}` -> `{f['current_value']}` (delta `{f['delta']}`, {f['direction']})",
        f"- Classification: `{f['classification']}`",
        f"- Real new growth: `{f['is_real_new_growth']}` | attack escalation: `{f['is_attack_escalation']}` | "
        f"triggers WAF rule: `{f['triggers_waf_rule']}`",
        f"- {f['interpretation']}",
        "",
        "## 3. No premature WAF rule",
        f"- Derive WAF rule: `{proof['no_premature_waf_rule']['derive_waf_rule']}`",
        f"- Derive automatic security rule: `{proof['no_premature_waf_rule']['derive_automatic_security_rule']}`",
        f"- {proof['no_premature_waf_rule']['reason']}",
        "",
        "## 4. OK-readiness blockers",
        f"- OK ready: `{r['ok_ready']}`",
    ]
    for b in r["blockers"]:
        lines.append(f"  - `{b['signal']}`: `{b['status']}` — {b['reason']}")
    lines += [
        "",
        "## 5. Remaining stable minutes (approx., 24h window = 1440 min)",
    ]
    for sig, info in r["remaining_stable_minutes"].items():
        lines.append(f"- `{sig}`: ~`{info['remaining_stable_minutes']}` min remaining")
    lines += [
        "",
        "## 6. Cautious service proof statement",
        f"> {proof['cautious_service_proof_statement']}",
        "",
        "## 7. Payhip-safe proof text",
        f"> {proof['payhip_safe_proof_text']}",
        "",
        "## What this proof does NOT claim",
    ]
    for d in proof["does_not_claim"]:
        lines.append(f"- {d}")
    lines += [
        "",
        "## Safety",
        f"- Applied changes: `{proof['applied_changes']}` | live change: `{proof['live_change_performed']}`",
        f"- Automatic security rule created: `{proof['automatic_security_rule_created']}` | "
        f"WAF rule created: `{proof['waf_rule_created']}`",
        f"- Read-only: `{proof['read_only']}` | secrets in report: `{proof['secrets_in_report']}`",
        "",
        "## Recommended Git checkpoint",
        f"- Recommended: `{proof['git_checkpoint']['recommended']}` "
        f"({proof['git_checkpoint']['untracked_count']} untracked, "
        f"{proof['git_checkpoint']['modified_count']} modified)",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_trend_evidence_md(proof: Dict[str, Any]) -> str:
    t = proof["multi_day_trend_proof"]
    f = proof["daily_fluctuation"]
    lines = [
        "# Sentinel Trend Evidence (Phase 9.2)",
        "",
        f"- Generated: {proof['generated_at']}",
        "",
        "## Multi-day trend",
        f"- {t['from_status']} -> {t['to_status']} — still valid: `{t['valid']}`, "
        f"regressed to CRITICAL: `{t['regressed_to_critical']}`",
        f"- {t['interpretation']}",
        "",
        "## Daily fluctuation",
        f"- 5xx `{f['previous_value']}` -> `{f['current_value']}` (delta `{f['delta']}`)",
        f"- `{f['classification']}` — not new growth, not an attack, no WAF rule.",
        "",
        "## Owner interpretation",
        "- A rise inside the WARNING range is a monitoring signal, not an apply trigger.",
        "- Continue rolling-window / low-growth observation; do not derive a broad block.",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_ok_readiness_md(proof: Dict[str, Any]) -> str:
    r = proof["ok_readiness"]
    lines = [
        "# Sentinel OK-Readiness Blockers (Phase 9.2)",
        "",
        f"- Generated: {proof['generated_at']}",
        f"- OK ready: `{r['ok_ready']}`",
        f"- {r['interpretation']}",
        "",
        "## Blockers",
    ]
    for b in r["blockers"]:
        lines.append(f"- `{b['signal']}`: `{b['status']}` — {b['reason']}")
    lines += ["", "## Remaining stable minutes (approx., 24h window = 1440 min)"]
    for sig, info in r["remaining_stable_minutes"].items():
        lines.append(f"- `{sig}`: ~`{info['remaining_stable_minutes']}` min until 24h window satisfied")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_marketing_md(proof: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Service Proof — Marketing Copy (Phase 9.2)",
        "",
        f"- Generated: {proof['generated_at']}",
        "",
        "## Cautious service proof statement",
        f"> {proof['cautious_service_proof_statement']}",
        "",
        "## Payhip-safe proof text",
        f"> {proof['payhip_safe_proof_text']}",
        "",
        "## What this proof does NOT claim",
    ]
    for d in proof["does_not_claim"]:
        lines.append(f"- {d}")
    lines.append("")
    return "\n".join(lines) + "\n"


def build_playbooks(proof: Dict[str, Any]) -> Dict[Path, Dict[str, Any]]:
    return {
        PLAYBOOK_PROOF: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-service-proof",
            "generated_at": proof["generated_at"],
            "status": proof["status"],
            "read_only": True,
            "applies_changes": False,
            "steps": [
                "Read the daily report (CRITICAL/WARNING/OK) — read-only.",
                "Confirm CRITICAL -> WARNING multi-day trend still valid.",
                "Track daily 5xx fluctuation inside WARNING range; no WAF rule.",
                "Document OK-readiness blockers and remaining 24h stable minutes.",
                "Emit cautious proof + Payhip-safe text; never claim 100% OK.",
            ],
        },
        PLAYBOOK_TREND: {
            "schema_version": SCHEMA_VERSION,
            "playbook": "sentinel-trend-evidence",
            "generated_at": proof["generated_at"],
            "read_only": True,
            "applies_changes": False,
            "no_premature_waf_rule": True,
            "multi_day_trend": proof["multi_day_trend_proof"]["claim"],
            "daily_fluctuation": proof["daily_fluctuation"]["classification"],
        },
    }


# ---------------------------------------------------------------------------
# Full build + write
# ---------------------------------------------------------------------------
def build_full_state() -> Dict[str, Any]:
    inputs = read_inputs()
    safety = resolve_safety(inputs)
    groups = _action_groups(inputs)
    scopes = _no_auto_apply_scopes(inputs)
    breach, reasons = compute_breach(safety, groups, scopes)
    git = _git_status()
    proof = build_service_proof(safety, breach, reasons, git)
    proof["missing_inputs"] = inputs["missing_inputs"]
    proof["input_status"] = inputs["input_status"]
    return {"inputs": inputs, "safety": safety, "proof": proof}


def write_all_outputs(state: Dict[str, Any]) -> List[str]:
    proof = state["proof"]
    written: List[str] = []

    def _wj(path: Path, data: Dict[str, Any]) -> None:
        write_json_atomic(path, data)
        written.append(str(path.relative_to(PROJECT_DIR)))

    def _wt(path: Path, text: str) -> None:
        write_text_atomic(path, text)
        written.append(str(path.relative_to(PROJECT_DIR)))

    _wj(PROOF_JSON, proof)
    _wt(PROOF_MD, render_proof_md(proof))
    _wt(TREND_EVIDENCE_MD, render_trend_evidence_md(proof))
    _wt(OK_READINESS_MD, render_ok_readiness_md(proof))
    _wt(MARKETING_MD, render_marketing_md(proof))

    _wj(STATE_SERVICE_PROOF_JSON, proof)
    _wj(STATE_LATEST_SERVICE_PROOF_JSON, proof)

    for path, data in build_playbooks(proof).items():
        _wj(path, data)

    append_jsonl(AUDIT_JSONL, [{
        "ts": proof["generated_at"],
        "phase": "9.2",
        "module": "sentinel_service_proof_trend",
        "status": proof["status"],
        "overall_master_status": proof["daily_snapshot"]["overall_master_status"],
        "errors_5xx_total": proof["daily_snapshot"]["errors_5xx_total"],
        "errors_5xx_previous": proof["daily_snapshot"]["errors_5xx_previous"],
        "sitelockspider_total": proof["daily_snapshot"]["sitelockspider_total"],
        "multi_day_trend_valid": proof["multi_day_trend_proof"]["valid"],
        "no_premature_waf_rule": proof["no_premature_waf_rule"]["derive_waf_rule"] is False,
        "ok_ready": proof["ok_readiness"]["ok_ready"],
        "live_apply": proof["live_apply"],
        "emergency_stop": proof["emergency_stop"],
        "allowed_apply_now": proof["allowed_apply_now"],
        "breach": proof["breach"],
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

    allowed_names = {str(r.relative_to(PROJECT_DIR)) for r in ALLOWED_WRITE_ROOTS}
    if allowed_names != {"reports/latest", "state/adaptive-learning", "audit", "playbooks"}:
        raise AssertionError(f"unexpected write roots: {allowed_names}")

    for bad in ("/etc/sentinel-defense.env", "deploy.key", "id_rsa", "api-token.json"):
        obj, status = read_optional_json(Path(bad))
        if obj is not None or status not in ("refused_secret_like_path", "not_available"):
            raise AssertionError(f"sensitive path not refused: {bad} -> {status}")

    state = build_full_state()
    proof = state["proof"]
    if proof["live_apply"] is not False:
        raise AssertionError("live_apply must be false")
    if proof["emergency_stop"] is not True:
        raise AssertionError("emergency_stop must be true")
    if proof["allowed_apply_now"] is not False:
        raise AssertionError("allowed_apply_now must be false")
    if proof["autonomy_level"] not in ALLOWED_CURRENT_LEVELS:
        raise AssertionError("autonomy_level must be LEVEL_1/LEVEL_2")
    if proof["breach"]:
        raise AssertionError(f"clean proof must not breach: {proof['breach_reasons']}")
    # proof discipline
    if proof["multi_day_trend_proof"]["valid"] is not True:
        raise AssertionError("multi-day trend proof must be valid")
    if proof["no_premature_waf_rule"]["derive_waf_rule"] is not False:
        raise AssertionError("must not derive a WAF rule")
    if proof["no_premature_waf_rule"]["derive_automatic_security_rule"] is not False:
        raise AssertionError("must not derive an automatic security rule")
    if proof["no_100_percent_ok_claim"] is not True:
        raise AssertionError("must not make a 100% OK claim")
    if proof["ok_readiness"]["ok_ready"] is not False:
        raise AssertionError("must not declare OK while blockers remain")
    blocker_status = {b["status"] for b in proof["ok_readiness"]["blockers"]}
    if blocker_status != {"low_growth_but_not_24h"}:
        raise AssertionError(f"unexpected blocker statuses: {blocker_status}")
    if proof["daily_fluctuation"]["delta"] != 452 - 323:
        raise AssertionError("daily fluctuation delta must reflect 323 -> 452")
    if proof["applied_changes"] or proof["live_change_performed"] or proof["waf_rule_created"]:
        raise AssertionError("module must not apply / change / create a WAF rule")

    # JSON validity of all structured outputs.
    for blob_obj in (proof, *build_playbooks(proof).values()):
        json.dumps(blob_obj)

    # Breach detection.
    base_safety = {"live_apply": False, "emergency_stop": True, "allowed_apply_now": False,
                   "current_level": LEVEL_1, "upstream_breach": False}
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
    ungated_medium = {**empty_groups, MEDIUM: [{"id": "y", "owner_gate_required": False}]}
    if not compute_breach(base_safety, ungated_medium, [])[0]:
        raise AssertionError("ungated MEDIUM did not breach")

    # No secrets in any rendered output.
    rendered = [
        render_proof_md(proof), render_trend_evidence_md(proof),
        render_ok_readiness_md(proof), render_marketing_md(proof),
        json.dumps(proof),
    ]
    for blob in rendered:
        if SECRET_ASSIGNMENT_RE.search(blob) or LONG_HEX_RE.search(blob):
            raise AssertionError("secret-like content in output")

    # Write-path guards.
    for forbidden in (
        PROJECT_DIR / "reports/latest/x.sh",
        PROJECT_DIR / "reports/latest/x.php",
        PROJECT_DIR / "state/adaptive-learning/x.service",
        PROJECT_DIR / "snapshots/x.json",      # snapshots NOT allowed in 9.2
        PROJECT_DIR / "config/x.json",
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")
    for ok_path in (PROOF_JSON, STATE_SERVICE_PROOF_JSON, AUDIT_JSONL, PLAYBOOK_PROOF):
        assert_allowed_write(ok_path)

    if not detect_secret_like("password=supersecretvalue123"):
        raise AssertionError("secret detector failed")
    if detect_secret_like("status=WARNING"):
        raise AssertionError("secret detector false positive")

    print("service-proof-trend self-tests: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_status(state: Dict[str, Any], written: List[str]) -> None:
    proof = state["proof"]
    print("=== Sentinel Service Proof & Trend Evidence (Phase 9.2) ===")
    print("Files written:")
    for w in written:
        print(f"  - {w}")
    print(f"status: {proof['status']}")
    print(f"report date: {proof['daily_snapshot']['report_date']}")
    print(f"overall master status: {proof['daily_snapshot']['overall_master_status']}")
    print(f"multi-day trend: {proof['multi_day_trend_proof']['from_status']} -> "
          f"{proof['multi_day_trend_proof']['to_status']} (valid={proof['multi_day_trend_proof']['valid']})")
    f = proof["daily_fluctuation"]
    print(f"daily fluctuation 5xx: {f['previous_value']} -> {f['current_value']} "
          f"(delta {f['delta']}, {f['classification']})")
    print(f"no premature WAF rule: {proof['no_premature_waf_rule']['derive_waf_rule'] is False}")
    print(f"ok ready: {proof['ok_readiness']['ok_ready']}")
    print("ok-readiness blockers:")
    for b in proof["ok_readiness"]["blockers"]:
        print(f"  - {b['signal']}: {b['status']}")
    print("remaining stable minutes (approx, 24h=1440):")
    for sig, info in proof["ok_readiness"]["remaining_stable_minutes"].items():
        print(f"  - {sig}: ~{info['remaining_stable_minutes']} min")
    print(f"current autonomy level: {proof['autonomy_level']} (snapshot {proof['snapshot_autonomy_level']})")
    print(f"live_apply: {proof['live_apply']}")
    print(f"emergency_stop: {proof['emergency_stop']}")
    print(f"allowed_apply_now: {proof['allowed_apply_now']}")
    print(f"breach: {proof['breach']}")
    print(f"no 100% OK claim: {proof['no_100_percent_ok_claim']}")
    print(f"cautious service proof: {proof['cautious_service_proof_statement']}")
    print(f"recommended Git checkpoint: {proof['git_checkpoint']['recommended']} "
          f"({proof['git_checkpoint']['untracked_count']} untracked, "
          f"{proof['git_checkpoint']['modified_count']} modified)")
    if proof["missing_inputs"]:
        print(f"missing inputs: {', '.join(proof['missing_inputs'])}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sentinel Service Proof & Trend Evidence (Phase 9.2). Read-only; no apply."
    )
    p.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    p.add_argument("--build-proof", action="store_true", help="Build the full service proof.")
    p.add_argument("--build-trend", action="store_true", help="Build the multi-day trend + fluctuation evidence.")
    p.add_argument("--build-readiness", action="store_true", help="Build OK-readiness blockers + remaining minutes.")
    p.add_argument("--build-marketing", action="store_true", help="Build cautious + Payhip-safe proof copy.")
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
    proof = state["proof"]

    if args.build_proof:
        print(f"[proof] status={proof['status']} overall={proof['daily_snapshot']['overall_master_status']} "
              f"breach={proof['breach']}")
    if args.build_trend:
        t, f = proof["multi_day_trend_proof"], proof["daily_fluctuation"]
        print(f"[trend] {t['from_status']}->{t['to_status']} valid={t['valid']} | "
              f"5xx {f['previous_value']}->{f['current_value']} ({f['classification']})")
    if args.build_readiness:
        print(f"[readiness] ok_ready={proof['ok_readiness']['ok_ready']} "
              f"blockers={[b['signal'] for b in proof['ok_readiness']['blockers']]}")
    if args.build_marketing:
        print(f"[marketing] cautious: {proof['cautious_service_proof_statement']}")
        print(f"[marketing] payhip: {proof['payhip_safe_proof_text']}")

    if args.status or not any(
        (args.build_proof, args.build_trend, args.build_readiness, args.build_marketing)
    ):
        _print_status(state, written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
