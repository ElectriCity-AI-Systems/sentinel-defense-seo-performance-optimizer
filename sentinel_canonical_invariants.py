#!/usr/bin/env python3
"""Sentinel canonical invariant validator — Phase 10.21.

Validates that no report presents two contradictory operational truths. The
canonical truth snapshot (`sentinel_canonical_truth.py`) is the reference; the
master report, the production pipeline report, the consistency evaluation and the
rendered daily summary text are the observed sides.

Checked invariants (Phase 10.21 section 23):
  * runtime        — header/master/pipeline runtime level must equal canonical
  * emergency stop — a header may not claim emergency_stop=true while the runtime says false
  * timer          — a header may not claim timer=not_installed while systemd timer is active
  * NowPlaying     — a header may not report 504=0 while current evidence reports >0
  * SourceMap      — a stale .map warning may not survive as current status when map_404=0
  * owner priority — SEO may not lead while the website is WARNING/CRITICAL with a higher cause
  * overall status — the master report may escalate, never understate, canonical status
  * breach         — breach flags must be identical everywhere

Read-only. No Cloudflare/WAF/DNS/TLS write, no systemd or timer change, no
LOW/MEDIUM/HIGH activation, no WordPress/database/nginx write, no credential
output, no cookie or Authorization header storage.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sentinel_canonical_truth as truth


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-canonical-invariants-10.21"

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"

CANONICAL_JSON = REPORT_DIR / "sentinel-canonical-truth.json"
MASTER_JSON = REPORT_DIR / "sentinel-master-report.json"
MASTER_MD = REPORT_DIR / "sentinel-master-report.md"
PIPELINE_JSON = REPORT_DIR / "sentinel-production-pipeline.json"
PIPELINE_MD = REPORT_DIR / "sentinel-production-pipeline.md"
CONSISTENCY_JSON = REPORT_DIR / "sentinel-master-consistency.json"
DAILY_HEADER_MD = REPORT_DIR / "sentinel-canonical-daily-header.md"

REPORT_JSON = REPORT_DIR / "sentinel-canonical-invariants.json"
REPORT_MD = REPORT_DIR / "sentinel-canonical-invariants.md"
DAILY_CONSISTENCY_JSON = REPORT_DIR / "sentinel-daily-summary-consistency.json"
DAILY_CONSISTENCY_MD = REPORT_DIR / "sentinel-daily-summary-consistency.md"

STATE_JSON = STATE_DIR / "canonical_invariants.json"
HISTORY_JSON = STATE_DIR / "canonical_invariants_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-canonical-invariants.jsonl"

PLAYBOOKS = (PLAYBOOK_DIR / "sentinel-daily-summary-consistency.playbook.json",)

OK = "OK"
VIOLATION = "VIOLATION"
NOT_EVALUATED = "NOT_EVALUATED"

UNKNOWN = truth.UNKNOWN

# Executive rows of the master report that assert current operational truth.
CURRENT_TRUTH_ROWS = {
    "Canonical Runtime Level": "autonomy_level",
    "Canonical Runtime Stage": "runtime_stage",
    "Canonical Monitoring Enabled": "monitoring_enabled",
    "Canonical systemd Timer Active": "timer_active",
    "Canonical Scheduler Status": "scheduler_status",
    "Canonical LOW_LIVE Enabled": "low_live_enabled",
    "Canonical Production Apply Lock": "production_apply_lock",
    "Canonical Emergency Stop": "emergency_stop",
    "Canonical Breach": "breach",
    "Canonical Write Canary": "write_canary_status",
    "Canonical Promotion": "promotion_status",
    "Canonical Owner Priority": "owner_priority",
    "Canonical Recovery Evidence Window": "recovery_evidence_window_status",
    "Canonical Website Snapshot": "current_snapshot_id",
    "Canonical Recovery Snapshot": "recovery_snapshot_id",
    "Canonical Monitoring Decision": "autonomous_monitoring_decision",
    "Canonical Primary Failure Focus": "primary_failure_focus",
    "Canonical Dominant 504 Endpoint": "dominant_504_endpoint",
    "Canonical Dominant 504 Share Percent": "dominant_504_share_percent",
    "Canonical Total 5xx (24h)": "total_5xx",
    "Canonical NowPlaying 504 (24h)": "nowplaying_504",
    "Canonical SourceMap 404 (24h)": "source_map_404",
    "Canonical SourceMap Status": "source_map_status",
    "Canonical Rolling Window": "rolling_window_status",
    "Website Status": "website_status",
    "Website Correlation Status": "website_correlation_status",
}

LEGACY_ROW_MARKERS = ("legacy", "superseded", "historical", "historisch")

SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|bearer|authorization|cookie|"
    r"private[_-]?key)\s*[:=]\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")

EXECUTION_BOUNDARIES = dict(truth.EXECUTION_BOUNDARIES)

REPORT_CLASSIFICATION = list(truth.REPORT_CLASSIFICATION)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR.resolve()))
    except (OSError, ValueError):
        return str(path)


def is_within_project(path: Path) -> bool:
    try:
        path.resolve().relative_to(PROJECT_DIR.resolve())
        return True
    except (OSError, ValueError):
        return False


def write_text(path: Path, text: str) -> None:
    if not is_within_project(path):
        raise RuntimeError(f"write outside project blocked: {path}")
    if SECRET_RE.search(text) or PRIVATE_KEY_RE.search(text):
        raise RuntimeError(f"secret-like content blocked: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text)


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    if not is_within_project(path):
        raise RuntimeError(f"audit path outside project blocked: {path}")
    line = json.dumps(row, sort_keys=True)
    if SECRET_RE.search(line) or PRIVATE_KEY_RE.search(line):
        raise RuntimeError("secret-like audit content blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = truth.read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def canonical_value(canonical: Dict[str, Any], field: str) -> Any:
    block = canonical.get(field)
    if not isinstance(block, dict) or block.get("resolution") != "RESOLVED":
        return None
    return block.get("value")


def normalize(value: Any) -> Optional[str]:
    """Compare report text and JSON values on a common footing."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip().strip("`").strip()
    if text.lower() in {"", "-", "none", "null", "n/a", UNKNOWN.lower()}:
        return None
    if text.lower() in {"true", "false"}:
        return text.lower()
    return text


def finding(
    invariant: str,
    verdict: str,
    detail: str,
    observed: Any = None,
    canonical: Any = None,
    location: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "invariant": invariant,
        "verdict": verdict,
        "detail": detail,
        "observed": observed,
        "canonical": canonical,
        "location": location,
    }


# --------------------------------------------------------------------------- #
# Master markdown executive table
# --------------------------------------------------------------------------- #

def executive_table_rows(master_md: str) -> Dict[str, str]:
    """Parse the executive `Master-Bewertung` table into label -> value."""
    rows: Dict[str, str] = {}
    inside = False
    for line in master_md.splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            if inside:
                break
            inside = "Master-Bewertung" in stripped
            continue
        if not inside or not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) != 2 or cells[0] in {"Signal", "---"} or set(cells[0]) <= {"-"}:
            continue
        rows[cells[0]] = cells[1]
    return rows


def is_legacy_label(label: str) -> bool:
    lowered = label.lower()
    return any(marker in lowered for marker in LEGACY_ROW_MARKERS)


# --------------------------------------------------------------------------- #
# Invariants
# --------------------------------------------------------------------------- #

def check_runtime_invariant(
    canonical: Dict[str, Any],
    observed: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Header runtime == master runtime == pipeline runtime == canonical."""
    findings: List[Dict[str, Any]] = []
    expected = normalize(canonical_value(canonical, "autonomy_level"))
    if expected is None:
        return [finding(
            "runtime",
            NOT_EVALUATED,
            "Canonical autonomy level is unresolved; runtime invariant cannot be evaluated.",
        )]
    for location, values in observed.items():
        seen = normalize(values.get("autonomy_level"))
        if seen is None:
            findings.append(finding(
                "runtime", NOT_EVALUATED,
                f"{location} does not expose a runtime level.", None, expected, location,
            ))
            continue
        if seen != expected:
            findings.append(finding(
                "runtime", VIOLATION,
                f"{location} reports runtime level {seen} while canonical runtime is {expected}.",
                seen, expected, location,
            ))
        else:
            findings.append(finding(
                "runtime", OK, f"{location} runtime level matches canonical.", seen, expected, location,
            ))
    return findings


def check_flag_invariant(
    name: str,
    field: str,
    canonical: Dict[str, Any],
    observed: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    expected = normalize(canonical_value(canonical, field))
    if expected is None:
        return [finding(name, NOT_EVALUATED, f"Canonical {field} is unresolved.")]
    for location, values in observed.items():
        seen = normalize(values.get(field))
        if seen is None:
            continue
        if seen != expected:
            findings.append(finding(
                name, VIOLATION,
                f"{location} reports {field}={seen} while the current runtime reports {expected}.",
                seen, expected, location,
            ))
        else:
            findings.append(finding(
                name, OK, f"{location} {field} matches canonical.", seen, expected, location,
            ))
    return findings


def check_nowplaying_invariant(
    canonical: Dict[str, Any],
    observed: Dict[str, Dict[str, Any]],
    master: Dict[str, Any],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    current = canonical_value(canonical, "nowplaying_504")
    if current is None:
        return [finding("nowplaying", NOT_EVALUATED, "Canonical NowPlaying 504 count is unresolved.")]
    for location, values in observed.items():
        seen = values.get("nowplaying_504")
        if seen is None:
            continue
        try:
            seen_int = int(seen)
        except (TypeError, ValueError):
            continue
        if seen_int != int(current):
            findings.append(finding(
                "nowplaying", VIOLATION,
                f"{location} reports NowPlaying 504={seen_int} while current website evidence "
                f"reports {int(current)}.",
                seen_int, int(current), location,
            ))
        else:
            findings.append(finding(
                "nowplaying", OK, f"{location} NowPlaying 504 matches current evidence.",
                seen_int, int(current), location,
            ))
    legacy = master.get("ai_radio_timeout_diagnosis")
    if isinstance(legacy, dict) and legacy.get("nowplaying_504") is not None:
        legacy_value = legacy.get("nowplaying_504")
        if int(current) > 0 and int(legacy_value or 0) != int(current):
            findings.append(finding(
                "nowplaying", OK,
                "Legacy AI-Radio NowPlaying count differs from current evidence and must stay "
                "informational only.",
                legacy_value, int(current), "master.ai_radio_timeout_diagnosis",
            ))
    return findings


def check_recovery_window_invariant(
    canonical: Dict[str, Any],
    observed: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Canonical, master and pipeline must carry one recovery snapshot truth."""
    findings: List[Dict[str, Any]] = []
    expected_window = canonical_value(canonical, "recovery_evidence_window_status")
    website_snapshot = canonical_value(canonical, "current_snapshot_id")
    recovery_snapshot = canonical_value(canonical, "recovery_snapshot_id")
    if expected_window != "EVIDENCE_WINDOW_ALIGNED":
        findings.append(finding(
            "recovery_window", VIOLATION,
            "Canonical recovery evidence window is not aligned; current recovery truth is blocked.",
            expected_window, "EVIDENCE_WINDOW_ALIGNED", "canonical",
        ))
    if not website_snapshot or not recovery_snapshot:
        findings.append(finding(
            "recovery_window", VIOLATION,
            "Canonical website or recovery snapshot identity is missing.",
            recovery_snapshot, website_snapshot, "canonical",
        ))
    elif website_snapshot != recovery_snapshot:
        findings.append(finding(
            "recovery_window", VIOLATION,
            "Canonical website and recovery snapshots are mixed.",
            recovery_snapshot, website_snapshot, "canonical",
        ))

    fields = (
        "recovery_evidence_window_status",
        "current_snapshot_id",
        "recovery_snapshot_id",
        "autonomous_monitoring_decision",
        "dominant_504_endpoint",
        "dominant_504_share_percent",
        "primary_failure_focus",
        "nowplaying_classification",
    )
    for location in ("master", "pipeline"):
        values = observed.get(location, {})
        for field in fields:
            expected = normalize(canonical_value(canonical, field))
            seen = normalize(values.get(field))
            if expected is None:
                findings.append(finding(
                    "recovery_window", NOT_EVALUATED,
                    f"Canonical {field} is unresolved.", None, None, "canonical",
                ))
            elif seen is None:
                findings.append(finding(
                    "recovery_window", VIOLATION,
                    f"{location} does not expose current recovery field {field}.",
                    None, expected, location,
                ))
            elif seen != expected:
                findings.append(finding(
                    "recovery_window", VIOLATION,
                    f"{location} reports {field}={seen} while canonical reports {expected}.",
                    seen, expected, location,
                ))
            else:
                findings.append(finding(
                    "recovery_window", OK,
                    f"{location} {field} matches canonical.", seen, expected, location,
                ))
    return findings


def check_sourcemap_invariant(
    canonical: Dict[str, Any],
    observed: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    map_404 = canonical_value(canonical, "source_map_404")
    canonical_status = normalize(canonical_value(canonical, "source_map_status"))
    if map_404 is None or canonical_status is None:
        return [finding("sourcemap", NOT_EVALUATED, "Canonical .map evidence is unresolved.")]
    for location, values in observed.items():
        seen_status = normalize(values.get("source_map_status"))
        seen_count = values.get("source_map_404")
        if seen_count is not None:
            try:
                if int(seen_count) != int(map_404):
                    findings.append(finding(
                        "sourcemap", VIOLATION,
                        f"{location} reports .map 404={int(seen_count)} while current evidence "
                        f"reports {int(map_404)}.",
                        int(seen_count), int(map_404), location,
                    ))
            except (TypeError, ValueError):
                pass
        if seen_status is None:
            continue
        if seen_status.upper() != canonical_status.upper():
            findings.append(finding(
                "sourcemap", VIOLATION,
                f"{location} presents SourceMap status {seen_status} as current while current "
                f"evidence yields {canonical_status} (.map 404={int(map_404)}).",
                seen_status, canonical_status, location,
            ))
        else:
            findings.append(finding(
                "sourcemap", OK, f"{location} SourceMap status matches current evidence.",
                seen_status, canonical_status, location,
            ))
    return findings


def check_owner_priority_invariant(
    canonical: Dict[str, Any],
    observed: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    expected = normalize(canonical_value(canonical, "owner_priority"))
    website_status = normalize(canonical_value(canonical, "website_status"))
    if expected is None:
        return [finding("owner_priority", NOT_EVALUATED, "Canonical owner priority is unresolved.")]
    priority_block = canonical.get("owner_priority") if isinstance(canonical.get("owner_priority"), dict) else {}
    seo_allowed = bool(priority_block.get("legacy_seo_checklist_allowed"))
    for location, values in observed.items():
        seen = normalize(values.get("owner_priority"))
        if seen is None:
            continue
        if seen != expected:
            findings.append(finding(
                "owner_priority", VIOLATION,
                f"{location} reports owner priority {seen} while the canonical priority is {expected}.",
                seen, expected, location,
            ))
            continue
        findings.append(finding(
            "owner_priority", OK, f"{location} owner priority matches canonical.",
            seen, expected, location,
        ))
    if not seo_allowed and website_status in {"WARNING", "CRITICAL"} and "SEO" in expected.upper():
        findings.append(finding(
            "owner_priority", VIOLATION,
            f"Canonical priority is SEO-led while the website status is {website_status}.",
            expected, "non-SEO priority", "canonical",
        ))
    return findings


def check_overall_status_invariant(
    canonical: Dict[str, Any],
    master: Dict[str, Any],
) -> List[Dict[str, Any]]:
    expected = normalize(canonical_value(canonical, "overall_status"))
    seen = normalize(master.get("overall_master_status"))
    if expected is None or seen is None:
        return [finding("overall_status", NOT_EVALUATED, "Overall status is not comparable.")]
    rank = truth.STATUS_RANK
    if seen == expected:
        return [finding("overall_status", OK, "Master overall status matches canonical.", seen, expected, "master")]
    if seen in rank and expected in rank and rank[seen] > rank[expected]:
        return [finding(
            "overall_status", OK,
            "Master overall status escalates canonical status through current sub-module findings; "
            "escalation is allowed, understating is not.",
            seen, expected, "master",
        )]
    return [finding(
        "overall_status", VIOLATION,
        f"Master overall status {seen} understates the canonical status {expected}.",
        seen, expected, "master",
    )]


def check_executive_table(
    canonical: Dict[str, Any],
    master_md: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Every current-truth row of the executive table must equal canonical."""
    findings: List[Dict[str, Any]] = []
    rows = executive_table_rows(master_md)
    if not rows:
        return [finding(
            "executive_table", NOT_EVALUATED, "Master report markdown has no executive table.",
        )], rows

    for label, field in CURRENT_TRUTH_ROWS.items():
        if label not in rows:
            continue
        expected = normalize(canonical_value(canonical, field))
        seen = normalize(rows[label])
        if expected is None:
            findings.append(finding(
                "executive_table", NOT_EVALUATED,
                f"Row {label} cannot be compared; canonical {field} is unresolved.",
                seen, None, "master.md",
            ))
            continue
        if seen != expected and (seen or "").upper() != expected.upper():
            findings.append(finding(
                "executive_table", VIOLATION,
                f"Executive row {label} shows {seen} while canonical {field} is {expected}.",
                seen, expected, "master.md",
            ))
        else:
            findings.append(finding(
                "executive_table", OK, f"Executive row {label} matches canonical {field}.",
                seen, expected, "master.md",
            ))

    # Legacy values may appear, but only under an explicitly legacy label.
    legacy_tokens = legacy_token_map(canonical)
    for label, value in rows.items():
        if is_legacy_label(label):
            continue
        normalized = (normalize(value) or "").upper()
        for token, reason in legacy_tokens.items():
            if normalized == token.upper():
                findings.append(finding(
                    "executive_table", VIOLATION,
                    f"Executive row {label} presents the legacy value {value} as current truth: {reason}",
                    value, reason, "master.md",
                ))
    return findings, rows


def legacy_token_map(canonical: Dict[str, Any]) -> Dict[str, str]:
    """Values that must not appear unlabelled once canonical says otherwise."""
    tokens: Dict[str, str] = {}
    autonomy = normalize(canonical_value(canonical, "autonomy_level"))
    if autonomy and autonomy != "LEVEL_1_DRAFT_ONLY":
        tokens["LEVEL_1_DRAFT_ONLY"] = f"canonical runtime level is {autonomy}"
    if canonical_value(canonical, "timer_active") is True:
        tokens["not_installed"] = "canonical systemd timer is active"
    classification = normalize(canonical_value(canonical, "nowplaying_classification"))
    if classification and classification != "NOWPLAYING_ROUTE_MISMATCH":
        tokens["NOWPLAYING_ROUTE_MISMATCH"] = (
            f"canonical Phase-10.22 recovery classification is {classification}"
        )
    return tokens


def current_truth_text(text: str) -> str:
    """Strip explicitly labelled legacy regions before scanning for stale claims.

    A legacy value inside a `Legacy / Historical Modules` block, or on a line that
    names itself legacy/superseded, is documentation — not a current-truth claim.
    """
    kept: List[str] = []
    in_legacy_block = False
    for line in text.splitlines():
        lowered = line.lower()
        is_heading = line.lstrip().startswith("#")
        has_marker = any(marker in lowered for marker in LEGACY_ROW_MARKERS)
        # Plain-text reports title the block without a markdown heading.
        if lowered.strip().strip("#").strip() in {
            "legacy / historical modules", "legacy/historical modules"
        }:
            in_legacy_block = True
            continue
        if is_heading:
            # A legacy-marked heading opens a legacy region; any other heading closes it.
            in_legacy_block = has_marker
            continue
        if in_legacy_block or has_marker:
            continue
        kept.append(line)
    return "\n".join(kept)


def check_forbidden_header_text(
    canonical: Dict[str, Any],
    header_text: str,
    location: str,
) -> List[Dict[str, Any]]:
    """The canonical daily header must not carry superseded operational claims."""
    findings: List[Dict[str, Any]] = []
    if not header_text.strip():
        return [finding("daily_header", NOT_EVALUATED, f"{location} is empty or missing.")]
    header_text = current_truth_text(header_text)
    for token, reason in legacy_token_map(canonical).items():
        if re.search(rf"(?<![\w-]){re.escape(token)}(?![\w-])", header_text):
            findings.append(finding(
                "daily_header", VIOLATION,
                f"{location} contains the superseded value {token}: {reason}.",
                token, reason, location,
            ))
    nowplaying = canonical_value(canonical, "nowplaying_504")
    if isinstance(nowplaying, int) and nowplaying > 0:
        if re.search(r"NowPlaying 504[^\n]*?:\s*0(?!\d)", header_text):
            findings.append(finding(
                "daily_header", VIOLATION,
                f"{location} reports NowPlaying 504 as 0 while current evidence reports {nowplaying}.",
                0, nowplaying, location,
            ))
    current_share = canonical_value(canonical, "dominant_504_share_percent")
    if current_share is not None and normalize(current_share) != "59.2":
        if re.search(r"Dominant 504 endpoint[^\n]*\(59\.2%", header_text, re.IGNORECASE):
            findings.append(finding(
                "daily_header", VIOLATION,
                f"{location} presents legacy dominant share 59.2% while current canonical share is {current_share}%.",
                59.2, current_share, location,
            ))
    if not findings:
        findings.append(finding(
            "daily_header", OK, f"{location} carries no superseded operational claim.",
            None, None, location,
        ))
    return findings


# --------------------------------------------------------------------------- #
# Observation collection
# --------------------------------------------------------------------------- #

def observed_from_master(master: Dict[str, Any]) -> Dict[str, Any]:
    """Read the master report's canonical header block, not its legacy modules."""
    header = master.get("canonical_header")
    if not isinstance(header, dict):
        return {}
    return {
        "autonomy_level": header.get("autonomy_level"),
        "runtime_stage": header.get("runtime_stage"),
        "monitoring_enabled": header.get("monitoring_enabled"),
        "timer_active": header.get("timer_active"),
        "scheduler_status": header.get("scheduler_status"),
        "low_live_enabled": header.get("low_live_enabled"),
        "production_apply_lock": header.get("production_apply_lock"),
        "emergency_stop": header.get("emergency_stop"),
        "breach": header.get("breach"),
        "owner_priority": header.get("owner_priority"),
        "nowplaying_504": header.get("nowplaying_504"),
        "source_map_404": header.get("source_map_404"),
        "source_map_status": header.get("source_map_status"),
        "website_status": header.get("website_status"),
        "total_5xx": header.get("total_5xx"),
        "current_snapshot_id": header.get("current_snapshot_id"),
        "recovery_evidence_window_status": header.get("recovery_evidence_window_status"),
        "recovery_snapshot_id": header.get("recovery_snapshot_id"),
        "autonomous_monitoring_decision": header.get("autonomous_monitoring_decision"),
        "dominant_504_endpoint": header.get("dominant_504_endpoint"),
        "dominant_504_share_percent": header.get("dominant_504_share_percent"),
        "primary_failure_focus": header.get("primary_failure_focus"),
        "nowplaying_classification": header.get("nowplaying_classification"),
    }


def observed_from_pipeline(pipeline: Dict[str, Any]) -> Dict[str, Any]:
    runtime = pipeline.get("runtime") if isinstance(pipeline.get("runtime"), dict) else {}
    website = pipeline.get("website") if isinstance(pipeline.get("website"), dict) else {}
    priority = pipeline.get("owner_priority") if isinstance(pipeline.get("owner_priority"), dict) else {}
    if not runtime and not website:
        return {}
    return {
        "autonomy_level": runtime.get("autonomy_level"),
        "runtime_stage": runtime.get("runtime_stage"),
        "monitoring_enabled": runtime.get("monitoring_enabled"),
        "timer_active": runtime.get("systemd_timer_active"),
        "scheduler_status": runtime.get("scheduler_verification_status"),
        "low_live_enabled": runtime.get("low_live_apply_enabled"),
        "production_apply_lock": runtime.get("production_apply_lock"),
        "emergency_stop": runtime.get("emergency_stop"),
        "breach": runtime.get("breach"),
        "owner_priority": priority.get("selected_priority"),
        "nowplaying_504": website.get("nowplaying_504"),
        "website_status": website.get("overall_status"),
        "total_5xx": website.get("total_5xx"),
        "source_map_404": website.get("source_map_404"),
        "source_map_status": website.get("source_map_status"),
        "current_snapshot_id": website.get("snapshot_id"),
        "recovery_evidence_window_status": website.get("recovery_evidence_window_status"),
        "recovery_snapshot_id": website.get("recovery_snapshot_id"),
        "autonomous_monitoring_decision": website.get("autonomous_monitoring_decision"),
        "dominant_504_endpoint": website.get("dominant_504_endpoint"),
        "dominant_504_share_percent": website.get("dominant_504_share_percent"),
        "primary_failure_focus": website.get("primary_failure_focus"),
        "nowplaying_classification": website.get("nowplaying_classification"),
    }


def observed_from_consistency(consistency: Dict[str, Any]) -> Dict[str, Any]:
    """Read the canonical runtime fields, not the module execution boundary flags.

    `safety.emergency_stop` in that module means "this module performs no productive
    apply"; the runtime state lives in `safety.runtime_*`.
    """
    priority = consistency.get("owner_priority") if isinstance(consistency.get("owner_priority"), dict) else {}
    safety = consistency.get("safety") if isinstance(consistency.get("safety"), dict) else {}
    evidence = consistency.get("current_website_evidence") if isinstance(
        consistency.get("current_website_evidence"), dict
    ) else {}
    if not priority and not safety:
        return {}
    return {
        "owner_priority": priority.get("selected_priority"),
        "autonomy_level": safety.get("runtime_autonomy_level"),
        "runtime_stage": safety.get("runtime_stage"),
        "timer_active": safety.get("runtime_systemd_timer_active"),
        "low_live_enabled": safety.get("runtime_low_live_apply_enabled"),
        "production_apply_lock": safety.get("runtime_production_apply_lock"),
        "emergency_stop": safety.get("runtime_emergency_stop"),
        "breach": safety.get("runtime_breach"),
        "website_status": evidence.get("website_status"),
        "total_5xx": evidence.get("total_5xx"),
        "source_map_404": evidence.get("map_404"),
    }


# --------------------------------------------------------------------------- #
# Validation entry point
# --------------------------------------------------------------------------- #

def evaluate(
    canonical_report: Dict[str, Any],
    master: Dict[str, Any],
    master_md: str,
    pipeline: Dict[str, Any],
    consistency: Dict[str, Any],
    daily_header: str,
    pipeline_md: str,
) -> Dict[str, Any]:
    canonical = canonical_report.get("canonical", {}) if isinstance(canonical_report, dict) else {}
    canonical_status = canonical_report.get("status") if isinstance(canonical_report, dict) else None

    observed: Dict[str, Dict[str, Any]] = {}
    for location, values in (
        ("master", observed_from_master(master)),
        ("pipeline", observed_from_pipeline(pipeline)),
        ("consistency", observed_from_consistency(consistency)),
    ):
        if values:
            observed[location] = values

    findings: List[Dict[str, Any]] = []
    if not canonical:
        findings.append(finding(
            "canonical_truth", VIOLATION,
            "Canonical truth snapshot is missing; no report may fall back to legacy values.",
        ))
        return {
            "status": "CANONICAL_INVARIANTS_FAILED",
            "canonical_truth_status": canonical_status or "MISSING",
            "findings": findings,
            "violations": findings,
            "observed": observed,
            "counts": {"checks": 1, "violations": 1, "not_evaluated": 0},
        }

    findings.extend(check_runtime_invariant(canonical, observed))
    findings.extend(check_flag_invariant("emergency_stop", "emergency_stop", canonical, observed))
    findings.extend(check_flag_invariant("timer", "timer_active", canonical, observed))
    findings.extend(check_flag_invariant("low_live", "low_live_enabled", canonical, observed))
    findings.extend(check_flag_invariant("breach", "breach", canonical, observed))
    findings.extend(check_flag_invariant("website_status", "website_status", canonical, observed))
    findings.extend(check_nowplaying_invariant(canonical, observed, master))
    findings.extend(check_recovery_window_invariant(canonical, observed))
    findings.extend(check_sourcemap_invariant(canonical, observed))
    findings.extend(check_owner_priority_invariant(canonical, observed))
    findings.extend(check_overall_status_invariant(canonical, master))
    table_findings, rows = check_executive_table(canonical, master_md)
    findings.extend(table_findings)
    findings.extend(check_forbidden_header_text(canonical, daily_header, "canonical daily header"))
    findings.extend(check_forbidden_header_text(canonical, pipeline_md, "production daily summary"))

    violations = [row for row in findings if row["verdict"] == VIOLATION]
    not_evaluated = [row for row in findings if row["verdict"] == NOT_EVALUATED]
    if violations:
        status = "CANONICAL_INVARIANTS_FAILED"
    elif canonical_status != "CANONICAL_TRUTH_OK":
        status = "CANONICAL_INVARIANTS_OK_TRUTH_INCOMPLETE"
    else:
        status = "CANONICAL_INVARIANTS_OK"

    return {
        "status": status,
        "canonical_truth_status": canonical_status,
        "findings": findings,
        "violations": violations,
        "not_evaluated": not_evaluated,
        "observed": observed,
        "executive_rows_checked": sorted(
            label for label in CURRENT_TRUTH_ROWS if label in rows
        ),
        "counts": {
            "checks": len(findings),
            "violations": len(violations),
            "not_evaluated": len(not_evaluated),
        },
    }


def build_report() -> Dict[str, Any]:
    canonical_report = load_dict(CANONICAL_JSON)
    master = load_dict(MASTER_JSON)
    pipeline = load_dict(PIPELINE_JSON)
    consistency = load_dict(CONSISTENCY_JSON)
    result = evaluate(
        canonical_report,
        master,
        read_text(MASTER_MD),
        pipeline,
        consistency,
        read_text(DAILY_HEADER_MD),
        read_text(PIPELINE_MD),
    )
    canonical = canonical_report.get("canonical", {})
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": result["status"],
        "report_classification": REPORT_CLASSIFICATION,
        "execution_boundaries": EXECUTION_BOUNDARIES,
        "canonical_truth_status": result["canonical_truth_status"],
        "canonical_reference": {
            "path": rel(CANONICAL_JSON),
            "generated_at_utc": canonical_report.get("generated_at_utc"),
            "autonomy_level": canonical_value(canonical, "autonomy_level"),
            "timer_active": canonical_value(canonical, "timer_active"),
            "emergency_stop": canonical_value(canonical, "emergency_stop"),
            "breach": canonical_value(canonical, "breach"),
            "owner_priority": canonical_value(canonical, "owner_priority"),
            "website_status": canonical_value(canonical, "website_status"),
            "overall_status": canonical_value(canonical, "overall_status"),
        },
        "invariants": [
            "runtime", "emergency_stop", "timer", "low_live", "breach", "website_status",
            "nowplaying", "sourcemap", "owner_priority", "overall_status",
            "executive_table", "daily_header",
        ],
        "observed": result["observed"],
        "executive_rows_checked": result.get("executive_rows_checked", []),
        "findings": result["findings"],
        "violations": result["violations"],
        "not_evaluated": result.get("not_evaluated", []),
        "counts": result["counts"],
        "breach": False,
    }


def build_daily_consistency(report: Dict[str, Any]) -> Dict[str, Any]:
    """Section 28 test H: header, master and pipeline must agree field by field."""
    canonical_report = load_dict(CANONICAL_JSON)
    canonical = canonical_report.get("canonical", {})
    observed = report.get("observed", {})
    compared_fields = (
        "autonomy_level",
        "runtime_stage",
        "timer_active",
        "emergency_stop",
        "breach",
        "owner_priority",
        "website_status",
        "total_5xx",
        "nowplaying_504",
        "low_live_enabled",
    )
    rows: List[Dict[str, Any]] = []
    for field in compared_fields:
        expected = normalize(canonical_value(canonical, field))
        row: Dict[str, Any] = {
            "field": field,
            "canonical": expected,
            "identical": True,
            "locations": {},
        }
        for location, values in observed.items():
            seen = normalize(values.get(field))
            row["locations"][location] = seen
            if seen is not None and expected is not None and seen != expected:
                row["identical"] = False
        rows.append(row)
    mismatched = [row["field"] for row in rows if not row["identical"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "status": "DAILY_SUMMARY_CONSISTENCY_OK" if not mismatched else "DAILY_SUMMARY_CONSISTENCY_FAILED",
        "report_classification": REPORT_CLASSIFICATION,
        "rule": (
            "daily header runtime = master runtime = pipeline runtime; the same holds for timer, "
            "emergency_stop, breach, owner_priority and website_status"
        ),
        "compared_locations": sorted(observed.keys()),
        "fields": rows,
        "mismatched_fields": mismatched,
        "canonical_truth_status": canonical_report.get("status"),
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def private_header(title: str) -> List[str]:
    return [f"# {title}", "", "Classification: " + " | ".join(REPORT_CLASSIFICATION), ""]


def render_md(report: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Canonical Invariants")
    lines.extend([
        f"- status: `{report['status']}`",
        f"- canonical truth: `{report['canonical_truth_status']}`",
        f"- generated: `{report['generated_at_utc']}`",
        f"- checks: `{report['counts']['checks']}`, violations: `{report['counts']['violations']}`, "
        f"not evaluated: `{report['counts']['not_evaluated']}`",
        "",
        "## Canonical Reference",
        "",
    ])
    for key, value in sorted(report["canonical_reference"].items()):
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Findings", "", "| Invariant | Verdict | Location | Observed | Canonical | Detail |", "|---|---|---|---|---|---|"])
    for row in report["findings"]:
        lines.append(
            f"| `{row['invariant']}` | `{row['verdict']}` | `{row['location'] or '-'}` | "
            f"`{row['observed']}` | `{row['canonical']}` | {row['detail']} |"
        )
    if report["violations"]:
        lines.extend(["", "## Violations", ""])
        for row in report["violations"]:
            lines.append(f"- `{row['invariant']}` at `{row['location']}`: {row['detail']}")
    else:
        lines.extend(["", "## Violations", "", "- none"])
    lines.extend([
        "",
        "## Safety",
        "",
        "- Validation only: no Cloudflare, systemd, timer, WordPress, database or nginx change.",
        "- No credential output, no cookie storage, no Authorization header storage.",
    ])
    return "\n".join(lines) + "\n"


def render_daily_consistency_md(report: Dict[str, Any]) -> str:
    lines = private_header("Sentinel Daily Summary Consistency")
    lines.extend([
        f"- status: `{report['status']}`",
        f"- canonical truth: `{report['canonical_truth_status']}`",
        f"- generated: `{report['generated_at_utc']}`",
        f"- compared locations: `{', '.join(report['compared_locations']) or 'none'}`",
        "",
        report["rule"],
        "",
        "| Field | Canonical | " + " | ".join(report["compared_locations"]) + " | Identical |",
        "|---|---|" + "---|" * (len(report["compared_locations"]) + 1),
    ])
    for row in report["fields"]:
        cells = [f"`{row['locations'].get(location)}`" for location in report["compared_locations"]]
        lines.append(
            f"| `{row['field']}` | `{row['canonical']}` | " + " | ".join(cells) +
            f" | `{str(row['identical']).lower()}` |"
        )
    if report["mismatched_fields"]:
        lines.extend(["", "## Mismatched Fields", ""])
        for field in report["mismatched_fields"]:
            lines.append(f"- `{field}`")
    else:
        lines.extend(["", "## Mismatched Fields", "", "- none"])
    return "\n".join(lines) + "\n"


def build_playbook() -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "name": "sentinel-daily-summary-consistency",
        "status": "PLAYBOOK_ACTIVE",
        "rule": "one operational fact = one canonical current value in every report section",
        "identical_fields": [
            "autonomy_level", "runtime_stage", "timer_active", "emergency_stop", "breach",
            "owner_priority", "website_status", "total_5xx", "nowplaying_504", "low_live_enabled",
        ],
        "illegal_combinations": [
            {"header_runtime": "LEVEL_1_DRAFT_ONLY", "pipeline_runtime": "LEVEL_2_MONITORING_ACTIVE"},
            {"header_emergency_stop": True, "runtime_emergency_stop": False},
            {"header_timer": "not_installed", "systemd_timer_active": True},
            {"header_nowplaying_504": 0, "current_nowplaying_504": "> 0"},
            {"header_source_map_warning": "from stale report", "current_source_map_404": 0},
            {"owner_priority": "SEO", "website_status": "WARNING or CRITICAL"},
        ],
        "fail_closed": "CANONICAL_TRUTH_INCOMPLETE is reported, never a legacy substitution",
        "execution_boundaries": EXECUTION_BOUNDARIES,
    }


def persist(report: Dict[str, Any], daily: Dict[str, Any]) -> None:
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR):
        directory.mkdir(parents=True, exist_ok=True)
    write_json(REPORT_JSON, report)
    write_text(REPORT_MD, render_md(report))
    write_json(DAILY_CONSISTENCY_JSON, daily)
    write_text(DAILY_CONSISTENCY_MD, render_daily_consistency_md(daily))
    for path in PLAYBOOKS:
        write_json(path, build_playbook())

    state = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": report["generated_at_utc"],
        "status": report["status"],
        "daily_summary_consistency": daily["status"],
        "violations": len(report["violations"]),
        "canonical_truth_status": report["canonical_truth_status"],
        "mismatched_fields": daily["mismatched_fields"],
    }
    write_json(STATE_JSON, state)
    history, read_status = truth.read_json(HISTORY_JSON)
    if read_status != "ok" or not isinstance(history, list):
        history = []
    history.append(state)
    write_json(HISTORY_JSON, history[-400:])
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": report["generated_at_utc"],
        "event": "canonical_invariants_validated",
        "status": report["status"],
        "violations": len(report["violations"]),
        "daily_summary_consistency": daily["status"],
    })


# --------------------------------------------------------------------------- #
# Self-test — the section 23 illegal combinations must all be detected
# --------------------------------------------------------------------------- #

def _canonical_fixture(**overrides: Any) -> Dict[str, Any]:
    base = {
        "generated_at": "2026-08-12T14:00:00Z",
        "runtime_status": "RUNTIME_HEALTHY_MONITORING",
        "local_status": "OK",
        "timer_enabled": True,
        "medium_live_enabled": False,
        "high_live_enabled": False,
        "circuit_breaker_status": "CIRCUIT_BREAKER_ARMED",
        "rollback_status": "NO_ROLLBACK_EXECUTED",
        "write_canary_status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
        "promotion_status": "RUNTIME_PROMOTION_BLOCKED_BY_WRITE_CANARY",
        "promotion_blockers": ["cloudflare_write_canary"],
        "last_cycle_id": "guarded-20260812T140000Z-fixture",
        "last_decision": "NO_ACTION",
        "current_snapshot_id": "20260812-140000",
        "current_growth": "GROWTH_PRESENT",
        "http_504": 285,
        "http_503": 163,
        "http_522": 2,
        "http_526": 1,
        "nowplaying_classification": "NOWPLAYING_EVIDENCE_INSUFFICIENT",
        "nowplaying_automatic_repair_allowed": False,
        "wp_users_me_classification": "WP_USERS_ME_ORIGIN_TIMEOUT",
        "autonomy_level": "LEVEL_2_MONITORING_ACTIVE",
        "runtime_stage": "LEVEL_2_MONITORING_ACTIVE",
        "monitoring_enabled": True,
        "timer_active": True,
        "scheduler_status": "SCHEDULER_VERIFICATION_GREEN",
        "low_live_enabled": False,
        "production_apply_lock": True,
        "emergency_stop": False,
        "breach": False,
        "owner_priority": "WEBSITE_ORIGIN_STABILITY",
        "website_status": "WARNING",
        "overall_status": "WARNING",
        "total_5xx": 451,
        "nowplaying_504": 133,
        "wp_users_me_504": 62,
        "source_map_404": 0,
        "source_map_status": "OK",
        "rolling_window_status": "NEW_GROWTH_PRESENT",
        "website_correlation_status": "NORMAL",
        "recovery_evidence_window_status": "EVIDENCE_WINDOW_ALIGNED",
        "recovery_snapshot_id": "20260812-140000",
        "autonomous_monitoring_decision": "OWNER_ACTION_REQUIRED",
        "dominant_504_endpoint": "/api/nowplaying/electri-city-ai-electro-radio",
        "dominant_504_share_percent": 46.67,
        "primary_failure_focus": "AI_RADIO_NOWPLAYING_RECOVERY",
    }
    base.update(overrides)
    canonical = {
        name: {
            "value": value,
            "source": "fixture",
            "source_class": truth.CLASS_RUNTIME,
            "generated_at": "2026-08-12T14:00:00Z",
            "freshness": truth.CURRENT,
            "operational_effect": True,
            "resolution": "RESOLVED",
        }
        for name, value in base.items()
    }
    canonical["owner_priority"]["legacy_seo_checklist_allowed"] = (
        str(base["owner_priority"]).upper().startswith("SEO")
        and base["website_status"] == "OK"
    )
    return {"status": "CANONICAL_TRUTH_OK", "generated_at_utc": "2026-08-12T14:00:00Z", "canonical": canonical}


def _master_fixture(**header_overrides: Any) -> Dict[str, Any]:
    header = {
        "autonomy_level": "LEVEL_2_MONITORING_ACTIVE",
        "runtime_stage": "LEVEL_2_MONITORING_ACTIVE",
        "monitoring_enabled": True,
        "timer_active": True,
        "scheduler_status": "SCHEDULER_VERIFICATION_GREEN",
        "low_live_enabled": False,
        "production_apply_lock": True,
        "emergency_stop": False,
        "breach": False,
        "owner_priority": "WEBSITE_ORIGIN_STABILITY",
        "website_status": "WARNING",
        "total_5xx": 451,
        "nowplaying_504": 133,
        "source_map_404": 0,
        "source_map_status": "OK",
        "current_snapshot_id": "20260812-140000",
        "recovery_evidence_window_status": "EVIDENCE_WINDOW_ALIGNED",
        "recovery_snapshot_id": "20260812-140000",
        "autonomous_monitoring_decision": "OWNER_ACTION_REQUIRED",
        "dominant_504_endpoint": "/api/nowplaying/electri-city-ai-electro-radio",
        "dominant_504_share_percent": 46.67,
        "primary_failure_focus": "AI_RADIO_NOWPLAYING_RECOVERY",
        "nowplaying_classification": "NOWPLAYING_EVIDENCE_INSUFFICIENT",
    }
    header.update(header_overrides)
    return {"overall_master_status": "WARNING", "canonical_header": header}


def _pipeline_fixture(**overrides: Any) -> Dict[str, Any]:
    runtime = {
        "autonomy_level": "LEVEL_2_MONITORING_ACTIVE",
        "runtime_stage": "LEVEL_2_MONITORING_ACTIVE",
        "monitoring_enabled": True,
        "systemd_timer_active": True,
        "scheduler_verification_status": "SCHEDULER_VERIFICATION_GREEN",
        "low_live_apply_enabled": False,
        "production_apply_lock": True,
        "emergency_stop": False,
        "breach": False,
    }
    website = {
        "overall_status": "WARNING",
        "total_5xx": 451,
        "nowplaying_504": 133,
        "snapshot_id": "20260812-140000",
        "recovery_evidence_window_status": "EVIDENCE_WINDOW_ALIGNED",
        "recovery_snapshot_id": "20260812-140000",
        "autonomous_monitoring_decision": "OWNER_ACTION_REQUIRED",
        "dominant_504_endpoint": "/api/nowplaying/electri-city-ai-electro-radio",
        "dominant_504_share_percent": 46.67,
        "primary_failure_focus": "AI_RADIO_NOWPLAYING_RECOVERY",
        "nowplaying_classification": "NOWPLAYING_EVIDENCE_INSUFFICIENT",
    }
    runtime.update(overrides.pop("runtime", {}))
    website.update(overrides.pop("website", {}))
    return {
        "runtime": runtime,
        "website": website,
        "owner_priority": {"selected_priority": overrides.pop("owner_priority", "WEBSITE_ORIGIN_STABILITY")},
    }


CLEAN_MASTER_MD = """# Sentinel Master Report

## Master-Bewertung

| Signal | Status |
|---|---|
| Website Status | `WARNING` |
| Canonical Runtime Level | `LEVEL_2_MONITORING_ACTIVE` |
| Canonical systemd Timer Active | `true` |
| Canonical Emergency Stop | `false` |
| Canonical NowPlaying 504 (24h) | `133` |
| Canonical Recovery Evidence Window | `EVIDENCE_WINDOW_ALIGNED` |
| Canonical Website Snapshot | `20260812-140000` |
| Canonical Recovery Snapshot | `20260812-140000` |
| Canonical Monitoring Decision | `OWNER_ACTION_REQUIRED` |
| Canonical Primary Failure Focus | `AI_RADIO_NOWPLAYING_RECOVERY` |
| Canonical Dominant 504 Endpoint | `/api/nowplaying/electri-city-ai-electro-radio` |
| Canonical Dominant 504 Share Percent | `46.67` |
| Canonical SourceMap Status | `OK` |
| Legacy Autonomy Level (superseded) | `LEVEL_1_DRAFT_ONLY` |

## Other Section

- unrelated
"""

DIRTY_MASTER_MD = """# Sentinel Master Report

## Master-Bewertung

| Signal | Status |
|---|---|
| Website Status | `WARNING` |
| Canonical Runtime Level | `LEVEL_1_DRAFT_ONLY` |
| Autonomy Level | `LEVEL_1_DRAFT_ONLY` |
| Safe Draft Scheduler Timer Install | `not_installed` |
| Canonical SourceMap Status | `WARNING` |
"""


def run_self_test() -> Dict[str, Any]:
    checks: Dict[str, Any] = {}

    def violated(result: Dict[str, Any], invariant: str) -> bool:
        return any(row["invariant"] == invariant and row["verdict"] == VIOLATION
                   for row in result["findings"])

    clean = evaluate(
        _canonical_fixture(), _master_fixture(), CLEAN_MASTER_MD, _pipeline_fixture(), {},
        "\n".join(["Runtime:", "LEVEL_2_MONITORING_ACTIVE", "NowPlaying 504: 133"]),
        "Runtime: LEVEL_2_MONITORING_ACTIVE",
    )
    checks["clean_state_passes"] = clean["status"] == "CANONICAL_INVARIANTS_OK"
    checks["clean_state_no_violation"] = not clean["violations"]

    # Runtime invariant: header LEVEL_1 vs pipeline LEVEL_2.
    result = evaluate(
        _canonical_fixture(), _master_fixture(autonomy_level="LEVEL_1_DRAFT_ONLY"),
        CLEAN_MASTER_MD, _pipeline_fixture(), {}, "", "",
    )
    checks["runtime_conflict_detected"] = violated(result, "runtime")

    # Emergency stop invariant: header true vs runtime false.
    result = evaluate(
        _canonical_fixture(), _master_fixture(emergency_stop=True), CLEAN_MASTER_MD,
        _pipeline_fixture(), {}, "", "",
    )
    checks["emergency_stop_conflict_detected"] = violated(result, "emergency_stop")

    # Timer invariant: header not_installed vs systemd timer active.
    result = evaluate(
        _canonical_fixture(), _master_fixture(timer_active="not_installed"), CLEAN_MASTER_MD,
        _pipeline_fixture(), {}, "", "",
    )
    checks["timer_conflict_detected"] = violated(result, "timer")

    # NowPlaying invariant: header 0 vs current 133.
    result = evaluate(
        _canonical_fixture(), _master_fixture(nowplaying_504=0), CLEAN_MASTER_MD,
        _pipeline_fixture(), {}, "", "",
    )
    checks["nowplaying_conflict_detected"] = violated(result, "nowplaying")

    result = evaluate(
        _canonical_fixture(), _master_fixture(recovery_snapshot_id="20260812-130000"),
        CLEAN_MASTER_MD, _pipeline_fixture(), {}, "", "",
    )
    checks["mixed_recovery_window_detected"] = violated(result, "recovery_window")

    # SourceMap invariant: header WARNING from stale report vs current map_404=0.
    result = evaluate(
        _canonical_fixture(), _master_fixture(source_map_status="WARNING", source_map_404=70),
        CLEAN_MASTER_MD, _pipeline_fixture(), {}, "", "",
    )
    checks["sourcemap_conflict_detected"] = violated(result, "sourcemap")

    # Owner priority invariant: SEO while the website is WARNING.
    result = evaluate(
        _canonical_fixture(), _master_fixture(owner_priority="SEO_TITLE_REVIEW"), CLEAN_MASTER_MD,
        _pipeline_fixture(), {}, "", "",
    )
    checks["owner_priority_conflict_detected"] = violated(result, "owner_priority")
    seo_canonical = _canonical_fixture(owner_priority="SEO_TITLE_REVIEW", website_status="WARNING")
    result = evaluate(
        seo_canonical, _master_fixture(owner_priority="SEO_TITLE_REVIEW"), CLEAN_MASTER_MD,
        _pipeline_fixture(owner_priority="SEO_TITLE_REVIEW"), {}, "", "",
    )
    checks["canonical_seo_with_warning_detected"] = violated(result, "owner_priority")

    # Overall status invariant: master understating canonical.
    master = _master_fixture()
    master["overall_master_status"] = "OK"
    result = evaluate(_canonical_fixture(), master, CLEAN_MASTER_MD, _pipeline_fixture(), {}, "", "")
    checks["overall_status_understatement_detected"] = violated(result, "overall_status")
    master["overall_master_status"] = "CRITICAL"
    result = evaluate(_canonical_fixture(), master, CLEAN_MASTER_MD, _pipeline_fixture(), {}, "", "")
    checks["overall_status_escalation_allowed"] = not violated(result, "overall_status")

    # Executive table: unlabelled legacy values are violations, labelled ones are not.
    result = evaluate(
        _canonical_fixture(), _master_fixture(), DIRTY_MASTER_MD, _pipeline_fixture(), {}, "", "",
    )
    checks["executive_table_legacy_detected"] = violated(result, "executive_table")
    result = evaluate(
        _canonical_fixture(), _master_fixture(), CLEAN_MASTER_MD, _pipeline_fixture(), {}, "", "",
    )
    checks["labelled_legacy_row_allowed"] = not violated(result, "executive_table")

    # Daily header text scan.
    result = evaluate(
        _canonical_fixture(), _master_fixture(), CLEAN_MASTER_MD, _pipeline_fixture(), {},
        "Runtime:\nLEVEL_1_DRAFT_ONLY\ntimer=not_installed\nNowPlaying 504: 0", "",
    )
    checks["daily_header_legacy_detected"] = violated(result, "daily_header")
    result = evaluate(
        _canonical_fixture(), _master_fixture(), CLEAN_MASTER_MD, _pipeline_fixture(), {},
        "Recovery classification: NOWPLAYING_ROUTE_MISMATCH\n"
        "Dominant 504 endpoint: /api/nowplaying/electri-city-ai-electro-radio (59.2% of current 504)",
        "",
    )
    checks["stale_recovery_claims_detected"] = violated(result, "daily_header")

    # A labelled legacy region is documentation, not a current-truth claim.
    labelled_legacy_header = "\n".join([
        "Runtime:", "LEVEL_2_MONITORING_ACTIVE", "", "NowPlaying 504: 133", "",
        "Legacy / Historical Modules", "",
        "- legacy_autonomy_policy",
        "  legacy status: Phase 1.5 autonomy policy report (LEVEL_1_DRAFT_ONLY era).",
        "  freshness: SUPERSEDED",
        "  timer_installation_status: not_installed",
        "  operational_effect=false",
    ])
    result = evaluate(
        _canonical_fixture(), _master_fixture(), CLEAN_MASTER_MD, _pipeline_fixture(), {},
        labelled_legacy_header, "",
    )
    checks["labelled_legacy_region_allowed"] = not violated(result, "daily_header")
    checks["legacy_region_stripper"] = (
        "LEVEL_1_DRAFT_ONLY" not in current_truth_text(labelled_legacy_header)
        and "LEVEL_2_MONITORING_ACTIVE" in current_truth_text(labelled_legacy_header)
    )
    # A stale claim after the legacy region still gets caught.
    checks["legacy_region_ends_at_heading"] = "not_installed" in current_truth_text(
        "## Legacy / Historical Modules\n- timer=not_installed\n\n## Runtime\ntimer=not_installed"
    ) and current_truth_text(
        "## Legacy / Historical Modules\n- timer=not_installed"
    ).strip() == ""
    # A legacy-marked appendix heading shields its whole section.
    checks["legacy_heading_opens_region"] = current_truth_text(
        "## Autonomy Runtime Lock (Legacy / Superseded)\n- Max autonomy level: LEVEL_1_DRAFT_ONLY"
    ).strip() == "" and "LEVEL_2" in current_truth_text(
        "## Runtime Status (Canonical)\n- level: LEVEL_2_MONITORING_ACTIVE"
    )

    # Missing canonical truth must fail closed.
    result = evaluate({}, _master_fixture(), CLEAN_MASTER_MD, _pipeline_fixture(), {}, "", "")
    checks["missing_canonical_fails_closed"] = result["status"] == "CANONICAL_INVARIANTS_FAILED"

    # Table parsing.
    rows = executive_table_rows(CLEAN_MASTER_MD)
    checks["table_parser"] = rows.get("Website Status") == "`WARNING`" and "unrelated" not in rows
    checks["legacy_label_detection"] = (
        is_legacy_label("Legacy Autonomy Level (superseded)") and not is_legacy_label("Website Status")
    )
    checks["normalize_booleans"] = normalize(True) == "true" and normalize("`false`") == "false"
    checks["normalize_unknown"] = normalize("UNKNOWN") is None and normalize("-") is None

    imported = truth.imported_module_roots()
    checks["truth_module_read_only"] = not (imported & truth.PROCESS_MODULES)

    findings = [name for name, value in checks.items() if not value]
    return {
        "status": "CANONICAL_INVARIANTS_SELF_TEST_OK" if not findings else "CANONICAL_INVARIANTS_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel canonical invariant validator (Phase 10.21)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = run_self_test()
        print(result["status"])
        for name in result["findings"]:
            print(f"finding={name}")
        return 0 if not result["findings"] else 1

    if args.validate:
        report = build_report()
        daily = build_daily_consistency(report)
        persist(report, daily)
        print(report["status"])
        print(f"daily_summary_consistency={daily['status']}")
        for row in report["violations"]:
            print(f"violation={row['invariant']}@{row['location']}: {row['detail']}")
        for row in report.get("not_evaluated", []):
            print(f"not_evaluated={row['invariant']}: {row['detail']}")
        return 0 if not report["violations"] else 2

    report = load_dict(REPORT_JSON)
    if not report:
        print("CANONICAL_INVARIANTS_NOT_RUN")
        return 1
    print(report.get("status", "NOT_RUN"))
    print(f"violations={len(report.get('violations', []))}")
    daily = load_dict(DAILY_CONSISTENCY_JSON)
    if daily:
        print(f"daily_summary_consistency={daily.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
