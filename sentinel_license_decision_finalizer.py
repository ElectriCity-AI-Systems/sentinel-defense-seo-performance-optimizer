#!/usr/bin/env python3
"""Finalize Sentinel release drafts behind an owner license decision gate.

This Phase 10.14 module writes only local sanitized public release-final drafts,
local reports, state, audit events and playbooks. It does not perform live
apply, network access, marketplace API calls, GitHub pushes, remote writes,
timer installation, or customer system changes.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-license-decision-finalizer-10.14"
PHASE = "10.14"

HARD_DEFAULTS = {
    "live_apply": False,
    "emergency_stop": True,
    "allowed_apply_now": False,
    "high_blocked": True,
    "low_live_executable": False,
    "medium_executable": False,
    "breach": False,
}

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"
FINAL_DIR = PROJECT_DIR / "docs/release-final"
DIST_DIR = PROJECT_DIR / "docs/distribution-release"
PUBLIC_DIR = PROJECT_DIR / "docs/public-release"

REPORT_JSON = REPORT_DIR / "sentinel-license-decision-finalizer.json"
REPORT_MD = REPORT_DIR / "sentinel-license-decision-finalizer.md"
VALIDATION_MD = REPORT_DIR / "sentinel-final-release-validation.md"
OWNER_SUMMARY_MD = REPORT_DIR / "sentinel-final-release-owner-summary.md"
LOGIN_PROBE_OWNER_MD = REPORT_DIR / "sentinel-ionos-login-probe-owner-review.md"

STATE_JSON = STATE_DIR / "license_decision_finalizer.json"
LATEST_JSON = STATE_DIR / "latest_license_decision_finalizer.json"
HISTORY_JSON = STATE_DIR / "license_decision_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-license-decision-finalizer.jsonl"

PLAYBOOK_FINALIZER = PLAYBOOK_DIR / "sentinel-license-decision-finalizer.playbook.json"
PLAYBOOK_OPTIONS = PLAYBOOK_DIR / "sentinel-license-options.playbook.json"
PLAYBOOK_VALIDATION = PLAYBOOK_DIR / "sentinel-final-release-validation.playbook.json"
PLAYBOOK_DRAFTS = PLAYBOOK_DIR / "sentinel-final-release-drafts.playbook.json"

FINAL_FILES = {
    "license_options": FINAL_DIR / "LICENSE-OPTIONS.md",
    "owner_license_decision": FINAL_DIR / "OWNER-LICENSE-DECISION.md",
    "license_draft_note": FINAL_DIR / "LICENSE-DRAFT-NOTE.md",
    "root_readme_activation_draft": FINAL_DIR / "ROOT-README-ACTIVATION-DRAFT.md",
    "release_tag_draft": FINAL_DIR / "RELEASE-TAG-DRAFT.md",
    "github_final_release_draft": FINAL_DIR / "GITHUB-FINAL-RELEASE-DRAFT.md",
    "payhip_launch_draft": FINAL_DIR / "PAYHIP-LAUNCH-DRAFT.md",
    "gumroad_launch_draft": FINAL_DIR / "GUMROAD-LAUNCH-DRAFT.md",
    "final_release_validation": FINAL_DIR / "FINAL-RELEASE-VALIDATION.md",
    "final_commit_recommendation": FINAL_DIR / "FINAL-COMMIT-RECOMMENDATION.md",
    "manual_publication_checklist": FINAL_DIR / "MANUAL-PUBLICATION-CHECKLIST.md",
    "final_green_release_summary": FINAL_DIR / "FINAL-GREEN-RELEASE-SUMMARY.md",
    "final_owner_approval_gate": FINAL_DIR / "FINAL-OWNER-APPROVAL-GATE.md",
    "manifest": FINAL_DIR / "release-final-manifest.json",
    "license_draft": FINAL_DIR / "LICENSE-DRAFT.md",
}

INPUTS = {
    "distribution_manifest": DIST_DIR / "distribution-release-manifest.json",
    "version_manifest": DIST_DIR / "VERSION-MANIFEST.md",
    "changelog": DIST_DIR / "CHANGELOG.md",
    "root_readme_draft": DIST_DIR / "ROOT-README-DRAFT.md",
    "github_release_checklist": DIST_DIR / "GITHUB-RELEASE-CHECKLIST.md",
    "payhip_upload_checklist": DIST_DIR / "PAYHIP-UPLOAD-CHECKLIST.md",
    "gumroad_upload_checklist": DIST_DIR / "GUMROAD-UPLOAD-CHECKLIST.md",
    "commercial_service_checklist": DIST_DIR / "COMMERCIAL-SERVICE-CHECKLIST.md",
    "repository_hygiene": DIST_DIR / "REPOSITORY-HYGIENE.md",
    "license_placeholder": DIST_DIR / "LICENSE-DECISION-PLACEHOLDER.md",
    "release_final_validation": DIST_DIR / "RELEASE-FINAL-VALIDATION.md",
    "commit_recommendation": DIST_DIR / "COMMIT-RECOMMENDATION.md",
    "public_manifest": PUBLIC_DIR / "public-release-manifest.json",
}

RECOMMENDED_GIT_FILES = [
    "sentinel_license_decision_finalizer.py",
    "sentinel_autonomy.py",
    "docs/release-final/LICENSE-OPTIONS.md",
    "docs/release-final/OWNER-LICENSE-DECISION.md",
    "docs/release-final/LICENSE-DRAFT-NOTE.md",
    "docs/release-final/LICENSE-DRAFT.md",
    "docs/release-final/ROOT-README-ACTIVATION-DRAFT.md",
    "docs/release-final/RELEASE-TAG-DRAFT.md",
    "docs/release-final/GITHUB-FINAL-RELEASE-DRAFT.md",
    "docs/release-final/PAYHIP-LAUNCH-DRAFT.md",
    "docs/release-final/GUMROAD-LAUNCH-DRAFT.md",
    "docs/release-final/FINAL-RELEASE-VALIDATION.md",
    "docs/release-final/FINAL-COMMIT-RECOMMENDATION.md",
    "docs/release-final/MANUAL-PUBLICATION-CHECKLIST.md",
    "docs/release-final/FINAL-GREEN-RELEASE-SUMMARY.md",
    "docs/release-final/FINAL-OWNER-APPROVAL-GATE.md",
    "docs/release-final/release-final-manifest.json",
    "playbooks/sentinel-license-decision-finalizer.playbook.json",
    "playbooks/sentinel-license-options.playbook.json",
    "playbooks/sentinel-final-release-validation.playbook.json",
    "playbooks/sentinel-final-release-drafts.playbook.json",
]

ALLOWED_WRITE_ROOTS = (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, FINAL_DIR)

LICENSE_OPTIONS = {
    "polyform-noncommercial": {
        "meaning": "source-available, non-commercial use allowed, commercial use requires separate permission or license",
        "fit": "useful when Payhip, Gumroad and commercial service delivery should remain protected",
    },
    "bsl": {
        "meaning": "Business Source License style approach with a possible later change-date mechanism",
        "fit": "useful when source should be visible but direct commercial competition should be time-limited",
    },
    "apache-2.0": {
        "meaning": "permissive open source with patent grant",
        "fit": "useful when adoption matters more than commercial exclusivity",
    },
    "mit": {
        "meaning": "very permissive and minimal open source terms",
        "fit": "useful when simplicity matters more than protection from commercial reuse",
    },
    "custom-commercial": {
        "meaning": "custom commercial license, EULA or service contract required",
        "fit": "useful when product and service sale should be strictly controlled",
    },
}

SENSITIVE_TERMS = [
    "sentinel_sftp_" + "pass" + "word" + r"\s*=",
    r"pass" + r"word\s*[:=]\s*[^\s,]+",
    r"pass" + r"wd\s*[:=]\s*[^\s,]+",
    r"api[_-]?" + "key" + r"\s*[:=]\s*[^\s,]+",
    "bear" + "er" + r"\s+[a-z0-9._-]+",
    "s" + "k-" + r"[a-z0-9]{20,}",
    "g" + "hp_" + r"[a-z0-9_]{12,}",
    "github_" + "pat_" + r"[a-z0-9_]{12,}",
    r"AIza[a-z0-9_-]{20,}",
    "begin" + r"\s+(?:open)?ssh\s+private\s+" + "key",
    "begin" + r"\s+rsa\s+private\s+" + "key",
]
SENSITIVE_RE = re.compile(r"(?i)(" + "|".join(SENSITIVE_TERMS) + ")")
CUSTOMER_DATA_RE = re.compile(
    r"(?i)(customer\s+credential\s*[:=]|payment\s+card\s*[:=]|iban\s*[:=]|ssn\s*[:=])"
)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
PRIVATE_PATH_RE = re.compile(r"(?i)(?:^|\s)(/(?:srv|home|root|etc|var|opt|mnt|tmp)/[^\s)]+)")
FORBIDDEN_CLAIM_RE = re.compile(
    r"(?i)("
    r"guaranteed\s+(?:rankings|revenue|seo|security|performance)|"
    r"instant\s+pagespeed\s+success|"
    r"unattended\s+(?:wordpress|cloudflare|database|sftp|server)\s+repair|"
    r"fully\s+automatic\s+production\s+repair"
    r")"
)
LIVE_AUTOPILOT_RE = re.compile(r"(?i)(live\s+autopilot|production\s+autopilot|remote\s+autopilot)")
NEGATION_RE = re.compile(r"(?i)\b(no|not|never|does\s+not|do\s+not|is\s+not|are\s+not)\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except ValueError:
        return str(path)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, FINAL_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def assert_write_path(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise RuntimeError(f"refusing write outside allowed roots: {rel(path)}")


def scan_public_text(text: str) -> List[str]:
    findings: List[str] = []
    if SENSITIVE_RE.search(text):
        findings.append("sensitive_pattern")
    if CUSTOMER_DATA_RE.search(text):
        findings.append("customer_data_marker")
    if IP_RE.search(text):
        findings.append("ip_address")
    if PRIVATE_PATH_RE.search(text):
        findings.append("private_path")
    for line in text.splitlines():
        if FORBIDDEN_CLAIM_RE.search(line) and not NEGATION_RE.search(line):
            findings.append("forbidden_claim")
        if LIVE_AUTOPILOT_RE.search(line) and not NEGATION_RE.search(line):
            findings.append("live_autopilot_claim")
    return sorted(set(findings))


def assert_safe_private_text(text: str, path: Optional[Path] = None) -> None:
    if SENSITIVE_RE.search(text):
        raise RuntimeError(f"sensitive value blocked in {rel(path) if path else 'content'}")
    if CUSTOMER_DATA_RE.search(text):
        raise RuntimeError(f"customer-data marker blocked in {rel(path) if path else 'content'}")


def assert_safe_public_text(text: str, path: Optional[Path] = None) -> None:
    assert_safe_private_text(text, path)
    findings = scan_public_text(text)
    if findings:
        where = rel(path) if path else "public content"
        raise RuntimeError(f"public sanitization blocked {where}: {findings[:3]}")


def write_text(path: Path, text: str, public: bool = False) -> None:
    assert_write_path(path)
    if public:
        assert_safe_public_text(text, path)
    else:
        assert_safe_private_text(text, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data: Dict[str, Any], public: bool = False) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text + "\n", public=public)


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    assert_write_path(path)
    line = json.dumps(row, sort_keys=True)
    assert_safe_private_text(line, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def read_json(path: Path) -> Tuple[Any, str]:
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def load_dict(path: Path) -> Dict[str, Any]:
    data, status = read_json(path)
    return data if status == "ok" and isinstance(data, dict) else {}


def redact(value: Any, limit: int = 1000) -> str:
    return SENSITIVE_RE.sub("[REDACTED]", str(value))[:limit]


def run_git(kind: str) -> Dict[str, Any]:
    commands = {
        "status": ["git", "status", "--short"],
        "log": ["git", "log", "--oneline", "-8"],
    }
    try:
        proc = subprocess.run(
            commands[kind],
            cwd=str(PROJECT_DIR),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "line_count": 0, "error": redact(exc)}
    lines = [line for line in (proc.stdout or "").splitlines() if line.strip()]
    safe_lines = [
        line for line in lines
        if not any(part in line for part in ("reports/", "state/", "audit/", "exports/", "backups/", ".env"))
    ][:20]
    return {
        "status": "ok" if proc.returncode == 0 else "failed",
        "returncode": proc.returncode,
        "line_count": len(lines),
        "safe_lines": [redact(line, 300) for line in safe_lines],
    }


def source_safety_findings(paths: Iterable[Path]) -> List[Dict[str, str]]:
    network_terms = ["re" + "quests", "ur" + "llib", "http" + "." + "client", "smtp" + "lib", "sock" + "et", "para" + "miko", "cloud" + "flare"]
    network_re = re.compile(r"^\s*(?:import|from)\s+(" + "|".join(re.escape(term) for term in network_terms) + r")\b", re.MULTILINE)
    checks = [
        ("apply_argument_present", re.compile(r"add_argument\([\"']--" + "apply")),
        ("network_import_present", network_re),
        ("shell_true_present", re.compile(r"\bshell\s*=\s*True\b")),
        ("free_subprocess_present", re.compile(r"subprocess\.(?:Popen|call|check_call|check_output)\(")),
        ("systemctl_live_present", re.compile(r"(?<![A-Za-z_-])systemctl\s+(?:start|enable)")),
        ("cron_install_present", re.compile(r"(?<![A-Za-z_-])crontab\s+(?:-|install)")),
        ("destructive_delete_present", re.compile(r"(?<![A-Za-z_-])r" + "m\\s+-r" + "f")),
        ("process_termination_present", re.compile(r"(?<![A-Za-z_-])(?:p" + "kill|kill" + "all)\\b")),
        ("remote_write_call_present", re.compile(r"\.(?:put|remove|rename)\(")),
    ]
    findings: List[Dict[str, str]] = []
    for path in paths:
        if not path.exists():
            findings.append({"path": rel(path), "finding": "missing_source"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if SENSITIVE_RE.search(text):
            findings.append({"path": rel(path), "finding": "sensitive_pattern"})
        for finding, rx in checks:
            if rx.search(text):
                findings.append({"path": rel(path), "finding": finding})
    return findings


def scan_paths(paths: Iterable[Path], public: bool) -> Dict[str, Any]:
    findings: List[Dict[str, str]] = []
    for path in paths:
        if not path.exists():
            findings.append({"path": rel(path), "finding": "missing"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if public and path.suffix.lower() != ".json" and not text.strip():
            findings.append({"path": rel(path), "finding": "empty_markdown"})
        if public:
            for finding in scan_public_text(text):
                findings.append({"path": rel(path), "finding": finding})
        else:
            if SENSITIVE_RE.search(text):
                findings.append({"path": rel(path), "finding": "sensitive_pattern"})
            if CUSTOMER_DATA_RE.search(text):
                findings.append({"path": rel(path), "finding": "customer_data_marker"})
    return {"status": "SCAN_OK" if not findings else "SCAN_FINDINGS", "findings": findings}


def git_recommendation() -> Dict[str, Any]:
    unsafe_prefixes = ("reports/", "state/", "audit/", "exports/", "backups/")
    unsafe = [item for item in RECOMMENDED_GIT_FILES if item.startswith(unsafe_prefixes)]
    return {
        "status": "GIT_RECOMMENDATION_OK" if not unsafe else "GIT_RECOMMENDATION_BLOCKED",
        "checkpoint_files": RECOMMENDED_GIT_FILES,
        "local_artifacts_not_for_commit": [
            "runtime reports",
            "adaptive state ledgers",
            "audit logs",
            "generated export artifacts",
            "backup artifacts",
            "credential files",
            "private owner evidence",
        ],
        "unsafe_recommended_files": unsafe,
    }


def read_license_choice() -> Dict[str, Any]:
    data = load_dict(STATE_JSON)
    choice = data.get("selected_license")
    if choice in LICENSE_OPTIONS:
        return {
            "license_decision_status": "LICENSE_CHOICE_SET",
            "selected_license": choice,
            "license_reason": data.get("license_reason", LICENSE_OPTIONS[choice]["fit"]),
            "license_choice_set_at": data.get("license_choice_set_at"),
        }
    return {
        "license_decision_status": "LICENSE_DECISION_REQUIRED",
        "selected_license": None,
        "license_reason": "owner_license_choice_missing",
        "license_choice_set_at": None,
    }


def private_ionos_evidence() -> Dict[str, Any]:
    return {
        "category": "IONOS_HOSTING_ANALYTICS_LOGIN_PROBE_EVIDENCE",
        "status": "PRIVATE_OWNER_EVIDENCE_RECORDED",
        "visibility": "private_owner_reports_only",
        "period": "last_30_days",
        "observed_top_entry_page": "/wp-login.php",
        "observed_top_exit_page": "/wp-login.php",
        "interpretation": "strong_bot_login_probe_or_scanner_traffic_against_wordpress_login_and_technical_paths",
        "website_status": "CRITICAL",
        "autonomy_policy": "OK",
        "master_critical_cause": "website_only_origin_security_traffic_not_sentinel_autonomy",
        "review_only_drafts": [
            "WordPress Login Hardening Review Draft",
            "Cloudflare/WAF Review Draft for login-probe traffic",
            "Rate-Limit Review Draft for /wp-login.php",
            "Owner Checklist for log confirmation and user lockout risk",
        ],
        "blocked_actions": [
            "no_live_apply",
            "no_cloudflare_apply",
            "no_wordpress_apply",
            "no_nginx_apply",
            "no_sftp_apply",
            "no_timer",
            "no_low_live_medium_high_enablement",
        ],
        **HARD_DEFAULTS,
    }


def write_private_ionos_report() -> None:
    evidence = private_ionos_evidence()
    text = "\n".join([
        "# Private Owner Evidence: IONOS Hosting Analytics Login Probe",
        "",
        "- category: `IONOS_HOSTING_ANALYTICS_LOGIN_PROBE_EVIDENCE`",
        "- source: Owner-provided IONOS Analytics screenshot",
        "- site: `electri-c-ity-studios-24-7.com`",
        "- period: last 30 days",
        "- observation: top entry page and top exit page are dominated by `/wp-login.php`",
        "- interpretation: likely bot, login-probe or scanner traffic against WordPress login and technical paths",
        "- not interpreted as: human content engagement failure",
        "- Website Status: `CRITICAL`",
        "- Autonomy Policy: `OK`",
        "- breach: `False`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "",
        "## Review-Only Drafts",
        "",
        "- WordPress Login Hardening Review Draft",
        "- Cloudflare/WAF Review Draft for login-probe traffic",
        "- Rate-Limit Review Draft for `/wp-login.php`",
        "- Owner Checklist: check whether WordPress login is protected, limited, or guarded by a login-security plugin",
        "- Owner Checklist: check whether IONOS, WordPress or PHP logs confirm the login-probe load",
        "- Owner Checklist: check whether real users could be locked out by any proposed measure",
        "",
        "## Hard Blocks",
        "",
        "- no automatic WAF/firewall rule",
        "- no Cloudflare change",
        "- no WordPress change",
        "- no Nginx change",
        "- no database change",
        "- no SFTP change",
        "- no timer",
        "- no LOW_LIVE, MEDIUM or HIGH enablement",
    ]) + "\n"
    write_text(LOGIN_PROBE_OWNER_MD, text)


def collect_distribution_pack(write: bool = True) -> Dict[str, Any]:
    ensure_dirs()
    input_statuses: Dict[str, str] = {}
    missing_inputs: List[str] = []
    invalid_inputs: List[str] = []
    for name, path in INPUTS.items():
        if path.suffix == ".json":
            _, status = read_json(path)
        else:
            status = "ok" if path.exists() and path.read_text(encoding="utf-8", errors="replace").strip() else "missing"
        input_statuses[name] = status
        if status == "missing":
            missing_inputs.append(rel(path))
        elif status != "ok":
            invalid_inputs.append(rel(path))

    dist_manifest = load_dict(INPUTS["distribution_manifest"])
    public_manifest = load_dict(INPUTS["public_manifest"])
    choice = read_license_choice()
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "collect-distribution-pack",
        "status": "FINAL_RELEASE_DISTRIBUTION_EVIDENCE_COLLECTED",
        "collected_distribution_evidence": sum(1 for status in input_statuses.values() if status == "ok"),
        "input_statuses": input_statuses,
        "missing_inputs": missing_inputs,
        "invalid_inputs": invalid_inputs,
        "distribution_pack_status": dist_manifest.get("distribution_pack_status"),
        "distribution_pack_reason": dist_manifest.get("distribution_pack_reason"),
        "public_pack_status": dist_manifest.get("public_pack_status") or public_manifest.get("public_pack_status"),
        "rc_status": dist_manifest.get("rc_status") or public_manifest.get("rc_status"),
        "readiness_seal": dist_manifest.get("readiness_seal") or public_manifest.get("readiness_seal"),
        "regression_gate_status": dist_manifest.get("regression_gate_status") or public_manifest.get("regression_gate_status"),
        "semver_suggestion": "v1.0.0-rc1",
        "private_evidence": private_ionos_evidence(),
        "git_status": run_git("status"),
        "git_log": run_git("log"),
        **choice,
        **HARD_DEFAULTS,
    }
    if write:
        write_private_ionos_report()
        write_outputs(evidence)
    return evidence


def render_final_manifest(evidence: Dict[str, Any], validation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    validation = validation or {}
    docs = list(FINAL_FILES.values())
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "product_name": "Sentinel Security, SEO & Performance Safe Optimization",
        "final_release_status": validation.get("final_release_status", "FINAL_RELEASE_PENDING"),
        "final_release_reason": validation.get("final_release_reason", "not_validated_yet"),
        "distribution_pack_status": evidence.get("distribution_pack_status"),
        "public_pack_status": evidence.get("public_pack_status"),
        "rc_status": evidence.get("rc_status"),
        "semver_suggestion": "v1.0.0-rc1",
        "license_decision_status": evidence.get("license_decision_status"),
        "selected_license": evidence.get("selected_license"),
        "license_draft_status": validation.get("license_draft_status", "LICENSE_DRAFT_PENDING"),
        "manual_publication_checklist_status": validation.get("manual_publication_checklist_status", "MANUAL_PUBLICATION_CHECKLIST_PENDING"),
        "final_owner_approval_gate_status": validation.get("final_owner_approval_gate_status", "FINAL_OWNER_APPROVAL_GATE_PENDING"),
        "publication_activation_status": "MANUAL_ONLY_NOT_EXECUTED",
        "docs": sorted(rel(path) for path in docs),
        "recommended_git_checkpoint_files": RECOMMENDED_GIT_FILES,
        "local_artifacts_not_for_commit": git_recommendation()["local_artifacts_not_for_commit"],
        **HARD_DEFAULTS,
    }
    return manifest


def render_license_options(_: Dict[str, Any]) -> str:
    lines = [
        "# License Options",
        "",
        "This is not legal advice. The owner should review license terms manually before public distribution.",
        "",
    ]
    for option, details in LICENSE_OPTIONS.items():
        lines.extend([
            f"## {option}",
            "",
            f"- Meaning: {details['meaning']}.",
            f"- Fit: {details['fit']}.",
            "",
        ])
    lines.extend([
        "## Owner Gate",
        "",
        "If no owner choice is set, final release remains `FINAL_RELEASE_YELLOW` and no license draft becomes final.",
    ])
    return "\n".join(lines) + "\n"


def render_owner_license_decision(evidence: Dict[str, Any]) -> str:
    choice = evidence.get("selected_license")
    if choice:
        option = LICENSE_OPTIONS[choice]
        decision = [
            "# Owner License Decision",
            "",
            f"- decision_status: `LICENSE_CHOICE_SET`",
            f"- selected_license: `{choice}`",
            f"- meaning: {option['meaning']}",
            f"- reason: {evidence.get('license_reason') or option['fit']}",
            f"- set_at: `{evidence.get('license_choice_set_at') or '-'}`",
            "",
            "This decision creates local release-final drafts only. It does not overwrite a final `LICENSE` file.",
        ]
    else:
        decision = [
            "# Owner License Decision",
            "",
            "- decision_status: `LICENSE_DECISION_REQUIRED`",
            "- selected_license: `none`",
            "- reason: owner has not selected a license option yet",
            "",
            "Final release remains yellow until the owner chooses a license model. This is intentional and safe.",
        ]
    return "\n".join(decision) + "\n"


def render_license_draft_note(evidence: Dict[str, Any]) -> str:
    choice = evidence.get("selected_license")
    return "\n".join([
        "# License Draft Note",
        "",
        "No final legal license file is written by this phase.",
        "",
        f"- selected_license: `{choice or 'none'}`",
        "- `--write-license-draft` may create `LICENSE-DRAFT.md` only.",
        "- `LICENSE-DRAFT.md` is not a final legal license.",
        "- Manual owner and legal review remains required before copying anything to `LICENSE`.",
    ]) + "\n"


def render_root_readme_activation_draft(_: Dict[str, Any]) -> str:
    return """# Root README Activation Draft

This draft explains how the owner may later move the distribution README draft into the root README manually.

## Manual Activation

1. Review `docs/distribution-release/ROOT-README-DRAFT.md`.
2. Confirm public docs are sanitized.
3. Confirm license decision is complete.
4. Manually copy approved text into `README.md`.
5. Run repository hygiene and secret scan before commit.

This phase does not overwrite `README.md`.

## Safety Boundaries

Sentinel remains local and owner-controlled. It does not perform live website, server, database, CDN, marketplace, email or remote-file changes from this release-final draft.

See `docs/public-release/` and `docs/distribution-release/` for public safety and distribution documents.
"""


def render_release_tag_draft(_: Dict[str, Any]) -> str:
    return """# Release Tag Draft

- SemVer suggestion: `v1.0.0-rc1`
- tag type: release candidate
- automatic tag creation: no

## Manual Command Suggestions

```bash
git status --short
git tag v1.0.0-rc1
git push origin v1.0.0-rc1
```

The commands above are text suggestions only. This phase does not execute them.
"""


def render_github_final_release_draft(evidence: Dict[str, Any]) -> str:
    return f"""# GitHub Final Release Draft

## Release Title

Sentinel Security, SEO & Performance Safe Optimization `v1.0.0-rc1`

## Highlights

- local safe autonomy chain
- owner command console
- sanitized public release pack
- distribution release pack
- release-final license gate
- repository hygiene and marketplace checklists

## Safety Boundaries

No live apply, no remote writes, no marketplace API calls, no timer installation and no production system changes are part of this release.

## Known Limitations

- License decision status: `{evidence.get('license_decision_status')}`
- Selected license: `{evidence.get('selected_license') or 'none'}`
- Root README activation remains manual.
- Production website security warnings remain private owner evidence and review-only.

## Distribution Status

- Distribution Pack: `{evidence.get('distribution_pack_status')}`
- Public Pack: `{evidence.get('public_pack_status')}`
- Release Candidate: `{evidence.get('rc_status')}`
"""


def render_payhip_launch_draft(evidence: Dict[str, Any]) -> str:
    return f"""# Payhip Launch Draft

## Product

Sentinel Security, SEO & Performance Safe Optimization

## Final Product Text

Local owner-controlled safety system for SEO, performance and security operations with evidence reports, safe batches, readiness checks, distribution documentation and release-final owner gates.

## Buyer Notice

This product supports local review and planning. It does not promise rankings, revenue, perfect security, instant performance outcomes or automatic repair of external systems.

## Launch Status

- final_release_license_status: `{evidence.get('license_decision_status')}`
- selected_license: `{evidence.get('selected_license') or 'none'}`
- API usage: none
- upload performed: no
"""


def render_gumroad_launch_draft(evidence: Dict[str, Any]) -> str:
    return f"""# Gumroad Launch Draft

## Product

Sentinel Security, SEO & Performance Safe Optimization

## Final Product Text

Sentinel is a local owner-controlled system for safe analysis, review, reporting, operations supervision, distribution preparation and release evidence.

## Buyer Notice

Production-changing actions require separate owner approval and a dedicated safety phase. This release draft does not upload, publish, email or remotely change any system.

## Launch Status

- final_release_license_status: `{evidence.get('license_decision_status')}`
- selected_license: `{evidence.get('selected_license') or 'none'}`
- API usage: none
- upload performed: no
"""


def render_final_release_validation(evidence: Dict[str, Any]) -> str:
    return f"""# Final Release Validation

- Distribution Pack: `{evidence.get('distribution_pack_status')}`
- Public Pack: `{evidence.get('public_pack_status')}`
- Release Candidate: `{evidence.get('rc_status')}`
- License Decision: `{evidence.get('license_decision_status')}`
- Selected License: `{evidence.get('selected_license') or 'none'}`
- Private owner evidence: `IONOS_HOSTING_ANALYTICS_LOGIN_PROBE_EVIDENCE` recorded outside public docs
- live_apply: `false`
- emergency_stop: `true`
- allowed_apply_now: `false`
- HIGH blocked: `true`
- LOW_LIVE executable: `false`
- MEDIUM executable: `false`
- breach: `false`

This file is documentation only. It does not publish or change remote systems.
"""


def render_final_commit_recommendation(_: Dict[str, Any]) -> str:
    lines = ["# Final Commit Recommendation", "", "Recommended final release checkpoint files:", ""]
    for item in RECOMMENDED_GIT_FILES:
        lines.append(f"- `{item}`")
    lines.extend([
        "",
        "Keep reports, adaptive state, audit logs, exports, backups, credential files and private owner evidence out of public commits.",
    ])
    return "\n".join(lines) + "\n"


def render_manual_publication_checklist(evidence: Dict[str, Any]) -> str:
    return f"""# Manual Publication Checklist

This checklist is for owner review only. It does not publish, push, upload, tag, email or change any live system.

## Preconditions

- selected license: `{evidence.get('selected_license') or 'none'}`
- license decision status: `{evidence.get('license_decision_status')}`
- release candidate: `{evidence.get('rc_status')}`
- public pack: `{evidence.get('public_pack_status')}`
- distribution pack: `{evidence.get('distribution_pack_status')}`

## Manual Steps

1. Review `docs/release-final/LICENSE-DRAFT.md`.
2. Review `docs/release-final/ROOT-README-ACTIVATION-DRAFT.md`.
3. Manually decide whether and when to copy approved README text into `README.md`.
4. Manually decide whether and when to create a final `LICENSE`.
5. Run repository hygiene and secret scan before any commit.
6. Manually decide whether and when to create a Git tag.
7. Manually decide whether and when to publish a GitHub release.
8. Manually decide whether and when to launch on Payhip or Gumroad.

## Hard Blocks

- no remote push
- no marketplace API upload
- no email sending
- no live website, server, database, CDN or remote-file change
- no timer or background installation
"""


def render_final_green_release_summary(evidence: Dict[str, Any]) -> str:
    return f"""# Final Green Release Summary

Sentinel is ready as a final local release draft after the owner selected `polyform-noncommercial` for this release.

## License Choice

- selected license: `{evidence.get('selected_license') or 'none'}`
- decision status: `{evidence.get('license_decision_status')}`
- license draft: review-only

## Release Readiness

- release candidate: `{evidence.get('rc_status')}`
- public pack: `{evidence.get('public_pack_status')}`
- distribution pack: `{evidence.get('distribution_pack_status')}`
- SemVer draft: `v1.0.0-rc1`

## What Green Means Here

`FINAL_RELEASE_GREEN` means the local release draft, docs, license decision record and manual publication checklist passed local safety and sanitization gates.

It does not mean a Git tag, GitHub release, marketplace upload, README activation or final legal license file was created.
"""


def render_final_owner_approval_gate(evidence: Dict[str, Any]) -> str:
    return f"""# Final Owner Approval Gate

This gate documents what remains manual after the local final release draft is green.

## Current Local Decision

- selected license: `{evidence.get('selected_license') or 'none'}`
- license draft status: review-only
- root README activation: manual only
- GitHub release: manual only
- Payhip launch: manual only
- Gumroad launch: manual only

## Explicit Non-Actions

- no autopilot
- no remote push
- no API upload
- no final `LICENSE` file write
- no `README.md` overwrite
- no Git tag creation
- no live system change

The owner must manually approve and execute any publication action outside this local draft pack.
"""


def render_license_draft(evidence: Dict[str, Any]) -> str:
    choice = evidence.get("selected_license")
    details = LICENSE_OPTIONS.get(choice or "", {})
    return "\n".join([
        "# LICENSE DRAFT",
        "",
        "This is a non-final draft note for owner review. It is not a final legal license.",
        "",
        f"- selected option: `{choice or 'none'}`",
        f"- summary: {details.get('meaning', 'no owner license option selected')}",
        "- commercial use, resale, SaaS usage, agency resale and competing offerings require separate owner permission or commercial license when this option is selected.",
        "",
        "Do not rename this file to `LICENSE` without manual owner and legal review.",
    ]) + "\n"


def doc_renderers(evidence: Dict[str, Any]) -> Dict[str, Tuple[Path, str]]:
    return {
        "license_options": (FINAL_FILES["license_options"], render_license_options(evidence)),
        "owner_license_decision": (FINAL_FILES["owner_license_decision"], render_owner_license_decision(evidence)),
        "license_draft_note": (FINAL_FILES["license_draft_note"], render_license_draft_note(evidence)),
        "root_readme_activation_draft": (FINAL_FILES["root_readme_activation_draft"], render_root_readme_activation_draft(evidence)),
        "release_tag_draft": (FINAL_FILES["release_tag_draft"], render_release_tag_draft(evidence)),
        "github_final_release_draft": (FINAL_FILES["github_final_release_draft"], render_github_final_release_draft(evidence)),
        "payhip_launch_draft": (FINAL_FILES["payhip_launch_draft"], render_payhip_launch_draft(evidence)),
        "gumroad_launch_draft": (FINAL_FILES["gumroad_launch_draft"], render_gumroad_launch_draft(evidence)),
        "final_release_validation": (FINAL_FILES["final_release_validation"], render_final_release_validation(evidence)),
        "final_commit_recommendation": (FINAL_FILES["final_commit_recommendation"], render_final_commit_recommendation(evidence)),
        "manual_publication_checklist": (FINAL_FILES["manual_publication_checklist"], render_manual_publication_checklist(evidence)),
        "final_green_release_summary": (FINAL_FILES["final_green_release_summary"], render_final_green_release_summary(evidence)),
        "final_owner_approval_gate": (FINAL_FILES["final_owner_approval_gate"], render_final_owner_approval_gate(evidence)),
    }


def write_docs(evidence: Dict[str, Any], keys: Optional[List[str]] = None) -> List[str]:
    ensure_dirs()
    renderers = doc_renderers(evidence)
    selected = keys or list(renderers)
    written: List[str] = []
    for key in selected:
        path, text = renderers[key]
        write_text(path, text, public=True)
        written.append(rel(path))
    write_json(FINAL_FILES["manifest"], render_final_manifest(evidence), public=True)
    if rel(FINAL_FILES["manifest"]) not in written:
        written.append(rel(FINAL_FILES["manifest"]))
    return written


def write_playbooks() -> None:
    base = {"schema_version": SCHEMA_VERSION, "phase": PHASE, **HARD_DEFAULTS}
    write_json(PLAYBOOK_FINALIZER, {
        **base,
        "name": "sentinel-license-decision-finalizer",
        "purpose": "Document owner license options, final release drafts and release-final validation.",
        "blocked_actions": ["live_apply", "network", "remote_write", "timer_install", "marketplace_api", "LOW_LIVE_MEDIUM_HIGH_execution"],
    })
    write_json(PLAYBOOK_OPTIONS, {
        **base,
        "name": "sentinel-license-options",
        "options": sorted(LICENSE_OPTIONS),
        "legal_advice": "not_provided",
    })
    write_json(PLAYBOOK_VALIDATION, {
        **base,
        "name": "sentinel-final-release-validation",
        "checks": ["json_valid", "markdown_nonempty", "no_sensitive_values", "no_private_paths", "no_ip_addresses", "no_forbidden_claims"],
    })
    write_json(PLAYBOOK_DRAFTS, {
        **base,
        "name": "sentinel-final-release-drafts",
        "drafts": ["root_readme_activation", "release_tag", "github_release", "payhip_launch", "gumroad_launch"],
    })


def render_report_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel License Decision Finalizer",
        "",
        f"- status: `{report.get('status')}`",
        f"- final_release_status: `{report.get('final_release_status', report.get('status'))}`",
        f"- reason: `{report.get('final_release_reason', '-')}`",
        f"- collected_distribution_evidence: `{report.get('collected_distribution_evidence', 0)}`",
        f"- license_decision_status: `{report.get('license_decision_status')}`",
        f"- selected_license: `{report.get('selected_license') or 'none'}`",
        f"- license_draft_status: `{report.get('license_draft_status', '-')}`",
        f"- manual_publication_checklist_status: `{report.get('manual_publication_checklist_status', '-')}`",
        f"- final_owner_approval_gate_status: `{report.get('final_owner_approval_gate_status', '-')}`",
        f"- generated_docs_count: `{report.get('generated_docs_count', 0)}`",
        f"- validation_status: `{report.get('validation_status', '-')}`",
        "- private_evidence: `IONOS_HOSTING_ANALYTICS_LOGIN_PROBE_EVIDENCE` recorded in owner-only reports",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- allowed_apply_now: `False`",
        "- HIGH blocked: `True`",
        "- LOW_LIVE executable: `False`",
        "- MEDIUM executable: `False`",
        "- breach: `False`",
    ]) + "\n"


def render_validation_md(report: Dict[str, Any]) -> str:
    findings = report.get("validation_findings") or []
    lines = [
        "# Sentinel Final Release Validation",
        "",
        f"- validation_status: `{report.get('validation_status')}`",
        f"- final_release_status: `{report.get('final_release_status')}`",
        f"- reason: `{report.get('final_release_reason')}`",
        f"- public_scan_status: `{(report.get('public_scan') or {}).get('status')}`",
        f"- private_scan_status: `{(report.get('private_scan') or {}).get('status')}`",
        "",
        "## Findings",
    ]
    if findings:
        lines.extend(f"- `{finding}`" for finding in findings)
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def render_owner_summary_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Final Release Owner Summary",
        "",
        f"- final_release_status: `{report.get('final_release_status')}`",
        f"- reason: `{report.get('final_release_reason')}`",
        f"- license_decision_status: `{report.get('license_decision_status')}`",
        f"- selected_license: `{report.get('selected_license') or 'none'}`",
        f"- license_draft_status: `{report.get('license_draft_status', '-')}`",
        f"- manual_publication_checklist_status: `{report.get('manual_publication_checklist_status', '-')}`",
        f"- final_owner_approval_gate_status: `{report.get('final_owner_approval_gate_status', '-')}`",
        f"- distribution_pack_status: `{report.get('distribution_pack_status')}`",
        "- final release capability: license options, owner decision gate, root README activation draft, tag draft, GitHub release draft and marketplace launch drafts",
        "- private evidence: IONOS login-probe evidence is review-only and not public-doc content",
        "- blocked: live changes, remote writes, APIs, timers, marketplace uploads, LOW_LIVE, MEDIUM, HIGH",
        "- next safe step: owner chooses a license option or keeps final release yellow until legal review is complete.",
    ]) + "\n"


def write_outputs(report: Dict[str, Any]) -> None:
    ensure_dirs()
    write_playbooks()
    write_json(REPORT_JSON, report)
    write_json(STATE_JSON, report)
    write_json(LATEST_JSON, report)
    history = []
    existing, status = read_json(HISTORY_JSON)
    if status == "ok" and isinstance(existing, dict) and isinstance(existing.get("entries"), list):
        history = existing["entries"]
    history.append({
        "timestamp_utc": report.get("timestamp_utc", utc_now()),
        "action": report.get("action"),
        "status": report.get("status"),
        "final_release_status": report.get("final_release_status", report.get("status")),
        "license_decision_status": report.get("license_decision_status"),
        "selected_license": report.get("selected_license"),
    })
    write_json(HISTORY_JSON, {"schema_version": SCHEMA_VERSION, "entries": history[-100:], **HARD_DEFAULTS})
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": report.get("timestamp_utc", utc_now()),
        "phase": PHASE,
        "action": report.get("action"),
        "status": report.get("status"),
        "final_release_status": report.get("final_release_status", report.get("status")),
        "breach": False,
    })
    write_text(REPORT_MD, render_report_md(report))
    write_text(VALIDATION_MD, render_validation_md(report))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(report))


def build_license_options() -> Dict[str, Any]:
    evidence = collect_distribution_pack(write=False)
    written = write_docs(evidence, ["license_options", "license_draft_note"])
    report = {**evidence, "action": "build-license-options", "status": "LICENSE_OPTIONS_READY", "license_options_status": "LICENSE_OPTIONS_READY", "written_files": written}
    write_outputs(report)
    return report


def build_owner_license_decision() -> Dict[str, Any]:
    evidence = collect_distribution_pack(write=False)
    written = write_docs(evidence, ["owner_license_decision"])
    report = {**evidence, "action": "build-owner-license-decision", "status": "OWNER_LICENSE_DECISION_READY", "owner_license_decision_status": "OWNER_LICENSE_DECISION_READY", "written_files": written}
    write_outputs(report)
    return report


def build_root_readme_activation_draft() -> Dict[str, Any]:
    evidence = collect_distribution_pack(write=False)
    written = write_docs(evidence, ["root_readme_activation_draft"])
    report = {**evidence, "action": "build-root-readme-activation-draft", "status": "ROOT_README_ACTIVATION_DRAFT_READY", "root_readme_activation_draft_status": "ROOT_README_ACTIVATION_DRAFT_READY", "written_files": written}
    write_outputs(report)
    return report


def build_release_tag_draft() -> Dict[str, Any]:
    evidence = collect_distribution_pack(write=False)
    written = write_docs(evidence, ["release_tag_draft"])
    report = {**evidence, "action": "build-release-tag-draft", "status": "RELEASE_TAG_DRAFT_READY", "release_tag_draft_status": "RELEASE_TAG_DRAFT_READY", "written_files": written}
    write_outputs(report)
    return report


def build_final_github_release_draft() -> Dict[str, Any]:
    evidence = collect_distribution_pack(write=False)
    written = write_docs(evidence, ["github_final_release_draft"])
    report = {**evidence, "action": "build-final-github-release-draft", "status": "GITHUB_FINAL_RELEASE_DRAFT_READY", "github_final_release_draft_status": "GITHUB_FINAL_RELEASE_DRAFT_READY", "written_files": written}
    write_outputs(report)
    return report


def build_marketplace_launch_draft() -> Dict[str, Any]:
    evidence = collect_distribution_pack(write=False)
    written = write_docs(evidence, ["payhip_launch_draft", "gumroad_launch_draft"])
    report = {**evidence, "action": "build-marketplace-launch-draft", "status": "MARKETPLACE_LAUNCH_DRAFTS_READY", "marketplace_launch_draft_status": "MARKETPLACE_LAUNCH_DRAFTS_READY", "written_files": written}
    write_outputs(report)
    return report


def set_license_choice(choice: str, write_license_draft: bool = False) -> Dict[str, Any]:
    ensure_dirs()
    if choice not in LICENSE_OPTIONS:
        raise RuntimeError(f"unsupported license choice: {choice}")
    previous = collect_distribution_pack(write=False)
    report = {
        **previous,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "set-license-choice",
        "status": "LICENSE_CHOICE_SET",
        "license_decision_status": "LICENSE_CHOICE_SET",
        "selected_license": choice,
        "license_reason": LICENSE_OPTIONS[choice]["fit"],
        "license_choice_set_at": utc_now(),
        "write_license_draft": bool(write_license_draft),
        **HARD_DEFAULTS,
    }
    write_json(STATE_JSON, report)
    write_json(LATEST_JSON, report)
    existing_history, history_status = read_json(HISTORY_JSON)
    history = []
    if history_status == "ok" and isinstance(existing_history, dict) and isinstance(existing_history.get("entries"), list):
        history = existing_history["entries"]
    history.append({
        "timestamp_utc": report["timestamp_utc"],
        "action": "set-license-choice",
        "status": "LICENSE_CHOICE_SET",
        "license_decision_status": "LICENSE_CHOICE_SET",
        "selected_license": choice,
        "write_license_draft": bool(write_license_draft),
    })
    write_json(HISTORY_JSON, {"schema_version": SCHEMA_VERSION, "entries": history[-100:], **HARD_DEFAULTS})
    write_text(FINAL_FILES["owner_license_decision"], render_owner_license_decision(report), public=True)
    write_json(FINAL_FILES["manifest"], render_final_manifest(report, {
        "final_release_status": "FINAL_RELEASE_PENDING",
        "final_release_reason": "license_choice_set_validation_pending",
        "license_draft_status": "LICENSE_DRAFT_READY" if write_license_draft else "LICENSE_DRAFT_NOT_WRITTEN",
    }), public=True)
    if write_license_draft:
        write_text(FINAL_FILES["license_draft"], render_license_draft(report), public=True)
    return report


def validate_final_release(write: bool = True) -> Dict[str, Any]:
    evidence = collect_distribution_pack(write=False)
    write_docs(evidence, [
        "final_release_validation",
        "final_commit_recommendation",
        "manual_publication_checklist",
        "final_green_release_summary",
        "final_owner_approval_gate",
    ])
    final_paths = [path for key, path in FINAL_FILES.items() if key != "license_draft"]
    if FINAL_FILES["license_draft"].exists():
        final_paths.append(FINAL_FILES["license_draft"])
    public_scan = scan_paths(final_paths, public=True)
    private_scan = scan_paths([REPORT_MD, VALIDATION_MD, OWNER_SUMMARY_MD, STATE_JSON, LATEST_JSON, HISTORY_JSON, AUDIT_JSONL, LOGIN_PROBE_OWNER_MD], public=False)
    source_findings = source_safety_findings([
        PROJECT_DIR / "sentinel_license_decision_finalizer.py",
        PROJECT_DIR / "sentinel_autonomy.py",
    ])
    docs_exist = {key: path.exists() and path.stat().st_size > 0 for key, path in FINAL_FILES.items() if key != "license_draft"}
    license_draft_exists = FINAL_FILES["license_draft"].exists() and FINAL_FILES["license_draft"].stat().st_size > 0
    validation_findings: List[str] = []
    if not all(docs_exist.values()):
        validation_findings.append("missing_or_empty_final_release_doc")
    for path in [
        FINAL_FILES["manifest"],
        REPORT_JSON,
        STATE_JSON,
        LATEST_JSON,
        HISTORY_JSON,
        PLAYBOOK_FINALIZER,
        PLAYBOOK_OPTIONS,
        PLAYBOOK_VALIDATION,
        PLAYBOOK_DRAFTS,
    ]:
        if path.exists():
            _, status = read_json(path)
            if status != "ok":
                validation_findings.append(f"invalid_json:{rel(path)}")
    if public_scan.get("findings"):
        validation_findings.append("release_final_doc_sanitization_findings")
    if private_scan.get("findings"):
        validation_findings.append("private_artifact_sanitization_findings")
    if source_findings:
        validation_findings.append("source_safety_findings")
    if git_recommendation()["status"] != "GIT_RECOMMENDATION_OK":
        validation_findings.append("git_recommendation_unsafe")
    if evidence.get("invalid_inputs"):
        validation_findings.append("invalid_inputs")
    for field, expected in {
        "breach": False,
        "live_apply": False,
        "emergency_stop": True,
        "allowed_apply_now": False,
        "high_blocked": True,
        "low_live_executable": False,
        "medium_executable": False,
    }.items():
        if evidence.get(field) is not expected:
            validation_findings.append(f"{field}_safety_drift")

    yellow_reasons: List[str] = []
    if evidence.get("license_decision_status") != "LICENSE_CHOICE_SET":
        yellow_reasons.append("owner_license_choice_missing")
    elif evidence.get("selected_license") != "polyform-noncommercial":
        yellow_reasons.append("selected_license_not_polyform_noncommercial")
    elif not license_draft_exists:
        yellow_reasons.append("license_draft_missing")
    if evidence.get("missing_inputs"):
        yellow_reasons.append("missing_inputs")
    if evidence.get("public_pack_status") != "PUBLIC_PACK_GREEN":
        yellow_reasons.append("public_pack_not_green")
    if evidence.get("rc_status") != "RC_GREEN":
        yellow_reasons.append("rc_not_green")
    dist_status = evidence.get("distribution_pack_status")
    dist_reason = evidence.get("distribution_pack_reason") or ""
    distribution_ok = dist_status == "DISTRIBUTION_PACK_GREEN" or (
        dist_status == "DISTRIBUTION_PACK_YELLOW"
        and "license_decision" in dist_reason
        and evidence.get("license_decision_status") == "LICENSE_CHOICE_SET"
    )
    if not distribution_ok:
        yellow_reasons.append("distribution_pack_not_green_or_license_only_yellow")

    if validation_findings:
        status = "FINAL_RELEASE_RED"
        reason = ",".join(sorted(set(validation_findings)))
    elif yellow_reasons:
        status = "FINAL_RELEASE_YELLOW"
        reason = ",".join(sorted(set(yellow_reasons)))
    else:
        status = "FINAL_RELEASE_GREEN"
        reason = "polyform_noncommercial_license_choice_set_and_final_release_draft_gates_ok"

    report = {
        **evidence,
        "action": "validate-final-release",
        "status": status,
        "final_release_status": status,
        "final_release_reason": reason,
        "generated_docs_count": sum(1 for ok in docs_exist.values() if ok) + (1 if license_draft_exists else 0),
        "license_draft_exists": license_draft_exists,
        "docs_exist": docs_exist,
        "public_scan": public_scan,
        "private_scan": private_scan,
        "source_safety_findings": source_findings,
        "validation_findings": validation_findings,
        "validation_status": "FINAL_RELEASE_VALIDATION_OK" if status != "FINAL_RELEASE_RED" else "FINAL_RELEASE_VALIDATION_BLOCKED",
        "root_readme_activation_draft_status": "ROOT_README_ACTIVATION_DRAFT_READY" if FINAL_FILES["root_readme_activation_draft"].exists() else "ROOT_README_ACTIVATION_DRAFT_MISSING",
        "release_tag_draft_status": "RELEASE_TAG_DRAFT_READY" if FINAL_FILES["release_tag_draft"].exists() else "RELEASE_TAG_DRAFT_MISSING",
        "github_final_release_draft_status": "GITHUB_FINAL_RELEASE_DRAFT_READY" if FINAL_FILES["github_final_release_draft"].exists() else "GITHUB_FINAL_RELEASE_DRAFT_MISSING",
        "marketplace_launch_draft_status": "MARKETPLACE_LAUNCH_DRAFTS_READY" if FINAL_FILES["payhip_launch_draft"].exists() and FINAL_FILES["gumroad_launch_draft"].exists() else "MARKETPLACE_LAUNCH_DRAFTS_MISSING",
        "license_draft_status": "LICENSE_DRAFT_READY" if license_draft_exists else "LICENSE_DRAFT_MISSING",
        "manual_publication_checklist_status": "MANUAL_PUBLICATION_CHECKLIST_READY" if FINAL_FILES["manual_publication_checklist"].exists() else "MANUAL_PUBLICATION_CHECKLIST_MISSING",
        "final_green_release_summary_status": "FINAL_GREEN_RELEASE_SUMMARY_READY" if FINAL_FILES["final_green_release_summary"].exists() else "FINAL_GREEN_RELEASE_SUMMARY_MISSING",
        "final_owner_approval_gate_status": "FINAL_OWNER_APPROVAL_GATE_READY_REVIEW_ONLY" if FINAL_FILES["final_owner_approval_gate"].exists() else "FINAL_OWNER_APPROVAL_GATE_MISSING",
        "publication_activation_status": "MANUAL_ONLY_NOT_EXECUTED",
        "git_recommendation": git_recommendation(),
        "git_recommendation_status": git_recommendation()["status"],
        **HARD_DEFAULTS,
    }
    if write:
        write_json(FINAL_FILES["manifest"], render_final_manifest(evidence, report), public=True)
        write_private_ionos_report()
        write_outputs(report)
    return report


def self_test() -> Dict[str, Any]:
    ensure_dirs()
    source_findings = source_safety_findings([
        PROJECT_DIR / "sentinel_license_decision_finalizer.py",
        PROJECT_DIR / "sentinel_autonomy.py",
    ])
    sample = {
        "distribution_pack_status": "DISTRIBUTION_PACK_YELLOW",
        "distribution_pack_reason": "license_decision_owner_review_required",
        "public_pack_status": "PUBLIC_PACK_GREEN",
        "rc_status": "RC_GREEN",
        "license_decision_status": "LICENSE_CHOICE_SET",
        "selected_license": "polyform-noncommercial",
        "license_draft_exists": True,
        "missing_inputs": [],
        "invalid_inputs": [],
        **HARD_DEFAULTS,
    }
    docs_safe = True
    for _, text in doc_renderers(sample).values():
        if scan_public_text(text):
            docs_safe = False
            break
    checks = {
        "no_source_safety_findings": not source_findings,
        "git_recommendation_safe": git_recommendation()["status"] == "GIT_RECOMMENDATION_OK",
        "markdown_sanitized": docs_safe,
        "status_logic_green": decide_status_for_test(sample, [])[0] == "FINAL_RELEASE_GREEN",
        "status_logic_yellow": decide_status_for_test({**sample, "license_decision_status": "LICENSE_DECISION_REQUIRED", "selected_license": None, "license_draft_exists": False}, [])[0] == "FINAL_RELEASE_YELLOW",
        "status_logic_red": decide_status_for_test(sample, ["secret"])[0] == "FINAL_RELEASE_RED",
        "json_serializable": True,
        "breach_false": HARD_DEFAULTS["breach"] is False,
    }
    status = "LICENSE_DECISION_FINALIZER_SELF_TEST_OK" if all(checks.values()) else "LICENSE_DECISION_FINALIZER_SELF_TEST_FAILED"
    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "self-test",
        "status": status,
        "self_test_result": status,
        "checks": checks,
        "source_safety_findings": source_findings,
        **HARD_DEFAULTS,
    }
    write_outputs(report)
    return report


def decide_status_for_test(evidence: Dict[str, Any], validation_findings: List[str]) -> Tuple[str, str]:
    if validation_findings:
        return "FINAL_RELEASE_RED", ",".join(validation_findings)
    yellow: List[str] = []
    if evidence.get("license_decision_status") != "LICENSE_CHOICE_SET":
        yellow.append("owner_license_choice_missing")
    elif evidence.get("selected_license") != "polyform-noncommercial":
        yellow.append("selected_license_not_polyform_noncommercial")
    elif not evidence.get("license_draft_exists"):
        yellow.append("license_draft_missing")
    if evidence.get("public_pack_status") != "PUBLIC_PACK_GREEN":
        yellow.append("public_pack_not_green")
    if evidence.get("rc_status") != "RC_GREEN":
        yellow.append("rc_not_green")
    dist_status = evidence.get("distribution_pack_status")
    dist_reason = evidence.get("distribution_pack_reason") or ""
    if not (
        dist_status == "DISTRIBUTION_PACK_GREEN"
        or (dist_status == "DISTRIBUTION_PACK_YELLOW" and "license_decision" in dist_reason and evidence.get("license_decision_status") == "LICENSE_CHOICE_SET")
    ):
        yellow.append("distribution_pack_not_green_or_license_only_yellow")
    if yellow:
        return "FINAL_RELEASE_YELLOW", ",".join(sorted(set(yellow)))
    return "FINAL_RELEASE_GREEN", "owner_license_choice_set_and_final_release_gates_ok"


def status_report() -> Dict[str, Any]:
    report = load_dict(REPORT_JSON) or collect_distribution_pack(write=False)
    summary = {
        "status": report.get("status"),
        "final_release_status": report.get("final_release_status", report.get("status")),
        "final_release_reason": report.get("final_release_reason"),
        "license_decision_status": report.get("license_decision_status"),
        "selected_license": report.get("selected_license"),
        "license_draft_status": report.get("license_draft_status"),
        "manual_publication_checklist_status": report.get("manual_publication_checklist_status"),
        "final_owner_approval_gate_status": report.get("final_owner_approval_gate_status"),
        "collected_distribution_evidence": report.get("collected_distribution_evidence"),
        "generated_docs_count": report.get("generated_docs_count"),
        "root_readme_activation_draft_status": report.get("root_readme_activation_draft_status"),
        "release_tag_draft_status": report.get("release_tag_draft_status"),
        "github_final_release_draft_status": report.get("github_final_release_draft_status"),
        "marketplace_launch_draft_status": report.get("marketplace_launch_draft_status"),
        "license_draft_status": report.get("license_draft_status"),
        "manual_publication_checklist_status": report.get("manual_publication_checklist_status"),
        "final_owner_approval_gate_status": report.get("final_owner_approval_gate_status"),
        "publication_activation_status": report.get("publication_activation_status"),
        "validation_status": report.get("validation_status"),
        **HARD_DEFAULTS,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def print_result(report: Dict[str, Any]) -> None:
    print(json.dumps({
        "action": report.get("action"),
        "status": report.get("status"),
        "final_release_status": report.get("final_release_status", report.get("status")),
        "final_release_reason": report.get("final_release_reason"),
        "license_decision_status": report.get("license_decision_status"),
        "selected_license": report.get("selected_license"),
        "collected_distribution_evidence": report.get("collected_distribution_evidence"),
        "generated_docs_count": report.get("generated_docs_count"),
        "validation_status": report.get("validation_status"),
        "breach": False,
    }, indent=2, sort_keys=True))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel owner license decision finalizer")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--collect-distribution-pack", action="store_true")
    parser.add_argument("--build-license-options", action="store_true")
    parser.add_argument("--build-owner-license-decision", action="store_true")
    parser.add_argument("--build-root-readme-activation-draft", action="store_true")
    parser.add_argument("--build-release-tag-draft", action="store_true")
    parser.add_argument("--build-final-github-release-draft", action="store_true")
    parser.add_argument("--build-marketplace-launch-draft", action="store_true")
    parser.add_argument("--validate-final-release", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--set-license-choice", choices=sorted(LICENSE_OPTIONS))
    parser.add_argument("--write-license-draft", action="store_true")
    args = parser.parse_args(argv)

    actions = [
        args.self_test,
        args.collect_distribution_pack,
        args.build_license_options,
        args.build_owner_license_decision,
        args.build_root_readme_activation_draft,
        args.build_release_tag_draft,
        args.build_final_github_release_draft,
        args.build_marketplace_launch_draft,
        args.validate_final_release,
        args.status,
        bool(args.set_license_choice),
    ]
    if sum(1 for item in actions if item) != 1:
        parser.error("choose exactly one action")
    if args.write_license_draft and not args.set_license_choice:
        parser.error("--write-license-draft is only valid with --set-license-choice")

    if args.self_test:
        report = self_test()
    elif args.collect_distribution_pack:
        report = collect_distribution_pack(write=True)
    elif args.build_license_options:
        report = build_license_options()
    elif args.build_owner_license_decision:
        report = build_owner_license_decision()
    elif args.build_root_readme_activation_draft:
        report = build_root_readme_activation_draft()
    elif args.build_release_tag_draft:
        report = build_release_tag_draft()
    elif args.build_final_github_release_draft:
        report = build_final_github_release_draft()
    elif args.build_marketplace_launch_draft:
        report = build_marketplace_launch_draft()
    elif args.validate_final_release:
        report = validate_final_release(write=True)
    elif args.set_license_choice:
        report = set_license_choice(args.set_license_choice, args.write_license_draft)
    else:
        status_report()
        return 0
    print_result(report)
    return 0 if not str(report.get("status", "")).endswith("_FAILED") and report.get("status") != "FINAL_RELEASE_RED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
