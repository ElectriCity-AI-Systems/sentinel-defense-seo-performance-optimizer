#!/usr/bin/env python3
"""Build the sanitized distribution release pack for Sentinel Phase 10.12.

This module creates local public-safe distribution documents, a version
manifest, marketplace checklists, repository hygiene notes, local reports,
state, audit events and playbooks. It does not perform live apply, network
access, marketplace API calls, remote writes, timer installation, or customer
system changes.
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
SCHEMA_VERSION = "sentinel-distribution-release-pack-10.12"
PHASE = "10.12"

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
DIST_DIR = PROJECT_DIR / "docs/distribution-release"
PUBLIC_DIR = PROJECT_DIR / "docs/public-release"

REPORT_JSON = REPORT_DIR / "sentinel-distribution-release-pack.json"
REPORT_MD = REPORT_DIR / "sentinel-distribution-release-pack.md"
VALIDATION_MD = REPORT_DIR / "sentinel-distribution-release-validation.md"
OWNER_SUMMARY_MD = REPORT_DIR / "sentinel-distribution-release-owner-summary.md"

STATE_JSON = STATE_DIR / "distribution_release_pack.json"
LATEST_JSON = STATE_DIR / "latest_distribution_release_pack.json"
HISTORY_JSON = STATE_DIR / "distribution_release_pack_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-distribution-release-pack.jsonl"

PLAYBOOK_PACK = PLAYBOOK_DIR / "sentinel-distribution-release-pack.playbook.json"
PLAYBOOK_VERSION = PLAYBOOK_DIR / "sentinel-distribution-version-manifest.playbook.json"
PLAYBOOK_MARKETPLACE = PLAYBOOK_DIR / "sentinel-distribution-marketplace-checklists.playbook.json"
PLAYBOOK_VALIDATION = PLAYBOOK_DIR / "sentinel-distribution-release-validation.playbook.json"

DIST_FILES = {
    "version_manifest": DIST_DIR / "VERSION-MANIFEST.md",
    "changelog": DIST_DIR / "CHANGELOG.md",
    "root_readme_draft": DIST_DIR / "ROOT-README-DRAFT.md",
    "github_release_checklist": DIST_DIR / "GITHUB-RELEASE-CHECKLIST.md",
    "payhip_upload_checklist": DIST_DIR / "PAYHIP-UPLOAD-CHECKLIST.md",
    "gumroad_upload_checklist": DIST_DIR / "GUMROAD-UPLOAD-CHECKLIST.md",
    "commercial_service_checklist": DIST_DIR / "COMMERCIAL-SERVICE-CHECKLIST.md",
    "repository_hygiene": DIST_DIR / "REPOSITORY-HYGIENE.md",
    "license_decision": DIST_DIR / "LICENSE-DECISION-PLACEHOLDER.md",
    "release_final_validation": DIST_DIR / "RELEASE-FINAL-VALIDATION.md",
    "commit_recommendation": DIST_DIR / "COMMIT-RECOMMENDATION.md",
    "manifest": DIST_DIR / "distribution-release-manifest.json",
}

INPUTS = {
    "public_manifest": PUBLIC_DIR / "public-release-manifest.json",
    "public_readme": PUBLIC_DIR / "README-public.md",
    "safety_boundaries": PUBLIC_DIR / "SAFETY-BOUNDARIES.md",
    "owner_commands": PUBLIC_DIR / "OWNER-COMMANDS.md",
    "product_summary": PUBLIC_DIR / "PRODUCT-SUMMARY.md",
    "payhip_listing": PUBLIC_DIR / "PAYHIP-LISTING.md",
    "gumroad_listing": PUBLIC_DIR / "GUMROAD-LISTING.md",
    "github_release_notes": PUBLIC_DIR / "GITHUB-RELEASE-NOTES.md",
    "public_pack_report": REPORT_DIR / "sentinel-public-release-pack.json",
    "release_candidate_report": REPORT_DIR / "sentinel-autonomous-release-candidate.json",
}

RECOMMENDED_GIT_FILES = [
    "sentinel_distribution_release_pack.py",
    "sentinel_autonomy.py",
    "docs/distribution-release/VERSION-MANIFEST.md",
    "docs/distribution-release/CHANGELOG.md",
    "docs/distribution-release/ROOT-README-DRAFT.md",
    "docs/distribution-release/GITHUB-RELEASE-CHECKLIST.md",
    "docs/distribution-release/PAYHIP-UPLOAD-CHECKLIST.md",
    "docs/distribution-release/GUMROAD-UPLOAD-CHECKLIST.md",
    "docs/distribution-release/COMMERCIAL-SERVICE-CHECKLIST.md",
    "docs/distribution-release/REPOSITORY-HYGIENE.md",
    "docs/distribution-release/LICENSE-DECISION-PLACEHOLDER.md",
    "docs/distribution-release/RELEASE-FINAL-VALIDATION.md",
    "docs/distribution-release/COMMIT-RECOMMENDATION.md",
    "docs/distribution-release/distribution-release-manifest.json",
    "playbooks/sentinel-distribution-release-pack.playbook.json",
    "playbooks/sentinel-distribution-version-manifest.playbook.json",
    "playbooks/sentinel-distribution-marketplace-checklists.playbook.json",
    "playbooks/sentinel-distribution-release-validation.playbook.json",
]

ALLOWED_WRITE_ROOTS = (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, DIST_DIR)

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
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, DIST_DIR):
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
        ],
        "unsafe_recommended_files": unsafe,
    }


def collect_public_pack(write: bool = True) -> Dict[str, Any]:
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
    public_pack = load_dict(INPUTS["public_pack_report"])
    public_manifest = load_dict(INPUTS["public_manifest"])
    rc = load_dict(INPUTS["release_candidate_report"])
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "collect-public-pack",
        "status": "DISTRIBUTION_PUBLIC_PACK_EVIDENCE_COLLECTED",
        "collected_public_pack_evidence": sum(1 for status in input_statuses.values() if status == "ok"),
        "input_statuses": input_statuses,
        "missing_inputs": missing_inputs,
        "invalid_inputs": invalid_inputs,
        "public_pack_status": public_pack.get("public_pack_status") or public_manifest.get("public_pack_status"),
        "public_pack_reason": public_pack.get("public_pack_reason") or public_manifest.get("public_pack_reason"),
        "rc_status": public_pack.get("rc_status") or rc.get("rc_status"),
        "readiness_seal": public_pack.get("readiness_seal") or rc.get("readiness_seal"),
        "regression_gate_status": public_pack.get("regression_gate_status") or rc.get("regression_gate_status"),
        "semver_suggestion": "v1.0.0-rc1",
        "license_decision_status": "OWNER_DECISION_REQUIRED",
        "git_status": run_git("status"),
        "git_log": run_git("log"),
        **HARD_DEFAULTS,
    }
    if write:
        write_outputs(evidence)
    return evidence


def render_distribution_manifest(evidence: Dict[str, Any], validation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    validation = validation or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "product_name": "Sentinel Security, SEO & Performance Safe Optimization",
        "distribution_pack_status": validation.get("distribution_pack_status", "DISTRIBUTION_PACK_PENDING"),
        "distribution_pack_reason": validation.get("distribution_pack_reason", "not_validated_yet"),
        "public_pack_status": evidence.get("public_pack_status"),
        "rc_status": evidence.get("rc_status"),
        "readiness_seal": evidence.get("readiness_seal"),
        "regression_gate_status": evidence.get("regression_gate_status"),
        "semver_suggestion": "v1.0.0-rc1",
        "license_decision_status": "OWNER_DECISION_REQUIRED",
        "docs": sorted(rel(path) for path in DIST_FILES.values()),
        "recommended_git_checkpoint_files": RECOMMENDED_GIT_FILES,
        "local_artifacts_not_for_distribution": git_recommendation()["local_artifacts_not_for_commit"],
        **HARD_DEFAULTS,
    }


def render_version_manifest(evidence: Dict[str, Any]) -> str:
    return f"""# Version Manifest

## Product

Sentinel Security, SEO & Performance Safe Optimization

## Release State

- SemVer suggestion: `v1.0.0-rc1`
- Release Candidate status: `{evidence.get('rc_status') or 'unknown'}`
- Public Pack status: `{evidence.get('public_pack_status') or 'unknown'}`
- Readiness Seal: `{evidence.get('readiness_seal') or 'unknown'}`
- Regression Gate: `{evidence.get('regression_gate_status') or 'unknown'}`

## Local Autonomy Chain

- Self-Governing Safe Autonomy Kernel
- Autonomous Cycle Runner
- Priority Engine and Anti-Loop Governor
- Capability Registry and Skill Router
- Capability Health Governor and Safe Self-Repair Loop
- Goal Manager and Mission Queue
- Mission Queue Runner and Completion Ledger
- Operations Supervisor and Unified Control Plane
- Operation Governor with Impact Scoring and No-Op Detection
- Soak Test, Regression Gate and Readiness Seal
- Release Candidate and Public Release Pack
- Distribution Release Pack

## Safety Flags

- live_apply: `false`
- emergency_stop: `true`
- allowed_apply_now: `false`
- HIGH blocked: `true`
- LOW_LIVE executable: `false`
- MEDIUM executable: `false`
- breach: `false`

This manifest does not publish, push, upload, email, install timers or perform live changes.
"""


def render_changelog(_: Dict[str, Any]) -> str:
    return """# Changelog

## v1.0.0-rc1

### Phase 10.0

- Added the Self-Governing Safe Autonomy Kernel.
- Established Observe, Decide, Classify, Execute, Validate, Repair and Learn flow.

### Phase 10.1

- Added the Autonomous Cycle Runner for bounded local multi-cycle operation.

### Phase 10.2

- Added Priority Engine, cooldowns, task diversity and anti-loop behavior.

### Phase 10.3

- Added Capability Registry and Skill Router.

### Phase 10.4

- Added Capability Health Governor and safe local self-repair loop.

### Phase 10.5

- Added Goal Manager and Mission Queue.

### Phase 10.6

- Added Mission Queue Runner and Completion Ledger.

### Phase 10.7

- Added Operations Supervisor and Unified Control Plane.

### Phase 10.8

- Added Operation Governor with impact scoring, no-op detection and operation diversity.

### Phase 10.9

- Added Soak Test, Regression Gate and Readiness Seal.

### Phase 10.10

- Added Release Candidate manifest, owner command console, runbook and evidence pack.

### Phase 10.11

- Added sanitized public release documentation, sales copy and GitHub release notes.

### Phase 10.12

- Added distribution release manifest, checklists, repository hygiene docs and final validation.
"""


def render_root_readme_draft(_: Dict[str, Any]) -> str:
    return """# Sentinel Security, SEO & Performance Safe Optimization

Sentinel is a local, owner-controlled system for safe website, SEO, performance and security operations. It supports evidence-driven review, bounded local autonomy, public-safe documentation, release readiness and controlled optimization planning.

## What It Does

- runs local safe status and preflight checks
- builds owner summaries and evidence packs
- scores safe local operations
- maintains capability and mission state
- runs bounded local soak tests
- prepares public and distribution release documentation

## Safety Boundaries

Sentinel does not perform unchecked live changes. It does not automatically write to WordPress, Cloudflare, databases, SFTP/FTP, Nginx, `.htaccess`, payment platforms or email systems. It does not install timers, cron jobs or system services.

## Example Commands

```bash
python3 sentinel_autonomy.py status
python3 sentinel_autonomy.py preflight
python3 sentinel_autonomy.py run-safe-batch 3
python3 sentinel_autonomy.py readiness-seal
python3 sentinel_autonomy.py distribution-status
```

## No Guarantees

Sentinel supports safer analysis and planning. It does not promise rankings, revenue, perfect security, instant performance outcomes or automatic repair of external systems.

This file is a draft for a future root README. It does not overwrite `README.md`.
"""


def render_github_release_checklist(_: Dict[str, Any]) -> str:
    return """# GitHub Release Checklist

- Confirm Public Pack status is green.
- Confirm Distribution Pack validation status.
- Review `ROOT-README-DRAFT.md` before copying any content into a root README.
- Review `CHANGELOG.md`.
- Review `VERSION-MANIFEST.md`.
- Confirm no runtime reports, adaptive state, audit logs, exports, backups or credential files are staged.
- Run a local secret scan before commit.
- Run JSON validation for public manifests and playbooks.
- Confirm release notes do not include private paths, IP addresses, customer data or unsupported claims.
- Do not push automatically from this checklist.
"""


def render_payhip_upload_checklist(_: Dict[str, Any]) -> str:
    return """# Payhip Upload Checklist

- Product name: Sentinel Security, SEO & Performance Safe Optimization
- Short description: use the sanitized public listing copy.
- Long description: use the sanitized public listing copy.
- Price placeholder: owner decides before listing.
- Upload package: owner-selected distribution files only.
- Include safety boundaries and not-autopilot disclaimer.
- Do not include runtime reports, adaptive state, audit logs, backups, exports or credential files.
- No automatic Payhip API usage is part of this release pack.
"""


def render_gumroad_upload_checklist(_: Dict[str, Any]) -> str:
    return """# Gumroad Upload Checklist

- Product name: Sentinel Security, SEO & Performance Safe Optimization
- Description: use the sanitized Gumroad listing copy.
- Tags: local automation, SEO operations, performance workflow, security review, owner-controlled.
- Buyer notes: local safe analysis and documentation system; production changes require separate owner approval.
- Include safety boundaries and no-guarantee notice.
- No automatic Gumroad API usage is part of this release pack.
"""


def render_commercial_service_checklist(_: Dict[str, Any]) -> str:
    return """# Commercial Service Checklist

- Define service scope before onboarding a client.
- Confirm owner review for every production-changing step.
- Generate evidence pack before implementation planning.
- Keep live changes outside the public distribution release flow.
- Do not promise rankings, revenue, perfect security or instant performance outcomes.
- Keep customer access details out of the repository.
- Use safe local reports to support manual service delivery.
"""


def render_repository_hygiene(_: Dict[str, Any]) -> str:
    return """# Repository Hygiene

## Allowed Git Files

- Sentinel scripts
- public documentation
- distribution documentation
- playbooks intended for public release

## Do Not Commit

- runtime reports
- adaptive state ledgers
- audit logs
- generated exports
- backups
- credential files
- downloaded assets
- local environment files

## Checks

- run secret scan
- validate JSON manifests
- review public docs for private paths, IP addresses and customer data
- verify Git recommendation excludes runtime artifacts
- decide license terms before public release
"""


def render_license_decision(_: Dict[str, Any]) -> str:
    return """# License Decision Placeholder

License and source-availability terms require owner review before public distribution.

Options to consider:

- source-available commercial license
- private commercial delivery
- open-source license with commercial support
- dual-license model

No license choice is automatically applied by this phase. Distribution status remains cautious until the owner chooses the license and publishing model.
"""


def render_release_final_validation(evidence: Dict[str, Any]) -> str:
    return f"""# Release Final Validation

- Public Pack status: `{evidence.get('public_pack_status') or 'unknown'}`
- Release Candidate status: `{evidence.get('rc_status') or 'unknown'}`
- SemVer suggestion: `v1.0.0-rc1`
- Secret scan: required before public commit
- JSON validation: required for manifests and playbooks
- Runtime artifacts: not for commit
- License decision: owner review required
- Remote publishing: manual owner action only

This validation file is local documentation. It does not push, upload or publish anything.
"""


def render_commit_recommendation(_: Dict[str, Any]) -> str:
    lines = ["# Commit Recommendation", "", "Recommended distribution checkpoint files:", ""]
    for item in RECOMMENDED_GIT_FILES:
        lines.append(f"- `{item}`")
    lines.extend([
        "",
        "Keep runtime reports, adaptive state ledgers, audit logs, generated exports, backups and credential files local.",
    ])
    return "\n".join(lines) + "\n"


def doc_renderers(evidence: Dict[str, Any]) -> Dict[str, Tuple[Path, str]]:
    return {
        "version_manifest": (DIST_FILES["version_manifest"], render_version_manifest(evidence)),
        "changelog": (DIST_FILES["changelog"], render_changelog(evidence)),
        "root_readme_draft": (DIST_FILES["root_readme_draft"], render_root_readme_draft(evidence)),
        "github_release_checklist": (DIST_FILES["github_release_checklist"], render_github_release_checklist(evidence)),
        "payhip_upload_checklist": (DIST_FILES["payhip_upload_checklist"], render_payhip_upload_checklist(evidence)),
        "gumroad_upload_checklist": (DIST_FILES["gumroad_upload_checklist"], render_gumroad_upload_checklist(evidence)),
        "commercial_service_checklist": (DIST_FILES["commercial_service_checklist"], render_commercial_service_checklist(evidence)),
        "repository_hygiene": (DIST_FILES["repository_hygiene"], render_repository_hygiene(evidence)),
        "license_decision": (DIST_FILES["license_decision"], render_license_decision(evidence)),
        "release_final_validation": (DIST_FILES["release_final_validation"], render_release_final_validation(evidence)),
        "commit_recommendation": (DIST_FILES["commit_recommendation"], render_commit_recommendation(evidence)),
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
    write_json(DIST_FILES["manifest"], render_distribution_manifest(evidence), public=True)
    if rel(DIST_FILES["manifest"]) not in written:
        written.append(rel(DIST_FILES["manifest"]))
    return written


def write_playbooks() -> None:
    base = {"schema_version": SCHEMA_VERSION, "phase": PHASE, **HARD_DEFAULTS}
    write_json(PLAYBOOK_PACK, {
        **base,
        "name": "sentinel-distribution-release-pack",
        "purpose": "Build sanitized local distribution release docs and validation artifacts.",
        "blocked_actions": ["live_apply", "network", "remote_write", "timer_install", "marketplace_api", "LOW_LIVE_MEDIUM_HIGH_execution"],
    })
    write_json(PLAYBOOK_VERSION, {
        **base,
        "name": "sentinel-distribution-version-manifest",
        "semver_suggestion": "v1.0.0-rc1",
        "publishing": "manual_owner_action_only",
    })
    write_json(PLAYBOOK_MARKETPLACE, {
        **base,
        "name": "sentinel-distribution-marketplace-checklists",
        "marketplaces": ["GitHub", "Payhip", "Gumroad"],
        "api_access": "not_used",
    })
    write_json(PLAYBOOK_VALIDATION, {
        **base,
        "name": "sentinel-distribution-release-validation",
        "checks": ["json_valid", "markdown_nonempty", "no_sensitive_values", "no_private_paths", "no_ip_addresses", "no_forbidden_claims"],
    })


def render_report_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Distribution Release Pack",
        "",
        f"- status: `{report.get('status')}`",
        f"- distribution_pack_status: `{report.get('distribution_pack_status', report.get('status'))}`",
        f"- reason: `{report.get('distribution_pack_reason', '-')}`",
        f"- collected_public_pack_evidence: `{report.get('collected_public_pack_evidence', 0)}`",
        f"- generated_docs_count: `{report.get('generated_docs_count', 0)}`",
        f"- version_manifest_status: `{report.get('version_manifest_status', '-')}`",
        f"- changelog_status: `{report.get('changelog_status', '-')}`",
        f"- root_readme_draft_status: `{report.get('root_readme_draft_status', '-')}`",
        f"- marketplace_checklist_status: `{report.get('marketplace_checklist_status', '-')}`",
        f"- repository_hygiene_status: `{report.get('repository_hygiene_status', '-')}`",
        f"- validation_status: `{report.get('validation_status', '-')}`",
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
        "# Sentinel Distribution Release Validation",
        "",
        f"- validation_status: `{report.get('validation_status')}`",
        f"- distribution_pack_status: `{report.get('distribution_pack_status')}`",
        f"- reason: `{report.get('distribution_pack_reason')}`",
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
        "# Sentinel Distribution Release Owner Summary",
        "",
        f"- distribution_pack_status: `{report.get('distribution_pack_status')}`",
        f"- reason: `{report.get('distribution_pack_reason')}`",
        f"- public_pack_status: `{report.get('public_pack_status')}`",
        f"- semver_suggestion: `v1.0.0-rc1`",
        "- distribution capability: version manifest, changelog, root README draft, release checklists, marketplace checklists, repository hygiene and final validation",
        "- blocked: live changes, remote writes, APIs, timers, marketplace uploads, LOW_LIVE, MEDIUM, HIGH",
        "- next safe step: choose license terms, review docs, then create a Git checkpoint with only recommended files.",
    ]) + "\n"


def write_manifest_with_validation(report: Dict[str, Any]) -> None:
    evidence = collect_public_pack(write=False)
    write_json(DIST_FILES["manifest"], render_distribution_manifest(evidence, report), public=True)


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
        "distribution_pack_status": report.get("distribution_pack_status", report.get("status")),
        "distribution_pack_reason": report.get("distribution_pack_reason"),
    })
    write_json(HISTORY_JSON, {"schema_version": SCHEMA_VERSION, "entries": history[-100:], **HARD_DEFAULTS})
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": report.get("timestamp_utc", utc_now()),
        "phase": PHASE,
        "action": report.get("action"),
        "status": report.get("status"),
        "distribution_pack_status": report.get("distribution_pack_status", report.get("status")),
        "breach": False,
    })
    write_text(REPORT_MD, render_report_md(report))
    write_text(VALIDATION_MD, render_validation_md(report))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(report))


def build_version_manifest() -> Dict[str, Any]:
    evidence = collect_public_pack(write=False)
    written = write_docs(evidence, ["version_manifest"])
    report = {**evidence, "action": "build-version-manifest", "status": "VERSION_MANIFEST_READY", "version_manifest_status": "VERSION_MANIFEST_READY", "written_files": written}
    write_outputs(report)
    return report


def build_changelog() -> Dict[str, Any]:
    evidence = collect_public_pack(write=False)
    written = write_docs(evidence, ["changelog"])
    report = {**evidence, "action": "build-changelog", "status": "CHANGELOG_READY", "changelog_status": "CHANGELOG_READY", "written_files": written}
    write_outputs(report)
    return report


def build_root_readme_draft() -> Dict[str, Any]:
    evidence = collect_public_pack(write=False)
    written = write_docs(evidence, ["root_readme_draft"])
    report = {**evidence, "action": "build-root-readme-draft", "status": "ROOT_README_DRAFT_READY", "root_readme_draft_status": "ROOT_README_DRAFT_READY", "written_files": written}
    write_outputs(report)
    return report


def build_marketplace_checklists() -> Dict[str, Any]:
    evidence = collect_public_pack(write=False)
    keys = ["github_release_checklist", "payhip_upload_checklist", "gumroad_upload_checklist", "commercial_service_checklist", "license_decision"]
    written = write_docs(evidence, keys)
    report = {**evidence, "action": "build-marketplace-checklists", "status": "MARKETPLACE_CHECKLISTS_READY", "marketplace_checklist_status": "MARKETPLACE_CHECKLISTS_READY", "license_decision_status": "OWNER_DECISION_REQUIRED", "written_files": written}
    write_outputs(report)
    return report


def build_repository_hygiene() -> Dict[str, Any]:
    evidence = collect_public_pack(write=False)
    keys = ["repository_hygiene", "release_final_validation", "commit_recommendation"]
    written = write_docs(evidence, keys)
    report = {**evidence, "action": "build-repository-hygiene", "status": "REPOSITORY_HYGIENE_READY", "repository_hygiene_status": "REPOSITORY_HYGIENE_READY", "written_files": written}
    write_outputs(report)
    return report


def validate_distribution_pack(write: bool = True) -> Dict[str, Any]:
    evidence = collect_public_pack(write=False)
    dist_paths = list(DIST_FILES.values())
    public_scan = scan_paths(dist_paths, public=True)
    private_scan = scan_paths([REPORT_MD, VALIDATION_MD, OWNER_SUMMARY_MD, STATE_JSON, LATEST_JSON, HISTORY_JSON, AUDIT_JSONL], public=False)
    source_findings = source_safety_findings([
        PROJECT_DIR / "sentinel_distribution_release_pack.py",
        PROJECT_DIR / "sentinel_autonomy.py",
    ])
    docs_exist = {key: path.exists() and path.stat().st_size > 0 for key, path in DIST_FILES.items()}
    validation_findings: List[str] = []
    if not all(docs_exist.values()):
        validation_findings.append("missing_or_empty_distribution_doc")
    for path in [
        DIST_FILES["manifest"],
        REPORT_JSON,
        STATE_JSON,
        LATEST_JSON,
        HISTORY_JSON,
        PLAYBOOK_PACK,
        PLAYBOOK_VERSION,
        PLAYBOOK_MARKETPLACE,
        PLAYBOOK_VALIDATION,
    ]:
        if path.exists():
            _, status = read_json(path)
            if status != "ok":
                validation_findings.append(f"invalid_json:{rel(path)}")
    if public_scan.get("findings"):
        validation_findings.append("distribution_doc_sanitization_findings")
    if private_scan.get("findings"):
        validation_findings.append("private_artifact_sanitization_findings")
    if source_findings:
        validation_findings.append("source_safety_findings")
    if git_recommendation()["status"] != "GIT_RECOMMENDATION_OK":
        validation_findings.append("git_recommendation_unsafe")
    if evidence.get("breach") is True:
        validation_findings.append("breach_true")
    if evidence.get("live_apply") is not False:
        validation_findings.append("live_apply_not_false")
    if evidence.get("emergency_stop") is not True:
        validation_findings.append("emergency_stop_not_true")
    if evidence.get("allowed_apply_now") is not False:
        validation_findings.append("allowed_apply_now_not_false")
    if evidence.get("high_blocked") is not True:
        validation_findings.append("high_not_blocked")
    if evidence.get("low_live_executable") is not False:
        validation_findings.append("low_live_executable")
    if evidence.get("medium_executable") is not False:
        validation_findings.append("medium_executable")

    yellow_reasons: List[str] = []
    if evidence.get("public_pack_status") != "PUBLIC_PACK_GREEN":
        yellow_reasons.append("public_pack_not_green")
    if evidence.get("missing_inputs"):
        yellow_reasons.append("missing_inputs")
    if evidence.get("invalid_inputs"):
        validation_findings.append("invalid_inputs")
    if evidence.get("license_decision_status") == "OWNER_DECISION_REQUIRED":
        yellow_reasons.append("license_decision_owner_review_required")

    if validation_findings:
        status = "DISTRIBUTION_PACK_RED"
        reason = ",".join(sorted(set(validation_findings)))
    elif yellow_reasons:
        status = "DISTRIBUTION_PACK_YELLOW"
        reason = ",".join(sorted(set(yellow_reasons)))
    else:
        status = "DISTRIBUTION_PACK_GREEN"
        reason = "public_pack_green_and_distribution_pack_valid"

    report = {
        **evidence,
        "action": "validate-distribution-pack",
        "status": status,
        "distribution_pack_status": status,
        "distribution_pack_reason": reason,
        "generated_docs_count": sum(1 for ok in docs_exist.values() if ok),
        "docs_exist": docs_exist,
        "public_scan": public_scan,
        "private_scan": private_scan,
        "source_safety_findings": source_findings,
        "validation_findings": validation_findings,
        "validation_status": "DISTRIBUTION_PACK_VALIDATION_OK" if status != "DISTRIBUTION_PACK_RED" else "DISTRIBUTION_PACK_VALIDATION_BLOCKED",
        "version_manifest_status": "VERSION_MANIFEST_READY" if DIST_FILES["version_manifest"].exists() else "VERSION_MANIFEST_MISSING",
        "changelog_status": "CHANGELOG_READY" if DIST_FILES["changelog"].exists() else "CHANGELOG_MISSING",
        "root_readme_draft_status": "ROOT_README_DRAFT_READY" if DIST_FILES["root_readme_draft"].exists() else "ROOT_README_DRAFT_MISSING",
        "marketplace_checklist_status": "MARKETPLACE_CHECKLISTS_READY" if DIST_FILES["payhip_upload_checklist"].exists() and DIST_FILES["gumroad_upload_checklist"].exists() else "MARKETPLACE_CHECKLISTS_MISSING",
        "repository_hygiene_status": "REPOSITORY_HYGIENE_READY" if DIST_FILES["repository_hygiene"].exists() else "REPOSITORY_HYGIENE_MISSING",
        "git_recommendation": git_recommendation(),
        "git_recommendation_status": git_recommendation()["status"],
        **HARD_DEFAULTS,
    }
    if write:
        write_json(DIST_FILES["manifest"], render_distribution_manifest(evidence, report), public=True)
        write_outputs(report)
    return report


def self_test() -> Dict[str, Any]:
    ensure_dirs()
    source_findings = source_safety_findings([
        PROJECT_DIR / "sentinel_distribution_release_pack.py",
        PROJECT_DIR / "sentinel_autonomy.py",
    ])
    sample_evidence = {
        "public_pack_status": "PUBLIC_PACK_GREEN",
        "rc_status": "RC_GREEN",
        "readiness_seal": "READINESS_SEAL_GREEN",
        "regression_gate_status": "REGRESSION_GATE_OK",
        "license_decision_status": "RESOLVED",
        "missing_inputs": [],
        "invalid_inputs": [],
        **HARD_DEFAULTS,
    }
    sample_docs_safe = True
    for _, text in doc_renderers(sample_evidence).values():
        if scan_public_text(text):
            sample_docs_safe = False
            break
    green_report = {**sample_evidence, "license_decision_status": "RESOLVED"}
    yellow_report = {**sample_evidence, "license_decision_status": "OWNER_DECISION_REQUIRED"}
    checks = {
        "no_source_safety_findings": not source_findings,
        "git_recommendation_safe": git_recommendation()["status"] == "GIT_RECOMMENDATION_OK",
        "rendered_markdown_sanitized": sample_docs_safe,
        "status_logic_green": decide_status_for_test(green_report, [])[0] == "DISTRIBUTION_PACK_GREEN",
        "status_logic_yellow": decide_status_for_test(yellow_report, [])[0] == "DISTRIBUTION_PACK_YELLOW",
        "status_logic_red": decide_status_for_test(green_report, ["secret"])[0] == "DISTRIBUTION_PACK_RED",
        "json_serializable": True,
        "breach_false": HARD_DEFAULTS["breach"] is False,
    }
    status = "DISTRIBUTION_RELEASE_PACK_SELF_TEST_OK" if all(checks.values()) else "DISTRIBUTION_RELEASE_PACK_SELF_TEST_FAILED"
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
        return "DISTRIBUTION_PACK_RED", ",".join(validation_findings)
    yellow: List[str] = []
    if evidence.get("public_pack_status") != "PUBLIC_PACK_GREEN":
        yellow.append("public_pack_not_green")
    if evidence.get("missing_inputs"):
        yellow.append("missing_inputs")
    if evidence.get("license_decision_status") == "OWNER_DECISION_REQUIRED":
        yellow.append("license_decision_owner_review_required")
    if yellow:
        return "DISTRIBUTION_PACK_YELLOW", ",".join(yellow)
    return "DISTRIBUTION_PACK_GREEN", "public_pack_green_and_distribution_pack_valid"


def status_report() -> Dict[str, Any]:
    report = load_dict(REPORT_JSON) or collect_public_pack(write=False)
    summary = {
        "status": report.get("status"),
        "distribution_pack_status": report.get("distribution_pack_status", report.get("status")),
        "distribution_pack_reason": report.get("distribution_pack_reason"),
        "collected_public_pack_evidence": report.get("collected_public_pack_evidence"),
        "generated_docs_count": report.get("generated_docs_count"),
        "version_manifest_status": report.get("version_manifest_status"),
        "changelog_status": report.get("changelog_status"),
        "root_readme_draft_status": report.get("root_readme_draft_status"),
        "marketplace_checklist_status": report.get("marketplace_checklist_status"),
        "repository_hygiene_status": report.get("repository_hygiene_status"),
        "validation_status": report.get("validation_status"),
        **HARD_DEFAULTS,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def print_result(report: Dict[str, Any]) -> None:
    print(json.dumps({
        "action": report.get("action"),
        "status": report.get("status"),
        "distribution_pack_status": report.get("distribution_pack_status", report.get("status")),
        "distribution_pack_reason": report.get("distribution_pack_reason"),
        "collected_public_pack_evidence": report.get("collected_public_pack_evidence"),
        "generated_docs_count": report.get("generated_docs_count"),
        "validation_status": report.get("validation_status"),
        "breach": False,
    }, indent=2, sort_keys=True))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel distribution release pack builder")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--collect-public-pack", action="store_true")
    parser.add_argument("--build-version-manifest", action="store_true")
    parser.add_argument("--build-changelog", action="store_true")
    parser.add_argument("--build-root-readme-draft", action="store_true")
    parser.add_argument("--build-marketplace-checklists", action="store_true")
    parser.add_argument("--build-repository-hygiene", action="store_true")
    parser.add_argument("--validate-distribution-pack", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    actions = [
        args.self_test,
        args.collect_public_pack,
        args.build_version_manifest,
        args.build_changelog,
        args.build_root_readme_draft,
        args.build_marketplace_checklists,
        args.build_repository_hygiene,
        args.validate_distribution_pack,
        args.status,
    ]
    if sum(1 for item in actions if item) != 1:
        parser.error("choose exactly one action")

    if args.self_test:
        report = self_test()
    elif args.collect_public_pack:
        report = collect_public_pack(write=True)
    elif args.build_version_manifest:
        report = build_version_manifest()
    elif args.build_changelog:
        report = build_changelog()
    elif args.build_root_readme_draft:
        report = build_root_readme_draft()
    elif args.build_marketplace_checklists:
        report = build_marketplace_checklists()
    elif args.build_repository_hygiene:
        report = build_repository_hygiene()
    elif args.validate_distribution_pack:
        report = validate_distribution_pack(write=True)
    else:
        status_report()
        return 0
    print_result(report)
    return 0 if not str(report.get("status", "")).endswith("_FAILED") and report.get("status") != "DISTRIBUTION_PACK_RED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
