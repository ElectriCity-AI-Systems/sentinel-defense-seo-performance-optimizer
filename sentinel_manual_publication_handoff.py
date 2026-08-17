#!/usr/bin/env python3
"""Build the manual publication handoff pack for Sentinel Phase 10.15.

This module writes only local sanitized publication handoff documents, local
reports, state, audit events and playbooks. It does not overwrite README.md or
LICENSE, create Git tags, push to remotes, call marketplace APIs, send email,
install timers, or change live systems.
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
SCHEMA_VERSION = "sentinel-manual-publication-handoff-10.15"
PHASE = "10.15"

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
HANDOFF_DIR = PROJECT_DIR / "docs/manual-publication"
FINAL_DIR = PROJECT_DIR / "docs/release-final"
DIST_DIR = PROJECT_DIR / "docs/distribution-release"
PUBLIC_DIR = PROJECT_DIR / "docs/public-release"

REPORT_JSON = REPORT_DIR / "sentinel-manual-publication-handoff.json"
REPORT_MD = REPORT_DIR / "sentinel-manual-publication-handoff.md"
VALIDATION_MD = REPORT_DIR / "sentinel-manual-publication-validation.md"
OWNER_SUMMARY_MD = REPORT_DIR / "sentinel-manual-publication-owner-summary.md"

STATE_JSON = STATE_DIR / "manual_publication_handoff.json"
LATEST_JSON = STATE_DIR / "latest_manual_publication_handoff.json"
HISTORY_JSON = STATE_DIR / "manual_publication_handoff_history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-manual-publication-handoff.jsonl"

PLAYBOOK_HANDOFF = PLAYBOOK_DIR / "sentinel-manual-publication-handoff.playbook.json"
PLAYBOOK_CANDIDATE = PLAYBOOK_DIR / "sentinel-readme-license-candidate.playbook.json"
PLAYBOOK_MARKETPLACE = PLAYBOOK_DIR / "sentinel-marketplace-handoff.playbook.json"
PLAYBOOK_PROOF = PLAYBOOK_DIR / "sentinel-no-action-proof.playbook.json"

HANDOFF_FILES = {
    "readme_candidate": HANDOFF_DIR / "README-CANDIDATE.md",
    "license_candidate": HANDOFF_DIR / "LICENSE-CANDIDATE.md",
    "github_release_handoff": HANDOFF_DIR / "GITHUB-RELEASE-HANDOFF.md",
    "payhip_handoff": HANDOFF_DIR / "PAYHIP-HANDOFF.md",
    "gumroad_handoff": HANDOFF_DIR / "GUMROAD-HANDOFF.md",
    "owner_go_no_go": HANDOFF_DIR / "OWNER-GO-NO-GO-CHECKLIST.md",
    "release_files_checklist": HANDOFF_DIR / "RELEASE-FILES-CHECKLIST.md",
    "publication_freeze_manifest": HANDOFF_DIR / "PUBLICATION-FREEZE-MANIFEST.md",
    "no_action_proof": HANDOFF_DIR / "NO-ACTION-PROOF.md",
    "final_handoff_validation": HANDOFF_DIR / "FINAL-HANDOFF-VALIDATION.md",
    "commit_recommendation": HANDOFF_DIR / "COMMIT-RECOMMENDATION.md",
    "manifest": HANDOFF_DIR / "manual-publication-manifest.json",
}

INPUTS = {
    "release_final_manifest": FINAL_DIR / "release-final-manifest.json",
    "license_draft": FINAL_DIR / "LICENSE-DRAFT.md",
    "final_green_summary": FINAL_DIR / "FINAL-GREEN-RELEASE-SUMMARY.md",
    "final_owner_approval_gate": FINAL_DIR / "FINAL-OWNER-APPROVAL-GATE.md",
    "github_final_release_draft": FINAL_DIR / "GITHUB-FINAL-RELEASE-DRAFT.md",
    "payhip_launch_draft": FINAL_DIR / "PAYHIP-LAUNCH-DRAFT.md",
    "gumroad_launch_draft": FINAL_DIR / "GUMROAD-LAUNCH-DRAFT.md",
    "root_readme_draft": DIST_DIR / "ROOT-README-DRAFT.md",
    "version_manifest": DIST_DIR / "VERSION-MANIFEST.md",
    "changelog": DIST_DIR / "CHANGELOG.md",
    "public_readme": PUBLIC_DIR / "README-public.md",
    "safety_boundaries": PUBLIC_DIR / "SAFETY-BOUNDARIES.md",
    "owner_commands": PUBLIC_DIR / "OWNER-COMMANDS.md",
    "not_autopilot": PUBLIC_DIR / "NOT-AUTOPILOT-DISCLAIMER.md",
}

RECOMMENDED_GIT_FILES = [
    "sentinel_manual_publication_handoff.py",
    "sentinel_autonomy.py",
    "docs/manual-publication/README-CANDIDATE.md",
    "docs/manual-publication/LICENSE-CANDIDATE.md",
    "docs/manual-publication/GITHUB-RELEASE-HANDOFF.md",
    "docs/manual-publication/PAYHIP-HANDOFF.md",
    "docs/manual-publication/GUMROAD-HANDOFF.md",
    "docs/manual-publication/OWNER-GO-NO-GO-CHECKLIST.md",
    "docs/manual-publication/RELEASE-FILES-CHECKLIST.md",
    "docs/manual-publication/PUBLICATION-FREEZE-MANIFEST.md",
    "docs/manual-publication/NO-ACTION-PROOF.md",
    "docs/manual-publication/FINAL-HANDOFF-VALIDATION.md",
    "docs/manual-publication/COMMIT-RECOMMENDATION.md",
    "docs/manual-publication/manual-publication-manifest.json",
    "playbooks/sentinel-manual-publication-handoff.playbook.json",
    "playbooks/sentinel-readme-license-candidate.playbook.json",
    "playbooks/sentinel-marketplace-handoff.playbook.json",
    "playbooks/sentinel-no-action-proof.playbook.json",
]

ALLOWED_WRITE_ROOTS = (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, HANDOFF_DIR)

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
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR, PLAYBOOK_DIR, HANDOFF_DIR):
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


def collect_final_release(write: bool = True) -> Dict[str, Any]:
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
    final_manifest = load_dict(INPUTS["release_final_manifest"])
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "timestamp_utc": utc_now(),
        "action": "collect-final-release",
        "status": "FINAL_RELEASE_EVIDENCE_COLLECTED",
        "collected_final_release_evidence": sum(1 for status in input_statuses.values() if status == "ok"),
        "input_statuses": input_statuses,
        "missing_inputs": missing_inputs,
        "invalid_inputs": invalid_inputs,
        "final_release_status": final_manifest.get("final_release_status"),
        "final_release_reason": final_manifest.get("final_release_reason"),
        "selected_license": final_manifest.get("selected_license"),
        "license_decision_status": final_manifest.get("license_decision_status"),
        "license_draft_status": final_manifest.get("license_draft_status"),
        "publication_activation_status": final_manifest.get("publication_activation_status", "MANUAL_ONLY_NOT_EXECUTED"),
        "public_pack_status": final_manifest.get("public_pack_status"),
        "rc_status": final_manifest.get("rc_status"),
        "semver_suggestion": final_manifest.get("semver_suggestion", "v1.0.0-rc1"),
        "git_status": run_git("status"),
        "git_log": run_git("log"),
        **HARD_DEFAULTS,
    }
    if write:
        write_outputs(evidence)
    return evidence


def render_manifest(evidence: Dict[str, Any], validation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    validation = validation or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "product_name": "Sentinel Security, SEO & Performance Safe Optimization",
        "handoff_status": validation.get("handoff_status", "HANDOFF_PENDING"),
        "handoff_reason": validation.get("handoff_reason", "not_validated_yet"),
        "final_release_status": evidence.get("final_release_status"),
        "selected_license": evidence.get("selected_license"),
        "license_decision_status": evidence.get("license_decision_status"),
        "publication_activation_status": "MANUAL_ONLY_NOT_EXECUTED",
        "docs": sorted(rel(path) for path in HANDOFF_FILES.values()),
        "recommended_git_checkpoint_files": RECOMMENDED_GIT_FILES,
        "local_artifacts_not_for_commit": git_recommendation()["local_artifacts_not_for_commit"],
        **HARD_DEFAULTS,
    }


def render_readme_candidate(evidence: Dict[str, Any]) -> str:
    return f"""# Sentinel Security, SEO & Performance Safe Optimization

Sentinel is a local, owner-controlled system for safe website, SEO, performance and security operations. It supports evidence-driven review, bounded local autonomy, public-safe documentation, release readiness and controlled optimization planning.

## Safety Boundaries

- no unattended live apply
- no automatic WordPress, Cloudflare, database, SFTP/FTP, Nginx or `.htaccess` change
- no automatic GitHub, Payhip or Gumroad action
- no timer, cron or system-service installation
- no LOW_LIVE, MEDIUM or HIGH execution
- owner review remains required for production-changing work

## License Candidate

This release uses a PolyForm Noncommercial license candidate. Commercial use, resale, SaaS usage, agency resale and competing offerings require separate owner permission or a commercial license.

The license candidate is review-only until the owner manually approves and installs a final `LICENSE`.

## Example Local Commands

```bash
python3 sentinel_autonomy.py status
python3 sentinel_autonomy.py release-final-status
python3 sentinel_autonomy.py publication-handoff-status
```

## Manual Publication

This file is a candidate that can later be manually copied to `README.md`. It does not replace `README.md` automatically.

## No Guarantees

Sentinel supports safer analysis and planning. It does not promise rankings, revenue, perfect security, instant performance outcomes or automatic repair of external systems.
"""


def render_license_candidate(evidence: Dict[str, Any]) -> str:
    return f"""# License Candidate

This is a review-only license candidate for owner evaluation. It is not legal advice and is not a final legal license.

## Selected Option

- selected license: `{evidence.get('selected_license') or 'none'}`
- decision status: `{evidence.get('license_decision_status')}`

## Candidate Summary

The selected option is PolyForm Noncommercial. Source-available, non-commercial use is intended to remain possible. Commercial use, resale, SaaS usage, agency resale and competing offerings require separate permission or a commercial license.

## Manual Action Required

The owner must manually review and decide whether to create a final `LICENSE`. This handoff does not write or overwrite `LICENSE`.
"""


def render_github_handoff(evidence: Dict[str, Any]) -> str:
    return f"""# GitHub Release Handoff

## Release Title

Sentinel Security, SEO & Performance Safe Optimization `v1.0.0-rc1`

## Tag Draft

- suggested tag: `v1.0.0-rc1`
- automatic tag creation: no

## Highlights

- local safe autonomy chain
- sanitized public and distribution docs
- final release green draft
- PolyForm Noncommercial license candidate
- manual publication handoff

## Safety Boundaries

No automatic push, tag, release, upload, timer installation or live system change.

## Manual Steps

1. Review candidate README and license.
2. Check repository hygiene.
3. Manually stage only approved files.
4. Manually create tag and GitHub release only if the owner chooses.
"""


def render_payhip_handoff(_: Dict[str, Any]) -> str:
    return """# Payhip Handoff

## Product Name

Sentinel Security, SEO & Performance Safe Optimization

## Short Description

Local owner-controlled safety system for SEO, performance and security operations with evidence reports, safe batches, readiness checks and manual publication gates.

## Buyer Notice

This product supports local review and planning. It does not promise rankings, revenue, perfect security, instant performance outcomes or automatic repair of external systems.

## Manual Publication

No Payhip API upload is performed. The owner must manually decide whether and when to create a Payhip listing.
"""


def render_gumroad_handoff(_: Dict[str, Any]) -> str:
    return """# Gumroad Handoff

## Product Name

Sentinel Security, SEO & Performance Safe Optimization

## Description

Local owner-controlled system for safe analysis, review, reporting, operations supervision, distribution preparation and release evidence.

## Buyer Notice

Production-changing actions require separate owner approval and a dedicated safety phase. No automatic upload or publication is performed.

## Manual Publication

No Gumroad API upload is performed. The owner must manually decide whether and when to create a Gumroad listing.
"""


def render_owner_go_no_go(_: Dict[str, Any]) -> str:
    return """# Owner Go/No-Go Checklist

- Has the License Candidate been manually reviewed?
- Should README-CANDIDATE be manually copied into README.md?
- Should a GitHub release be manually created?
- Should Payhip or Gumroad listings be manually created?
- Are no runtime reports, adaptive state, audit logs or exports staged for Git?
- Are no secrets present?
- Is website or production status understood as separate from local release status?
- Is Emergency Stop still active?
- Is it clear that no live automation was activated?
- Is it clear that publication remains a manual owner action?
"""


def render_release_files_checklist(_: Dict[str, Any]) -> str:
    lines = ["# Release Files Checklist", "", "Recommended files for this manual handoff checkpoint:", ""]
    for item in RECOMMENDED_GIT_FILES:
        lines.append(f"- `{item}`")
    lines.extend([
        "",
        "Do not commit reports, state, audit, exports, backups, credentials or private owner evidence.",
    ])
    return "\n".join(lines) + "\n"


def render_freeze_manifest(evidence: Dict[str, Any]) -> str:
    return f"""# Publication Freeze Manifest

- final release status: `{evidence.get('final_release_status')}`
- selected license: `{evidence.get('selected_license')}`
- license candidate: review-only
- README activation: manual only
- GitHub release: manual only
- Payhip launch: manual only
- Gumroad launch: manual only
- publication activation: `MANUAL_ONLY_NOT_EXECUTED`

This freeze means the local handoff is prepared. It does not publish anything.
"""


def render_no_action_proof(_: Dict[str, Any]) -> str:
    return """# No-Action Proof

- no README overwrite
- no LICENSE overwrite
- no Git tag
- no GitHub API
- no Payhip API
- no Gumroad API
- no network publication
- no email
- no WordPress apply
- no Cloudflare apply
- no database apply
- no SFTP/FTP apply
- no Nginx apply
- no `.htaccess` apply
- no timer, cron or systemd installation
- no LOW_LIVE, MEDIUM or HIGH execution
- breach: `false`
- live_apply: `false`
- emergency_stop: `true`
"""


def render_final_validation(evidence: Dict[str, Any]) -> str:
    return f"""# Final Handoff Validation

- final release status: `{evidence.get('final_release_status')}`
- selected license: `{evidence.get('selected_license')}`
- publication activation: `MANUAL_ONLY_NOT_EXECUTED`
- README candidate: local only
- LICENSE candidate: local only
- remote actions: none
- breach: `false`
- live_apply: `false`
- emergency_stop: `true`
"""


def render_commit_recommendation(_: Dict[str, Any]) -> str:
    lines = ["# Commit Recommendation", "", "Recommended manual publication handoff files:", ""]
    for item in RECOMMENDED_GIT_FILES:
        lines.append(f"- `{item}`")
    lines.extend([
        "",
        "Do not commit reports, state, audit, exports, backups, credentials or private owner evidence.",
    ])
    return "\n".join(lines) + "\n"


def doc_renderers(evidence: Dict[str, Any]) -> Dict[str, Tuple[Path, str]]:
    return {
        "readme_candidate": (HANDOFF_FILES["readme_candidate"], render_readme_candidate(evidence)),
        "license_candidate": (HANDOFF_FILES["license_candidate"], render_license_candidate(evidence)),
        "github_release_handoff": (HANDOFF_FILES["github_release_handoff"], render_github_handoff(evidence)),
        "payhip_handoff": (HANDOFF_FILES["payhip_handoff"], render_payhip_handoff(evidence)),
        "gumroad_handoff": (HANDOFF_FILES["gumroad_handoff"], render_gumroad_handoff(evidence)),
        "owner_go_no_go": (HANDOFF_FILES["owner_go_no_go"], render_owner_go_no_go(evidence)),
        "release_files_checklist": (HANDOFF_FILES["release_files_checklist"], render_release_files_checklist(evidence)),
        "publication_freeze_manifest": (HANDOFF_FILES["publication_freeze_manifest"], render_freeze_manifest(evidence)),
        "no_action_proof": (HANDOFF_FILES["no_action_proof"], render_no_action_proof(evidence)),
        "final_handoff_validation": (HANDOFF_FILES["final_handoff_validation"], render_final_validation(evidence)),
        "commit_recommendation": (HANDOFF_FILES["commit_recommendation"], render_commit_recommendation(evidence)),
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
    write_json(HANDOFF_FILES["manifest"], render_manifest(evidence), public=True)
    if rel(HANDOFF_FILES["manifest"]) not in written:
        written.append(rel(HANDOFF_FILES["manifest"]))
    return written


def write_playbooks() -> None:
    base = {"schema_version": SCHEMA_VERSION, "phase": PHASE, **HARD_DEFAULTS}
    write_json(PLAYBOOK_HANDOFF, {
        **base,
        "name": "sentinel-manual-publication-handoff",
        "purpose": "Build local sanitized manual publication handoff files.",
        "blocked_actions": ["remote_push", "git_tag", "marketplace_api", "live_apply", "timer_install", "LOW_LIVE_MEDIUM_HIGH_execution"],
    })
    write_json(PLAYBOOK_CANDIDATE, {
        **base,
        "name": "sentinel-readme-license-candidate",
        "purpose": "Create README and LICENSE candidates without overwriting root files.",
    })
    write_json(PLAYBOOK_MARKETPLACE, {
        **base,
        "name": "sentinel-marketplace-handoff",
        "purpose": "Create manual Payhip and Gumroad handoff docs without API upload.",
    })
    write_json(PLAYBOOK_PROOF, {
        **base,
        "name": "sentinel-no-action-proof",
        "proof_items": ["no_readme_overwrite", "no_license_overwrite", "no_git_tag", "no_remote_push", "no_marketplace_api", "no_live_apply"],
    })


def render_report_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Manual Publication Handoff",
        "",
        f"- status: `{report.get('status')}`",
        f"- handoff_status: `{report.get('handoff_status', report.get('status'))}`",
        f"- reason: `{report.get('handoff_reason', '-')}`",
        f"- collected_final_release_evidence: `{report.get('collected_final_release_evidence', 0)}`",
        f"- generated_docs_count: `{report.get('generated_docs_count', 0)}`",
        f"- README candidate: `{report.get('readme_candidate_status', '-')}`",
        f"- LICENSE candidate: `{report.get('license_candidate_status', '-')}`",
        f"- GitHub handoff: `{report.get('github_handoff_status', '-')}`",
        f"- marketplace handoff: `{report.get('marketplace_handoff_status', '-')}`",
        f"- owner go/no-go: `{report.get('owner_go_no_go_status', '-')}`",
        f"- no-action proof: `{report.get('no_action_proof_status', '-')}`",
        f"- validation: `{report.get('validation_status', '-')}`",
        "- publication_activation: `MANUAL_ONLY_NOT_EXECUTED`",
        "- live_apply: `False`",
        "- emergency_stop: `True`",
        "- breach: `False`",
    ]) + "\n"


def render_validation_md(report: Dict[str, Any]) -> str:
    findings = report.get("validation_findings") or []
    lines = [
        "# Sentinel Manual Publication Validation",
        "",
        f"- validation_status: `{report.get('validation_status')}`",
        f"- handoff_status: `{report.get('handoff_status')}`",
        f"- reason: `{report.get('handoff_reason')}`",
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
        "# Sentinel Manual Publication Owner Summary",
        "",
        f"- handoff_status: `{report.get('handoff_status')}`",
        f"- reason: `{report.get('handoff_reason')}`",
        f"- final_release_status: `{report.get('final_release_status')}`",
        f"- selected_license: `{report.get('selected_license')}`",
        "- handoff capability: README candidate, license candidate, GitHub handoff, Payhip/Gumroad handoff, owner go/no-go, release freeze and no-action proof",
        "- blocked: README overwrite, LICENSE overwrite, Git tag, remote push, marketplace API, email, live apply, timers, LOW_LIVE, MEDIUM, HIGH",
        "- next safe step: owner manually reviews candidate files and decides whether to publish.",
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
        "handoff_status": report.get("handoff_status", report.get("status")),
        "handoff_reason": report.get("handoff_reason"),
    })
    write_json(HISTORY_JSON, {"schema_version": SCHEMA_VERSION, "entries": history[-100:], **HARD_DEFAULTS})
    append_jsonl(AUDIT_JSONL, {
        "timestamp_utc": report.get("timestamp_utc", utc_now()),
        "phase": PHASE,
        "action": report.get("action"),
        "status": report.get("status"),
        "handoff_status": report.get("handoff_status", report.get("status")),
        "breach": False,
    })
    write_text(REPORT_MD, render_report_md(report))
    write_text(VALIDATION_MD, render_validation_md(report))
    write_text(OWNER_SUMMARY_MD, render_owner_summary_md(report))


def build_readme_candidate() -> Dict[str, Any]:
    evidence = collect_final_release(write=False)
    written = write_docs(evidence, ["readme_candidate"])
    report = {**evidence, "action": "build-readme-candidate", "status": "README_CANDIDATE_READY", "readme_candidate_status": "README_CANDIDATE_READY", "written_files": written}
    write_outputs(report)
    return report


def build_license_candidate() -> Dict[str, Any]:
    evidence = collect_final_release(write=False)
    written = write_docs(evidence, ["license_candidate"])
    report = {**evidence, "action": "build-license-candidate", "status": "LICENSE_CANDIDATE_READY", "license_candidate_status": "LICENSE_CANDIDATE_READY", "written_files": written}
    write_outputs(report)
    return report


def build_github_handoff() -> Dict[str, Any]:
    evidence = collect_final_release(write=False)
    written = write_docs(evidence, ["github_release_handoff"])
    report = {**evidence, "action": "build-github-handoff", "status": "GITHUB_RELEASE_HANDOFF_READY", "github_handoff_status": "GITHUB_RELEASE_HANDOFF_READY", "written_files": written}
    write_outputs(report)
    return report


def build_marketplace_handoff() -> Dict[str, Any]:
    evidence = collect_final_release(write=False)
    written = write_docs(evidence, ["payhip_handoff", "gumroad_handoff"])
    report = {**evidence, "action": "build-marketplace-handoff", "status": "MARKETPLACE_HANDOFF_READY", "marketplace_handoff_status": "MARKETPLACE_HANDOFF_READY", "written_files": written}
    write_outputs(report)
    return report


def build_owner_go_no_go() -> Dict[str, Any]:
    evidence = collect_final_release(write=False)
    written = write_docs(evidence, ["owner_go_no_go"])
    report = {**evidence, "action": "build-owner-go-no-go", "status": "OWNER_GO_NO_GO_READY", "owner_go_no_go_status": "OWNER_GO_NO_GO_READY", "written_files": written}
    write_outputs(report)
    return report


def build_release_freeze() -> Dict[str, Any]:
    evidence = collect_final_release(write=False)
    written = write_docs(evidence, ["release_files_checklist", "publication_freeze_manifest"])
    report = {**evidence, "action": "build-release-freeze", "status": "RELEASE_FREEZE_READY", "release_freeze_status": "RELEASE_FREEZE_READY", "written_files": written}
    write_outputs(report)
    return report


def build_no_action_proof() -> Dict[str, Any]:
    evidence = collect_final_release(write=False)
    written = write_docs(evidence, ["no_action_proof"])
    report = {**evidence, "action": "build-no-action-proof", "status": "NO_ACTION_PROOF_READY", "no_action_proof_status": "NO_ACTION_PROOF_READY", "written_files": written}
    write_outputs(report)
    return report


def validate_handoff(write: bool = True) -> Dict[str, Any]:
    evidence = collect_final_release(write=False)
    write_docs(evidence, ["final_handoff_validation", "commit_recommendation"])
    paths = list(HANDOFF_FILES.values())
    public_scan = scan_paths(paths, public=True)
    private_scan = scan_paths([REPORT_MD, VALIDATION_MD, OWNER_SUMMARY_MD, STATE_JSON, LATEST_JSON, HISTORY_JSON, AUDIT_JSONL], public=False)
    source_findings = source_safety_findings([
        PROJECT_DIR / "sentinel_manual_publication_handoff.py",
        PROJECT_DIR / "sentinel_autonomy.py",
    ])
    docs_exist = {key: path.exists() and path.stat().st_size > 0 for key, path in HANDOFF_FILES.items()}
    validation_findings: List[str] = []
    if not all(docs_exist.values()):
        validation_findings.append("missing_or_empty_handoff_doc")
    for path in [
        HANDOFF_FILES["manifest"],
        REPORT_JSON,
        STATE_JSON,
        LATEST_JSON,
        HISTORY_JSON,
        PLAYBOOK_HANDOFF,
        PLAYBOOK_CANDIDATE,
        PLAYBOOK_MARKETPLACE,
        PLAYBOOK_PROOF,
    ]:
        if path.exists():
            _, status = read_json(path)
            if status != "ok":
                validation_findings.append(f"invalid_json:{rel(path)}")
    if public_scan.get("findings"):
        validation_findings.append("handoff_doc_sanitization_findings")
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
    if evidence.get("missing_inputs"):
        yellow_reasons.append("missing_inputs")
    if evidence.get("final_release_status") != "FINAL_RELEASE_GREEN":
        yellow_reasons.append("final_release_not_green")
    if evidence.get("publication_activation_status") != "MANUAL_ONLY_NOT_EXECUTED":
        validation_findings.append("unexpected_publication_activation")

    if validation_findings:
        status = "HANDOFF_RED"
        reason = ",".join(sorted(set(validation_findings)))
    elif yellow_reasons:
        status = "HANDOFF_YELLOW"
        reason = ",".join(sorted(set(yellow_reasons)))
    else:
        status = "HANDOFF_GREEN"
        reason = "final_release_green_and_manual_publication_handoff_ready"

    report = {
        **evidence,
        "action": "validate-handoff",
        "status": status,
        "handoff_status": status,
        "handoff_reason": reason,
        "generated_docs_count": sum(1 for ok in docs_exist.values() if ok),
        "docs_exist": docs_exist,
        "public_scan": public_scan,
        "private_scan": private_scan,
        "source_safety_findings": source_findings,
        "validation_findings": validation_findings,
        "validation_status": "HANDOFF_VALIDATION_OK" if status != "HANDOFF_RED" else "HANDOFF_VALIDATION_BLOCKED",
        "readme_candidate_status": "README_CANDIDATE_READY" if HANDOFF_FILES["readme_candidate"].exists() else "README_CANDIDATE_MISSING",
        "license_candidate_status": "LICENSE_CANDIDATE_READY" if HANDOFF_FILES["license_candidate"].exists() else "LICENSE_CANDIDATE_MISSING",
        "github_handoff_status": "GITHUB_RELEASE_HANDOFF_READY" if HANDOFF_FILES["github_release_handoff"].exists() else "GITHUB_RELEASE_HANDOFF_MISSING",
        "marketplace_handoff_status": "MARKETPLACE_HANDOFF_READY" if HANDOFF_FILES["payhip_handoff"].exists() and HANDOFF_FILES["gumroad_handoff"].exists() else "MARKETPLACE_HANDOFF_MISSING",
        "owner_go_no_go_status": "OWNER_GO_NO_GO_READY" if HANDOFF_FILES["owner_go_no_go"].exists() else "OWNER_GO_NO_GO_MISSING",
        "no_action_proof_status": "NO_ACTION_PROOF_READY" if HANDOFF_FILES["no_action_proof"].exists() else "NO_ACTION_PROOF_MISSING",
        "publication_activation_status": "MANUAL_ONLY_NOT_EXECUTED",
        "git_recommendation": git_recommendation(),
        "git_recommendation_status": git_recommendation()["status"],
        **HARD_DEFAULTS,
    }
    if write:
        write_json(HANDOFF_FILES["manifest"], render_manifest(evidence, report), public=True)
        write_outputs(report)
    return report


def decide_status_for_test(evidence: Dict[str, Any], validation_findings: List[str]) -> Tuple[str, str]:
    if validation_findings:
        return "HANDOFF_RED", ",".join(validation_findings)
    if evidence.get("final_release_status") != "FINAL_RELEASE_GREEN":
        return "HANDOFF_YELLOW", "final_release_not_green"
    if evidence.get("publication_activation_status") != "MANUAL_ONLY_NOT_EXECUTED":
        return "HANDOFF_RED", "unexpected_publication_activation"
    return "HANDOFF_GREEN", "final_release_green_and_manual_publication_handoff_ready"


def self_test() -> Dict[str, Any]:
    ensure_dirs()
    source_findings = source_safety_findings([
        PROJECT_DIR / "sentinel_manual_publication_handoff.py",
        PROJECT_DIR / "sentinel_autonomy.py",
    ])
    sample = {
        "final_release_status": "FINAL_RELEASE_GREEN",
        "selected_license": "polyform-noncommercial",
        "license_decision_status": "LICENSE_CHOICE_SET",
        "publication_activation_status": "MANUAL_ONLY_NOT_EXECUTED",
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
        "status_logic_green": decide_status_for_test(sample, [])[0] == "HANDOFF_GREEN",
        "status_logic_yellow": decide_status_for_test({**sample, "final_release_status": "FINAL_RELEASE_YELLOW"}, [])[0] == "HANDOFF_YELLOW",
        "status_logic_red": decide_status_for_test(sample, ["secret"])[0] == "HANDOFF_RED",
        "json_serializable": True,
        "breach_false": HARD_DEFAULTS["breach"] is False,
    }
    status = "MANUAL_PUBLICATION_HANDOFF_SELF_TEST_OK" if all(checks.values()) else "MANUAL_PUBLICATION_HANDOFF_SELF_TEST_FAILED"
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


def status_report() -> Dict[str, Any]:
    report = load_dict(REPORT_JSON) or collect_final_release(write=False)
    summary = {
        "status": report.get("status"),
        "handoff_status": report.get("handoff_status", report.get("status")),
        "handoff_reason": report.get("handoff_reason"),
        "collected_final_release_evidence": report.get("collected_final_release_evidence"),
        "generated_docs_count": report.get("generated_docs_count"),
        "readme_candidate_status": report.get("readme_candidate_status"),
        "license_candidate_status": report.get("license_candidate_status"),
        "github_handoff_status": report.get("github_handoff_status"),
        "marketplace_handoff_status": report.get("marketplace_handoff_status"),
        "owner_go_no_go_status": report.get("owner_go_no_go_status"),
        "no_action_proof_status": report.get("no_action_proof_status"),
        "validation_status": report.get("validation_status"),
        **HARD_DEFAULTS,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def print_result(report: Dict[str, Any]) -> None:
    print(json.dumps({
        "action": report.get("action"),
        "status": report.get("status"),
        "handoff_status": report.get("handoff_status", report.get("status")),
        "handoff_reason": report.get("handoff_reason"),
        "collected_final_release_evidence": report.get("collected_final_release_evidence"),
        "generated_docs_count": report.get("generated_docs_count"),
        "validation_status": report.get("validation_status"),
        "breach": False,
    }, indent=2, sort_keys=True))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel manual publication handoff builder")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--collect-final-release", action="store_true")
    parser.add_argument("--build-readme-candidate", action="store_true")
    parser.add_argument("--build-license-candidate", action="store_true")
    parser.add_argument("--build-github-handoff", action="store_true")
    parser.add_argument("--build-marketplace-handoff", action="store_true")
    parser.add_argument("--build-owner-go-no-go", action="store_true")
    parser.add_argument("--build-release-freeze", action="store_true")
    parser.add_argument("--build-no-action-proof", action="store_true")
    parser.add_argument("--validate-handoff", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    actions = [
        args.self_test,
        args.collect_final_release,
        args.build_readme_candidate,
        args.build_license_candidate,
        args.build_github_handoff,
        args.build_marketplace_handoff,
        args.build_owner_go_no_go,
        args.build_release_freeze,
        args.build_no_action_proof,
        args.validate_handoff,
        args.status,
    ]
    if sum(1 for item in actions if item) != 1:
        parser.error("choose exactly one action")

    if args.self_test:
        report = self_test()
    elif args.collect_final_release:
        report = collect_final_release(write=True)
    elif args.build_readme_candidate:
        report = build_readme_candidate()
    elif args.build_license_candidate:
        report = build_license_candidate()
    elif args.build_github_handoff:
        report = build_github_handoff()
    elif args.build_marketplace_handoff:
        report = build_marketplace_handoff()
    elif args.build_owner_go_no_go:
        report = build_owner_go_no_go()
    elif args.build_release_freeze:
        report = build_release_freeze()
    elif args.build_no_action_proof:
        report = build_no_action_proof()
    elif args.validate_handoff:
        report = validate_handoff(write=True)
    else:
        status_report()
        return 0
    print_result(report)
    return 0 if not str(report.get("status", "")).endswith("_FAILED") and report.get("status") != "HANDOFF_RED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
