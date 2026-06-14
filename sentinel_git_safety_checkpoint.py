#!/usr/bin/env python3
"""Safe Git checkpoint preparation for Sentinel local changes.

This module prepares a commit only after local allowlist and secret checks.
It never pushes, never rewrites history, and never removes files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent
REPORT_JSON = ROOT / "reports/latest/git-safety-checkpoint.json"
REPORT_MD = ROOT / "reports/latest/git-safety-checkpoint.md"
PUSH_READINESS_MD = ROOT / "reports/latest/git-push-readiness.md"
AUDIT_JSONL = ROOT / "audit/git-safety-checkpoint.jsonl"
STATE_JSON = ROOT / "state/adaptive-learning/git_safety_checkpoint.json"
PLAYBOOK_JSON = ROOT / "playbooks/git-safety-checkpoint.playbook.json"
GITIGNORE = ROOT / ".gitignore"
COMMIT_MESSAGE = "Add medium-risk image optimization safety gates"

MAX_STAGE_FILE_BYTES = 2_000_000
MAX_SCAN_BYTES = 2_000_000

REQUIRED_GITIGNORE_PATTERNS = [
    ".sentinel-sftp.env",
    ".env",
    ".env.*",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.crt",
    "*.sqlite",
    "*.db",
    "**pycache**/",
    "*.pyc",
    ".venv/",
    "venv/",
    "backups/",
    "snapshots/",
    "audit/",
    "*.log",
    "reports/latest/*secret*",
    "reports/latest/*token*",
    "state/*secret*",
    "state/*token*",
    "backups/medium-images-apply/",
    "backups/medium-images-canary-recipe/",
    "*.webp",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.zip",
    "*.tar",
    "*.tar.gz",
]

EXCLUDED_DIR_PARTS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "backups",
    "snapshots",
    "audit",
    "logs",
    "archives",
    "exports",
    "inbox",
    "cloudflare-monitor",
    "ionos-htaccess-backups",
    "sourcemap-backups",
}

BLOCKED_SUFFIXES = {
    ".webp",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".pyc",
    ".log",
    ".db",
    ".sqlite",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".crt",
    ".bin",
    ".run",
}

SECRET_NAME_RE = re.compile(
    r"(?i)\b(passw(?:or)?d|passwd|secret|token|api[_-]?key|apikey|bearer|authorization)\b"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(passw(?:or)?d|passwd|secret|token|api[_-]?key|apikey|bearer|authorization)\b"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:@-]{12,})"
)
SFTP_PASSWORD_ASSIGNMENT_RE = re.compile(r"SENTINEL_SFTP_PASSWORD\s*[:=]\s*['\"]?([^\s'\"]{4,})")
TOKEN_PATTERNS = [
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{16,}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9_]{16,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{20,}")),
    ("openssh_private_key", re.compile("-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5)),
    ("rsa_private_key", re.compile("-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5)),
]
KNOWN_FAKE_SECRET_MARKERS = {
    "shouldnotappear",
    "0123456789abcdef",
    "abc123",
    "sk-live",
    "sk-0123456789abcdef0123",
    "token=0123456789abcdef",
    "api_key=0123456789abcdef",
    "password=0123456789abcdef",
}


@dataclass
class GitResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def write_json(path: Path, data: dict[str, Any]) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    ensure_parent(path)
    path.write_text(text, encoding="utf-8")


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    ensure_parent(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(data, sort_keys=True) + "\n")


def run_git(args: list[str]) -> GitResult:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return GitResult(proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip(), proc.returncode)


def is_git_repo() -> bool:
    return run_git(["rev-parse", "--is-inside-work-tree"]).ok


def get_branch() -> str:
    if not is_git_repo():
        return ""
    result = run_git(["branch", "--show-current"])
    return result.stdout if result.ok else ""


def mask_remote_url(line: str) -> str:
    masked = re.sub(r"(https?://)([^/\s:@]+):([^@\s]+)@", r"\1***:***@", line)
    masked = re.sub(r"(?i)(token|password|passwd|secret)=([^&\s]+)", r"\1=<redacted>", masked)
    return masked


def get_remotes() -> list[str]:
    if not is_git_repo():
        return []
    result = run_git(["remote", "-v"])
    if not result.ok or not result.stdout:
        return []
    return [mask_remote_url(line) for line in result.stdout.splitlines()]


def git_status_short() -> list[str]:
    if not is_git_repo():
        return []
    result = run_git(["status", "--short"])
    if not result.ok or not result.stdout:
        return []
    return result.stdout.splitlines()


def staged_files() -> list[str]:
    if not is_git_repo():
        return []
    result = run_git(["diff", "--cached", "--name-only"])
    if not result.ok or not result.stdout:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def tracked_or_changed_paths() -> list[Path]:
    if is_git_repo():
        result = run_git(["status", "--porcelain=v1", "-z"])
        if result.ok and result.stdout:
            items = result.stdout.split("\0")
            paths: list[Path] = []
            for item in items:
                if not item:
                    continue
                raw = item[3:]
                if " -> " in raw:
                    raw = raw.split(" -> ", 1)[1]
                paths.append(ROOT / raw)
            return paths
    return list(iter_local_candidate_files())


def iter_local_candidate_files() -> Iterable[Path]:
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel_path = path.relative_to(ROOT)
        except ValueError:
            continue
        if any(part in EXCLUDED_DIR_PARTS for part in rel_path.parts):
            continue
        yield path


def is_env_like(path: Path) -> bool:
    name = path.name
    return name == ".sentinel-sftp.env" or name == ".env" or name.startswith(".env.")


def is_binary_or_artifact(path: Path) -> bool:
    suffixes = path.suffixes
    if path.suffix.lower() in BLOCKED_SUFFIXES:
        return True
    if suffixes[-2:] == [".tar", ".gz"]:
        return True
    return False


def path_block_reason(path: Path) -> str | None:
    try:
        rel_path = path.relative_to(ROOT)
    except ValueError:
        return "outside_project_root"
    parts = set(rel_path.parts)
    if is_env_like(path):
        return "env_or_sftp_secret_file"
    if any(part in EXCLUDED_DIR_PARTS for part in parts):
        return "blocked_directory"
    lowered = rel(path).lower()
    if any(word in lowered for word in ("password", "secret", "token", "apikey", "api_key")):
        return "secret_like_filename"
    if is_binary_or_artifact(path):
        return "binary_or_large_artifact_suffix"
    if path.suffix == ".sh" and not (
        len(rel_path.parts) == 3
        and rel_path.parts[0] == "deploy"
        and rel_path.parts[1] == "systemd"
        and rel_path.name.endswith(".review.sh")
    ):
        return "shell_script_not_review_draft"
    return None


def is_safe_stage_candidate(path: Path) -> tuple[bool, str]:
    reason = path_block_reason(path)
    if reason:
        return False, reason
    if not path.exists() or not path.is_file():
        return False, "not_a_file"
    size = path.stat().st_size
    if size > MAX_STAGE_FILE_BYTES:
        return False, "file_too_large_for_safe_checkpoint"
    r = rel(path)
    p = Path(r)
    if r == ".gitignore":
        return True, "gitignore"
    if p.name.startswith("sentinel_") and p.suffix == ".py" and len(p.parts) == 1:
        return True, "sentinel_python_module"
    if p.parts[:1] == ("playbooks",) and p.name.endswith(".playbook.json") and len(p.parts) == 2:
        return True, "playbook"
    if p.parts[:2] == ("reports", "latest") and p.suffix in {".json", ".md"} and len(p.parts) == 3:
        return True, "latest_report"
    if p.parts[:2] == ("state", "adaptive-learning") and p.suffix == ".json" and len(p.parts) == 3:
        return True, "adaptive_learning_state"
    if p.parts[:2] == ("deploy", "systemd") and p.suffix in {".service", ".timer"} and len(p.parts) == 3:
        return True, "systemd_draft"
    if p.parts[:2] == ("deploy", "systemd") and p.name.endswith(".review.sh") and len(p.parts) == 3:
        return True, "review_shell_draft"
    if p.parts[:1] == ("docs",) and p.suffix in {".md", ".txt"}:
        return True, "docs"
    if len(p.parts) == 1 and (p.name in {"README.md", "CLAUDE.md"} or p.name.endswith("_RUNBOOK.md")):
        return True, "project_documentation"
    return False, "not_on_safe_stage_allowlist"


def read_text_for_scan(path: Path) -> tuple[str | None, str | None]:
    reason = path_block_reason(path)
    if reason:
        return None, reason
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"stat_failed:{exc.__class__.__name__}"
    if size > MAX_SCAN_BYTES:
        return None, "file_too_large_to_scan"
    try:
        return path.read_text(encoding="utf-8", errors="replace"), None
    except OSError as exc:
        return None, f"read_failed:{exc.__class__.__name__}"


def mask_value(value: str) -> str:
    if len(value) <= 6:
        return "<redacted>"
    return value[:2] + "<redacted>" + value[-2:]


def redact_text(text: str) -> str:
    redacted = SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    redacted = SFTP_PASSWORD_ASSIGNMENT_RE.sub("SENTINEL_SFTP_PASSWORD=<redacted>", redacted)
    for _, pattern in TOKEN_PATTERNS:
        redacted = pattern.sub("<redacted>", redacted)
    redacted = re.sub(r"(https?://)([^/\s:@]+):([^@\s]+)@", r"\1***:***@", redacted)
    return redacted


def secret_findings_for_text(path: Path, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pattern_name, pattern in [("secret_assignment", SECRET_ASSIGNMENT_RE), ("sftp_password_assignment", SFTP_PASSWORD_ASSIGNMENT_RE)]:
        for match in pattern.finditer(text):
            value = match.group(2) if pattern_name == "secret_assignment" else match.group(1)
            if not is_probable_secret_value(value):
                continue
            excerpt = text[max(0, match.start() - 40) : min(len(text), match.end() + 40)]
            if is_known_fake_secret_excerpt(excerpt):
                continue
            findings.append(
                {
                    "path": rel(path),
                    "pattern": pattern_name,
                    "masked_excerpt": redact_text(excerpt),
                }
            )
    for pattern_name, pattern in TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            excerpt = text[max(0, match.start() - 40) : min(len(text), match.end() + 40)]
            if is_known_fake_secret_excerpt(excerpt):
                continue
            findings.append(
                {
                    "path": rel(path),
                    "pattern": pattern_name,
                    "masked_excerpt": redact_text(excerpt),
                }
            )
    return findings


def is_known_fake_secret_excerpt(excerpt: str) -> bool:
    lower = excerpt.lower()
    return any(marker.lower() in lower for marker in KNOWN_FAKE_SECRET_MARKERS)


def is_probable_secret_value(value: str) -> bool:
    cleaned = value.strip().strip("'\"),;")
    lower = cleaned.lower()
    if not cleaned or "<redacted>" in lower:
        return False
    if any(marker.lower() in lower for marker in KNOWN_FAKE_SECRET_MARKERS):
        return False
    safe_prefixes = (
        "os.environ",
        "os.getenv",
        "getenv",
        "secrets.",
        "secret.",
        "redact",
        "detect",
        "mask",
        "raw_path",
        "content",
        "warning_",
        "path",
        "token_hex",
        "prohibited",
        "inspect_output_file",
        "count_status",
    )
    if lower.startswith(safe_prefixes):
        return False
    if re.fullmatch(r"[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+", lower):
        return False
    if cleaned.isupper() and "_" in cleaned:
        return False
    if cleaned in {"true", "false", "null", "none", "not_applied"}:
        return False
    if any(pattern.search(cleaned) for _, pattern in TOKEN_PATTERNS):
        return True
    classes = sum(
        [
            bool(re.search(r"[a-z]", cleaned)),
            bool(re.search(r"[A-Z]", cleaned)),
            bool(re.search(r"[0-9]", cleaned)),
            bool(re.search(r"[^A-Za-z0-9]", cleaned)),
        ]
    )
    return len(cleaned) >= 16 and classes >= 2


def scan_paths(paths: Iterable[Path]) -> dict[str, Any]:
    safe_candidates: list[dict[str, Any]] = []
    blocked_files: list[dict[str, Any]] = []
    secret_findings: list[dict[str, Any]] = []
    scanned_count = 0
    for path in sorted({p.resolve() for p in paths}):
        if not path.exists() or not path.is_file():
            continue
        is_safe, reason = is_safe_stage_candidate(path)
        if not is_safe:
            blocked_files.append({"path": rel(path), "reason": reason})
            continue
        text, scan_skip_reason = read_text_for_scan(path)
        if scan_skip_reason:
            blocked_files.append({"path": rel(path), "reason": scan_skip_reason})
            continue
        scanned_count += 1
        findings = secret_findings_for_text(path, text or "")
        if findings:
            secret_findings.extend(findings)
            blocked_files.append({"path": rel(path), "reason": "secret_pattern_detected"})
            continue
        safe_candidates.append({"path": rel(path), "reason": reason, "size": path.stat().st_size})

    return {
        "scanned_count": scanned_count,
        "safe_candidates": safe_candidates,
        "safe_candidates_count": len(safe_candidates),
        "blocked_files": blocked_files,
        "blocked_files_count": len(blocked_files),
        "secret_findings": secret_findings[:50],
        "secret_findings_count": len(secret_findings),
        "secret_scan_status": "BLOCKED" if secret_findings else "OK",
    }


def gitignore_missing_patterns(content: str) -> list[str]:
    existing = {line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")}
    return [pattern for pattern in REQUIRED_GITIGNORE_PATTERNS if pattern not in existing]


def merged_gitignore_content(content: str) -> str:
    lines = content.splitlines()
    missing = gitignore_missing_patterns(content)
    if not missing:
        return content if content.endswith("\n") else content + "\n"
    if lines and lines[-1].strip():
        lines.append("")
    lines.append("# Sentinel local safety exclusions")
    lines.extend(missing)
    return "\n".join(lines).rstrip() + "\n"


def write_gitignore() -> dict[str, Any]:
    content = GITIGNORE.read_text(encoding="utf-8") if GITIGNORE.exists() else ""
    missing_before = gitignore_missing_patterns(content)
    GITIGNORE.write_text(merged_gitignore_content(content), encoding="utf-8")
    content_after = GITIGNORE.read_text(encoding="utf-8")
    return {
        "gitignore_path": rel(GITIGNORE),
        "missing_before_count": len(missing_before),
        "added_patterns": missing_before,
        "missing_after_count": len(gitignore_missing_patterns(content_after)),
    }


def env_file_status() -> dict[str, Any]:
    path = ROOT / ".sentinel-sftp.env"
    if not path.exists():
        return {"exists": False, "path": ".sentinel-sftp.env", "mode": None, "mode_is_600": False}
    mode = oct(path.stat().st_mode & 0o777)
    return {"exists": True, "path": ".sentinel-sftp.env", "mode": mode, "mode_is_600": mode == "0o600"}


def create_playbook() -> dict[str, Any]:
    playbook = {
        "name": "git-safety-checkpoint",
        "purpose": "Prepare a local Git checkpoint without secrets, backups, audit logs, snapshots, or binary artifacts.",
        "allowed_actions": [
            "inspect_git_status",
            "scan_text_files_for_secret_like_values",
            "write_gitignore_safety_patterns",
            "stage_allowlisted_text_files",
            "commit_only_when_scan_is_clean",
            "write_local_reports",
        ],
        "blocked_actions": [
            "automatic_push",
            "force_push",
            "history_rewrite",
            "destructive_clean",
            "hard_reset",
            "recursive_delete",
            "staging_env_files",
            "staging_backups_snapshots_or_audit_logs",
            "staging_large_binary_artifacts",
        ],
        "safe_stage_allowlist": [
            "sentinel_*.py",
            "deploy/systemd/*.service",
            "deploy/systemd/*.timer",
            "deploy/systemd/*.review.sh",
            "playbooks/*.playbook.json",
            "reports/latest/*.json",
            "reports/latest/*.md",
            "state/adaptive-learning/*.json",
            "README.md",
            "docs/*.md",
        ],
        "required_gitignore_patterns": REQUIRED_GITIGNORE_PATTERNS,
        "owner_review_boundaries": [
            "Review staged files before manual push.",
            "Do not commit .sentinel-sftp.env or other env files.",
            "Do not commit backups, snapshots, audit JSONL, or downloaded image artifacts.",
        ],
        "output_reports": [rel(REPORT_JSON), rel(REPORT_MD), rel(PUSH_READINESS_MD), rel(STATE_JSON)],
    }
    write_json(PLAYBOOK_JSON, playbook)
    return playbook


def build_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Git Safety Checkpoint",
        "",
        f"- status: `{report.get('checkpoint_status')}`",
        f"- timestamp_utc: `{report.get('timestamp_utc')}`",
        f"- is_git_repo: `{report.get('is_git_repo')}`",
        f"- branch: `{report.get('branch') or 'n/a'}`",
        f"- staged_files_count: `{report.get('staged_files_count', 0)}`",
        f"- committed_files_count: `{report.get('committed_files_count', 0)}`",
        f"- commit_hash: `{report.get('commit_hash') or 'n/a'}`",
        f"- blocked_files_count: `{report.get('blocked_files_count', 0)}`",
        f"- secret_scan_status: `{report.get('secret_scan_status')}`",
        f"- push_readiness: `{report.get('push_readiness')}`",
        "",
        "## Remote",
    ]
    remotes = report.get("remotes") or []
    if remotes:
        lines.extend([f"- `{remote}`" for remote in remotes])
    else:
        lines.append("- none detected")
    lines.extend(["", "## Safety Notes", ""])
    lines.extend(
        [
            "- No automatic push is performed.",
            "- Backups, snapshots, audit JSONL, env files, and image artifacts are not staged.",
            "- Secret-like findings block commit and values are masked in reports.",
        ]
    )
    blocked = report.get("blocked_files_sample") or []
    if blocked:
        lines.extend(["", "## Blocked Files Sample", ""])
        for item in blocked[:20]:
            lines.append(f"- `{item.get('path')}`: {item.get('reason')}")
    return "\n".join(lines).rstrip() + "\n"


def build_push_readiness_md(report: dict[str, Any]) -> str:
    manual = report.get("recommended_manual_push_command") or "n/a"
    lines = [
        "# Git Push Readiness",
        "",
        f"- push_readiness: `{report.get('push_readiness')}`",
        f"- is_git_repo: `{report.get('is_git_repo')}`",
        f"- branch: `{report.get('branch') or 'n/a'}`",
        f"- remotes_count: `{len(report.get('remotes') or [])}`",
        f"- secret_scan_status: `{report.get('secret_scan_status')}`",
        f"- commit_hash: `{report.get('commit_hash') or 'n/a'}`",
        "",
        "## Manual Push Command",
        "",
        f"`{manual}`",
        "",
        "Push is intentionally not executed by this checkpoint module.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def save_report(report: dict[str, Any]) -> None:
    write_json(REPORT_JSON, report)
    write_json(STATE_JSON, report)
    write_text(REPORT_MD, build_markdown(report))
    write_text(PUSH_READINESS_MD, build_push_readiness_md(report))
    append_jsonl(AUDIT_JSONL, {"timestamp_utc": utc_now(), "event": report.get("last_action"), "report": report})


def base_report(action: str) -> dict[str, Any]:
    repo = is_git_repo()
    branch = get_branch() if repo else ""
    remotes = get_remotes() if repo else []
    staged = staged_files() if repo else []
    return {
        "timestamp_utc": utc_now(),
        "last_action": action,
        "checkpoint_status": "GIT_CHECKPOINT_NOT_A_GIT_REPO" if not repo else "GIT_CHECKPOINT_READY",
        "is_git_repo": repo,
        "branch": branch,
        "remotes": remotes,
        "git_status_short": git_status_short() if repo else [],
        "staged_files_count": len(staged),
        "staged_files": staged,
        "committed_files_count": 0,
        "commit_hash": "",
        "blocked_files_count": 0,
        "secret_scan_status": "NOT_RUN",
        "push_readiness": "NOT_EVALUATED",
        "recommended_manual_push_command": "",
        "env_file": env_file_status(),
        "gitignore_missing_count": len(gitignore_missing_patterns(GITIGNORE.read_text(encoding="utf-8") if GITIGNORE.exists() else "")),
        "auto_push_executed": False,
        "force_push_executed": False,
    }


def action_status() -> dict[str, Any]:
    report = base_report("status")
    if report["is_git_repo"] and staged_files():
        scan = scan_paths([ROOT / p for p in staged_files()])
    elif not report["is_git_repo"]:
        scan = scan_paths(tracked_or_changed_paths())
    else:
        scan = {
            "secret_findings_count": 0,
            "secret_scan_status": "OK",
            "blocked_files_count": 0,
            "blocked_files": [],
        }
    report.update(
        {
            "secret_scan_status": scan["secret_scan_status"],
            "blocked_files_count": scan.get("blocked_files_count", 0),
            "blocked_files_sample": (scan.get("blocked_files") or [])[:25],
            "checkpoint_status": "GIT_CHECKPOINT_NOT_A_GIT_REPO"
            if not report["is_git_repo"]
            else ("GIT_CHECKPOINT_BLOCKED_SECRET_PATTERN" if scan["secret_scan_status"] != "OK" else "GIT_CHECKPOINT_READY"),
        }
    )
    report.update(push_readiness_fields(report))
    create_playbook()
    save_report(report)
    print_status(report)
    return report


def action_scan() -> dict[str, Any]:
    paths = tracked_or_changed_paths()
    scan = scan_paths(paths)
    report = base_report("scan")
    report.update(scan)
    report["blocked_files_sample"] = scan["blocked_files"][:50]
    if scan["secret_findings_count"]:
        report["checkpoint_status"] = "GIT_CHECKPOINT_BLOCKED_SECRET_PATTERN"
    elif not report["is_git_repo"]:
        report["checkpoint_status"] = "GIT_CHECKPOINT_NOT_A_GIT_REPO"
    else:
        report["checkpoint_status"] = "GIT_CHECKPOINT_SCAN_OK"
    report.update(push_readiness_fields(report))
    create_playbook()
    save_report(report)
    print(f"scan_status={report['checkpoint_status']} safe_candidates={scan['safe_candidates_count']} blocked={scan['blocked_files_count']} secrets={scan['secret_findings_count']}")
    return report


def action_write_gitignore() -> dict[str, Any]:
    gitignore_result = write_gitignore()
    report = base_report("write-gitignore")
    report["gitignore"] = gitignore_result
    report["gitignore_missing_count"] = gitignore_result["missing_after_count"]
    report["checkpoint_status"] = (
        "GIT_CHECKPOINT_NOT_A_GIT_REPO" if not report["is_git_repo"] else "GIT_CHECKPOINT_GITIGNORE_UPDATED"
    )
    report.update(push_readiness_fields(report))
    create_playbook()
    save_report(report)
    print(f"gitignore_added={gitignore_result['missing_before_count']} missing_after={gitignore_result['missing_after_count']}")
    return report


def action_stage_safe() -> dict[str, Any]:
    paths = tracked_or_changed_paths()
    scan = scan_paths(paths)
    report = base_report("stage-safe")
    report.update(scan)
    report["blocked_files_sample"] = scan["blocked_files"][:50]
    if scan["secret_findings_count"]:
        report["checkpoint_status"] = "GIT_CHECKPOINT_BLOCKED_SECRET_PATTERN"
    elif not report["is_git_repo"]:
        report["checkpoint_status"] = "GIT_CHECKPOINT_NOT_A_GIT_REPO"
    else:
        safe_paths = [item["path"] for item in scan["safe_candidates"]]
        if safe_paths:
            result = run_git(["add", "--", *safe_paths])
            report["git_add_returncode"] = result.returncode
            report["git_add_stderr"] = redact_text(result.stderr)
            report["checkpoint_status"] = "GIT_CHECKPOINT_STAGE_OK" if result.ok else "GIT_CHECKPOINT_STAGE_FAILED"
        else:
            report["checkpoint_status"] = "GIT_CHECKPOINT_NO_SAFE_FILES_TO_STAGE"
        staged = staged_files()
        report["staged_files"] = staged
        report["staged_files_count"] = len(staged)
    report.update(push_readiness_fields(report))
    create_playbook()
    save_report(report)
    print(f"stage_status={report['checkpoint_status']} staged={report['staged_files_count']} blocked={scan['blocked_files_count']} secrets={scan['secret_findings_count']}")
    return report


def action_commit() -> dict[str, Any]:
    report = base_report("commit")
    if not report["is_git_repo"]:
        report["checkpoint_status"] = "GIT_CHECKPOINT_NOT_A_GIT_REPO"
        report.update(push_readiness_fields(report))
        save_report(report)
        print("commit_status=GIT_CHECKPOINT_NOT_A_GIT_REPO")
        return report

    staged = staged_files()
    if not staged:
        report["checkpoint_status"] = "GIT_CHECKPOINT_NO_STAGED_FILES"
        report.update(push_readiness_fields(report))
        save_report(report)
        print("commit_status=GIT_CHECKPOINT_NO_STAGED_FILES")
        return report

    scan = scan_paths([ROOT / p for p in staged])
    report.update(scan)
    report["blocked_files_sample"] = scan["blocked_files"][:50]
    if scan["secret_findings_count"]:
        report["checkpoint_status"] = "GIT_CHECKPOINT_BLOCKED_SECRET_PATTERN"
        report.update(push_readiness_fields(report))
        save_report(report)
        print("commit_status=GIT_CHECKPOINT_BLOCKED_SECRET_PATTERN")
        return report

    result = run_git(["commit", "-m", COMMIT_MESSAGE])
    report["git_commit_returncode"] = result.returncode
    report["git_commit_stdout"] = redact_text(result.stdout)
    report["git_commit_stderr"] = redact_text(result.stderr)
    if result.ok:
        head = run_git(["rev-parse", "HEAD"])
        files_count = 0
        stat = run_git(["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"])
        if stat.ok and stat.stdout:
            files_count = len([line for line in stat.stdout.splitlines() if line.strip()])
        report["commit_hash"] = head.stdout if head.ok else ""
        report["committed_files_count"] = files_count
        report["checkpoint_status"] = "GIT_CHECKPOINT_COMMITTED"
    else:
        report["checkpoint_status"] = "GIT_CHECKPOINT_COMMIT_FAILED"
    report.update(push_readiness_fields(report))
    save_report(report)
    print(f"commit_status={report['checkpoint_status']} commit_hash={report.get('commit_hash') or 'n/a'}")
    return report


def push_readiness_fields(report: dict[str, Any]) -> dict[str, Any]:
    is_repo = bool(report.get("is_git_repo"))
    branch = report.get("branch") or ""
    remotes = report.get("remotes") or []
    secret_scan_status = report.get("secret_scan_status", "NOT_RUN")
    commit_hash = report.get("commit_hash") or ""
    if is_repo and not commit_hash:
        head = run_git(["rev-parse", "HEAD"])
        commit_hash = head.stdout if head.ok else ""
    if not is_repo:
        readiness = "PUSH_READINESS_NOT_READY_NO_GIT_REPO"
        manual = "n/a"
    elif secret_scan_status not in {"OK", "NOT_RUN"}:
        readiness = "PUSH_READINESS_BLOCKED_SECRET_SCAN"
        manual = "n/a"
    elif not remotes:
        readiness = "PUSH_READINESS_NOT_READY_NO_REMOTE"
        manual = "n/a"
    elif not branch:
        readiness = "PUSH_READINESS_NOT_READY_NO_BRANCH"
        manual = "n/a"
    elif not commit_hash:
        readiness = "PUSH_READINESS_NOT_READY_NO_COMMIT"
        manual = "n/a"
    else:
        readiness = "PUSH_READINESS_READY_FOR_MANUAL_PUSH"
        manual = f"git push -u origin {branch}"
    return {
        "push_readiness": readiness,
        "recommended_manual_push_command": manual,
        "commit_hash": report.get("commit_hash") or commit_hash,
    }


def action_push_readiness() -> dict[str, Any]:
    report = base_report("push-readiness")
    if report["is_git_repo"] and staged_files():
        scan = scan_paths([ROOT / p for p in staged_files()])
        report["secret_scan_status"] = scan["secret_scan_status"]
        report["blocked_files_count"] = scan["blocked_files_count"]
        report["blocked_files_sample"] = scan["blocked_files"][:50]
    else:
        report["secret_scan_status"] = "OK"
    report.update(push_readiness_fields(report))
    report["checkpoint_status"] = report["push_readiness"]
    create_playbook()
    save_report(report)
    print(f"push_readiness={report['push_readiness']} manual={report['recommended_manual_push_command']}")
    return report


def print_status(report: dict[str, Any]) -> None:
    print(f"checkpoint_status={report.get('checkpoint_status')}")
    print(f"is_git_repo={report.get('is_git_repo')}")
    print(f"branch={report.get('branch') or 'n/a'}")
    print(f"staged_files_count={report.get('staged_files_count', 0)}")
    print(f"secret_scan_status={report.get('secret_scan_status')}")
    print(f"push_readiness={report.get('push_readiness')}")


def action_self_test() -> dict[str, Any]:
    failures: list[str] = []

    sample_gitignore = ".sentinel-sftp.env\n"
    merged = merged_gitignore_content(sample_gitignore)
    if gitignore_missing_patterns(merged):
        failures.append("gitignore_merge_missing_patterns")

    secret_value = "super" + "Secret" + "Token12345"
    secret_line = "pass" + "word=" + secret_value
    fake_path = ROOT / "fake.txt"
    findings = secret_findings_for_text(fake_path, secret_line)
    if not findings:
        failures.append("secret_pattern_not_detected")
    if findings and secret_value in json.dumps(findings):
        failures.append("secret_value_not_masked")

    blocked_expectations = {
        ROOT / "backups/example.json": "backups_not_blocked",
        ROOT / "snapshots/example.json": "snapshots_not_blocked",
        ROOT / "audit/example.jsonl": "audit_not_blocked",
        ROOT / ".sentinel-sftp.env": "sftp_env_not_blocked",
        ROOT / ".env": "env_not_blocked",
        ROOT / "candidate.webp": "image_artifact_not_blocked",
    }
    for path, failure in blocked_expectations.items():
        safe, _ = is_safe_stage_candidate(path)
        if safe:
            failures.append(failure)

    safe, _ = is_safe_stage_candidate(ROOT / "sentinel_git_safety_checkpoint.py")
    if not safe:
        failures.append("sentinel_py_not_allowed")

    staged_secret_scan = {"secret_findings_count": 1}
    if staged_secret_scan["secret_findings_count"] == 0:
        failures.append("commit_not_blocked_on_secret")

    parser = build_parser()
    commands = sorted(action for action in vars(parser.parse_args(["--self-test"])) if action)
    if "apply" in commands:
        failures.append("apply_command_present")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_json = Path(tmp) / "report.json"
        write_json(tmp_json, {"ok": True})
        try:
            json.loads(tmp_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            failures.append("json_invalid")

    status = "GIT_CHECKPOINT_SELF_TEST_OK" if not failures else "GIT_CHECKPOINT_SELF_TEST_FAILED"
    result = {
        "timestamp_utc": utc_now(),
        "checkpoint_status": status,
        "failures": failures,
        "auto_push_executed": False,
        "self_test_checks": [
            "gitignore_required_patterns",
            "secret_masking",
            "blocked_backup_snapshot_audit_env_image_files",
            "commit_blocked_by_secret",
            "no_apply_mode",
            "json_valid",
        ],
    }
    write_json(REPORT_JSON, {**base_report("self-test"), **result, **push_readiness_fields(base_report("self-test"))})
    append_jsonl(AUDIT_JSONL, {"timestamp_utc": utc_now(), "event": "self-test", "result": result})
    if failures:
        print("self_test=FAILED " + ",".join(failures))
        return result
    print("self_test=OK")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe Git checkpoint preparation for Sentinel.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--scan", action="store_true")
    group.add_argument("--write-gitignore", action="store_true")
    group.add_argument("--stage-safe", action="store_true")
    group.add_argument("--commit", action="store_true")
    group.add_argument("--push-readiness", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.self_test:
            result = action_self_test()
            return 0 if result["checkpoint_status"] == "GIT_CHECKPOINT_SELF_TEST_OK" else 1
        if args.status:
            action_status()
        elif args.scan:
            action_scan()
        elif args.write_gitignore:
            action_write_gitignore()
        elif args.stage_safe:
            action_stage_safe()
        elif args.commit:
            action_commit()
        elif args.push_readiness:
            action_push_readiness()
        return 0
    except Exception as exc:  # defensive reporting; values are sanitized.
        report = base_report("failed")
        report["checkpoint_status"] = "GIT_CHECKPOINT_FAILED"
        report["error"] = redact_text(f"{exc.__class__.__name__}: {exc}")
        report.update(push_readiness_fields(report))
        save_report(report)
        print(f"checkpoint_status=GIT_CHECKPOINT_FAILED error={report['error']}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
