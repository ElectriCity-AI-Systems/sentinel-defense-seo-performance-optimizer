#!/usr/bin/env python3
"""Safe-End Archive Integrity Verifier (Phase 5.12).

Read-only verifier for the latest Safe-End archive. It checks manifest presence,
copied archive files, SHA256 integrity, forbidden artifacts, and locked safety
flags. It never restores, installs, activates autonomy, or creates executable
artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")
ARCHIVE_ROOT = PROJECT_DIR / "archives/safe-end"

ARCHIVE_SNAPSHOT_JSON = PROJECT_DIR / "reports/latest/safe-end-archive-snapshot.json"
ARCHIVE_SNAPSHOT_MD = PROJECT_DIR / "reports/latest/safe-end-archive-snapshot.md"
SAFE_END_SUMMARY_JSON = PROJECT_DIR / "reports/latest/safe-end-summary.json"
MASTER_JSON = PROJECT_DIR / "reports/latest/sentinel-master-report.json"
MASTER_MD = PROJECT_DIR / "reports/latest/sentinel-master-report.md"

REPORT_JSON = PROJECT_DIR / "reports/latest/safe-end-archive-integrity-verifier.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-end-archive-integrity-verifier.md"
OWNER_MD = PROJECT_DIR / "drafts/owner/safe-end-archive-integrity-owner-checklist.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/safe-end-archive-integrity-verifier.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/safe-end-archive-integrity-verifier.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-end-archive-integrity-verifier.jsonl"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, OWNER_MD, SNAPSHOT_JSON, SNAPSHOT_MD, AUDIT_JSONL)

FORBIDDEN_SUFFIXES = {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".env", ".bin", ".run"}
SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")

SCHEMA_VERSION = "safe-end-archive-integrity-verifier-5.12"
APPLY_NOT_APPLIED = "not_applied"

STATUS_VERIFIED_LOCKED = "SAFE_END_ARCHIVE_INTEGRITY_VERIFIED_LOCKED"
STATUS_PARTIAL = "SAFE_END_ARCHIVE_INTEGRITY_PARTIAL"
STATUS_MISMATCH = "SAFE_END_ARCHIVE_INTEGRITY_MISMATCH"
STATUS_FORBIDDEN = "SAFE_END_ARCHIVE_INTEGRITY_FORBIDDEN_ARTIFACT"
STATUS_BLOCKED_BY_BREACH = "SAFE_END_ARCHIVE_INTEGRITY_BLOCKED_BY_BREACH"
STATUS_BREACH = "SAFE_END_ARCHIVE_INTEGRITY_BREACH"

ACTION_BY_STATUS = {
    STATUS_VERIFIED_LOCKED: "Safe-End archive integrity verified. Keep Emergency Stop active. Do not enable autonomy. Use archive only for audit and manual reference.",
    STATUS_PARTIAL: "Archive verification partial. Review missing inputs before relying on this archive.",
    STATUS_MISMATCH: "Do not rely on archive. Investigate checksum mismatch.",
    STATUS_FORBIDDEN: "Do not rely on archive. Remove forbidden artifact and recreate archive.",
    STATUS_BLOCKED_BY_BREACH: "Do not proceed. Resolve breach first.",
    STATUS_BREACH: "Do not proceed. Resolve breach first.",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def redact_text(value: Any, default: str = "-", max_len: int = 1000) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
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
    if path not in ALLOWED_OUTPUT_PATHS and not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed verifier roots: {path}")
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install/restore artifact: {path}")
    if SECRET_NAME_RE.search(path.name):
        raise ValueError(f"Refusing secret-like output path: {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def read_json_file(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    try:
        if not path.exists():
            return None, "missing"
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"
    if not isinstance(data, dict):
        return None, "json_root_not_object"
    return data, "ok"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def latest_archive(root: Path = ARCHIVE_ROOT) -> Tuple[Optional[Path], str]:
    try:
        if not root.exists():
            return None, "archive_root_missing"
        candidates = [path for path in root.iterdir() if path.is_dir()]
    except OSError:
        return None, "archive_root_read_error"
    if not candidates:
        return None, "no_archives"
    candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return candidates[0], "ok"


def parse_checksums(path: Path) -> Tuple[Dict[str, str], str]:
    try:
        if not path.exists():
            return {}, "missing"
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}, "read_error"
    checksums: Dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            return checksums, "invalid_line"
        digest, file_path = parts
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", digest):
            return checksums, "invalid_digest"
        checksums[file_path.strip()] = digest.lower()
    return checksums, "ok"


def bool_from(data: Optional[Dict[str, Any]], key: str, default: bool = False) -> bool:
    if not isinstance(data, dict):
        return default
    return bool(data.get(key, default))


def text_from(data: Optional[Dict[str, Any]], key: str, default: str = "") -> str:
    if not isinstance(data, dict):
        return default
    return redact_text(data.get(key), default=default, max_len=300)


def parse_count(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def forbidden_artifacts(archive_dir: Optional[Path]) -> List[str]:
    if archive_dir is None or not archive_dir.exists():
        return []
    found: List[str] = []
    try:
        for path in archive_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() in FORBIDDEN_SUFFIXES or SECRET_NAME_RE.search(path.name):
                found.append(str(path))
    except OSError:
        return found
    return sorted(found)


def copied_records(manifest: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(manifest, dict):
        return []
    records = manifest.get("copied_files")
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict) and record.get("copied")]


def verify_copied_files(
    archive_dir: Optional[Path],
    manifest: Optional[Dict[str, Any]],
    checksums: Dict[str, str],
) -> Tuple[List[Dict[str, Any]], int, int, int]:
    results: List[Dict[str, Any]] = []
    verified = 0
    missing = 0
    mismatch = 0
    for record in copied_records(manifest):
        source = str(record.get("source", ""))
        dest = Path(str(record.get("destination", "")))
        if archive_dir is None or not str(dest):
            missing += 1
            results.append({"source": source, "destination": str(dest), "status": "missing_destination"})
            continue
        if not is_within(dest, archive_dir):
            missing += 1
            results.append({"source": source, "destination": str(dest), "status": "destination_outside_archive"})
            continue
        if not dest.exists():
            missing += 1
            results.append({"source": source, "destination": str(dest), "status": "missing"})
            continue
        expected = checksums.get(source)
        if not expected:
            mismatch += 1
            results.append({"source": source, "destination": str(dest), "status": "missing_expected_checksum"})
            continue
        try:
            actual = sha256_file(dest)
        except OSError:
            missing += 1
            results.append({"source": source, "destination": str(dest), "status": "read_error"})
            continue
        if actual.lower() == expected.lower():
            verified += 1
            status = "verified"
        else:
            mismatch += 1
            status = "checksum_mismatch"
        results.append(
            {
                "source": source,
                "destination": str(dest),
                "status": status,
                "expected_sha256": expected,
                "actual_sha256": actual,
            }
        )
    return results, verified, missing, mismatch


def required_archive_files(archive_dir: Optional[Path]) -> List[Path]:
    if archive_dir is None:
        return []
    return [
        archive_dir / "manifest.json",
        archive_dir / "manifest.md",
        archive_dir / "checksums.sha256.txt",
        archive_dir / "owner-restore-readiness.md",
    ]


def missing_required_files(archive_dir: Optional[Path]) -> List[str]:
    missing: List[str] = []
    for path in required_archive_files(archive_dir):
        if not path.exists():
            missing.append(str(path))
    return missing


def count_breach_flags(data: Optional[Dict[str, Any]], prefix: str) -> List[str]:
    if not isinstance(data, dict):
        return []
    reasons: List[str] = []
    for key, value in data.items():
        if key.lower().endswith("breach") and bool(value):
            reasons.append(f"{prefix}:{key}=true")
    return reasons


def detect_safety_breaches(
    manifest: Optional[Dict[str, Any]],
    archive_snapshot: Optional[Dict[str, Any]],
    safe_end: Optional[Dict[str, Any]],
) -> Tuple[List[str], Dict[str, Any]]:
    reasons: List[str] = []
    aggregate = {
        "safe_end_status": text_from(safe_end, "safe_end_status", text_from(manifest, "safe_end_status", "NOT_AVAILABLE")),
        "archive_status": text_from(manifest, "archive_status", text_from(archive_snapshot, "archive_status", "NOT_AVAILABLE")),
        "emergency_stop_active": bool_from(manifest, "emergency_stop_active") or bool_from(archive_snapshot, "emergency_stop_active") or bool_from(safe_end, "emergency_stop_active"),
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "restore_executed": False,
        "total_breaches": 0,
    }
    for label, data in (("manifest", manifest), ("archive_snapshot", archive_snapshot), ("safe_end", safe_end)):
        if not isinstance(data, dict):
            continue
        for key in ("low_risk_autonomy_allowed_now", "policy_activation_allowed", "live_apply", "install_allowed_now", "can_install_timer_now", "restore_executed"):
            if bool_from(data, key):
                aggregate[key] = True
                reasons.append(f"{label}:{key}=true")
        apply_status = data.get("apply_status")
        if apply_status is not None and str(apply_status) != APPLY_NOT_APPLIED:
            aggregate["apply_status"] = redact_text(apply_status, max_len=120)
            reasons.append(f"{label}:apply_status != not_applied")
        reasons.extend(count_breach_flags(data, label))
        aggregate["total_breaches"] += parse_count(data.get("total_breaches"))
    return sorted(set(reasons)), aggregate


def determine_status(
    *,
    partial_inputs: bool,
    missing_file_count: int,
    checksum_mismatch_count: int,
    forbidden_artifact_count: int,
    safety_reasons: List[str],
    aggregate: Dict[str, Any],
) -> Tuple[str, bool, List[str]]:
    reasons = list(safety_reasons)
    if forbidden_artifact_count > 0:
        reasons.append("forbidden artifact found")
        return STATUS_FORBIDDEN, True, sorted(set(reasons))
    if checksum_mismatch_count > 0:
        reasons.append("checksum mismatch")
        return STATUS_MISMATCH, True, sorted(set(reasons))
    if safety_reasons:
        return STATUS_BLOCKED_BY_BREACH, True, sorted(set(reasons))
    if partial_inputs or missing_file_count > 0:
        return STATUS_PARTIAL, False, sorted(set(reasons))
    if (
        aggregate.get("safe_end_status") == "SAFE_END_COMPLETE_LOCKED"
        and aggregate.get("archive_status") == "SAFE_END_ARCHIVE_COMPLETE_LOCKED"
        and aggregate.get("emergency_stop_active")
        and not aggregate.get("low_risk_autonomy_allowed_now")
        and not aggregate.get("policy_activation_allowed")
        and not aggregate.get("install_allowed_now")
        and not aggregate.get("can_install_timer_now")
        and not aggregate.get("live_apply")
        and not aggregate.get("restore_executed")
        and aggregate.get("apply_status") == APPLY_NOT_APPLIED
    ):
        return STATUS_VERIFIED_LOCKED, False, []
    return STATUS_PARTIAL, False, []


def build_report(*, generated_at: Optional[str] = None, forced_archive_dir: Optional[Path] = None) -> Dict[str, Any]:
    generated = generated_at or utc_now()
    archive_dir, archive_status = (forced_archive_dir, "ok") if forced_archive_dir is not None else latest_archive()

    archive_snapshot, archive_snapshot_status = read_json_file(ARCHIVE_SNAPSHOT_JSON)
    safe_end, safe_end_status = read_json_file(SAFE_END_SUMMARY_JSON)
    _master, master_status = read_json_file(MASTER_JSON)

    manifest_path = archive_dir / "manifest.json" if archive_dir else Path("")
    checksums_path = archive_dir / "checksums.sha256.txt" if archive_dir else Path("")
    manifest, manifest_status = read_json_file(manifest_path) if archive_dir else (None, "missing")
    checksums, checksums_status = parse_checksums(checksums_path) if archive_dir else ({}, "missing")

    required_missing = missing_required_files(archive_dir)
    verification_results, verified_count, copied_missing_count, mismatch_count = verify_copied_files(archive_dir, manifest, checksums)
    forbidden = forbidden_artifacts(archive_dir)
    safety_reasons, aggregate = detect_safety_breaches(manifest, archive_snapshot, safe_end)

    partial_inputs = any(
        status != "ok"
        for status in (archive_status, archive_snapshot_status, safe_end_status, master_status, manifest_status, checksums_status)
    )
    missing_file_count = copied_missing_count + len(required_missing)
    forbidden_count = len(forbidden)
    manifest_file_count = len(copied_records(manifest))
    checksum_file_count = len(checksums)
    checksum_mismatch_count = mismatch_count

    status, breach, breach_reasons = determine_status(
        partial_inputs=partial_inputs,
        missing_file_count=missing_file_count,
        checksum_mismatch_count=checksum_mismatch_count,
        forbidden_artifact_count=forbidden_count,
        safety_reasons=safety_reasons,
        aggregate=aggregate,
    )
    recommended_owner_action = ACTION_BY_STATUS.get(status, ACTION_BY_STATUS[STATUS_PARTIAL])

    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": generated,
        "integrity_status": status,
        "latest_archive_path": str(archive_dir) if archive_dir else "",
        "manifest_path": str(manifest_path) if archive_dir else "",
        "manifest_file_count": manifest_file_count,
        "checksum_file_count": checksum_file_count,
        "verified_checksum_count": verified_count,
        "missing_file_count": missing_file_count,
        "checksum_mismatch_count": checksum_mismatch_count,
        "forbidden_artifact_count": forbidden_count,
        "restore_executed": False,
        "safe_end_status": aggregate.get("safe_end_status"),
        "archive_status": aggregate.get("archive_status"),
        "emergency_stop_active": bool(aggregate.get("emergency_stop_active")),
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "total_breaches": parse_count(aggregate.get("total_breaches")),
        "integrity_breach": breach,
        "integrity_breach_reasons": breach_reasons,
        "recommended_owner_action": recommended_owner_action,
        "read_only": True,
        "network_access": False,
        "api_access": False,
        "wordpress_login": False,
        "restore_script_generated": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "executable_install_script_generated": False,
        "input_statuses": {
            "archive_root": archive_status,
            "safe_end_archive_snapshot_json": archive_snapshot_status,
            "safe_end_summary_json": safe_end_status,
            "sentinel_master_json": master_status,
            "manifest_json": manifest_status,
            "checksums_sha256": checksums_status,
        },
        "missing_required_archive_files": required_missing,
        "forbidden_artifacts": forbidden,
        "verification_results": verification_results,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_md": str(OWNER_MD),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
        },
    }


def render_owner_checklist(report: Dict[str, Any]) -> str:
    lines = [
        "# Safe-End Archive Integrity Owner Checklist",
        "",
        "> Review-only. This verifier does not restore, install, activate or apply anything.",
        "",
        f"- Integrity status: `{report.get('integrity_status')}`",
        f"- Latest archive path: `{report.get('latest_archive_path')}`",
        f"- Verified checksums: `{report.get('verified_checksum_count')}`",
        f"- Checksum mismatches: `{report.get('checksum_mismatch_count')}`",
        f"- Forbidden artifacts: `{report.get('forbidden_artifact_count')}`",
        f"- Restore executed: `{report.get('restore_executed')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- Integrity breach: `{report.get('integrity_breach')}`",
        "",
        "## Manual Review Steps",
        "",
        "- Confirm the archive is used only as audit/reference material.",
        "- Confirm `checksums.sha256.txt` and `manifest.json` exist in the archive.",
        "- Confirm no executable, systemd, timer, Python, env or secret-like file appears in the archive.",
        "- Confirm `restore_executed=false` and `live_apply=false` remain true in the verifier report.",
        "- Do not run restore, install, systemctl, Cloudflare, WordPress, Nginx or .htaccess actions from this checklist.",
        "",
    ]
    return "\n".join(lines)


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Safe-End Archive Integrity Verifier",
        "",
        "> Phase 5.12 verifies the locked archive. It is not restore, not activation, not install.",
        "",
        f"- Timestamp (UTC): `{report.get('timestamp_utc')}`",
        f"- Integrity status: `{report.get('integrity_status')}`",
        f"- Latest archive path: `{report.get('latest_archive_path')}`",
        f"- Manifest path: `{report.get('manifest_path')}`",
        f"- Manifest file count: `{report.get('manifest_file_count')}`",
        f"- Checksum file count: `{report.get('checksum_file_count')}`",
        f"- Verified checksum count: `{report.get('verified_checksum_count')}`",
        f"- Missing file count: `{report.get('missing_file_count')}`",
        f"- Checksum mismatch count: `{report.get('checksum_mismatch_count')}`",
        f"- Forbidden artifact count: `{report.get('forbidden_artifact_count')}`",
        f"- Restore executed: `{report.get('restore_executed')}`",
        f"- Safe end status: `{report.get('safe_end_status')}`",
        f"- Archive status: `{report.get('archive_status')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- LOW-RISK autonomy allowed now: `{report.get('low_risk_autonomy_allowed_now')}`",
        f"- Policy activation allowed: `{report.get('policy_activation_allowed')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Total breaches: `{report.get('total_breaches')}`",
        f"- Integrity breach: `{report.get('integrity_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
    ]
    if report.get("integrity_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in report.get("integrity_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=500)}")
        lines.append("")
    if report.get("missing_required_archive_files"):
        lines.extend(["## Missing Archive Files", ""])
        for path in report.get("missing_required_archive_files", []):
            lines.append(f"- `{redact_text(path, max_len=600)}`")
        lines.append("")
    if report.get("forbidden_artifacts"):
        lines.extend(["## Forbidden Artifacts", ""])
        for path in report.get("forbidden_artifacts", []):
            lines.append(f"- `{redact_text(path, max_len=600)}`")
        lines.append("")
    return "\n".join(lines)


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("timestamp_utc"),
        "schema_version": SCHEMA_VERSION,
        "integrity_status": report.get("integrity_status"),
        "latest_archive_path": report.get("latest_archive_path"),
        "verified_checksum_count": report.get("verified_checksum_count"),
        "checksum_mismatch_count": report.get("checksum_mismatch_count"),
        "forbidden_artifact_count": report.get("forbidden_artifact_count"),
        "restore_executed": False,
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "integrity_breach": report.get("integrity_breach"),
        "network_access": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    markdown = render_markdown(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, markdown)
    write_text_atomic(OWNER_MD, render_owner_checklist(report))
    write_json_atomic(SNAPSHOT_JSON, report)
    write_text_atomic(SNAPSHOT_MD, markdown)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def run_self_test() -> int:
    aggregate = {
        "safe_end_status": "SAFE_END_COMPLETE_LOCKED",
        "archive_status": "SAFE_END_ARCHIVE_COMPLETE_LOCKED",
        "emergency_stop_active": True,
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "restore_executed": False,
    }
    status, breach, _ = determine_status(
        partial_inputs=False,
        missing_file_count=0,
        checksum_mismatch_count=0,
        forbidden_artifact_count=0,
        safety_reasons=[],
        aggregate=aggregate,
    )
    if status != STATUS_VERIFIED_LOCKED or breach:
        raise AssertionError("verified locked failed")
    status, breach, _ = determine_status(partial_inputs=True, missing_file_count=0, checksum_mismatch_count=0, forbidden_artifact_count=0, safety_reasons=[], aggregate=aggregate)
    if status != STATUS_PARTIAL or breach:
        raise AssertionError("partial failed")
    status, breach, _ = determine_status(partial_inputs=False, missing_file_count=0, checksum_mismatch_count=1, forbidden_artifact_count=0, safety_reasons=[], aggregate=aggregate)
    if status != STATUS_MISMATCH or not breach:
        raise AssertionError("mismatch failed")
    status, breach, _ = determine_status(partial_inputs=False, missing_file_count=0, checksum_mismatch_count=0, forbidden_artifact_count=1, safety_reasons=[], aggregate=aggregate)
    if status != STATUS_FORBIDDEN or not breach:
        raise AssertionError("forbidden artifact failed")
    for key in ("low_risk_autonomy_allowed_now", "policy_activation_allowed", "live_apply", "install_allowed_now", "can_install_timer_now", "restore_executed"):
        bad = {key: True, "apply_status": APPLY_NOT_APPLIED}
        reasons, _agg = detect_safety_breaches(bad, {}, {})
        if not reasons:
            raise AssertionError(f"{key} did not breach")
    reasons, _agg = detect_safety_breaches({"apply_status": "applied"}, {}, {})
    if not reasons:
        raise AssertionError("apply_status breach failed")
    reasons, _agg = detect_safety_breaches({"archive_breach": True}, {}, {})
    if not reasons:
        raise AssertionError("archive_breach failed")
    reasons, _agg = detect_safety_breaches({}, {"safe_end_breach": True}, {})
    if not reasons:
        raise AssertionError("safe_end_breach failed")
    for forbidden in (PROJECT_DIR / "reports/latest/bad.sh", PROJECT_DIR / "drafts/owner/bad.service", PROJECT_DIR / "snapshots/bad.py", PROJECT_DIR / "audit/token.jsonl", Path("/tmp/outside.json")):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden output accepted: {forbidden}")
    if not SECRET_NAME_RE.search("token.json"):
        raise AssertionError("secret filename detector failed")
    print("safe-end-archive-integrity-verifier self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify latest Safe-End archive integrity; read-only, no restore.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report = build_report()
    write_outputs(report)
    print(
        "Safe-End Archive Integrity Verifier: "
        f"status={report.get('integrity_status')}, "
        f"archive={report.get('latest_archive_path')}, "
        f"verified={report.get('verified_checksum_count')}, "
        f"mismatch={report.get('checksum_mismatch_count')}, "
        f"forbidden={report.get('forbidden_artifact_count')}, "
        f"breach={report.get('integrity_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
