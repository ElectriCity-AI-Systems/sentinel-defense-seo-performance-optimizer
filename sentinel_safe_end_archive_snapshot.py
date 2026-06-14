#!/usr/bin/env python3
"""Safe-End Archive & Restore Readiness Snapshot (Phase 5.11).

This module archives the locked Safe-End state for audit/manual reference only.
It is not an apply mechanism, not autonomy activation, not installation, not a
timer, and not a restore tool. It creates checksums, a manifest, copied
non-executable JSON/MD/TXT artifacts, and an owner restore-readiness checklist.
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

INPUT_PATHS = (
    PROJECT_DIR / "reports/latest/safe-end-summary.json",
    PROJECT_DIR / "reports/latest/safe-end-summary.md",
    PROJECT_DIR / "reports/latest/low-risk-autonomy-final-safety-seal.json",
    PROJECT_DIR / "reports/latest/low-risk-policy-review-completion-gate.json",
    PROJECT_DIR / "reports/latest/low-risk-policy-owner-review-tracker.json",
    PROJECT_DIR / "reports/latest/low-risk-policy-boundary-draft.json",
    PROJECT_DIR / "reports/latest/final-owner-decision-snapshot.json",
    PROJECT_DIR / "reports/latest/sentinel-master-report.json",
    PROJECT_DIR / "reports/latest/sentinel-master-report.md",
    PROJECT_DIR / "config/autonomy-runtime-lock.json",
    PROJECT_DIR / "state/low-risk-policy-owner-review.json",
    PROJECT_DIR / "state/manual-evidence-review-completion.json",
)

REPORT_JSON = PROJECT_DIR / "reports/latest/safe-end-archive-snapshot.json"
REPORT_MD = PROJECT_DIR / "reports/latest/safe-end-archive-snapshot.md"
OWNER_MD = PROJECT_DIR / "drafts/owner/safe-end-archive-owner-summary.md"
SNAPSHOT_JSON = PROJECT_DIR / "snapshots/safe-end-archive-snapshot.json"
SNAPSHOT_MD = PROJECT_DIR / "snapshots/safe-end-archive-snapshot.md"
AUDIT_JSONL = PROJECT_DIR / "audit/safe-end-archive-snapshot.jsonl"
ARCHIVE_ROOT = PROJECT_DIR / "archives/safe-end"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "drafts/owner",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "archives/safe-end",
)
ALLOWED_OUTPUT_PATHS = (REPORT_JSON, REPORT_MD, OWNER_MD, SNAPSHOT_JSON, SNAPSHOT_MD, AUDIT_JSONL)

ALLOWED_COPY_SUFFIXES = {".json", ".md", ".txt"}
FORBIDDEN_COPY_SUFFIXES = {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".bin", ".run", ".env"}
FORBIDDEN_OUTPUT_SUFFIXES = FORBIDDEN_COPY_SUFFIXES
FORBIDDEN_PATH_TOKENS = (
    "/etc/systemd",
    "systemd/system",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/etc/cron",
    "cron.d",
    "crontab",
    "/wp-admin",
    "/wp-content",
    "/wp-includes",
    "cloudflare",
    "nginx",
    ".htaccess",
)
SECRET_NAME_RE = re.compile(r"(?i)(secret|token|password|passwd|api[_-]?key|credential|authorization|cookie|session)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")

SCHEMA_VERSION = "safe-end-archive-snapshot-5.11"
APPLY_NOT_APPLIED = "not_applied"

STATUS_COMPLETE_LOCKED = "SAFE_END_ARCHIVE_COMPLETE_LOCKED"
STATUS_INCOMPLETE = "SAFE_END_ARCHIVE_INCOMPLETE"
STATUS_BLOCKED_BY_BREACH = "SAFE_END_ARCHIVE_BLOCKED_BY_BREACH"
STATUS_PARTIAL_INPUTS = "SAFE_END_ARCHIVE_PARTIAL_INPUTS"
STATUS_BREACH = "SAFE_END_ARCHIVE_BREACH"

ACTION_BY_STATUS = {
    STATUS_COMPLETE_LOCKED: "Safe-End archive created. Keep Emergency Stop active. Do not enable autonomy. Use archive only for audit and manual reference.",
    STATUS_INCOMPLETE: "Safe-End is not complete. Finish locked review chain before treating archive as final.",
    STATUS_PARTIAL_INPUTS: "Archive created with partial inputs. Review missing files.",
    STATUS_BLOCKED_BY_BREACH: "Do not proceed. Resolve breach before archiving as final.",
    STATUS_BREACH: "Do not proceed. Resolve breach before archiving as final.",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_slug(timestamp_utc: str) -> str:
    return timestamp_utc.replace("-", "").replace(":", "").replace("T", "-").replace("Z", "")


def redact_text(value: Any, default: str = "-", max_len: int = 1000) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def has_secret_like_text(value: Any) -> bool:
    text = "" if value is None else str(value)
    return bool(SECRET_ASSIGNMENT_RE.search(text) or LONG_HEX_RE.search(text))


def has_secret_like_name(path: Path) -> bool:
    return bool(SECRET_NAME_RE.search(path.name))


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def assert_allowed_write(path: Path) -> None:
    if path not in ALLOWED_OUTPUT_PATHS and not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing to write outside allowed archive roots: {path}")
    if path.suffix.lower() in FORBIDDEN_OUTPUT_SUFFIXES:
        raise ValueError(f"Refusing to write executable/install/restore artifact: {path}")
    path_text = str(path)
    if any(token in path_text for token in FORBIDDEN_PATH_TOKENS):
        raise ValueError(f"Refusing to write forbidden system/productive path: {path}")
    if has_secret_like_name(path):
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


def safe_input_path(path: Path) -> Tuple[bool, str]:
    if ".env" in str(path).lower():
        return False, "env path refused"
    if path.suffix.lower() in FORBIDDEN_COPY_SUFFIXES:
        return False, f"forbidden suffix {path.suffix}"
    if path.suffix.lower() not in ALLOWED_COPY_SUFFIXES:
        return False, f"suffix {path.suffix} not allowlisted"
    if has_secret_like_name(path):
        return False, "secret-like filename"
    path_text = str(path)
    if any(token in path_text for token in FORBIDDEN_PATH_TOKENS):
        return False, "forbidden productive/system path token"
    if not is_within(path, PROJECT_DIR):
        return False, "outside project"
    return True, "ok"


def read_json(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    ok, reason = safe_input_path(path)
    if not ok:
        return None, reason
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


def relative_copy_path(path: Path) -> Path:
    try:
        rel = path.resolve().relative_to(PROJECT_DIR.resolve())
    except (ValueError, OSError):
        rel = Path(path.name)
    return Path("copied") / rel


def copy_file_safe(source: Path, archive_dir: Path) -> Dict[str, Any]:
    ok, reason = safe_input_path(source)
    if not ok:
        return {"source": str(source), "copied": False, "reason": reason}
    if not source.exists():
        return {"source": str(source), "copied": False, "reason": "missing"}
    destination = archive_dir / relative_copy_path(source)
    assert_allowed_write(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = source.read_bytes()
    destination.write_bytes(data)
    return {"source": str(source), "destination": str(destination), "copied": True, "bytes": len(data)}


def count_breach_flags(data: Optional[Dict[str, Any]]) -> Tuple[int, List[str]]:
    if not isinstance(data, dict):
        return 0, []
    reasons: List[str] = []
    for key, value in data.items():
        lowered = key.lower()
        if lowered.endswith("breach") and bool(value):
            reasons.append(f"{key}=true")
    return len(reasons), reasons


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


def input_records(paths: Iterable[Path]) -> Tuple[List[Dict[str, Any]], Dict[str, Tuple[Optional[Dict[str, Any]], str]]]:
    records: List[Dict[str, Any]] = []
    json_data: Dict[str, Tuple[Optional[Dict[str, Any]], str]] = {}
    for path in paths:
        ok, safe_reason = safe_input_path(path)
        exists = path.exists() if ok else False
        checksum = None
        size = None
        read_status = safe_reason if not ok else ("ok" if exists else "missing")
        if ok and exists:
            try:
                checksum = sha256_file(path)
                size = path.stat().st_size
            except OSError:
                read_status = "read_error"
        if ok and path.suffix.lower() == ".json":
            json_data[str(path)] = read_json(path)
            read_status = json_data[str(path)][1] if exists else read_status
        records.append(
            {
                "path": str(path),
                "exists": exists,
                "read_status": read_status,
                "sha256": checksum,
                "size_bytes": size,
                "copy_allowed": ok and exists,
            }
        )
    return records, json_data


def detect_activation_breaches(json_data: Dict[str, Tuple[Optional[Dict[str, Any]], str]]) -> Tuple[int, List[str], Dict[str, Any]]:
    reasons: List[str] = []
    aggregate = {
        "safe_end_status": "NOT_AVAILABLE",
        "emergency_stop_active": False,
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "total_breaches": 0,
    }

    for path, (data, status) in json_data.items():
        if status != "ok" or not isinstance(data, dict):
            continue
        label = Path(path).name
        if label == "safe-end-summary.json":
            aggregate["safe_end_status"] = text_from(data, "safe_end_status", "NOT_AVAILABLE")
        if bool_from(data, "emergency_stop_active") or bool_from(data, "emergency_stop"):
            aggregate["emergency_stop_active"] = True
        for key in ("low_risk_autonomy_allowed_now", "policy_activation_allowed", "install_allowed_now", "can_install_timer_now", "live_apply"):
            if bool_from(data, key):
                aggregate[key] = True
                reasons.append(f"{label}:{key}=true")
        apply_status = data.get("apply_status")
        if apply_status is not None and str(apply_status) != APPLY_NOT_APPLIED:
            aggregate["apply_status"] = redact_text(apply_status, max_len=120)
            reasons.append(f"{label}:apply_status != not_applied")
        count, breach_reasons = count_breach_flags(data)
        if count:
            reasons.extend(f"{label}:{reason}" for reason in breach_reasons)
            aggregate["total_breaches"] += count
        if bool_from(data, "systemd_file_written"):
            reasons.append(f"{label}:systemd_file_written=true")
        if bool_from(data, "crontab_file_written"):
            reasons.append(f"{label}:crontab_file_written=true")
        if bool_from(data, "executable_install_script_generated"):
            reasons.append(f"{label}:executable artifact generated")
        if has_secret_like_text(json.dumps(data, ensure_ascii=False)):
            reasons.append(f"{label}:secret-like output")

    return len(set(reasons)), sorted(set(reasons)), aggregate


def build_manifest(
    *,
    generated_at: str,
    archive_dir: Optional[Path],
    input_records_data: List[Dict[str, Any]],
    copied_records: List[Dict[str, Any]],
    archive_status: str,
    archive_breach: bool,
    breach_reasons: List[str],
    aggregate: Dict[str, Any],
) -> Dict[str, Any]:
    checksums = [record for record in input_records_data if record.get("sha256")]
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": generated_at,
        "archive_status": archive_status,
        "archive_path": str(archive_dir) if archive_dir else "",
        "read_only_archive": True,
        "not_activation": True,
        "not_installation": True,
        "not_restore": True,
        "network_access": False,
        "api_access": False,
        "wordpress_login": False,
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "safe_end_status": aggregate.get("safe_end_status"),
        "emergency_stop_active": bool(aggregate.get("emergency_stop_active")),
        "total_breaches": parse_count(aggregate.get("total_breaches")),
        "archive_breach": archive_breach,
        "archive_breach_reasons": breach_reasons,
        "input_files": input_records_data,
        "copied_files": copied_records,
        "copied_file_count": sum(1 for record in copied_records if record.get("copied")),
        "checksum_count": len(checksums),
    }


def determine_status(
    input_records_data: List[Dict[str, Any]],
    aggregate: Dict[str, Any],
    breach_count: int,
) -> Tuple[str, bool]:
    if breach_count:
        return STATUS_BLOCKED_BY_BREACH, True
    missing = [record for record in input_records_data if not record.get("exists")]
    if missing:
        return STATUS_PARTIAL_INPUTS, False
    if (
        aggregate.get("safe_end_status") == "SAFE_END_COMPLETE_LOCKED"
        and aggregate.get("emergency_stop_active")
        and not aggregate.get("low_risk_autonomy_allowed_now")
        and not aggregate.get("policy_activation_allowed")
        and not aggregate.get("install_allowed_now")
        and not aggregate.get("can_install_timer_now")
        and not aggregate.get("live_apply")
        and aggregate.get("apply_status") == APPLY_NOT_APPLIED
        and parse_count(aggregate.get("total_breaches")) == 0
    ):
        return STATUS_COMPLETE_LOCKED, False
    return STATUS_INCOMPLETE, False


def render_checksums(input_records_data: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for record in input_records_data:
        if record.get("sha256"):
            lines.append(f"{record['sha256']}  {record['path']}")
    return "\n".join(lines) + ("\n" if lines else "")


def render_owner_restore_readiness(manifest: Dict[str, Any]) -> str:
    lines = [
        "# Safe-End Owner Restore Readiness Checklist",
        "",
        "> Review-only archive reference. This is not a restore script and must not be used as automation.",
        "",
        f"- Archive status: `{manifest.get('archive_status')}`",
        f"- Emergency stop active: `{manifest.get('emergency_stop_active')}`",
        f"- LOW-RISK autonomy allowed now: `{manifest.get('low_risk_autonomy_allowed_now')}`",
        f"- Policy activation allowed: `{manifest.get('policy_activation_allowed')}`",
        f"- Install allowed now: `{manifest.get('install_allowed_now')}`",
        f"- Can install timer now: `{manifest.get('can_install_timer_now')}`",
        f"- Live apply: `{manifest.get('live_apply')}`",
        f"- Apply status: `{manifest.get('apply_status')}`",
        f"- Archive breach: `{manifest.get('archive_breach')}`",
        "",
        "## Manual Readiness Checks",
        "",
        "- Confirm this archive is used only for audit/manual reference.",
        "- Confirm no autonomy activation is inferred from this archive.",
        "- Confirm no systemd, crontab, WordPress, Cloudflare, Nginx or .htaccess action is performed.",
        "- Confirm any future restore would be a separate owner-approved manual procedure.",
        "- Compare `checksums.sha256.txt` before trusting archived files as reference material.",
        "",
        "## Do Not Proceed Conditions",
        "",
        "- Any breach flag is true.",
        "- Emergency Stop is not intentionally active.",
        "- Any activation/apply/install/live flag is true.",
        "- Any requested action would create a restore script or execute a restore.",
        "",
    ]
    return "\n".join(lines)


def render_manifest_markdown(manifest: Dict[str, Any]) -> str:
    lines = [
        "# Safe-End Archive Manifest",
        "",
        f"- Timestamp (UTC): `{manifest.get('timestamp_utc')}`",
        f"- Archive status: `{manifest.get('archive_status')}`",
        f"- Archive path: `{manifest.get('archive_path')}`",
        f"- Copied files: `{manifest.get('copied_file_count')}`",
        f"- Checksums: `{manifest.get('checksum_count')}`",
        f"- Safe end status: `{manifest.get('safe_end_status')}`",
        f"- Emergency stop active: `{manifest.get('emergency_stop_active')}`",
        f"- Live apply: `{manifest.get('live_apply')}`",
        f"- Apply status: `{manifest.get('apply_status')}`",
        f"- Archive breach: `{manifest.get('archive_breach')}`",
        "",
    ]
    if manifest.get("archive_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in manifest.get("archive_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=500)}")
        lines.append("")
    lines.extend(["## Copied Files", ""])
    copied = [record for record in manifest.get("copied_files", []) if record.get("copied")]
    if copied:
        for record in copied:
            lines.append(f"- `{redact_text(record.get('source'), max_len=600)}` -> `{redact_text(record.get('destination'), max_len=600)}`")
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def render_report_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Safe-End Archive Snapshot",
        "",
        "> Phase 5.11 archives the locked safe end state. It is not activation, not install, not restore.",
        "",
        f"- Timestamp (UTC): `{report.get('timestamp_utc')}`",
        f"- Archive status: `{report.get('archive_status')}`",
        f"- Archive path: `{report.get('archive_path')}`",
        f"- Manifest path: `{report.get('manifest_path')}`",
        f"- Copied file count: `{report.get('copied_file_count')}`",
        f"- Checksum count: `{report.get('checksum_count')}`",
        f"- Safe end status: `{report.get('safe_end_status')}`",
        f"- Emergency stop active: `{report.get('emergency_stop_active')}`",
        f"- LOW-RISK autonomy allowed now: `{report.get('low_risk_autonomy_allowed_now')}`",
        f"- Policy activation allowed: `{report.get('policy_activation_allowed')}`",
        f"- Install allowed now: `{report.get('install_allowed_now')}`",
        f"- Can install timer now: `{report.get('can_install_timer_now')}`",
        f"- Live apply: `{report.get('live_apply')}`",
        f"- Apply status: `{report.get('apply_status')}`",
        f"- Total breaches: `{report.get('total_breaches')}`",
        f"- Archive breach: `{report.get('archive_breach')}`",
        f"- Recommended owner action: {redact_text(report.get('recommended_owner_action'), max_len=900)}",
        "",
    ]
    if report.get("archive_breach_reasons"):
        lines.extend(["## Breach Reasons", ""])
        for reason in report.get("archive_breach_reasons", []):
            lines.append(f"- {redact_text(reason, max_len=500)}")
        lines.append("")
    lines.extend(["## Inputs", "", "| Path | Exists | Status | SHA256 |", "|---|---:|---|---|"])
    for record in report.get("input_files", []):
        lines.append(
            f"| `{redact_text(record.get('path'), max_len=600)}` | "
            f"`{record.get('exists')}` | `{redact_text(record.get('read_status'), max_len=120)}` | "
            f"`{redact_text(record.get('sha256'), default='-', max_len=90)}` |"
        )
    lines.append("")
    return "\n".join(lines)


def archive_files(
    archive_dir: Path,
    input_records_data: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    copied: List[Dict[str, Any]] = []
    for record in input_records_data:
        copied.append(copy_file_safe(Path(str(record["path"])), archive_dir))
    return copied


def build_report(*, generated_at: Optional[str] = None, forced_inputs: Optional[Tuple[List[Dict[str, Any]], Dict[str, Tuple[Optional[Dict[str, Any]], str]]]] = None) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    generated = generated_at or utc_now()
    slug = timestamp_slug(generated)
    input_records_data, json_data = forced_inputs if forced_inputs is not None else input_records(INPUT_PATHS)
    breach_count, breach_reasons, aggregate = detect_activation_breaches(json_data)
    status, archive_breach = determine_status(input_records_data, aggregate, breach_count)

    archive_dir: Optional[Path] = None
    copied_records: List[Dict[str, Any]] = []
    manifest: Optional[Dict[str, Any]] = None
    if not archive_breach:
        archive_dir = ARCHIVE_ROOT / slug
        assert_allowed_write(archive_dir / "manifest.json")
        archive_dir.mkdir(parents=True, exist_ok=True)
        copied_records = archive_files(archive_dir, input_records_data)
        executable_copies = [record for record in copied_records if record.get("copied") and Path(str(record.get("destination"))).suffix.lower() in FORBIDDEN_COPY_SUFFIXES]
        secret_copies = [record for record in copied_records if record.get("copied") and has_secret_like_name(Path(str(record.get("destination"))))]
        if executable_copies or secret_copies:
            archive_breach = True
            status = STATUS_BREACH
            breach_reasons = sorted(set(breach_reasons + ["executable artifact copied or generated" for _ in executable_copies] + ["secret-like file copied or output" for _ in secret_copies]))

    manifest = build_manifest(
        generated_at=generated,
        archive_dir=archive_dir,
        input_records_data=input_records_data,
        copied_records=copied_records,
        archive_status=status,
        archive_breach=archive_breach,
        breach_reasons=breach_reasons,
        aggregate=aggregate,
    )

    if archive_dir and not archive_breach:
        write_json_atomic(archive_dir / "manifest.json", manifest)
        write_text_atomic(archive_dir / "manifest.md", render_manifest_markdown(manifest))
        write_text_atomic(archive_dir / "checksums.sha256.txt", render_checksums(input_records_data))
        write_text_atomic(archive_dir / "owner-restore-readiness.md", render_owner_restore_readiness(manifest))

    recommended_owner_action = ACTION_BY_STATUS.get(status, ACTION_BY_STATUS[STATUS_INCOMPLETE])
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": generated,
        "archive_status": status,
        "archive_path": str(archive_dir) if archive_dir else "",
        "manifest_path": str(archive_dir / "manifest.json") if archive_dir and not archive_breach else "",
        "copied_file_count": manifest.get("copied_file_count", 0),
        "checksum_count": manifest.get("checksum_count", 0),
        "safe_end_status": aggregate.get("safe_end_status"),
        "emergency_stop_active": bool(aggregate.get("emergency_stop_active")),
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "total_breaches": parse_count(aggregate.get("total_breaches")),
        "archive_breach": archive_breach,
        "archive_breach_reasons": breach_reasons,
        "recommended_owner_action": recommended_owner_action,
        "read_only_archive": True,
        "network_access": False,
        "api_access": False,
        "wordpress_login": False,
        "cloudflare_mutations": False,
        "wordpress_mutations": False,
        "nginx_mutations": False,
        "htaccess_mutations": False,
        "systemd_file_written": False,
        "crontab_file_written": False,
        "executable_install_script_generated": False,
        "restore_script_generated": False,
        "restore_executed": False,
        "input_files": input_records_data,
        "copied_files": copied_records,
        "outputs": {
            "report_json": str(REPORT_JSON),
            "report_md": str(REPORT_MD),
            "owner_md": str(OWNER_MD),
            "snapshot_json": str(SNAPSHOT_JSON),
            "snapshot_md": str(SNAPSHOT_MD),
            "audit_jsonl": str(AUDIT_JSONL),
            "archive_manifest_json": str(archive_dir / "manifest.json") if archive_dir and not archive_breach else "",
        },
    }
    return report, manifest if archive_dir and not archive_breach else None


def audit_record(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp_utc": report.get("timestamp_utc"),
        "schema_version": SCHEMA_VERSION,
        "archive_status": report.get("archive_status"),
        "archive_path": report.get("archive_path"),
        "copied_file_count": report.get("copied_file_count"),
        "checksum_count": report.get("checksum_count"),
        "safe_end_status": report.get("safe_end_status"),
        "emergency_stop_active": report.get("emergency_stop_active"),
        "low_risk_autonomy_allowed_now": False,
        "policy_activation_allowed": False,
        "install_allowed_now": False,
        "can_install_timer_now": False,
        "live_apply": False,
        "apply_status": APPLY_NOT_APPLIED,
        "total_breaches": report.get("total_breaches"),
        "archive_breach": report.get("archive_breach"),
        "network_access": False,
        "restore_executed": False,
    }


def write_outputs(report: Dict[str, Any]) -> None:
    markdown = render_report_markdown(report)
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, markdown)
    write_text_atomic(OWNER_MD, markdown)
    write_json_atomic(SNAPSHOT_JSON, report)
    write_text_atomic(SNAPSHOT_MD, markdown)
    append_jsonl(AUDIT_JSONL, [audit_record(report)])


def _json_input(path: str, data: Dict[str, Any], status: str = "ok") -> Tuple[str, Tuple[Optional[Dict[str, Any]], str]]:
    return str(PROJECT_DIR / path), (data, status)


def run_self_test() -> int:
    base_records = [
        {"path": str(PROJECT_DIR / "reports/latest/safe-end-summary.json"), "exists": True, "read_status": "ok", "sha256": "abc", "size_bytes": 1, "copy_allowed": True},
        {"path": str(PROJECT_DIR / "reports/latest/sentinel-master-report.md"), "exists": True, "read_status": "ok", "sha256": "def", "size_bytes": 1, "copy_allowed": True},
    ]
    base_json = dict(
        [
            _json_input(
                "reports/latest/safe-end-summary.json",
                {
                    "safe_end_status": "SAFE_END_COMPLETE_LOCKED",
                    "emergency_stop_active": True,
                    "low_risk_autonomy_allowed_now": False,
                    "policy_activation_allowed": False,
                    "install_allowed_now": False,
                    "can_install_timer_now": False,
                    "live_apply": False,
                    "apply_status": APPLY_NOT_APPLIED,
                    "total_breaches": 0,
                    "safe_end_breach": False,
                },
            )
        ]
    )

    status, breach = determine_status(base_records, detect_activation_breaches(base_json)[2], 0)
    if status != STATUS_COMPLETE_LOCKED or breach:
        raise AssertionError("complete locked status failed")

    incomplete_json = dict(base_json)
    incomplete_json[str(PROJECT_DIR / "reports/latest/safe-end-summary.json")] = (
        dict(base_json[str(PROJECT_DIR / "reports/latest/safe-end-summary.json")][0], safe_end_status="SAFE_END_INCOMPLETE_LOCKED"),
        "ok",
    )
    breach_count, _, aggregate = detect_activation_breaches(incomplete_json)
    status, breach = determine_status(base_records, aggregate, breach_count)
    if status != STATUS_INCOMPLETE or breach:
        raise AssertionError("incomplete status failed")

    partial_records = [dict(base_records[0]), dict(base_records[1], exists=False, read_status="missing", sha256=None)]
    status, breach = determine_status(partial_records, detect_activation_breaches(base_json)[2], 0)
    if status != STATUS_PARTIAL_INPUTS or breach:
        raise AssertionError("partial inputs status failed")

    for key in ("low_risk_autonomy_allowed_now", "policy_activation_allowed", "live_apply", "install_allowed_now", "can_install_timer_now"):
        bad_json = dict(base_json)
        bad_json[str(PROJECT_DIR / "reports/latest/safe-end-summary.json")] = (
            dict(base_json[str(PROJECT_DIR / "reports/latest/safe-end-summary.json")][0], **{key: True}),
            "ok",
        )
        breach_count, reasons, _ = detect_activation_breaches(bad_json)
        if not breach_count or not reasons:
            raise AssertionError(f"{key} did not breach")

    bad_apply = dict(base_json)
    bad_apply[str(PROJECT_DIR / "reports/latest/safe-end-summary.json")] = (
        dict(base_json[str(PROJECT_DIR / "reports/latest/safe-end-summary.json")][0], apply_status="applied"),
        "ok",
    )
    if not detect_activation_breaches(bad_apply)[0]:
        raise AssertionError("apply_status breach failed")

    bad_breach = dict(base_json)
    bad_breach[str(PROJECT_DIR / "reports/latest/safe-end-summary.json")] = (
        dict(base_json[str(PROJECT_DIR / "reports/latest/safe-end-summary.json")][0], safe_end_breach=True),
        "ok",
    )
    if not detect_activation_breaches(bad_breach)[0]:
        raise AssertionError("upstream breach failed")

    for forbidden in (
        PROJECT_DIR / "reports/latest/bad.sh",
        PROJECT_DIR / "reports/latest/bad.service",
        PROJECT_DIR / "reports/latest/bad.timer",
        PROJECT_DIR / "reports/latest/bad.py",
        PROJECT_DIR / "reports/latest/bad.env",
        PROJECT_DIR / "reports/latest/token.json",
        Path("/tmp/outside.json"),
    ):
        try:
            if forbidden.suffix in ALLOWED_COPY_SUFFIXES:
                safe_input_path(forbidden)
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            if forbidden.name == "token.json" and not safe_input_path(forbidden)[0]:
                pass
            else:
                raise AssertionError(f"forbidden path accepted: {forbidden}")
    if safe_input_path(PROJECT_DIR / "reports/latest/bad.sh")[0]:
        raise AssertionError(".sh copy not refused")
    if safe_input_path(PROJECT_DIR / "reports/latest/token.json")[0]:
        raise AssertionError("secret-like filename not refused")
    if not has_secret_like_text("token=abc12345"):
        raise AssertionError("secret detector failed")
    print("safe-end-archive-snapshot self-tests: OK")
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Safe-End archive snapshot; read-only, no activation/install/restore.")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory safety tests and exit.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    report, _manifest = build_report()
    write_outputs(report)
    print(
        "Safe-End Archive Snapshot: "
        f"status={report.get('archive_status')}, "
        f"archive={report.get('archive_path')}, "
        f"copied={report.get('copied_file_count')}, "
        f"checksums={report.get('checksum_count')}, "
        f"breach={report.get('archive_breach')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
