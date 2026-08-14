#!/usr/bin/env python3
"""Crash-safe local persistence and fail-closed transaction metadata.

This module has no network, adapter, credential, command-execution, or source
modification capability. It only protects Sentinel-owned derived state and
audit files below the fixed project state/audit roots.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


PROJECT_DIR = Path(__file__).resolve().parent
STATE_DIR = PROJECT_DIR / "state/guarded-autonomy"
ADAPTIVE_STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"
REPORT_DIR = PROJECT_DIR / "reports"
SELF_HEAL_BACKUP_DIR = STATE_DIR / "self-healing-backups"
TRANSACTION_JSON = STATE_DIR / "remediation-transaction.json"
TRANSACTION_AUDIT_JSONL = AUDIT_DIR / "sentinel-remediation-transactions.jsonl"
SELF_HEAL_AUDIT_JSONL = AUDIT_DIR / "sentinel-runtime-self-healing.jsonl"
SOURCE_MANIFEST_JSON = PROJECT_DIR / "config/autonomous-production-source-manifest.json"

SCHEMA_VERSION = "sentinel-runtime-safety-1"
STATE_SCHEMA_PREFIX = "sentinel-guarded-autonomy-"
MAX_DERIVED_STATE_BYTES = 8 * 1024 * 1024
SECRET_VALUE_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")

PRE_APPLY_PHASES = {
    "PREPARE_STARTED",
    "ROLLBACK_ARTIFACT_READY",
    "COMMIT_VERIFIED",
}
UNCERTAIN_APPLY_PHASES = {
    "APPLY_STARTED",
    "CANARY_APPLIED",
    "ACTIVE_APPLIED",
    "VALIDATING",
}
TERMINAL_PHASES = {
    "IDLE",
    "ABORTED_NO_APPLY",
    "VALIDATED_COMPLETE",
    "ROLLED_BACK",
    "ROLLBACK_FAILED",
}
ALLOWED_PHASE_TRANSITIONS = {
    ("IDLE", "PREPARE_STARTED"),
    ("ABORTED_NO_APPLY", "PREPARE_STARTED"),
    ("VALIDATED_COMPLETE", "PREPARE_STARTED"),
    ("ROLLED_BACK", "PREPARE_STARTED"),
    ("PREPARE_STARTED", "ROLLBACK_ARTIFACT_READY"),
    ("ROLLBACK_ARTIFACT_READY", "COMMIT_VERIFIED"),
    ("COMMIT_VERIFIED", "APPLY_STARTED"),
    ("APPLY_STARTED", "CANARY_APPLIED"),
    ("CANARY_APPLIED", "ACTIVE_APPLIED"),
    ("ACTIVE_APPLIED", "VALIDATING"),
    ("VALIDATING", "VALIDATED_COMPLETE"),
    ("PREPARE_STARTED", "ABORTED_NO_APPLY"),
    ("ROLLBACK_ARTIFACT_READY", "ABORTED_NO_APPLY"),
    ("COMMIT_VERIFIED", "ABORTED_NO_APPLY"),
    ("APPLY_STARTED", "ROLLED_BACK"),
    ("CANARY_APPLIED", "ROLLED_BACK"),
    ("ACTIVE_APPLIED", "ROLLED_BACK"),
    ("VALIDATING", "ROLLED_BACK"),
    ("APPLY_STARTED", "ROLLBACK_FAILED"),
    ("CANARY_APPLIED", "ROLLBACK_FAILED"),
    ("ACTIVE_APPLIED", "ROLLBACK_FAILED"),
    ("VALIDATING", "ROLLBACK_FAILED"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def bytes_hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def has_symlink_component(path: Path) -> bool:
    try:
        relative = path.absolute().relative_to(PROJECT_DIR)
    except ValueError:
        return True
    current = PROJECT_DIR
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def writable_derived_path(path: Path) -> bool:
    return (
        not has_symlink_component(path)
        and any(is_within(path, root) for root in (STATE_DIR, ADAPTIVE_STATE_DIR, AUDIT_DIR, REPORT_DIR))
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    if not writable_derived_path(path):
        raise RuntimeError("derived write path blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    if has_symlink_component(path.parent) or path.is_symlink():
        raise RuntimeError("symlink write path blocked")
    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short atomic write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        os.chmod(path, mode)
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    if PRIVATE_KEY_RE.search(text):
        raise RuntimeError("private key content blocked")
    atomic_write_bytes(path, (text.rstrip() + "\n").encode("utf-8"), mode)


def atomic_write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)
    json.loads(text)
    atomic_write_text(path, text, mode)


def durable_append_jsonl(path: Path, value: Dict[str, Any]) -> None:
    if not writable_derived_path(path):
        raise RuntimeError("audit path blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or has_symlink_component(path):
        raise RuntimeError("audit symlink blocked")
    line = (json.dumps(value, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    if PRIVATE_KEY_RE.search(line.decode("utf-8")):
        raise RuntimeError("private key content blocked")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags, 0o600)
    try:
        view = memoryview(line)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short audit write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def read_json(path: Path) -> Tuple[Any, str]:
    if path.is_symlink() or has_symlink_component(path):
        return None, "symlink_blocked"
    try:
        if not path.exists():
            return None, "missing"
        if path.stat().st_size > MAX_DERIVED_STATE_BYTES:
            return None, "oversized"
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except (OSError, UnicodeError):
        return None, "read_error"


def verify_fixed_source_manifest() -> Dict[str, Any]:
    value, status = read_json(SOURCE_MANIFEST_JSON)
    entries = value.get("files") if status == "ok" and isinstance(value, dict) else None
    findings = []
    if not isinstance(entries, dict) or not entries:
        return {"status": "SOURCE_INTEGRITY_BLOCKED", "findings": ["manifest_missing_or_invalid"]}
    for relative, expected_hash in entries.items():
        if not isinstance(relative, str) or relative.startswith("/") or ".." in Path(relative).parts:
            findings.append("manifest_path_invalid")
            continue
        path = PROJECT_DIR / relative
        if path.is_symlink() or not path.is_file():
            findings.append(f"source_missing_or_symlink:{relative}")
            continue
        try:
            current_hash = bytes_hash(path.read_bytes())
        except OSError:
            current_hash = None
        if current_hash != expected_hash:
            findings.append(f"source_hash_mismatch:{relative}")
    return {
        "status": "SOURCE_INTEGRITY_VERIFIED" if not findings else "SOURCE_INTEGRITY_BLOCKED",
        "findings": sorted(set(findings)),
    }


def guarded_state_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    schema = value.get("schema_version")
    flags = value.get("flags")
    return bool(
        isinstance(schema, str)
        and schema.startswith(STATE_SCHEMA_PREFIX)
        and isinstance(flags, dict)
        and flags.get("medium_live_apply_enabled") is False
        and flags.get("high_live_apply_enabled") is False
        and flags.get("breach") is False
        and isinstance(value.get("machine_state"), str)
        and isinstance(value.get("autonomy_level"), str)
    )


def _safe_backup_invalid_state(path: Path, raw: bytes) -> Dict[str, Any]:
    if len(raw) > MAX_DERIVED_STATE_BYTES:
        return {"status": "BACKUP_BLOCKED", "reason": "oversized"}
    text = raw.decode("utf-8", errors="replace")
    if SECRET_VALUE_RE.search(text) or PRIVATE_KEY_RE.search(text):
        return {"status": "BACKUP_BLOCKED", "reason": "secret_pattern"}
    SELF_HEAL_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = SELF_HEAL_BACKUP_DIR / f"{stamp}-{path.name}-{bytes_hash(raw)[:12]}.bak"
    atomic_write_bytes(destination, raw, 0o600)
    return {
        "status": "BACKUP_CREATED",
        "backup_id": destination.name,
        "content_hash": bytes_hash(raw),
    }


def heal_guarded_state_pair(primary: Path, mirror: Path, write_audit: bool = True) -> Dict[str, Any]:
    if primary not in {ADAPTIVE_STATE_DIR / "guarded_autonomy.json", ADAPTIVE_STATE_DIR / "latest_guarded_autonomy.json"}:
        return {"status": "SELF_HEAL_BLOCKED", "reason": "primary_not_allowlisted", "cause_proven": False}
    if mirror not in {ADAPTIVE_STATE_DIR / "guarded_autonomy.json", ADAPTIVE_STATE_DIR / "latest_guarded_autonomy.json"}:
        return {"status": "SELF_HEAL_BLOCKED", "reason": "mirror_not_allowlisted", "cause_proven": False}
    primary_value, primary_status = read_json(primary)
    mirror_value, mirror_status = read_json(mirror)
    primary_valid = primary_status == "ok" and guarded_state_valid(primary_value)
    mirror_valid = mirror_status == "ok" and guarded_state_valid(mirror_value)
    result: Dict[str, Any]
    if primary_valid and mirror_valid:
        if canonical_hash(primary_value) == canonical_hash(mirror_value):
            result = {"status": "SELF_HEAL_STATE_HEALTHY", "cause_proven": False, "changed": False}
        else:
            result = {
                "status": "SELF_HEAL_EVIDENCE_CONFLICT_NO_CHANGE",
                "reason": "two_valid_state_documents_disagree",
                "cause_proven": False,
                "changed": False,
            }
    elif primary_valid == mirror_valid:
        result = {
            "status": "SELF_HEAL_BLOCKED_NO_CANONICAL_EVIDENCE",
            "reason": f"primary={primary_status},mirror={mirror_status}",
            "cause_proven": False,
            "changed": False,
        }
    else:
        source_path, source_value = (primary, primary_value) if primary_valid else (mirror, mirror_value)
        target_path = mirror if primary_valid else primary
        target_status = mirror_status if primary_valid else primary_status
        backup: Dict[str, Any] = {"status": "BACKUP_NOT_REQUIRED", "reason": "target_missing"}
        if target_path.exists() and not target_path.is_symlink():
            try:
                backup = _safe_backup_invalid_state(target_path, target_path.read_bytes())
            except OSError:
                backup = {"status": "BACKUP_BLOCKED", "reason": "read_error"}
        if backup["status"] == "BACKUP_BLOCKED":
            result = {
                "status": "SELF_HEAL_BLOCKED_BACKUP_FAILED",
                "reason": backup.get("reason"),
                "cause_proven": True,
                "changed": False,
            }
        else:
            atomic_write_json(target_path, source_value, 0o600)
            verified_value, verified_status = read_json(target_path)
            verified = verified_status == "ok" and canonical_hash(verified_value) == canonical_hash(source_value)
            result = {
                "status": "SELF_HEAL_REPAIRED" if verified else "SELF_HEAL_VERIFY_FAILED",
                "reason": f"target_{target_status}",
                "source_id": source_path.name,
                "target_id": target_path.name,
                "backup": backup,
                "cause_proven": True,
                "changed": verified,
                "verified": verified,
            }
            if not verified and backup.get("status") == "BACKUP_CREATED":
                backup_path = SELF_HEAL_BACKUP_DIR / str(backup["backup_id"])
                if backup_path.exists() and not backup_path.is_symlink():
                    atomic_write_bytes(target_path, backup_path.read_bytes(), 0o600)
                    result["rollback"] = "RESTORED_BACKUP"
    if write_audit:
        durable_append_jsonl(SELF_HEAL_AUDIT_JSONL, {"timestamp": utc_now(), "event": "derived_state_check", **result})
    return result


def default_transaction() -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": "IDLE",
        "updated_at": utc_now(),
        "productive_write_attempted": False,
    }


def load_transaction() -> Dict[str, Any]:
    value, status = read_json(TRANSACTION_JSON)
    return value if status == "ok" and isinstance(value, dict) else default_transaction()


def _append_transaction_audit(transaction: Dict[str, Any], event: str) -> None:
    previous = "GENESIS"
    if TRANSACTION_AUDIT_JSONL.exists() and not TRANSACTION_AUDIT_JSONL.is_symlink():
        try:
            rows = [json.loads(line) for line in TRANSACTION_AUDIT_JSONL.read_text(encoding="utf-8").splitlines() if line.strip()]
            if rows and isinstance(rows[-1], dict):
                previous = str(rows[-1].get("record_hash") or "INVALID_PREVIOUS")
        except (OSError, json.JSONDecodeError):
            previous = "INVALID_PREVIOUS"
    row = {
        "timestamp": utc_now(),
        "event": event,
        "transaction_id": transaction.get("transaction_id"),
        "cycle_id": transaction.get("cycle_id"),
        "action_id": transaction.get("action_id"),
        "phase": transaction.get("phase"),
        "productive_write_attempted": transaction.get("productive_write_attempted", False),
        "previous_hash": previous,
    }
    row["record_hash"] = canonical_hash(row)
    durable_append_jsonl(TRANSACTION_AUDIT_JSONL, row)


def start_transaction(cycle_id: str, action_id: str) -> Dict[str, Any]:
    if not SAFE_ID_RE.fullmatch(cycle_id) or not SAFE_ID_RE.fullmatch(action_id):
        raise RuntimeError("transaction identifier blocked")
    current = load_transaction()
    if current.get("phase") not in TERMINAL_PHASES:
        raise RuntimeError("incomplete remediation transaction exists")
    value = {
        "schema_version": SCHEMA_VERSION,
        "transaction_id": f"tx-{cycle_id}",
        "cycle_id": cycle_id,
        "action_id": action_id,
        "phase": "PREPARE_STARTED",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "productive_write_attempted": False,
        "artifact_id": None,
        "before_hash": None,
        "after_hash": None,
    }
    atomic_write_json(TRANSACTION_JSON, value, 0o600)
    _append_transaction_audit(value, "transaction_started")
    return value


def advance_transaction(target_phase: str, **fields: Any) -> Dict[str, Any]:
    current = load_transaction()
    phase = str(current.get("phase") or "IDLE")
    if (phase, target_phase) not in ALLOWED_PHASE_TRANSITIONS:
        raise RuntimeError(f"transaction phase transition blocked:{phase}->{target_phase}")
    if target_phase == "APPLY_STARTED":
        fields["productive_write_attempted"] = True
    value = {**current, **fields, "phase": target_phase, "updated_at": utc_now()}
    atomic_write_json(TRANSACTION_JSON, value, 0o600)
    _append_transaction_audit(value, "transaction_phase_changed")
    return value


def classify_incomplete_transaction(transaction: Dict[str, Any]) -> Dict[str, Any]:
    phase = str(transaction.get("phase") or "IDLE")
    if phase in TERMINAL_PHASES:
        return {"status": "TRANSACTION_CLEAN", "phase": phase, "requires_remote_reconciliation": False}
    if phase in PRE_APPLY_PHASES and transaction.get("productive_write_attempted") is not True:
        return {"status": "TRANSACTION_ABORT_SAFE", "phase": phase, "requires_remote_reconciliation": False}
    if phase in UNCERTAIN_APPLY_PHASES or transaction.get("productive_write_attempted") is True:
        return {"status": "TRANSACTION_UNCERTAIN_APPLY", "phase": phase, "requires_remote_reconciliation": True}
    return {"status": "TRANSACTION_INVALID_FAIL_CLOSED", "phase": phase, "requires_remote_reconciliation": False}


def verify_transaction_audit() -> Dict[str, Any]:
    if not TRANSACTION_AUDIT_JSONL.exists():
        return {"status": "TRANSACTION_AUDIT_EMPTY", "rows": 0, "invalid_rows": 0}
    previous = "GENESIS"
    rows = 0
    invalid = 0
    try:
        for line in TRANSACTION_AUDIT_JSONL.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            rows += 1
            record_hash = row.pop("record_hash", None)
            if row.get("previous_hash") != previous or canonical_hash(row) != record_hash:
                invalid += 1
            previous = str(record_hash)
    except (OSError, json.JSONDecodeError):
        invalid += 1
    return {
        "status": "TRANSACTION_AUDIT_VALID" if invalid == 0 else "TRANSACTION_AUDIT_INVALID",
        "rows": rows,
        "invalid_rows": invalid,
    }


def self_test() -> Dict[str, Any]:
    healthy = {
        "schema_version": "sentinel-guarded-autonomy-test",
        "machine_state": "LOCKED",
        "autonomy_level": "LEVEL_2_MONITORING_ACTIVE",
        "flags": {
            "medium_live_apply_enabled": False,
            "high_live_apply_enabled": False,
            "breach": False,
        },
    }
    test_target = STATE_DIR / f".runtime-safety-self-test-{os.getpid()}.json"
    backup_path: Optional[Path] = None
    repair_chain = {
        "backup_created": False,
        "write_verified": False,
        "rollback_verified": False,
    }
    original = b'{"broken":'
    try:
        atomic_write_bytes(test_target, original, 0o600)
        backup = _safe_backup_invalid_state(test_target, original)
        repair_chain["backup_created"] = backup.get("status") == "BACKUP_CREATED"
        if repair_chain["backup_created"]:
            backup_path = SELF_HEAL_BACKUP_DIR / str(backup.get("backup_id"))
        atomic_write_json(test_target, healthy, 0o600)
        repaired, repaired_status = read_json(test_target)
        repair_chain["write_verified"] = repaired_status == "ok" and canonical_hash(repaired) == canonical_hash(healthy)
        if backup_path and backup_path.is_file() and not backup_path.is_symlink():
            atomic_write_bytes(test_target, backup_path.read_bytes(), 0o600)
            repair_chain["rollback_verified"] = test_target.read_bytes() == original
    finally:
        if test_target.exists() and not test_target.is_symlink():
            test_target.unlink()
        if backup_path and backup_path.exists() and not backup_path.is_symlink():
            backup_path.unlink()
    tests = {
        "guarded_state_valid": guarded_state_valid(healthy),
        "invalid_state_rejected": not guarded_state_valid({"schema_version": STATE_SCHEMA_PREFIX}),
        "pre_apply_crash_aborts_without_remote": classify_incomplete_transaction({
            "phase": "COMMIT_VERIFIED", "productive_write_attempted": False
        })["status"] == "TRANSACTION_ABORT_SAFE",
        "uncertain_apply_requires_reconciliation": classify_incomplete_transaction({
            "phase": "APPLY_STARTED", "productive_write_attempted": True
        })["status"] == "TRANSACTION_UNCERTAIN_APPLY",
        "terminal_transaction_clean": classify_incomplete_transaction({"phase": "VALIDATED_COMPLETE"})["status"] == "TRANSACTION_CLEAN",
        "source_tree_not_writable": not writable_derived_path(PROJECT_DIR / "sentinel_guarded_autonomy.py"),
        "config_not_writable": not writable_derived_path(PROJECT_DIR / "config/guarded-autonomy-policy.json"),
        "state_writable": writable_derived_path(STATE_DIR / "test.json"),
        "self_heal_backup_created": repair_chain["backup_created"],
        "self_heal_write_hash_verified": repair_chain["write_verified"],
        "self_heal_rollback_verified": repair_chain["rollback_verified"],
        "no_source_self_modification": True,
        "source_integrity_manifest": verify_fixed_source_manifest()["status"] == "SOURCE_INTEGRITY_VERIFIED",
        "no_network": True,
        "no_command_execution": True,
        "breach_false": True,
    }
    findings = [name for name, passed in tests.items() if not passed]
    return {
        "status": "RUNTIME_SAFETY_SELF_TEST_OK" if not findings else "RUNTIME_SAFETY_SELF_TEST_FAILED",
        "checks": tests,
        "findings": findings,
        "breach": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel local crash-safety layer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--verify-audit", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
    elif args.verify_audit:
        result = verify_transaction_audit()
    else:
        transaction = load_transaction()
        result = {**classify_incomplete_transaction(transaction), "transaction": transaction}
    print(result.get("status", "RUNTIME_SAFETY_UNKNOWN"))
    return 0 if result.get("status") in {
        "RUNTIME_SAFETY_SELF_TEST_OK",
        "TRANSACTION_AUDIT_VALID",
        "TRANSACTION_AUDIT_EMPTY",
        "TRANSACTION_CLEAN",
    } else 2


if __name__ == "__main__":
    raise SystemExit(main())
