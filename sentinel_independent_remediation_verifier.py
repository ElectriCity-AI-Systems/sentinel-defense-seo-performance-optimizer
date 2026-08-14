#!/usr/bin/env python3
"""Independently verify proof envelopes before guarded remediation commits.

The verifier has no adapter, credential, network, subprocess, or production
write capability. It reads only fixed local policy, evidence, and state paths.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sentinel_runtime_safety as runtime_safety


PROJECT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_DIR / "config/proof-carrying-remediation-policy.json"
GUARDED_POLICY_PATH = PROJECT_DIR / "config/guarded-autonomy-policy.json"
REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/guarded-autonomy"
ADAPTIVE_STATE_DIR = PROJECT_DIR / "state/adaptive-learning"
AUDIT_DIR = PROJECT_DIR / "audit"

PENDING_PROOF_JSON = STATE_DIR / "pending-remediation-proof.json"
VERIFICATION_JSON = STATE_DIR / "proof-verification.json"
REPORT_JSON = REPORT_DIR / "sentinel-independent-remediation-verification.json"
REPORT_MD = REPORT_DIR / "sentinel-independent-remediation-verification.md"
AUDIT_JSONL = AUDIT_DIR / "sentinel-independent-remediation-verifier.jsonl"
ACTION_REGISTRY_PATH = STATE_DIR / "action-registry.json"
ROLLBACK_DIR = STATE_DIR / "rollback-artifacts"

EVIDENCE_PATHS = {
    "website_report": REPORT_DIR / "sentinel-defense-report.json",
    "origin_diagnostics": REPORT_DIR / "sentinel-origin-failure-diagnostics.json",
    "health_baseline": STATE_DIR / "health-baseline.json",
    "tls_gate": STATE_DIR / "tls-gate.json",
    "write_canary": STATE_DIR / "write-canary.json",
    "runtime_state": ADAPTIVE_STATE_DIR / "guarded_autonomy.json",
    "circuit_breaker": STATE_DIR / "circuit-breaker.json",
    "origin_evidence": REPORT_DIR / "sentinel-origin-evidence-collector.json",
}

SCHEMA_VERSION = "sentinel-independent-remediation-verifier-1"
PROOF_SCHEMA_VERSION = "sentinel-proof-carrying-remediation-1"
PROOF_ID_RE = re.compile(r"^proof-[a-f0-9]{32}$")
ARTIFACT_NAME_RE = re.compile(r"^guarded-\d{8}T\d{6}Z-[a-f0-9]{8}-temporary_scanner_managed_challenge_v1\.json$")
HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")

GREEN_HEALTH = {"HEALTH_TARGET_GATE_GREEN", "HEALTH_TARGET_GATE_GREEN_CHALLENGE_AWARE"}
GREEN_TLS = {"TLS_GATE_GREEN", "TLS_GATE_GREEN_WITH_STALE_HISTORY"}
LIVE_STAGES = {"LEVEL_2_GUARDED_CANARY", "LEVEL_2_GUARDED_AUTONOMY"}
LIVE_MACHINE_STATES = {"CANARY", "ACTIVE"}
EXPECTED_CONTRACT_IDS = {
    "temporary_scanner_managed_challenge_v1",
    "rollback_sentinel_owned_rule_v1",
}
EXPECTED_SCANNER_EXACT_PATHS = {
    "/.env",
    "/wp-config.php.bak",
    "/wp-config.old",
    "/phpinfo.php",
}
EXPECTED_SCANNER_PATH_PREFIXES = {
    "/.env.",
    "/alfacgiapi/",
    "/.git/",
    "/vendor/phpunit/",
}
EXPECTED_SCANNER_SCOPE = {
    "type": "cloudflare_custom_rule",
    "action": "managed_challenge",
    "canary_expression": '(http.request.uri.path eq "/.env")',
    "full_expression": (
        '((http.request.uri.path eq "/.env") or '
        '(starts_with(http.request.uri.path, "/.env.")) or '
        '(http.request.uri.path eq "/wp-config.php.bak") or '
        '(http.request.uri.path eq "/wp-config.old") or '
        '(starts_with(http.request.uri.path, "/alfacgiapi/")) or '
        '(starts_with(http.request.uri.path, "/.git/")) or '
        '(starts_with(http.request.uri.path, "/vendor/phpunit/")) or '
        '(http.request.uri.path eq "/phpinfo.php"))'
    ),
    "sentinel_owned_ref": "sentinel_guarded_scanner_challenge_v1",
}
POLICY_SAFETY_FALSE_KEYS = {
    "network_access",
    "credential_access",
    "shell_execution",
    "live_apply",
    "remote_write",
    "medium_executable",
    "high_executable",
    "breach",
}
EVIDENCE_MAX_AGE_CAPS = {
    "website_report": 900,
    "origin_diagnostics": 1800,
    "health_baseline": 600,
    "tls_gate": 1800,
    "write_canary": 86400,
    "runtime_state": 600,
    "circuit_breaker": 600,
    "origin_evidence": 1800,
}


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def utc_now() -> str:
    return utc_now_dt().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def policy_int(value: Any, default: int = -1) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def policy_boundary_findings(policy: Dict[str, Any]) -> List[str]:
    findings: List[str] = []
    if not (
        policy.get("schema_version") == "sentinel-proof-carrying-remediation-policy-1"
        and policy.get("policy_version") == 1
        and policy.get("mode") == "ENFORCEMENT_GATE_ONLY"
        and policy.get("proof_gate_required") is True
        and policy.get("independent_verifier_required") is True
        and policy.get("activation_effect") is False
        and policy.get("automatic_policy_expansion") is False
        and policy.get("cause_proof_required") is True
        and 30 <= policy_int(policy.get("proof_ttl_seconds"), 0) <= 120
    ):
        findings.append("proof_policy_boundary_invalid")
    max_ages = policy.get("evidence_max_age_seconds", {})
    if not isinstance(max_ages, dict) or set(max_ages) != set(EVIDENCE_MAX_AGE_CAPS) or any(
        not 0 < policy_int(max_ages.get(name), 0) <= maximum
        for name, maximum in EVIDENCE_MAX_AGE_CAPS.items()
    ):
        findings.append("evidence_freshness_boundary_invalid")
    budget = policy.get("change_budget", {})
    if not isinstance(budget, dict) or not (
        policy_int(budget.get("max_active_actions"), 0) == 1
        and policy_int(budget.get("max_actions_per_hour"), 0) == 1
        and 0 <= policy_int(budget.get("max_failed_actions_per_hour"), -1) <= 1
        and policy_int(budget.get("max_failed_rollbacks"), -1) == 0
        and 0 < policy_int(budget.get("maximum_ttl_minutes"), 0) <= 10
    ):
        findings.append("change_budget_boundary_invalid")
    contracts = policy.get("contracts", [])
    if not isinstance(contracts, list):
        contracts = []
    ids = {item.get("action_id") for item in contracts if isinstance(item, dict)}
    if ids != EXPECTED_CONTRACT_IDS or len(contracts) != 2:
        findings.append("contract_set_boundary_invalid")
    scanner = contract_by_id(policy, "temporary_scanner_managed_challenge_v1") or {}
    trigger = scanner.get("trigger_requirements", {})
    if not isinstance(trigger, dict):
        trigger = {}
    if not (
        scanner.get("action_version") == 1
        and scanner.get("enabled") is True
        and scanner.get("risk") == "LOW_LIVE"
        and scanner.get("requires_existing_runtime_authorization") is True
        and scanner.get("scope") == EXPECTED_SCANNER_SCOPE
        and set(scanner.get("allowed_exact_paths", [])) == EXPECTED_SCANNER_EXACT_PATHS
        and set(scanner.get("allowed_path_prefixes", [])) == EXPECTED_SCANNER_PATH_PREFIXES
        and policy_int(trigger.get("minimum_requests"), 0) >= 100
        and policy_int(trigger.get("minimum_actor_groups"), 0) >= 2
        and 0 < policy_int(trigger.get("maximum_window_minutes"), 0) <= 5
        and trigger.get("fresh_exact_path_evidence") is True
        and trigger.get("all_observed_paths_allowlisted") is True
        and trigger.get("legitimate_use_absent") is True
    ):
        findings.append("scanner_contract_boundary_invalid")
    rollback = contract_by_id(policy, "rollback_sentinel_owned_rule_v1") or {}
    if not (
        rollback.get("action_version") == 1
        and rollback.get("enabled") is True
        and rollback.get("risk") == "LOW_LIVE"
        and rollback.get("safety_recovery_action") is True
        and rollback.get("requires_existing_runtime_authorization") is True
        and rollback.get("scope") == {"type": "sentinel_owned_rule_only"}
    ):
        findings.append("rollback_contract_boundary_invalid")
    safety = policy.get("safety", {})
    if not isinstance(safety, dict) or any(safety.get(key) is not False for key in POLICY_SAFETY_FALSE_KEYS):
        findings.append("proof_policy_safety_drift")
    if isinstance(safety, dict) and (
        safety.get("autonomous_waf_execution") is not False
        or safety.get("source_self_modification") is not False
    ):
        findings.append("proof_policy_autonomous_mutation_drift")
    return findings


def recent_row_count(rows: Any, now: datetime, window_seconds: int) -> int:
    if not isinstance(rows, list):
        return 0
    count = 0
    for row in rows:
        timestamp = parse_timestamp(row.get("timestamp")) if isinstance(row, dict) else None
        if timestamp and 0 <= (now - timestamp).total_seconds() <= window_seconds:
            count += 1
    return count


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def read_json(path: Path) -> Tuple[Any, str]:
    if path.is_symlink() or not is_within(path, PROJECT_DIR):
        return None, "blocked_path"
    try:
        if not path.exists():
            return None, "missing"
        if path.stat().st_size > 16 * 1024 * 1024:
            return None, "too_large"
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def load_dict(path: Path) -> Dict[str, Any]:
    value, status = read_json(path)
    return value if status == "ok" and isinstance(value, dict) else {}


def file_hash(path: Path) -> Optional[str]:
    if path.is_symlink() or not is_within(path, PROJECT_DIR) or not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_DIR, AUDIT_DIR):
        if directory.is_symlink() or not is_within(directory, PROJECT_DIR):
            raise RuntimeError(f"unsafe output directory: {directory.name}")
        directory.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    if path.is_symlink() or not any(is_within(path, root) for root in (REPORT_DIR, STATE_DIR, AUDIT_DIR)):
        raise RuntimeError(f"blocked output path: {path.name}")
    if PRIVATE_KEY_RE.search(text):
        raise RuntimeError("private key material blocked")
    mode = 0o600 if is_within(path, STATE_DIR) or is_within(path, AUDIT_DIR) else 0o644
    runtime_safety.atomic_write_text(path, text, mode)


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))


def append_hash_chained_audit(value: Dict[str, Any]) -> Dict[str, Any]:
    if AUDIT_JSONL.is_symlink() or not is_within(AUDIT_JSONL, AUDIT_DIR):
        raise RuntimeError("blocked audit path")
    previous_hash = "GENESIS"
    if AUDIT_JSONL.exists() and not AUDIT_JSONL.is_symlink():
        try:
            rows = [json.loads(line) for line in AUDIT_JSONL.read_text(encoding="utf-8").splitlines() if line.strip()]
            if rows:
                previous_hash = str(rows[-1].get("record_hash") or "INVALID_PREVIOUS")
        except (OSError, json.JSONDecodeError):
            previous_hash = "INVALID_PREVIOUS"
    row = {**value, "previous_hash": previous_hash}
    row["record_hash"] = canonical_hash(row)
    runtime_safety.durable_append_jsonl(AUDIT_JSONL, row)
    return row


def content_timestamp(value: Dict[str, Any], path: Path) -> Optional[datetime]:
    for key in ("generated_at_utc", "generated_at", "checked_at", "updated_at", "timestamp"):
        parsed = parse_timestamp(value.get(key))
        if parsed:
            return parsed
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


def contract_by_id(policy: Dict[str, Any], action_id: str) -> Optional[Dict[str, Any]]:
    return next((
        item for item in policy.get("contracts", [])
        if isinstance(item, dict) and item.get("action_id") == action_id
    ), None)


def build_context(now: Optional[datetime] = None) -> Dict[str, Any]:
    current_time = now or utc_now_dt()
    policy = load_dict(CONFIG_PATH)
    max_ages = policy.get("evidence_max_age_seconds", {})
    if not isinstance(max_ages, dict):
        max_ages = {}
    evidence: Dict[str, Any] = {}
    for name, path in EVIDENCE_PATHS.items():
        value, status = read_json(path)
        document = value if status == "ok" and isinstance(value, dict) else {}
        timestamp = content_timestamp(document, path) if document else None
        age = max(0.0, (current_time - timestamp).total_seconds()) if timestamp else None
        evidence[name] = {
            "read_status": status,
            "content_hash": file_hash(path),
            "timestamp": iso_utc(timestamp) if timestamp else None,
            "age_seconds": age,
            "fresh": age is not None and age <= policy_int(max_ages.get(name), 0),
            "document": document,
        }
    registry = load_dict(ACTION_REGISTRY_PATH)
    return {
        "policy": policy,
        "policy_hash": canonical_hash(policy) if policy else None,
        "guarded_policy_content_hash": file_hash(GUARDED_POLICY_PATH),
        "registry": registry,
        "evidence": evidence,
        "runtime_state": evidence.get("runtime_state", {}).get("document", {}),
        "health": evidence.get("health_baseline", {}).get("document", {}),
        "tls": evidence.get("tls_gate", {}).get("document", {}),
        "write_canary": evidence.get("write_canary", {}).get("document", {}),
        "circuit": evidence.get("circuit_breaker", {}).get("document", {}),
        "now": current_time,
    }


def proof_hash_valid(envelope: Dict[str, Any]) -> bool:
    proof_id = str(envelope.get("proof_id") or "")
    if not PROOF_ID_RE.fullmatch(proof_id):
        return False
    payload = {key: value for key, value in envelope.items() if key != "proof_id"}
    return proof_id == "proof-" + canonical_hash(payload)[:32]


def verify_envelope(
    envelope: Dict[str, Any],
    expected_phase: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    current = context or build_context()
    now = current.get("now") if isinstance(current.get("now"), datetime) else utc_now_dt()
    policy = current.get("policy", {})
    contract = contract_by_id(policy, str(envelope.get("action_id") or ""))
    checks: Dict[str, bool] = {}
    policy_findings = policy_boundary_findings(policy) if isinstance(policy, dict) else ["proof_policy_not_object"]
    checks["proof_policy_boundary"] = not policy_findings
    checks["proof_schema"] = envelope.get("schema_version") == PROOF_SCHEMA_VERSION
    checks["proof_hash"] = proof_hash_valid(envelope)
    checks["proof_phase"] = envelope.get("proof_phase") == expected_phase
    checks["contract_exists_enabled"] = bool(contract and contract.get("enabled") is True)
    checks["policy_hash"] = envelope.get("proof_policy_hash") == current.get("policy_hash")
    checks["contract_hash"] = bool(contract) and envelope.get("action_contract_hash") == canonical_hash(contract)
    checks["scope_exact"] = bool(contract) and (
        envelope.get("action_scope_hash") == envelope.get("contract_scope_hash") == canonical_hash(contract.get("scope"))
    )
    checks["owner_policy_reference"] = envelope.get("owner_policy_reference") == policy.get("owner_policy_reference")
    created = parse_timestamp(envelope.get("created_at"))
    expires = parse_timestamp(envelope.get("expires_at"))
    checks["proof_time_valid"] = bool(created and expires and created <= now <= expires)
    checks["proof_lifetime_bounded"] = bool(
        created and expires and (expires - created).total_seconds() <= policy_int(policy.get("proof_ttl_seconds"), 0)
    )
    evidence_refs = {
        str(item.get("evidence_id")): item
        for item in envelope.get("evidence_references", [])
        if isinstance(item, dict)
    }
    required = set(contract.get("required_evidence", [])) if contract else set()
    checks["required_evidence_complete"] = required.issubset(evidence_refs)
    evidence_hashes_match = True
    evidence_fresh = True
    evidence_paths_fixed = True
    for name in required:
        proof_ref = evidence_refs.get(name, {})
        current_ref = current.get("evidence", {}).get(name, {})
        evidence_hashes_match = evidence_hashes_match and bool(
            proof_ref.get("content_hash")
            and proof_ref.get("content_hash") == current_ref.get("content_hash")
        )
        evidence_fresh = evidence_fresh and proof_ref.get("fresh") is True and current_ref.get("fresh") is True
        evidence_paths_fixed = evidence_paths_fixed and proof_ref.get("path_id") == name and proof_ref.get("symlink") is False
    checks["evidence_hashes_current"] = evidence_hashes_match
    checks["evidence_fresh"] = evidence_fresh
    checks["evidence_paths_fixed"] = evidence_paths_fixed
    runtime = current.get("runtime_state", {})
    flags = runtime.get("flags", {})
    envelope_flags = envelope.get("runtime_flags", {})
    checks["runtime_state_hash"] = envelope.get("runtime_state_hash") == canonical_hash(runtime)
    checks["runtime_stage"] = runtime.get("activation_stage") in LIVE_STAGES and envelope.get("runtime_stage") == runtime.get("activation_stage")
    checks["runtime_machine_state"] = runtime.get("machine_state") in LIVE_MACHINE_STATES and envelope.get("runtime_machine_state") == runtime.get("machine_state")
    required_true = ("guarded_live_autonomy_enabled", "low_live_apply_enabled")
    required_false = (
        "medium_live_apply_enabled", "high_live_apply_enabled", "unrestricted_shell_enabled",
        "production_apply_lock", "remote_write_lock", "emergency_stop", "breach",
    )
    checks["runtime_flags_current"] = all(flags.get(key) is True for key in required_true) and all(
        flags.get(key) is False for key in required_false
    )
    checks["runtime_flags_bound"] = all(envelope_flags.get(key) == flags.get(key) for key in (*required_true, *required_false))
    active_actions = runtime.get("active_actions", [])
    checks["no_active_action"] = (
        isinstance(active_actions, list)
        and len(active_actions) == 0
        and policy_int(envelope.get("active_action_count"), -1) == 0
    )
    checks["guarded_policy_content_hash"] = envelope.get("guarded_policy_content_hash") == current.get("guarded_policy_content_hash")
    registry = current.get("registry", {})
    checks["registry_hash"] = bool(registry) and envelope.get("guarded_registry_hash") == registry.get("registry_hash") == runtime.get("registry_hash")
    checks["guarded_policy_hash"] = envelope.get("guarded_policy_hash") == runtime.get("policy_hash")
    checks["health_gate"] = current.get("health", {}).get("status") in GREEN_HEALTH
    checks["tls_gate"] = current.get("tls", {}).get("status") in GREEN_TLS
    checks["write_canary"] = current.get("write_canary", {}).get("status") == "CLOUDFLARE_WRITE_CANARY_OK"
    circuit = current.get("circuit", {})
    budget = policy.get("change_budget", {})
    if not isinstance(budget, dict):
        budget = {}
    failures = circuit.get("failures", []) if isinstance(circuit.get("failures"), list) else []
    failed_rollbacks = circuit.get("failed_rollbacks", []) if isinstance(circuit.get("failed_rollbacks"), list) else []
    checks["circuit_breaker"] = (
        circuit.get("status") == "CIRCUIT_BREAKER_ARMED"
        and circuit.get("emergency_stop") is not True
        and recent_row_count(failures, now, 3600) <= policy_int(budget.get("max_failed_actions_per_hour"), 0)
        and len(failed_rollbacks) <= policy_int(budget.get("max_failed_rollbacks"), 0)
    )
    trigger = envelope.get("trigger_proof", {})
    checks["trigger_proven"] = trigger.get("trigger_satisfied") is True
    checks["trigger_exact_allowlist"] = (
        trigger.get("all_observed_paths_allowlisted") is True
        and trigger.get("request_count_attributable_to_allowlisted_paths") is True
        and trigger.get("legitimate_use_absent") is True
    )
    checks["trigger_fresh"] = trigger.get("evidence_fresh") is True
    checks["cause_proven"] = envelope.get("causality_proven") is True
    checks["no_authority_expansion"] = envelope.get("would_expand_authority") is False
    checks["post_validation_required"] = envelope.get("post_validation_required") is True
    checks["ttl_within_contract"] = bool(contract) and (
        0 < policy_int(envelope.get("maximum_ttl_minutes"), 0)
        <= policy_int(contract.get("maximum_ttl_minutes"), 0)
    )
    if expected_phase == "PREPARE":
        checks["prepare_has_no_remote_state_claim"] = (
            envelope.get("before_hash") is None
            and envelope.get("rollback_artifact_hash") is None
            and envelope.get("rollback_artifact_path_id") is None
        )
    elif expected_phase == "COMMIT":
        artifact_name = str(envelope.get("rollback_artifact_path_id") or "")
        artifact_path = ROLLBACK_DIR / artifact_name
        artifact_documents = current.get("artifact_documents", {})
        artifact_hashes = current.get("artifact_hashes", {})
        if artifact_name in artifact_documents:
            artifact = artifact_documents.get(artifact_name, {})
            current_artifact_hash = artifact_hashes.get(artifact_name)
        else:
            artifact = load_dict(artifact_path) if ARTIFACT_NAME_RE.fullmatch(artifact_name) else {}
            current_artifact_hash = file_hash(artifact_path)
        checks["before_hash"] = bool(HEX64_RE.fullmatch(str(envelope.get("before_hash") or "")))
        checks["artifact_name_fixed"] = bool(ARTIFACT_NAME_RE.fullmatch(artifact_name))
        checks["artifact_hash"] = bool(
            artifact
            and envelope.get("rollback_artifact_hash") == current_artifact_hash
        )
        checks["artifact_identity"] = bool(
            artifact
            and artifact.get("cycle_id") == envelope.get("cycle_id")
            and artifact.get("action_id") == envelope.get("action_id")
            and artifact.get("before_hash") == envelope.get("before_hash")
            and artifact.get("after_hash") is None
        )
    findings = [name for name, passed in checks.items() if not passed]
    status = (
        "PROOF_COMMIT_VERIFIED" if expected_phase == "COMMIT" and not findings
        else "PROOF_PREPARE_VERIFIED" if expected_phase == "PREPARE" and not findings
        else "PROOF_VERIFICATION_BLOCKED"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": status,
        "proof_id": envelope.get("proof_id"),
        "proof_phase": expected_phase,
        "cycle_id": envelope.get("cycle_id"),
        "action_id": envelope.get("action_id"),
        "checks": checks,
        "findings": findings,
        "policy_boundary_findings": policy_findings,
        "verified": not findings,
        "productive_action_executed": False,
        "credential_values_accessed": False,
        "network_access": False,
        "breach": False,
    }


def verify_runtime_envelope(
    envelope: Dict[str, Any], expected_phase: str, write: bool = True
) -> Dict[str, Any]:
    result = verify_envelope(envelope, expected_phase)
    if write:
        ensure_dirs()
        write_json(VERIFICATION_JSON, result)
        write_json(REPORT_JSON, result)
        lines = [
            "# Sentinel Independent Remediation Verification",
            "",
            f"- Status: `{result['status']}`",
            f"- Proof phase: `{result['proof_phase']}`",
            f"- Action: `{result.get('action_id')}`",
            f"- Verified: `{str(result['verified']).lower()}`",
            f"- Credential values accessed: `false`",
            f"- Network access: `false`",
            f"- Productive action executed: `false`",
            f"- breach: `false`",
            "",
            "## Findings",
            "",
        ]
        lines.extend(f"- `{item}`" for item in result["findings"] or ["none"])
        write_text(REPORT_MD, "\n".join(lines))
        append_hash_chained_audit({
            "timestamp": result["generated_at"],
            "event": "proof_verified",
            "proof_id": result.get("proof_id"),
            "proof_phase": expected_phase,
            "cycle_id": result.get("cycle_id"),
            "action_id": result.get("action_id"),
            "status": result["status"],
            "finding_count": len(result["findings"]),
            "productive_action_executed": False,
            "credential_values_accessed": False,
            "breach": False,
        })
    return result


def verify_pending(write: bool = True) -> Dict[str, Any]:
    envelope = load_dict(PENDING_PROOF_JSON)
    if not envelope:
        result = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "status": "PROOF_VERIFICATION_BLOCKED",
            "proof_phase": None,
            "findings": ["pending_proof_missing_or_invalid"],
            "verified": False,
            "productive_action_executed": False,
            "credential_values_accessed": False,
            "network_access": False,
            "breach": False,
        }
        if write:
            ensure_dirs()
            write_json(VERIFICATION_JSON, result)
            write_json(REPORT_JSON, result)
            write_text(REPORT_MD, "\n".join([
                "# Sentinel Independent Remediation Verification",
                "",
                "- Status: `PROOF_VERIFICATION_BLOCKED`",
                "- Finding: `pending_proof_missing_or_invalid`",
                "- Productive action executed: `false`",
                "- Credential values accessed: `false`",
                "- Network access: `false`",
                "- breach: `false`",
            ]))
            append_hash_chained_audit({
                "timestamp": result["generated_at"],
                "event": "proof_verification_blocked",
                "status": result["status"],
                "finding_count": 1,
                "productive_action_executed": False,
                "credential_values_accessed": False,
                "breach": False,
            })
        return result
    phase = str(envelope.get("proof_phase") or "")
    return verify_runtime_envelope(envelope, phase, write=write)


def verify_audit_chain() -> Dict[str, Any]:
    if not AUDIT_JSONL.exists():
        return {"status": "VERIFIER_AUDIT_CHAIN_EMPTY", "rows": 0, "invalid_rows": 0}
    previous = "GENESIS"
    rows = 0
    invalid = 0
    try:
        for line in AUDIT_JSONL.read_text(encoding="utf-8").splitlines():
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
        "status": "VERIFIER_AUDIT_CHAIN_VALID" if not invalid else "VERIFIER_AUDIT_CHAIN_INVALID",
        "rows": rows,
        "invalid_rows": invalid,
    }


def synthetic_context(policy: Dict[str, Any], envelope: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    runtime = {
        "activation_stage": "LEVEL_2_GUARDED_CANARY",
        "machine_state": "CANARY",
        "policy_hash": "a" * 64,
        "registry_hash": "b" * 64,
        "flags": {
            "guarded_live_autonomy_enabled": True,
            "low_live_apply_enabled": True,
            "medium_live_apply_enabled": False,
            "high_live_apply_enabled": False,
            "unrestricted_shell_enabled": False,
            "production_apply_lock": False,
            "remote_write_lock": False,
            "emergency_stop": False,
            "breach": False,
        },
        "active_actions": [],
    }
    envelope["runtime_state_hash"] = canonical_hash(runtime)
    envelope["guarded_registry_hash"] = "b" * 64
    envelope["guarded_policy_hash"] = "a" * 64
    envelope["guarded_policy_content_hash"] = "d" * 64
    envelope["runtime_stage"] = runtime["activation_stage"]
    envelope["runtime_machine_state"] = runtime["machine_state"]
    envelope["runtime_flags"] = runtime["flags"]
    envelope["active_action_count"] = 0
    envelope["proof_policy_hash"] = canonical_hash(policy)
    contract = contract_by_id(policy, envelope["action_id"]) or {}
    envelope["action_contract_hash"] = canonical_hash(contract)
    envelope["action_scope_hash"] = canonical_hash(contract.get("scope"))
    envelope["contract_scope_hash"] = canonical_hash(contract.get("scope"))
    envelope["proof_id"] = "proof-" + canonical_hash({key: value for key, value in envelope.items() if key != "proof_id"})[:32]
    evidence = {
        item["evidence_id"]: {
            "read_status": "ok",
            "content_hash": item["content_hash"],
            "fresh": True,
            "document": {},
        }
        for item in envelope["evidence_references"]
    }
    return {
        "policy": policy,
        "policy_hash": canonical_hash(policy),
        "guarded_policy_content_hash": "d" * 64,
        "registry": {"registry_hash": "b" * 64},
        "evidence": evidence,
        "runtime_state": runtime,
        "health": {"status": "HEALTH_TARGET_GATE_GREEN_CHALLENGE_AWARE"},
        "tls": {"status": "TLS_GATE_GREEN"},
        "write_canary": {"status": "CLOUDFLARE_WRITE_CANARY_OK"},
        "circuit": {"status": "CIRCUIT_BREAKER_ARMED", "emergency_stop": False, "failures": [], "failed_rollbacks": []},
        "now": now,
    }


def self_test() -> Dict[str, Any]:
    policy = load_dict(CONFIG_PATH)
    contract = contract_by_id(policy, "temporary_scanner_managed_challenge_v1") or {}
    now = datetime(2026, 7, 16, 18, 0, 30, tzinfo=timezone.utc)
    envelope: Dict[str, Any] = {
        "schema_version": PROOF_SCHEMA_VERSION,
        "proof_phase": "PREPARE",
        "created_at": "2026-07-16T18:00:00Z",
        "expires_at": "2026-07-16T18:02:00Z",
        "cycle_id": "guarded-20260716T180000Z-a1b2c3d4",
        "action_id": contract.get("action_id"),
        "action_version": 1,
        "risk": "LOW_LIVE",
        "owner_policy_reference": policy.get("owner_policy_reference"),
        "proof_policy_hash": None,
        "action_contract_hash": None,
        "action_scope_hash": None,
        "contract_scope_hash": None,
        "guarded_policy_content_hash": None,
        "guarded_registry_hash": None,
        "guarded_policy_hash": None,
        "runtime_state_hash": None,
        "runtime_stage": None,
        "runtime_machine_state": None,
        "runtime_flags": {},
        "active_action_count": 0,
        "evidence_references": [{
            "evidence_id": name,
            "path_id": name,
            "read_status": "ok",
            "content_hash": "c" * 64,
            "timestamp": "2026-07-16T18:00:00Z",
            "timestamp_source": "generated_at",
            "age_seconds": 30,
            "maximum_age_seconds": 900,
            "fresh": True,
            "symlink": False,
        } for name in contract.get("required_evidence", [])],
        "trigger_proof": {
            "trigger_satisfied": True,
            "all_observed_paths_allowlisted": True,
            "request_count_attributable_to_allowlisted_paths": True,
            "legitimate_use_absent": True,
            "evidence_fresh": True,
        },
        "canary": contract.get("canary"),
        "maximum_ttl_minutes": 10,
        "rollback_contract": contract.get("rollback_contract"),
        "health_profile": contract.get("health_profile"),
        "global_invariants": policy.get("global_invariants"),
        "before_hash": None,
        "rollback_artifact_hash": None,
        "rollback_artifact_path_id": None,
        "post_validation_required": True,
        "causality_proven": True,
        "verified_user_impact": "unknown",
        "would_expand_authority": False,
    }
    context = synthetic_context(policy, envelope, now)
    verified = verify_envelope(envelope, "PREPARE", context)
    expanded_policy = json.loads(json.dumps(policy))
    expanded_scanner = contract_by_id(expanded_policy, "temporary_scanner_managed_challenge_v1") or {}
    expanded_scanner.setdefault("allowed_exact_paths", []).append("/")
    expanded_envelope = json.loads(json.dumps(envelope))
    expanded_context = synthetic_context(expanded_policy, expanded_envelope, now)
    expanded_policy_blocked = verify_envelope(expanded_envelope, "PREPARE", expanded_context)
    tampered = json.loads(json.dumps(envelope))
    tampered["trigger_proof"]["all_observed_paths_allowlisted"] = False
    blocked = verify_envelope(tampered, "PREPARE", context)
    unproven = json.loads(json.dumps(envelope))
    unproven["causality_proven"] = False
    unproven["proof_id"] = "proof-" + canonical_hash({key: value for key, value in unproven.items() if key != "proof_id"})[:32]
    unproven_blocked = verify_envelope(unproven, "PREPARE", context)
    stale = json.loads(json.dumps(envelope))
    stale["expires_at"] = "2026-07-16T18:00:01Z"
    stale["proof_id"] = "proof-" + canonical_hash({key: value for key, value in stale.items() if key != "proof_id"})[:32]
    stale_blocked = verify_envelope(stale, "PREPARE", context)
    commit_envelope = {key: value for key, value in envelope.items() if key != "proof_id"}
    artifact_name = "guarded-20260716T180000Z-a1b2c3d4-temporary_scanner_managed_challenge_v1.json"
    commit_envelope.update({
        "proof_phase": "COMMIT",
        "before_hash": "e" * 64,
        "rollback_artifact_hash": "f" * 64,
        "rollback_artifact_path_id": artifact_name,
    })
    commit_envelope["proof_id"] = "proof-" + canonical_hash(commit_envelope)[:32]
    commit_context = dict(context)
    commit_context["artifact_documents"] = {
        artifact_name: {
            "cycle_id": commit_envelope["cycle_id"],
            "action_id": commit_envelope["action_id"],
            "before_hash": commit_envelope["before_hash"],
            "after_hash": None,
        }
    }
    commit_context["artifact_hashes"] = {artifact_name: "f" * 64}
    commit_verified = verify_envelope(commit_envelope, "COMMIT", commit_context)
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: List[str] = []
    command_calls: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {
            "Popen", "run", "call", "check_call", "check_output", "system"
        }:
            command_calls.append(node.func.attr)
    forbidden_roots = {"requests", "urllib", "http", "socket", "smtplib", "paramiko", "cloudflare", "subprocess"}
    forbidden_imports = [name for name in imports if name.split(".")[0] in forbidden_roots]
    tests = {
        "valid_prepare_verified": verified["status"] == "PROOF_PREPARE_VERIFIED",
        "policy_scope_expansion_blocked": expanded_policy_blocked["status"] == "PROOF_VERIFICATION_BLOCKED",
        "tamper_blocked": blocked["status"] == "PROOF_VERIFICATION_BLOCKED",
        "unproven_cause_blocked": unproven_blocked["status"] == "PROOF_VERIFICATION_BLOCKED"
        and "cause_proven" in unproven_blocked["findings"],
        "stale_proof_blocked": stale_blocked["status"] == "PROOF_VERIFICATION_BLOCKED",
        "valid_commit_verified": commit_verified["status"] == "PROOF_COMMIT_VERIFIED",
        "no_network_imports": not forbidden_imports,
        "no_command_execution": not command_calls,
        "fixed_pending_path": PENDING_PROOF_JSON == STATE_DIR / "pending-remediation-proof.json",
        "fixed_evidence_paths": set(EVIDENCE_PATHS) == {
            "website_report", "origin_diagnostics", "health_baseline", "tls_gate", "write_canary",
            "runtime_state", "circuit_breaker", "origin_evidence",
        },
        "no_adapter_or_credentials": (
            not any(name == "sentinel_guarded_autonomy" or name.startswith("sentinel_guarded_autonomy.") for name in imports)
            and all(is_within(path, PROJECT_DIR) for path in (*EVIDENCE_PATHS.values(), CONFIG_PATH, GUARDED_POLICY_PATH))
        ),
        "breach_false": verified["breach"] is False,
    }
    findings = [name for name, passed in tests.items() if not passed]
    return {
        "status": "INDEPENDENT_REMEDIATION_VERIFIER_SELF_TEST_OK" if not findings else "INDEPENDENT_REMEDIATION_VERIFIER_SELF_TEST_FAILED",
        "checks": tests,
        "findings": findings,
        "forbidden_imports": forbidden_imports,
        "command_calls": command_calls,
        "breach": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent proof verifier")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--verify-pending", action="store_true")
    group.add_argument("--verify-audit", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
        print(result["status"])
        return 0 if not result["findings"] else 1
    if args.verify_audit:
        result = verify_audit_chain()
        print(result["status"])
        return 0 if result["invalid_rows"] == 0 else 1
    if args.verify_pending:
        result = verify_pending()
    else:
        result = load_dict(VERIFICATION_JSON)
    if not result:
        print("PROOF_VERIFICATION_NOT_RUN")
        return 1
    print(result.get("status", "PROOF_VERIFICATION_UNKNOWN"))
    print(f"VERIFIED_{str(result.get('verified', False)).upper()}")
    print("CREDENTIAL_VALUES_ACCESSED_FALSE")
    print("NETWORK_ACCESS_FALSE")
    print("BREACH_FALSE")
    return 0 if result.get("verified") else 2


if __name__ == "__main__":
    raise SystemExit(main())
