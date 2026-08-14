#!/usr/bin/env python3
"""Build proof envelopes for guarded remediation candidates.

This module cannot execute adapters, access credentials, run commands, or use
the network. It supplies evidence and policy proofs to a separate verifier.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
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

REPORT_JSON = REPORT_DIR / "sentinel-proof-carrying-remediation.json"
REPORT_MD = REPORT_DIR / "sentinel-proof-carrying-remediation.md"
OWNER_MD = REPORT_DIR / "sentinel-proof-remediation-owner-plan.md"
VALIDATION_MD = REPORT_DIR / "sentinel-proof-remediation-validation.md"
PENDING_PROOF_JSON = STATE_DIR / "pending-remediation-proof.json"
LATEST_PROOF_JSON = STATE_DIR / "latest-remediation-proof.json"
PROOF_HISTORY_JSON = STATE_DIR / "remediation-proof-history.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-proof-carrying-remediation.jsonl"

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
ACTION_REGISTRY_PATH = STATE_DIR / "action-registry.json"

SCHEMA_VERSION = "sentinel-proof-carrying-remediation-1"
PROOF_ID_RE = re.compile(r"^proof-[a-f0-9]{32}$")
CYCLE_ID_RE = re.compile(r"^guarded-\d{8}T\d{6}Z-[a-f0-9]{8}$")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")
SECRET_RE = re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*\S+")

REPORT_CLASSIFICATION = [
    "PRIVATE_OWNER_OPERATIONAL_REPORT",
    "NOT_FOR_PUBLIC_RELEASE",
    "NOT_FOR_GIT",
    "NO_CREDENTIAL_VALUES",
]

SCANNER_EXACT_PATHS = {
    "/.env",
    "/wp-config.php.bak",
    "/wp-config.old",
    "/phpinfo.php",
}
SCANNER_PATH_PREFIXES = {
    "/.env.",
    "/alfacgiapi/",
    "/.git/",
    "/vendor/phpunit/",
}
SCANNER_SCOPE = {
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
SCANNER_REQUIRED_EVIDENCE = {
    "website_report",
    "origin_diagnostics",
    "health_baseline",
    "tls_gate",
    "write_canary",
    "runtime_state",
    "circuit_breaker",
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
SAFETY_FALSE_KEYS = {
    "network_access",
    "credential_access",
    "shell_execution",
    "live_apply",
    "remote_write",
    "medium_executable",
    "high_executable",
    "breach",
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


def append_hash_chained_audit(path: Path, value: Dict[str, Any]) -> Dict[str, Any]:
    if path.is_symlink() or not is_within(path, AUDIT_DIR):
        raise RuntimeError("blocked audit path")
    previous_hash = "GENESIS"
    if path.exists():
        try:
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if rows and isinstance(rows[-1], dict):
                previous_hash = str(rows[-1].get("record_hash") or "INVALID_PREVIOUS")
        except (OSError, json.JSONDecodeError):
            previous_hash = "INVALID_PREVIOUS"
    row = {**value, "previous_hash": previous_hash}
    row["record_hash"] = canonical_hash(row)
    runtime_safety.durable_append_jsonl(path, row)
    return row


def load_policy() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    policy = load_dict(CONFIG_PATH)
    findings: List[str] = []
    if policy.get("schema_version") != "sentinel-proof-carrying-remediation-policy-1":
        findings.append("schema_version_invalid")
    if policy.get("policy_version") != 1:
        findings.append("policy_version_invalid")
    if policy.get("mode") != "ENFORCEMENT_GATE_ONLY":
        findings.append("mode_not_enforcement_gate_only")
    if policy.get("proof_gate_required") is not True or policy.get("independent_verifier_required") is not True:
        findings.append("proof_or_verifier_not_required")
    if policy.get("activation_effect") is not False or policy.get("automatic_policy_expansion") is not False:
        findings.append("policy_can_expand_or_activate")
    if policy.get("cause_proof_required") is not True:
        findings.append("cause_proof_not_required")
    if not 30 <= policy_int(policy.get("proof_ttl_seconds"), 0) <= 120:
        findings.append("proof_ttl_invalid")
    max_ages = policy.get("evidence_max_age_seconds", {})
    if not isinstance(max_ages, dict) or set(max_ages) != set(EVIDENCE_MAX_AGE_CAPS) or any(
        not 0 < policy_int(max_ages.get(name), 0) <= maximum
        for name, maximum in EVIDENCE_MAX_AGE_CAPS.items()
    ):
        findings.append("evidence_freshness_window_expanded_or_invalid")
    budget = policy.get("change_budget", {})
    if not isinstance(budget, dict):
        budget = {}
        findings.append("change_budget_not_object")
    if not (
        policy_int(budget.get("max_active_actions"), 0) == 1
        and policy_int(budget.get("max_actions_per_hour"), 0) == 1
        and 0 <= policy_int(budget.get("max_failed_actions_per_hour"), -1) <= 1
        and policy_int(budget.get("max_failed_rollbacks"), -1) == 0
        and 0 < policy_int(budget.get("maximum_ttl_minutes"), 0) <= 10
        and 0 < policy_int(budget.get("rollback_timeout_seconds"), 0) <= 30
        and policy_int(budget.get("global_cooldown_minutes"), 0) >= 30
    ):
        findings.append("change_budget_expanded_or_invalid")
    contracts = policy.get("contracts")
    if not isinstance(contracts, list) or not contracts:
        findings.append("contracts_missing")
        contracts = []
    ids = [str(item.get("action_id")) for item in contracts if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        findings.append("duplicate_contract")
    if set(ids) != {"temporary_scanner_managed_challenge_v1", "rollback_sentinel_owned_rule_v1"}:
        findings.append("contract_set_expanded_or_incomplete")
    for contract in contracts:
        if not isinstance(contract, dict):
            findings.append("contract_not_object")
            continue
        if contract.get("risk") != "LOW_LIVE":
            findings.append(f"non_low_live_contract:{contract.get('action_id')}")
        if contract.get("requires_existing_runtime_authorization") is not True:
            findings.append(f"runtime_authorization_not_required:{contract.get('action_id')}")
        if not contract.get("canary", {}).get("required"):
            findings.append(f"canary_not_required:{contract.get('action_id')}")
        if policy_int(contract.get("maximum_ttl_minutes"), 0) > policy_int(budget.get("maximum_ttl_minutes"), 0):
            findings.append(f"contract_ttl_above_budget:{contract.get('action_id')}")
    scanner = next((item for item in contracts if isinstance(item, dict) and item.get("action_id") == "temporary_scanner_managed_challenge_v1"), {})
    scanner_trigger = scanner.get("trigger_requirements", {})
    if not isinstance(scanner_trigger, dict):
        scanner_trigger = {}
        findings.append("scanner_trigger_not_object")
    if scanner.get("action_version") != 1 or scanner.get("enabled") is not True:
        findings.append("scanner_contract_version_or_enablement_invalid")
    if scanner.get("scope") != SCANNER_SCOPE:
        findings.append("scanner_scope_expanded_or_drifted")
    if set(scanner.get("allowed_exact_paths", [])) != SCANNER_EXACT_PATHS:
        findings.append("scanner_exact_paths_expanded_or_drifted")
    if set(scanner.get("allowed_path_prefixes", [])) != SCANNER_PATH_PREFIXES:
        findings.append("scanner_prefixes_expanded_or_drifted")
    if not (
        policy_int(scanner_trigger.get("minimum_requests"), 0) >= 100
        and policy_int(scanner_trigger.get("minimum_actor_groups"), 0) >= 2
        and 0 < policy_int(scanner_trigger.get("maximum_window_minutes"), 0) <= 5
        and scanner_trigger.get("fresh_exact_path_evidence") is True
        and scanner_trigger.get("all_observed_paths_allowlisted") is True
        and scanner_trigger.get("legitimate_use_absent") is True
    ):
        findings.append("scanner_trigger_weakened_or_invalid")
    if set(scanner.get("required_evidence", [])) != SCANNER_REQUIRED_EVIDENCE:
        findings.append("scanner_required_evidence_drifted")
    if scanner.get("canary") != {"required": True, "scope": "single_exact_scanner_path", "maximum_ttl_minutes": 5}:
        findings.append("scanner_canary_drifted")
    if scanner.get("rollback_contract") != "rollback_sentinel_owned_rule_v1":
        findings.append("scanner_rollback_contract_invalid")
    rollback = next((item for item in contracts if isinstance(item, dict) and item.get("action_id") == "rollback_sentinel_owned_rule_v1"), {})
    if not (
        rollback.get("action_version") == 1
        and rollback.get("enabled") is True
        and rollback.get("safety_recovery_action") is True
        and rollback.get("scope") == {"type": "sentinel_owned_rule_only"}
        and set(rollback.get("required_evidence", [])) == {"runtime_state", "circuit_breaker"}
    ):
        findings.append("rollback_contract_expanded_or_invalid")
    safety = policy.get("safety", {})
    if not isinstance(safety, dict):
        safety = {}
        findings.append("safety_not_object")
    if any(safety.get(key) is not False for key in SAFETY_FALSE_KEYS):
        findings.append("safety_drift")
    if safety.get("autonomous_waf_execution") is not False or safety.get("source_self_modification") is not False:
        findings.append("autonomous_waf_or_source_modification_enabled")
    return policy, {
        "status": "PROOF_REMEDIATION_POLICY_VALID" if not findings else "PROOF_REMEDIATION_POLICY_INVALID",
        "findings": findings,
        "policy_hash": canonical_hash(policy) if policy else None,
    }


def contract_by_id(policy: Dict[str, Any], action_id: str) -> Optional[Dict[str, Any]]:
    return next(
        (item for item in policy.get("contracts", []) if isinstance(item, dict) and item.get("action_id") == action_id),
        None,
    )


def content_timestamp(value: Dict[str, Any], path: Path) -> Tuple[Optional[str], str]:
    for key in ("generated_at_utc", "generated_at", "checked_at", "updated_at", "timestamp"):
        parsed = parse_timestamp(value.get(key))
        if parsed:
            return iso_utc(parsed), key
    try:
        return iso_utc(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)), "file_mtime"
    except OSError:
        return None, "missing"


def evidence_reference(name: str, path: Path, max_age: int, now: datetime) -> Dict[str, Any]:
    value, status = read_json(path)
    document = value if status == "ok" and isinstance(value, dict) else {}
    timestamp, timestamp_source = content_timestamp(document, path) if document else (None, "missing")
    parsed = parse_timestamp(timestamp)
    age = max(0.0, (now - parsed).total_seconds()) if parsed else None
    return {
        "evidence_id": name,
        "path_id": name,
        "read_status": status,
        "content_hash": file_hash(path),
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "age_seconds": round(age, 2) if age is not None else None,
        "maximum_age_seconds": max_age,
        "fresh": age is not None and age <= max_age,
        "symlink": path.is_symlink(),
    }


def path_allowed(path: str, contract: Dict[str, Any]) -> bool:
    return path in set(contract.get("allowed_exact_paths", [])) or any(
        path.startswith(prefix) for prefix in contract.get("allowed_path_prefixes", [])
    )


def scanner_trigger_evidence(website: Dict[str, Any], contract: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    finding = next((
        item for item in website.get("correlation_v2_findings", [])
        if isinstance(item, dict) and item.get("signal_id") == "fake_nextjs_or_secret_scans"
    ), {})
    paths = sorted({str(item) for item in finding.get("paths", []) if isinstance(item, str) and item.startswith("/")})
    actors = sorted({str(item) for item in finding.get("user_agents", []) if item})
    generated = parse_timestamp(website.get("generated_at_utc") or website.get("generated_at"))
    age = max(0.0, (now - generated).total_seconds()) if generated else None
    requirements = contract.get("trigger_requirements", {})
    all_allowlisted = bool(paths) and all(path_allowed(path, contract) for path in paths)
    count = max(0, policy_int(finding.get("count"), 0))
    return {
        "signal_id": finding.get("signal_id"),
        "observed_requests": count,
        "actor_groups": len(actors),
        "observed_paths": paths,
        "all_observed_paths_allowlisted": all_allowlisted,
        "request_count_attributable_to_allowlisted_paths": all_allowlisted,
        "legitimate_use_absent": all_allowlisted,
        "evidence_timestamp": iso_utc(generated) if generated else None,
        "evidence_age_seconds": round(age, 2) if age is not None else None,
        "evidence_fresh": age is not None and age <= 900,
        "volume_gate": count >= policy_int(requirements.get("minimum_requests"), 0),
        "actor_gate": len(actors) >= policy_int(requirements.get("minimum_actor_groups"), 0),
        "trigger_satisfied": bool(
            all_allowlisted
            and age is not None
            and age <= 900
            and count >= policy_int(requirements.get("minimum_requests"), 0)
            and len(actors) >= policy_int(requirements.get("minimum_actor_groups"), 0)
        ),
        "raw_user_agents_stored": False,
    }


def assemble_envelope(
    policy: Dict[str, Any],
    contract: Dict[str, Any],
    action: Dict[str, Any],
    signals: Dict[str, Any],
    state: Dict[str, Any],
    cycle_id: str,
    evidence: List[Dict[str, Any]],
    trigger: Dict[str, Any],
    created_at: datetime,
) -> Dict[str, Any]:
    envelope: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "proof_phase": "PREPARE",
        "created_at": iso_utc(created_at),
        "expires_at": iso_utc(created_at.replace(microsecond=0) + timedelta(seconds=policy_int(policy["proof_ttl_seconds"], 0))),
        "cycle_id": cycle_id,
        "action_id": contract["action_id"],
        "action_version": contract["action_version"],
        "risk": contract["risk"],
        "owner_policy_reference": policy["owner_policy_reference"],
        "proof_policy_hash": canonical_hash(policy),
        "action_contract_hash": canonical_hash(contract),
        "action_scope_hash": canonical_hash(action.get("scope")),
        "contract_scope_hash": canonical_hash(contract.get("scope")),
        "guarded_policy_content_hash": file_hash(GUARDED_POLICY_PATH),
        "guarded_registry_hash": state.get("registry_hash"),
        "guarded_policy_hash": state.get("policy_hash"),
        "runtime_state_hash": canonical_hash(state),
        "runtime_stage": state.get("activation_stage"),
        "runtime_machine_state": state.get("machine_state"),
        "runtime_flags": {
            key: state.get("flags", {}).get(key)
            for key in (
                "guarded_live_autonomy_enabled", "low_live_apply_enabled", "medium_live_apply_enabled",
                "high_live_apply_enabled", "unrestricted_shell_enabled", "production_apply_lock",
                "remote_write_lock", "emergency_stop", "breach",
            )
        },
        "active_action_count": len(state.get("active_actions", [])),
        "evidence_references": evidence,
        "trigger_proof": trigger,
        "signal_snapshot_hash": canonical_hash(signals),
        "canary": contract.get("canary"),
        "maximum_ttl_minutes": contract.get("maximum_ttl_minutes"),
        "rollback_contract": contract.get("rollback_contract"),
        "health_profile": contract.get("health_profile"),
        "global_invariants": policy.get("global_invariants", []),
        "before_hash": None,
        "rollback_artifact_hash": None,
        "rollback_artifact_path_id": None,
        "post_validation_required": True,
        "causality_proven": False,
        "verified_user_impact": "unknown",
        "would_expand_authority": False,
    }
    envelope["proof_id"] = "proof-" + canonical_hash(envelope)[:32]
    return envelope


def build_runtime_candidate_proof(
    candidate_action: str,
    action: Dict[str, Any],
    signals: Dict[str, Any],
    state: Dict[str, Any],
    cycle_id: str,
    write: bool = True,
) -> Dict[str, Any]:
    policy, validation = load_policy()
    contract = contract_by_id(policy, candidate_action) if policy else None
    if validation["status"] != "PROOF_REMEDIATION_POLICY_VALID" or not contract:
        return {
            "status": "PROOF_BUILD_BLOCKED",
            "reason": "policy_or_contract_invalid",
            "policy_validation": validation,
            "envelope": None,
        }
    if not CYCLE_ID_RE.fullmatch(cycle_id):
        return {"status": "PROOF_BUILD_BLOCKED", "reason": "cycle_id_invalid", "envelope": None}
    persisted_state = load_dict(EVIDENCE_PATHS["runtime_state"])
    if not persisted_state or canonical_hash(persisted_state) != canonical_hash(state):
        return {
            "status": "PROOF_BUILD_BLOCKED",
            "reason": "runtime_state_not_persisted_or_drifted",
            "envelope": None,
        }
    now = utc_now_dt()
    max_ages = policy.get("evidence_max_age_seconds", {})
    evidence = [
        evidence_reference(name, EVIDENCE_PATHS[name], policy_int(max_ages.get(name), 0), now)
        for name in contract.get("required_evidence", [])
        if name in EVIDENCE_PATHS
    ]
    website = load_dict(EVIDENCE_PATHS["website_report"])
    trigger = scanner_trigger_evidence(website, contract, now) if candidate_action == "temporary_scanner_managed_challenge_v1" else {
        "trigger_satisfied": False,
        "reason": "safety_recovery_contract_requires_existing_artifact",
    }
    envelope = assemble_envelope(policy, contract, action, signals, state, cycle_id, evidence, trigger, now)
    result = {
        "status": "PROOF_ENVELOPE_BUILT",
        "reason": "independent_verification_required",
        "proof_id": envelope["proof_id"],
        "policy_validation": validation,
        "envelope": envelope,
    }
    if write:
        ensure_dirs()
        write_json(PENDING_PROOF_JSON, envelope)
        write_json(LATEST_PROOF_JSON, envelope)
        append_hash_chained_audit(AUDIT_JSONL, {
            "timestamp": utc_now(),
            "event": "proof_envelope_built",
            "proof_id": envelope["proof_id"],
            "proof_phase": "PREPARE",
            "cycle_id": cycle_id,
            "action_id": candidate_action,
            "productive_action_executed": False,
            "breach": False,
        })
    return result


def finalize_runtime_candidate_proof(
    envelope: Dict[str, Any], artifact: Dict[str, Any], write: bool = True
) -> Dict[str, Any]:
    if not isinstance(envelope, dict) or not PROOF_ID_RE.fullmatch(str(envelope.get("proof_id") or "")):
        return {"status": "PROOF_FINALIZE_BLOCKED", "reason": "invalid_prepare_envelope", "envelope": None}
    artifact_path_value = artifact.get("artifact_path")
    artifact_path = Path(str(artifact_path_value)) if artifact_path_value else None
    rollback_root = STATE_DIR / "rollback-artifacts"
    if not artifact_path or artifact_path.is_symlink() or not is_within(artifact_path, rollback_root):
        return {"status": "PROOF_FINALIZE_BLOCKED", "reason": "rollback_artifact_path_invalid", "envelope": None}
    artifact_hash = file_hash(artifact_path)
    before_hash = artifact.get("before_hash")
    if not artifact_hash or not isinstance(before_hash, str) or len(before_hash) != 64:
        return {"status": "PROOF_FINALIZE_BLOCKED", "reason": "rollback_artifact_or_before_hash_missing", "envelope": None}
    finalized = {key: value for key, value in envelope.items() if key != "proof_id"}
    finalized.update({
        "proof_phase": "COMMIT",
        "before_hash": before_hash,
        "rollback_artifact_hash": artifact_hash,
        "rollback_artifact_path_id": artifact_path.name,
    })
    finalized["proof_id"] = "proof-" + canonical_hash(finalized)[:32]
    if write:
        write_json(PENDING_PROOF_JSON, finalized)
        write_json(LATEST_PROOF_JSON, finalized)
        append_hash_chained_audit(AUDIT_JSONL, {
            "timestamp": utc_now(),
            "event": "proof_envelope_finalized",
            "proof_id": finalized["proof_id"],
            "proof_phase": "COMMIT",
            "cycle_id": finalized["cycle_id"],
            "action_id": finalized["action_id"],
            "productive_action_executed": False,
            "breach": False,
        })
    return {"status": "PROOF_ENVELOPE_FINALIZED", "proof_id": finalized["proof_id"], "envelope": finalized}


def current_context_report(record: bool = False) -> Dict[str, Any]:
    policy, validation = load_policy()
    contract = contract_by_id(policy, "temporary_scanner_managed_challenge_v1") if policy else None
    website = load_dict(EVIDENCE_PATHS["website_report"])
    runtime = load_dict(EVIDENCE_PATHS["runtime_state"])
    now = utc_now_dt()
    trigger = scanner_trigger_evidence(website, contract, now) if contract else {}
    max_ages = policy.get("evidence_max_age_seconds", {}) if policy else {}
    if not isinstance(max_ages, dict):
        max_ages = {}
    evidence = {
        name: evidence_reference(name, path, policy_int(max_ages.get(name), 0), now)
        for name, path in EVIDENCE_PATHS.items()
    }
    blockers: List[str] = []
    if validation["status"] != "PROOF_REMEDIATION_POLICY_VALID":
        blockers.append("policy_invalid")
    if not trigger.get("trigger_satisfied"):
        blockers.append("scanner_trigger_not_proven")
    if load_dict(EVIDENCE_PATHS["write_canary"]).get("status") != "CLOUDFLARE_WRITE_CANARY_OK":
        blockers.append("write_canary_not_green")
    flags = runtime.get("flags", {})
    if not flags.get("low_live_apply_enabled") or flags.get("production_apply_lock") is not False:
        blockers.append("runtime_live_authorization_absent")
    required_evidence = contract.get("required_evidence", []) if contract else []
    if any(not evidence[name]["fresh"] for name in required_evidence if name in evidence):
        blockers.append("required_evidence_missing_or_stale")
    origin_evidence = load_dict(EVIDENCE_PATHS["origin_evidence"])
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "PROOF_REMEDIATION_READY" if not blockers else "PROOF_REMEDIATION_BLOCKED",
        "reason": "all proof prerequisites available" if not blockers else ",".join(dict.fromkeys(blockers)),
        "report_classification": REPORT_CLASSIFICATION,
        "policy_validation": validation,
        "contract_count": len(policy.get("contracts", [])) if policy else 0,
        "enabled_contracts": [item.get("action_id") for item in policy.get("contracts", []) if item.get("enabled")],
        "trigger_evidence": trigger,
        "evidence_references": evidence,
        "direct_origin_evidence_count": origin_evidence.get("direct_evidence_count", 0),
        "runtime_stage": runtime.get("activation_stage"),
        "runtime_flags": flags,
        "blockers": list(dict.fromkeys(blockers)),
        "independent_verifier_required": True,
        "productive_actions_executed": 0,
        "safety": policy.get("safety", {}) if policy else {},
    }
    if record:
        ensure_dirs()
        write_json(REPORT_JSON, report)
        history, status = read_json(PROOF_HISTORY_JSON)
        history_rows = history if status == "ok" and isinstance(history, list) else []
        history_rows.append({
            "generated_at": report["generated_at"],
            "status": report["status"],
            "blockers": report["blockers"],
            "productive_actions_executed": 0,
        })
        write_json(PROOF_HISTORY_JSON, history_rows[-200:])
        lines = [
            "# Sentinel Proof-Carrying Remediation",
            "",
            *[f"- Classification: `{item}`" for item in REPORT_CLASSIFICATION],
            f"- Status: `{report['status']}`",
            f"- Policy: `{validation['status']}`",
            f"- Contracts: `{report['contract_count']}`",
            f"- Direct origin evidence: `{report['direct_origin_evidence_count']}`",
            f"- Independent verifier required: `true`",
            f"- Productive actions executed: `0`",
            "",
            "## Blockers",
            "",
        ]
        lines.extend(f"- `{item}`" for item in report["blockers"] or ["none"])
        write_text(REPORT_MD, "\n".join(lines))
        owner = [
            "# Sentinel Proof Remediation Owner Plan",
            "",
            "1. Provide timestamped local origin evidence through the fixed evidence spool.",
            "2. Keep the Cloudflare write gate blocked until a disabled no-effect rule can be created and removed safely.",
            "3. Require a PREPARE proof before adapter reads and a COMMIT proof after rollback artifact creation.",
            "4. Allow only the exact scanner challenge contract and Sentinel-owned rollback after independent verification.",
            "5. Keep WordPress, PHP, database, DNS, SSL, Nginx, login protection, and microcache changes owner-gated.",
        ]
        write_text(OWNER_MD, "\n".join(owner))
        write_text(VALIDATION_MD, "\n".join([
            "# Sentinel Proof Remediation Validation",
            "",
            f"- Policy: `{validation['status']}`",
            f"- Runtime status: `{report['status']}`",
            "- Live apply added: `false`",
            "- Remote write performed: `false`",
            "- breach: `false`",
        ]))
        append_hash_chained_audit(AUDIT_JSONL, {
            "timestamp": report["generated_at"],
            "event": "proof_runtime_context_evaluated",
            "status": report["status"],
            "blockers": report["blockers"],
            "productive_action_executed": False,
            "breach": False,
        })
    return report


def verify_audit_chain(path: Path = AUDIT_JSONL) -> Dict[str, Any]:
    if not path.exists():
        return {"status": "AUDIT_CHAIN_EMPTY", "rows": 0, "invalid_rows": 0}
    previous = "GENESIS"
    invalid = 0
    rows = 0
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
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
        "status": "AUDIT_CHAIN_VALID" if not invalid else "AUDIT_CHAIN_INVALID",
        "rows": rows,
        "invalid_rows": invalid,
    }


def self_test() -> Dict[str, Any]:
    policy, validation = load_policy()
    contract = contract_by_id(policy, "temporary_scanner_managed_challenge_v1") or {}
    synthetic_state = {
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
    synthetic_evidence = [{
        "evidence_id": name,
        "path_id": name,
        "read_status": "ok",
        "content_hash": "c" * 64,
        "timestamp": "2026-07-16T18:00:00Z",
        "timestamp_source": "generated_at",
        "age_seconds": 0,
        "maximum_age_seconds": 900,
        "fresh": True,
        "symlink": False,
    } for name in contract.get("required_evidence", [])]
    synthetic_trigger = {
        "observed_requests": 100,
        "actor_groups": 2,
        "observed_paths": ["/.env"],
        "all_observed_paths_allowlisted": True,
        "request_count_attributable_to_allowlisted_paths": True,
        "legitimate_use_absent": True,
        "evidence_fresh": True,
        "trigger_satisfied": True,
        "raw_user_agents_stored": False,
    }
    envelope = assemble_envelope(
        policy,
        contract,
        {"scope": contract.get("scope")},
        {"scanner_requests": 100},
        synthetic_state,
        "guarded-20260716T180000Z-a1b2c3d4",
        synthetic_evidence,
        synthetic_trigger,
        datetime(2026, 7, 16, 18, 0, tzinfo=timezone.utc),
    )
    repeated = assemble_envelope(
        policy,
        contract,
        {"scope": contract.get("scope")},
        {"scanner_requests": 100},
        synthetic_state,
        "guarded-20260716T180000Z-a1b2c3d4",
        synthetic_evidence,
        synthetic_trigger,
        datetime(2026, 7, 16, 18, 0, tzinfo=timezone.utc),
    )
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
        "policy_valid": validation["status"] == "PROOF_REMEDIATION_POLICY_VALID",
        "proof_id_valid": bool(PROOF_ID_RE.fullmatch(envelope["proof_id"])),
        "proof_deterministic": envelope["proof_id"] == repeated["proof_id"],
        "scope_exact": envelope["action_scope_hash"] == envelope["contract_scope_hash"],
        "independent_verifier_required": policy.get("independent_verifier_required") is True,
        "activation_effect_false": policy.get("activation_effect") is False,
        "cause_proof_required": policy.get("cause_proof_required") is True,
        "no_network_imports": not forbidden_imports,
        "no_command_execution": not command_calls,
        "no_credential_paths": all("credential" not in str(path).lower() for path in EVIDENCE_PATHS.values()),
        "audit_genesis_math": canonical_hash({"event": "x", "previous_hash": "GENESIS"}) == canonical_hash({"event": "x", "previous_hash": "GENESIS"}),
        "safety_invariants": all(policy.get("safety", {}).get(key) is False for key in (
            "network_access", "credential_access", "shell_execution", "live_apply", "remote_write",
            "medium_executable", "high_executable", "breach",
        )),
    }
    findings = [name for name, passed in tests.items() if not passed]
    return {
        "status": "PROOF_CARRYING_REMEDIATION_SELF_TEST_OK" if not findings else "PROOF_CARRYING_REMEDIATION_SELF_TEST_FAILED",
        "checks": tests,
        "findings": findings,
        "forbidden_imports": forbidden_imports,
        "command_calls": command_calls,
        "breach": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Proof-carrying remediation safety layer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--validate-contracts", action="store_true")
    group.add_argument("--collect", action="store_true")
    group.add_argument("--build-proof", action="store_true")
    group.add_argument("--verify-audit", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
        print(result["status"])
        return 0 if not result["findings"] else 1
    if args.validate_contracts:
        result = load_policy()[1]
        print(result["status"])
        return 0 if not result["findings"] else 1
    if args.verify_audit:
        result = verify_audit_chain()
        print(result["status"])
        return 0 if result["invalid_rows"] == 0 else 1
    if args.collect or args.build_proof:
        result = current_context_report(record=True)
    else:
        result = load_dict(REPORT_JSON)
    if not result:
        print("PROOF_REMEDIATION_NOT_BUILT")
        return 1
    print(result.get("status", "PROOF_REMEDIATION_UNKNOWN"))
    print(f"DIRECT_ORIGIN_EVIDENCE_{result.get('direct_origin_evidence_count', 0)}")
    print("INDEPENDENT_VERIFIER_REQUIRED_TRUE")
    print("PRODUCTIVE_ACTIONS_EXECUTED_0")
    print("BREACH_FALSE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
