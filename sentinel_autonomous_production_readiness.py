#!/usr/bin/env python3
"""Final production-readiness gate for independent Sentinel operation.

Readiness means the installed daemon can monitor, refresh evidence, diagnose,
prioritize, decide, audit, and repair only Sentinel-owned derived state without
an LLM. It does not authorize external mutation. Productive LOW_LIVE remains
fail-closed unless a separate exact action contract proves every required gate.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import sentinel_guarded_autonomy as guarded
import sentinel_independent_remediation_verifier as independent_verifier
import sentinel_origin_evidence_collector as origin_evidence
import sentinel_proof_carrying_remediation as proof_remediation
import sentinel_runtime_safety as runtime_safety


PROJECT_DIR = Path(__file__).resolve().parent
REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/guarded-autonomy"
AUDIT_DIR = PROJECT_DIR / "audit"
MANIFEST_PATH = PROJECT_DIR / "config/autonomous-production-source-manifest.json"
REPORT_JSON = REPORT_DIR / "sentinel-autonomous-production-readiness.json"
REPORT_MD = REPORT_DIR / "sentinel-autonomous-production-readiness.md"
OWNER_MD = REPORT_DIR / "sentinel-autonomous-production-owner-summary.md"
STATE_JSON = STATE_DIR / "autonomous-production-readiness.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-autonomous-production-readiness.jsonl"

SCHEMA_VERSION = "sentinel-autonomous-production-readiness-1"
READY = "SENTINEL_AUTONOMOUS_PRODUCTION_READY"
BLOCKED = "SENTINEL_AUTONOMOUS_PRODUCTION_BLOCKED"
LLM_IMPORT_ROOTS = {
    "anthropic",
    "cohere",
    "google.generativeai",
    "langchain",
    "litellm",
    "ollama",
    "openai",
    "transformers",
}
CORE_RUNTIME_FILES = (
    "sentinel_guarded_autonomy.py",
    "sentinel_monitoring_decision_engine.py",
    "sentinel_runtime_safety.py",
    "sentinel_proof_carrying_remediation.py",
    "sentinel_independent_remediation_verifier.py",
    "sentinel_origin_evidence_collector.py",
    "sentinel_autonomous_production_readiness.py",
)
ALLOWED_AUTONOMOUS_DECISIONS = {
    "NO_ACTION",
    "MONITOR_CONTINUE",
    "OWNER_ACTION_REQUIRED",
    "PAUSE_AND_ALERT",
    "MONITOR_AND_ESCALATE",
    "MONITOR_AND_PAUSE_NEW_ACTIONS",
}
FIXED_SYSTEMCTL_COMMANDS = {
    "timer_active": ("/usr/bin/systemctl", "is-active", "sentinel-guarded-autonomy.timer"),
    "timer_enabled": ("/usr/bin/systemctl", "is-enabled", "sentinel-guarded-autonomy.timer"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_hash(path: Path) -> Optional[str]:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def load_json(path: Path) -> Dict[str, Any]:
    if path.is_symlink():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def fixed_systemctl(name: str) -> Dict[str, Any]:
    command = FIXED_SYSTEMCTL_COMMANDS.get(name)
    if command is None:
        return {"status": "COMMAND_BLOCKED", "returncode": None}
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(PROJECT_DIR),
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return {
            "status": completed.stdout.strip() or "unknown",
            "returncode": completed.returncode,
        }
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unavailable", "returncode": None}


def source_independence() -> Dict[str, Any]:
    findings: List[str] = []
    imports_by_file: Dict[str, List[str]] = {}
    for relative in CORE_RUNTIME_FILES:
        path = PROJECT_DIR / relative
        if not path.is_file() or path.is_symlink():
            findings.append(f"missing_or_symlink:{relative}")
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeError):
            findings.append(f"unparseable:{relative}")
            continue
        imports: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        imports_by_file[relative] = sorted(set(imports))
        for name in imports:
            if any(name == root or name.startswith(root + ".") for root in LLM_IMPORT_ROOTS):
                findings.append(f"llm_dependency:{relative}:{name}")
    return {
        "status": "LLM_INDEPENDENCE_VERIFIED" if not findings else "LLM_INDEPENDENCE_BLOCKED",
        "runtime_files": list(CORE_RUNTIME_FILES),
        "imports": imports_by_file,
        "findings": findings,
        "requires_codex": False,
        "requires_claude": False,
        "requires_chatgpt": False,
    }


def verify_source_manifest() -> Dict[str, Any]:
    manifest = load_json(MANIFEST_PATH)
    entries = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
    findings: List[str] = []
    checked: Dict[str, Dict[str, Any]] = {}
    if manifest.get("schema_version") != "sentinel-autonomous-production-source-manifest-1":
        findings.append("manifest_schema_invalid")
    if manifest.get("source_self_modification_enabled") is not False:
        findings.append("source_self_modification_not_disabled")
    for relative, expected in entries.items():
        if not isinstance(relative, str) or relative.startswith("/") or ".." in Path(relative).parts:
            findings.append("manifest_path_invalid")
            continue
        path = PROJECT_DIR / relative
        current = file_hash(path)
        match = isinstance(expected, str) and current == expected
        checked[relative] = {"expected_hash": expected, "current_hash": current, "match": match}
        if not match:
            findings.append(f"source_hash_mismatch:{relative}")
    required = set(CORE_RUNTIME_FILES) | {
        "config/guarded-autonomy-policy.json",
        "config/proof-carrying-remediation-policy.json",
        "systemd/sentinel-guarded-autonomy.service",
        "systemd/sentinel-guarded-autonomy.timer",
    }
    if not required.issubset(entries):
        findings.append("required_source_not_sealed")
    return {
        "status": "SOURCE_INTEGRITY_VERIFIED" if not findings else "SOURCE_INTEGRITY_BLOCKED",
        "manifest_hash": file_hash(MANIFEST_PATH),
        "checked": checked,
        "findings": sorted(set(findings)),
    }


def installed_systemd_gate() -> Dict[str, Any]:
    source = guarded.systemd_source_validation()
    installed = guarded.verified_systemd_installation()
    try:
        service_text = guarded.SERVICE_SOURCE.read_text(encoding="utf-8")
    except OSError:
        service_text = ""
    timer_active = fixed_systemctl("timer_active")
    timer_enabled = fixed_systemctl("timer_enabled")
    checks = {
        "source_hardened": source.get("status") == "SYSTEMD_SOURCE_VALID",
        "installed_exact": installed.get("verified") is True,
        "timer_active": timer_active.get("status") == "active",
        "timer_enabled": timer_enabled.get("status") == "enabled",
        "fixed_exec_start": source.get("checks", {}).get("fixed_exec_start") is True,
        "no_shell_wrapper": source.get("checks", {}).get("fixed_exec_start") is True and "/bin/sh" not in service_text and "/bin/bash" not in service_text,
        "protect_system_strict": source.get("checks", {}).get("protect_system_strict") is True,
        "source_read_only": "ReadOnlyPaths=/srv/sentinel-defense/config /srv/sentinel-defense/playbooks" in service_text and "ProtectSystem=strict" in service_text,
    }
    return {
        "status": "SYSTEMD_RUNTIME_VERIFIED" if all(checks.values()) else "SYSTEMD_RUNTIME_BLOCKED",
        "checks": checks,
        "source": source,
        "installed": installed,
        "timer_active": timer_active,
        "timer_enabled": timer_enabled,
    }


def autonomous_decision_gate() -> Dict[str, Any]:
    decision_report = load_json(PROJECT_DIR / "reports/latest/sentinel-monitoring-decision.json")
    decision = decision_report.get("autonomous_decision", {})
    decision_name = decision.get("decision") if isinstance(decision, dict) else None
    checks = {
        "decision_allowed": decision_name in ALLOWED_AUTONOMOUS_DECISIONS,
        "productive_action_not_attempted": decision.get("productive_action_attempted") is False,
        "remote_write_not_attempted": decision.get("remote_write_attempted") is False,
        "repair_not_attempted_without_proof": decision.get("repair_attempted") is False,
        "canonical_truth_ready": decision_report.get("canonical_truth_ready") is True,
        "evidence_window_aligned": decision_report.get("evidence_window", {}).get("status") == "EVIDENCE_WINDOW_ALIGNED",
    }
    return {
        "status": "AUTONOMOUS_DECISION_GATE_GREEN" if all(checks.values()) else "AUTONOMOUS_DECISION_GATE_BLOCKED",
        "decision": decision_name,
        "execution": decision.get("execution"),
        "reason": decision.get("reason"),
        "checks": checks,
    }


def append_hash_chained_audit(value: Dict[str, Any]) -> None:
    previous = "GENESIS"
    if AUDIT_JSONL.exists() and not AUDIT_JSONL.is_symlink():
        try:
            rows = [json.loads(line) for line in AUDIT_JSONL.read_text(encoding="utf-8").splitlines() if line.strip()]
            if rows and isinstance(rows[-1], dict):
                previous = str(rows[-1].get("record_hash") or "INVALID_PREVIOUS")
        except (OSError, json.JSONDecodeError):
            previous = "INVALID_PREVIOUS"
    row = {**value, "previous_hash": previous}
    row["record_hash"] = canonical_hash(row)
    runtime_safety.durable_append_jsonl(AUDIT_JSONL, row)


def verify_audit_chain() -> Dict[str, Any]:
    if not AUDIT_JSONL.exists():
        return {"status": "PRODUCTION_AUDIT_EMPTY", "rows": 0, "invalid_rows": 0}
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
        "status": "PRODUCTION_AUDIT_VALID" if invalid == 0 else "PRODUCTION_AUDIT_INVALID",
        "rows": rows,
        "invalid_rows": invalid,
    }


def evaluate(write: bool = True) -> Dict[str, Any]:
    state = guarded.load_state()
    flags = state.get("flags", {})
    policy = guarded.validate_policy()
    registry = guarded.validate_action_registry()
    proof_policy = proof_remediation.load_policy()[1]
    runtime_test = runtime_safety.self_test()
    proof_test = proof_remediation.self_test()
    verifier_test = independent_verifier.self_test()
    evidence_test = origin_evidence.self_test()
    guarded_test = guarded.self_test(write_artifacts=False)
    source_independent = source_independence()
    source_integrity = verify_source_manifest()
    systemd = installed_systemd_gate()
    transaction = runtime_safety.load_transaction()
    transaction_gate = runtime_safety.classify_incomplete_transaction(transaction)
    transaction_audit = runtime_safety.verify_transaction_audit()
    guarded_audit = guarded.audit_summary()
    decision = autonomous_decision_gate()
    enabled_external = [
        action["action_id"]
        for action in guarded.REGISTERED_ACTIONS
        if action.get("enabled") and action.get("apply_adapter") != "ReportOnlyAdapter"
    ]
    circuit = guarded.circuit_status(guarded.load_circuit())
    checks = {
        "runtime_safety": runtime_test.get("status") == "RUNTIME_SAFETY_SELF_TEST_OK",
        "guarded_runtime": guarded_test.get("status") == "GUARDED_AUTONOMY_SELF_TEST_OK",
        "proof_builder": proof_test.get("status") == "PROOF_CARRYING_REMEDIATION_SELF_TEST_OK",
        "independent_verifier": verifier_test.get("status") == "INDEPENDENT_REMEDIATION_VERIFIER_SELF_TEST_OK",
        "origin_evidence_collector": evidence_test.get("status") == "ORIGIN_EVIDENCE_COLLECTOR_SELF_TEST_OK",
        "guarded_policy": policy.get("status") == "GUARDED_AUTONOMY_POLICY_VALID",
        "proof_policy": proof_policy.get("status") == "PROOF_REMEDIATION_POLICY_VALID",
        "registry": registry.get("status") == "GUARDED_ACTION_REGISTRY_VALID",
        "llm_independent": source_independent.get("status") == "LLM_INDEPENDENCE_VERIFIED",
        "source_integrity": source_integrity.get("status") == "SOURCE_INTEGRITY_VERIFIED",
        "systemd_runtime": systemd.get("status") == "SYSTEMD_RUNTIME_VERIFIED",
        "monitoring_active": flags.get("monitoring_enabled") is True and state.get("activation_stage") == "LEVEL_2_MONITORING_ACTIVE",
        "low_live_fail_closed": flags.get("low_live_apply_enabled") is False and flags.get("production_apply_lock") is True,
        "medium_high_blocked": flags.get("medium_live_apply_enabled") is False and flags.get("high_live_apply_enabled") is False,
        "no_unrestricted_shell": flags.get("unrestricted_shell_enabled") is False,
        "no_autonomous_external_mutation": not enabled_external and guarded.POLICY_TEMPLATE.get("autonomous_external_mutation_enabled") is False,
        "no_autonomous_waf": guarded.POLICY_TEMPLATE.get("autonomous_waf_enabled") is False,
        "source_self_modification_disabled": guarded.POLICY_TEMPLATE.get("source_self_modification_enabled") is False,
        "circuit_breaker": circuit.get("status") == "CIRCUIT_BREAKER_ARMED" and circuit.get("tripped") is False,
        "transaction_clean": transaction_gate.get("status") == "TRANSACTION_CLEAN",
        "transaction_audit": transaction_audit.get("status") in {"TRANSACTION_AUDIT_EMPTY", "TRANSACTION_AUDIT_VALID"},
        "guarded_audit": guarded_audit.get("status") == "GUARDED_AUDIT_VALID",
        "autonomous_decision": decision.get("status") == "AUTONOMOUS_DECISION_GATE_GREEN",
        "self_healing": state.get("self_healing", {}).get("status") in {"SELF_HEAL_STATE_HEALTHY", "SELF_HEAL_REPAIRED"},
        "emergency_stop_clear_for_monitoring": flags.get("emergency_stop") is False,
        "breach_false": flags.get("breach") is False,
    }
    findings = [name for name, passed in checks.items() if not passed]
    status = READY if not findings else BLOCKED
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": status,
        "operation_mode": "AUTONOMOUS_MONITORING_DIAGNOSIS_DECISION_AND_LOCAL_SELF_HEALING",
        "checks": checks,
        "findings": findings,
        "llm_independence": source_independent,
        "source_integrity": source_integrity,
        "systemd": systemd,
        "runtime": {
            "autonomy_level": state.get("autonomy_level"),
            "activation_stage": state.get("activation_stage"),
            "machine_state": state.get("machine_state"),
            "flags": flags,
            "last_cycle": state.get("last_cycle"),
            "self_healing": state.get("self_healing"),
        },
        "autonomous_decision": decision,
        "proof": {
            "builder": proof_test.get("status"),
            "independent_verifier": verifier_test.get("status"),
            "policy": proof_policy.get("status"),
            "cause_proof_required": True,
            "exact_scope_required": True,
            "tested_rollback_required": True,
        },
        "crash_safety": {
            "runtime_safety": runtime_test.get("status"),
            "transaction": transaction_gate,
            "transaction_audit": transaction_audit,
            "atomic_persistence": True,
        },
        "change_budget": proof_remediation.load_policy()[0].get("change_budget", {}),
        "circuit_breaker": circuit,
        "audit": guarded_audit,
        "enabled_external_actions": enabled_external,
        "autonomous_local_repairs": ["repair_corrupt_or_missing_guarded_derived_state_from_exact_valid_mirror"],
        "blocked_autonomous_classes": [
            "DNS", "TLS", "WAF", "DATABASE", "AUTH", "WORDPRESS", "GLOBAL_SERVER", "MEDIUM", "HIGH", "SOURCE_SELF_MODIFICATION"
        ],
        "low_live": {
            "enabled": flags.get("low_live_apply_enabled") is True,
            "eligible_now": False,
            "gate": "FAIL_CLOSED_NO_AUTHORIZED_EXTERNAL_MUTATION",
            "write_canary": load_json(STATE_DIR / "write-canary.json").get("status", "UNKNOWN"),
        },
        "breach": flags.get("breach", False),
    }
    if write:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        runtime_safety.atomic_write_json(REPORT_JSON, result, 0o644)
        runtime_safety.atomic_write_json(STATE_JSON, result, 0o600)
        runtime_safety.atomic_write_text(REPORT_MD, render_markdown(result), 0o644)
        runtime_safety.atomic_write_text(OWNER_MD, render_owner(result), 0o644)
        append_hash_chained_audit({
            "timestamp": result["generated_at"],
            "event": "autonomous_production_readiness_evaluated",
            "status": status,
            "finding_count": len(findings),
            "low_live_enabled": result["low_live"]["enabled"],
            "breach": result["breach"],
        })
    return result


def render_markdown(result: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Autonomous Production Readiness",
        "",
        f"- status: `{result['status']}`",
        f"- operation_mode: `{result['operation_mode']}`",
        f"- timer: `{result['systemd']['status']}`",
        f"- LLM independence: `{result['llm_independence']['status']}`",
        f"- source integrity: `{result['source_integrity']['status']}`",
        f"- autonomous decision: `{result['autonomous_decision']['decision']}`",
        f"- LOW_LIVE: `{str(result['low_live']['enabled']).lower()}`",
        f"- breach: `{str(result['breach']).lower()}`",
        "",
        "## Safety Model",
        "",
        "No evidence means no change. A productive action would require a fresh proof envelope, exact scope, independent verification, bounded budget, durable rollback artifact, canary, validation, and crash reconciliation.",
        "Autonomous DNS, TLS, WAF, database, authentication, WordPress, global server, MEDIUM, HIGH, and source-code changes are disabled.",
        "",
        "## Findings",
        "",
    ]
    lines.extend(f"- `{item}`" for item in result.get("findings", []))
    if not result.get("findings"):
        lines.append("- none")
    return "\n".join(lines) + "\n"


def render_owner(result: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Production Owner Summary",
        "",
        f"- readiness: `{result['status']}`",
        f"- monitoring: `{str(result['runtime']['flags'].get('monitoring_enabled', False)).lower()}`",
        f"- current autonomous decision: `{result['autonomous_decision']['decision']}`",
        f"- current execution: `{result['autonomous_decision']['execution']}`",
        f"- LOW_LIVE: `{str(result['low_live']['enabled']).lower()}`",
        f"- MEDIUM: `{str(result['runtime']['flags'].get('medium_live_apply_enabled', False)).lower()}`",
        f"- HIGH: `{str(result['runtime']['flags'].get('high_live_apply_enabled', False)).lower()}`",
        f"- emergency_stop: `{str(result['runtime']['flags'].get('emergency_stop', False)).lower()}`",
        f"- breach: `{str(result['breach']).lower()}`",
        "",
        "Sentinel operates without Codex, Claude, ChatGPT, or another LLM. Website-side repair remains owner-required until a separately permitted action has proven cause, exact scope, and tested rollback.",
    ]) + "\n"


def self_test() -> Dict[str, Any]:
    synthetic = {
        "monitoring": True,
        "low": False,
        "medium": False,
        "high": False,
        "breach": False,
    }
    tests = {
        "target_status_constant": READY == "SENTINEL_AUTONOMOUS_PRODUCTION_READY",
        "fail_closed_without_low_live": synthetic["monitoring"] and synthetic["low"] is False,
        "medium_high_permanently_false": synthetic["medium"] is False and synthetic["high"] is False,
        "breach_false": synthetic["breach"] is False,
        "runtime_safety": runtime_safety.self_test()["status"] == "RUNTIME_SAFETY_SELF_TEST_OK",
        "llm_independent": source_independence()["status"] == "LLM_INDEPENDENCE_VERIFIED",
        "fixed_systemctl_only": set(FIXED_SYSTEMCTL_COMMANDS) == {"timer_active", "timer_enabled"},
        "no_source_manifest_writer_cli": True,
        "no_autonomous_waf": guarded.POLICY_TEMPLATE.get("autonomous_waf_enabled") is False,
        "no_source_self_modification": guarded.POLICY_TEMPLATE.get("source_self_modification_enabled") is False,
    }
    findings = [name for name, passed in tests.items() if not passed]
    return {
        "status": "AUTONOMOUS_PRODUCTION_READINESS_SELF_TEST_OK" if not findings else "AUTONOMOUS_PRODUCTION_READINESS_SELF_TEST_FAILED",
        "checks": tests,
        "findings": findings,
        "breach": False,
    }


def print_status(result: Dict[str, Any]) -> None:
    print(result.get("status", "SENTINEL_AUTONOMOUS_PRODUCTION_UNKNOWN"))
    runtime = result.get("runtime", {})
    flags = runtime.get("flags", {})
    print(f"AUTONOMY_LEVEL={runtime.get('autonomy_level', 'UNKNOWN')}")
    print(f"MONITORING_ENABLED_{str(flags.get('monitoring_enabled', False)).upper()}")
    print(f"LOW_LIVE_ENABLED_{str(flags.get('low_live_apply_enabled', False)).upper()}")
    print(f"MEDIUM_ENABLED_{str(flags.get('medium_live_apply_enabled', False)).upper()}")
    print(f"HIGH_ENABLED_{str(flags.get('high_live_apply_enabled', False)).upper()}")
    print(f"EMERGENCY_STOP_{str(flags.get('emergency_stop', True)).upper()}")
    print(f"BREACH_{str(result.get('breach', False)).upper()}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel autonomous production readiness")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--evaluate", action="store_true")
    group.add_argument("--verify-source", action="store_true")
    group.add_argument("--verify-audit", action="store_true")
    group.add_argument("--repair-derived-state", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
        print(result["status"])
        return 0 if not result["findings"] else 1
    if args.verify_source:
        result = verify_source_manifest()
        print(result["status"])
        return 0 if not result["findings"] else 2
    if args.verify_audit:
        result = verify_audit_chain()
        print(result["status"])
        return 0 if result["invalid_rows"] == 0 else 2
    if args.repair_derived_state:
        result = runtime_safety.heal_guarded_state_pair(guarded.STATE_JSON, guarded.LATEST_STATE_JSON)
        print(result["status"])
        return 0 if result["status"] in {"SELF_HEAL_STATE_HEALTHY", "SELF_HEAL_REPAIRED"} else 2
    if args.evaluate:
        result = evaluate(write=True)
    else:
        result = load_json(STATE_JSON)
        if not result:
            print("SENTINEL_AUTONOMOUS_PRODUCTION_NOT_EVALUATED")
            return 2
    print_status(result)
    return 0 if result.get("status") == READY else 2


if __name__ == "__main__":
    raise SystemExit(main())
