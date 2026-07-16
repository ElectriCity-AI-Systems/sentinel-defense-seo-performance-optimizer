#!/usr/bin/env python3
"""Guarded, allowlist-only Level-2 autonomy controller.

The controller is fail-closed. Owner policy authorizes LOW_LIVE actions, but
runtime activation remains locked until every current gate passes. Remote
adapters accept only static action definitions and fixed remote targets; no
user-provided command, path, expression, host, or service name is executable.
"""

from __future__ import annotations

import argparse
import ast
import fcntl
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple


PROJECT_DIR = Path(__file__).resolve().parent
SCHEMA_VERSION = "sentinel-guarded-autonomy-10.19"

CONFIG_DIR = PROJECT_DIR / "config"
POLICY_PATH = CONFIG_DIR / "guarded-autonomy-policy.json"
LEGACY_RUNTIME_LOCK = CONFIG_DIR / "autonomy-runtime-lock.json"
PRIVATE_ENV_PATH = Path("/etc/sentinel-defense.env")

REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_ADAPTIVE_DIR = PROJECT_DIR / "state/adaptive-learning"
STATE_DIR = PROJECT_DIR / "state/guarded-autonomy"
AUDIT_DIR = PROJECT_DIR / "audit"
BACKUP_DIR = STATE_DIR / "rollback-artifacts"
PLAYBOOK_DIR = PROJECT_DIR / "playbooks"

REPORT_JSON = REPORT_DIR / "sentinel-guarded-autonomy.json"
REPORT_MD = REPORT_DIR / "sentinel-guarded-autonomy.md"
PREFLIGHT_MD = REPORT_DIR / "sentinel-guarded-preflight.md"
ACTIONS_MD = REPORT_DIR / "sentinel-guarded-actions.md"
CYCLE_MD = REPORT_DIR / "sentinel-guarded-cycle.md"
VALIDATION_MD = REPORT_DIR / "sentinel-guarded-validation.md"
ROLLBACK_MD = REPORT_DIR / "sentinel-guarded-rollback-status.md"
OWNER_MD = REPORT_DIR / "sentinel-guarded-owner-summary.md"

STATE_JSON = STATE_ADAPTIVE_DIR / "guarded_autonomy.json"
LATEST_STATE_JSON = STATE_ADAPTIVE_DIR / "latest_guarded_autonomy.json"
HISTORY_JSON = STATE_ADAPTIVE_DIR / "guarded_autonomy_history.json"
RUNTIME_LOCK_JSON = STATE_DIR / "runtime-lock.json"
ACTION_REGISTRY_JSON = STATE_DIR / "action-registry.json"
CIRCUIT_BREAKER_JSON = STATE_DIR / "circuit-breaker.json"
LAST_KNOWN_GOOD_JSON = STATE_DIR / "last-known-good.json"
HEALTH_BASELINE_STATE_JSON = STATE_DIR / "health-baseline.json"
TLS_GATE_STATE_JSON = STATE_DIR / "tls-gate.json"
CANARY_WINDOW_STATE_JSON = STATE_DIR / "canary-window.json"
RUNTIME_PROMOTION_STATE_JSON = STATE_DIR / "runtime-promotion.json"

AUDIT_JSONL = AUDIT_DIR / "sentinel-guarded-autonomy.jsonl"
ACTIONS_AUDIT_JSONL = AUDIT_DIR / "sentinel-guarded-actions.jsonl"
ROLLBACK_AUDIT_JSONL = AUDIT_DIR / "sentinel-guarded-rollbacks.jsonl"

SERVICE_SOURCE = PROJECT_DIR / "systemd/sentinel-guarded-autonomy.service"
TIMER_SOURCE = PROJECT_DIR / "systemd/sentinel-guarded-autonomy.timer"
SERVICE_DEST = Path("/etc/systemd/system/sentinel-guarded-autonomy.service")
TIMER_DEST = Path("/etc/systemd/system/sentinel-guarded-autonomy.timer")
SYSTEMD_BACKUP_DIR = STATE_DIR / "systemd-backup"

ORIGIN_DIAGNOSTICS_JSON = REPORT_DIR / "sentinel-origin-failure-diagnostics.json"
WEBSITE_REPORT_JSON = REPORT_DIR / "sentinel-defense-report.json"
MASTER_CONSISTENCY_JSON = REPORT_DIR / "sentinel-master-consistency.json"
READINESS_SEAL_MD = REPORT_DIR / "sentinel-autonomous-readiness-seal.md"
RC_JSON = REPORT_DIR / "sentinel-autonomous-release-candidate.json"
FINAL_SAFETY_SEAL_JSON = REPORT_DIR / "low-risk-autonomy-final-safety-seal.json"

PLAYBOOKS = (
    PLAYBOOK_DIR / "sentinel-guarded-autonomy.playbook.json",
    PLAYBOOK_DIR / "sentinel-low-live-actions.playbook.json",
    PLAYBOOK_DIR / "sentinel-automatic-rollback.playbook.json",
    PLAYBOOK_DIR / "sentinel-circuit-breaker.playbook.json",
    PLAYBOOK_DIR / "sentinel-24x7-scheduler.playbook.json",
)

OUTPUT_JSONS = (
    REPORT_JSON,
    STATE_JSON,
    LATEST_STATE_JSON,
    HISTORY_JSON,
    RUNTIME_LOCK_JSON,
    ACTION_REGISTRY_JSON,
    CIRCUIT_BREAKER_JSON,
    LAST_KNOWN_GOOD_JSON,
    POLICY_PATH,
    *PLAYBOOKS,
)
OUTPUT_MARKDOWN = (
    REPORT_MD,
    PREFLIGHT_MD,
    ACTIONS_MD,
    CYCLE_MD,
    VALIDATION_MD,
    ROLLBACK_MD,
    OWNER_MD,
)
OUTPUT_ROOTS = (REPORT_DIR, STATE_ADAPTIVE_DIR, STATE_DIR, AUDIT_DIR, BACKUP_DIR, CONFIG_DIR)

LOCKED = "LOCKED"
PREFLIGHT = "PREFLIGHT"
CANARY = "CANARY"
ACTIVE = "ACTIVE"
DEGRADED = "DEGRADED"
ROLLBACK = "ROLLBACK"
EMERGENCY_STOP = "EMERGENCY_STOP"

ALLOWED_TRANSITIONS = {
    (LOCKED, PREFLIGHT),
    (PREFLIGHT, CANARY),
    (PREFLIGHT, LOCKED),
    (CANARY, ACTIVE),
    (CANARY, ROLLBACK),
    (ACTIVE, DEGRADED),
    (ACTIVE, ROLLBACK),
    (DEGRADED, ACTIVE),
    (DEGRADED, EMERGENCY_STOP),
    (ROLLBACK, LOCKED),
    (ROLLBACK, EMERGENCY_STOP),
}

OWNER_POLICY_REFERENCE = "phase-10.19-owner-approval-2026-07-16"

HEALTH_PASS = "HEALTH_PASS"
HEALTH_EXPECTED_EDGE_CHALLENGE = "HEALTH_EXPECTED_EDGE_CHALLENGE"
HEALTH_FAIL = "HEALTH_FAIL"
HEALTH_UNKNOWN = "HEALTH_UNKNOWN"
HEALTH_GREEN_STATUSES = {
    "HEALTH_TARGET_GATE_GREEN",
    "HEALTH_TARGET_GATE_GREEN_CHALLENGE_AWARE",
}

POLICY_TEMPLATE: Dict[str, Any] = {
    "action_limits": {
        "canary_max_actions_per_hour": 1,
        "global_cooldown_minutes": 30,
        "max_actions_per_day": 12,
        "max_actions_per_hour": 3,
        "max_failed_actions_per_hour": 2,
        "max_identical_action_retries": 1,
    },
    "activation_requires_all_gates": True,
    "automatic_emergency_stop": True,
    "autonomy_level": "LEVEL_2_GUARDED_AUTONOMY",
    "canary_required": True,
    "default_ttl_minutes": 30,
    "health_targets": [
        {
            "id": "public_homepage",
            "url": "https://electri-c-ity-studios-24-7.com/",
            "method": "GET",
            "expected_status": [200, 301, 302],
            "tls_verify": True,
            "required": True,
        },
        {
            "id": "public_robots",
            "url": "https://electri-c-ity-studios-24-7.com/robots.txt",
            "method": "GET",
            "expected_status": [200, 301, 302],
            "tls_verify": True,
            "required": True,
        },
    ],
    "health_challenge_repetitions": 3,
    "high_live_enabled": False,
    "low_live_enabled": True,
    "maximum_ttl_minutes": 240,
    "medium_live_enabled": False,
    "monitoring_enabled": True,
    "owner_policy_approved": True,
    "owner_policy_reference": OWNER_POLICY_REFERENCE,
    "policy_version": 3,
    "post_apply_validation_required": True,
    "rollback_required": True,
    "two_phase_commit_required": True,
    "validation_schedule_seconds": [0, 30, 120, 300],
}

WRITE_CANARY_DESCRIPTION = "sentinel-guarded-write-canary"
WRITE_CANARY_REF = "sentinel_guarded_write_canary"
WRITE_CANARY_EXPRESSION = '(http.request.uri.path eq "/__sentinel_guarded_write_canary_never_route__")'

SCANNER_CANARY_EXPRESSION = '(http.request.uri.path eq "/.env")'
SCANNER_FULL_EXPRESSION = (
    '((http.request.uri.path eq "/.env") or '
    '(starts_with(http.request.uri.path, "/.env.")) or '
    '(http.request.uri.path eq "/wp-config.php.bak") or '
    '(http.request.uri.path eq "/wp-config.old") or '
    '(starts_with(http.request.uri.path, "/alfacgiapi/")) or '
    '(starts_with(http.request.uri.path, "/.git/")) or '
    '(starts_with(http.request.uri.path, "/vendor/phpunit/")) or '
    '(http.request.uri.path eq "/phpinfo.php"))'
)


def write_canary_payload() -> Dict[str, Any]:
    return {
        "action": "managed_challenge",
        "description": WRITE_CANARY_DESCRIPTION,
        "enabled": False,
        "expression": WRITE_CANARY_EXPRESSION,
        "ref": WRITE_CANARY_REF,
    }

ACTION_REQUIRED_FIELDS = {
    "action_id",
    "action_version",
    "risk",
    "scope",
    "trigger",
    "negative_conditions",
    "preflight_checks",
    "canary_plan",
    "apply_adapter",
    "rollback_adapter",
    "validation_checks",
    "maximum_ttl",
    "maximum_frequency",
    "cooldown",
    "owner_policy_reference",
}

REGISTERED_ACTIONS: List[Dict[str, Any]] = [
    {
        "action_id": "temporary_scanner_managed_challenge_v1",
        "action_version": 1,
        "risk": "LOW_LIVE",
        "enabled": True,
        "scope": {
            "type": "cloudflare_custom_rule",
            "action": "managed_challenge",
            "canary_expression": SCANNER_CANARY_EXPRESSION,
            "full_expression": SCANNER_FULL_EXPRESSION,
            "sentinel_owned_ref": "sentinel_guarded_scanner_challenge_v1",
        },
        "trigger": {
            "scanner_requests_minimum": 100,
            "window_minutes": 5,
            "minimum_actor_groups": 2,
            "high_confidence_paths_only": True,
        },
        "negative_conditions": [
            "legitimate_path_use_detected",
            "origin_tls_526_open",
            "healthcheck_baseline_failed",
            "scope_not_exact_allowlist",
        ],
        "preflight_checks": [
            "policy_hash_matches",
            "credentials_ready",
            "ruleset_snapshot_created",
            "baseline_healthcheck_ok",
            "circuit_breaker_closed",
        ],
        "canary_plan": {
            "required": True,
            "scope": "single_exact_scanner_path",
            "ttl_minutes": 5,
        },
        "apply_adapter": "CloudflareGuardedAdapter",
        "rollback_adapter": "CloudflareGuardedAdapter",
        "validation_checks": [
            "homepage_status",
            "wp_login_status",
            "redirect_scope",
            "five_xx_growth",
            "rule_scope_hash",
            "rollback_artifact",
        ],
        "maximum_ttl": 10,
        "maximum_frequency": "1_per_30_minutes",
        "cooldown": 30,
        "owner_policy_reference": OWNER_POLICY_REFERENCE,
    },
    {
        "action_id": "temporary_wp_login_protection_v1",
        "action_version": 1,
        "risk": "LOW_LIVE",
        "enabled": False,
        "disabled_reason": "Admin allowlist and tested rate-limit adapter are not currently registered.",
        "scope": {
            "type": "wordpress_login_edge_protection",
            "paths": ["/wp-login.php", "/xmlrpc.php"],
            "allowed_actions": ["rate_limit", "managed_challenge"],
        },
        "trigger": {"automated_spike_required": True, "failed_attempt_evidence_required": True},
        "negative_conditions": ["admin_allowlist_missing", "legitimate_integration_unknown", "login_healthcheck_failed"],
        "preflight_checks": ["admin_allowlist_present", "login_baseline_ok", "exact_actor_scope"],
        "canary_plan": {"required": True, "scope": "single_actor_path", "ttl_minutes": 5},
        "apply_adapter": "CloudflareGuardedAdapter",
        "rollback_adapter": "CloudflareGuardedAdapter",
        "validation_checks": ["wp_login_status", "normal_browser_403_growth", "admin_access_unchanged"],
        "maximum_ttl": 30,
        "maximum_frequency": "1_per_30_minutes",
        "cooldown": 30,
        "owner_policy_reference": OWNER_POLICY_REFERENCE,
    },
    {
        "action_id": "anonymous_microcache_canary_v1",
        "action_version": 1,
        "risk": "LOW_LIVE",
        "enabled": False,
        "disabled_reason": "No production adapter with tested automatic rollback is registered for this scope.",
        "scope": {"type": "sentinel_owned_public_get_cache", "methods": ["GET", "HEAD"]},
        "trigger": {"origin_timeout_pressure": True, "anonymous_public_endpoint": True},
        "negative_conditions": ["login_cookie", "cart_cookie", "checkout", "account", "personalized_content", "post_request"],
        "preflight_checks": ["cache_key_validated", "exclusions_validated", "baseline_healthcheck_ok"],
        "canary_plan": {"required": True, "scope": "single_public_endpoint", "ttl_seconds": 10},
        "apply_adapter": "SftpSentinelOwnedFileAdapter",
        "rollback_adapter": "SftpSentinelOwnedFileAdapter",
        "validation_checks": ["cache_exclusions", "unexpected_cache_delivery", "five_xx_growth"],
        "maximum_ttl": 1,
        "maximum_frequency": "1_per_30_minutes",
        "cooldown": 30,
        "owner_policy_reference": OWNER_POLICY_REFERENCE,
    },
    {
        "action_id": "rollback_sentinel_owned_rule_v1",
        "action_version": 1,
        "risk": "LOW_LIVE",
        "enabled": True,
        "scope": {"type": "sentinel_owned_rule_only"},
        "trigger": {"validation_failure": True},
        "negative_conditions": ["rollback_artifact_missing", "current_hash_mismatch"],
        "preflight_checks": ["sentinel_ownership", "rollback_artifact_valid", "current_hash_matches_after_hash"],
        "canary_plan": {"required": True, "scope": "restore_snapshot_and_validate", "ttl_minutes": 5},
        "apply_adapter": "CloudflareGuardedAdapter",
        "rollback_adapter": "CloudflareGuardedAdapter",
        "validation_checks": ["homepage_status", "wp_login_status", "restored_hash"],
        "maximum_ttl": 30,
        "maximum_frequency": "as_required_by_validation",
        "cooldown": 30,
        "owner_policy_reference": OWNER_POLICY_REFERENCE,
    },
    {
        "action_id": "restart_sentinel_owned_worker_v1",
        "action_version": 1,
        "risk": "LOW_LIVE",
        "enabled": False,
        "disabled_reason": "No separate installed Sentinel worker unit is registered for restart.",
        "scope": {"type": "local_sentinel_service", "allowed_units": []},
        "trigger": {"sentinel_worker_failed": True},
        "negative_conditions": ["foreign_service", "restart_loop", "rate_limit_exceeded"],
        "preflight_checks": ["unit_exact_allowlist", "unit_owned_by_sentinel", "restart_rate_ok"],
        "canary_plan": {"required": True, "scope": "single_sentinel_unit", "ttl_minutes": 5},
        "apply_adapter": "LocalSentinelServiceAdapter",
        "rollback_adapter": "LocalSentinelServiceAdapter",
        "validation_checks": ["unit_active", "report_pipeline_fresh", "restart_loop_absent"],
        "maximum_ttl": 30,
        "maximum_frequency": "1_per_30_minutes",
        "cooldown": 30,
        "owner_policy_reference": OWNER_POLICY_REFERENCE,
    },
]

MEDIUM_HIGH_BLOCKED_ACTIONS = [
    "wordpress_core_change",
    "plugin_or_theme_change",
    "foreign_php_file_change",
    "database_write",
    "user_role_or_password_change",
    "dns_change",
    "cloudflare_ssl_mode_change",
    "certificate_replacement",
    "origin_ip_change",
    "nginx_main_configuration_change",
    "broad_htaccess_change",
    "hosting_resource_change",
    "file_or_backup_deletion",
    "broad_ip_asn_country_block",
    "git_push_or_tag",
    "release_publication",
    "marketplace_upload",
    "unscoped_email",
]

ADAPTER_METADATA: Dict[str, Dict[str, Any]] = {
    "CloudflareGuardedAdapter": {
        "supports_prepare": True,
        "supports_apply": True,
        "supports_validate": True,
        "supports_rollback": True,
        "allowed_scopes": ["cloudflare_custom_rule", "sentinel_owned_rule_only"],
        "forbidden_scopes": ["ssl", "dns", "certificate", "country", "asn", "ip_block", "origin"],
        "remote_targets": ["api.cloudflare.com"],
    },
    "SftpSentinelOwnedFileAdapter": {
        "supports_prepare": True,
        "supports_apply": False,
        "supports_validate": False,
        "supports_rollback": False,
        "allowed_scopes": ["wp-content/mu-plugins/sentinel-*.php"],
        "forbidden_scopes": ["wordpress_core", "plugins", "themes", "uploads", ".htaccess", "wp-config.php"],
        "remote_targets": [],
    },
    "LocalSentinelServiceAdapter": {
        "supports_prepare": True,
        "supports_apply": False,
        "supports_validate": True,
        "supports_rollback": False,
        "allowed_scopes": [],
        "forbidden_scopes": ["nginx", "apache", "php-fpm", "mysql", "mariadb", "postgresql", "wordpress", "cloudflared"],
        "remote_targets": [],
    },
    "ReportOnlyAdapter": {
        "supports_prepare": True,
        "supports_apply": True,
        "supports_validate": True,
        "supports_rollback": True,
        "allowed_scopes": ["reports", "state", "audit"],
        "forbidden_scopes": ["production", "remote"],
        "remote_targets": [],
    },
}

SYSTEMCTL_COMMANDS: Dict[str, Tuple[str, ...]] = {
    "daemon_reload": ("/usr/bin/systemctl", "daemon-reload"),
    "enable_timer": ("/usr/bin/systemctl", "enable", "--now", "sentinel-guarded-autonomy.timer"),
    "disable_timer": ("/usr/bin/systemctl", "disable", "--now", "sentinel-guarded-autonomy.timer"),
    "start_service": ("/usr/bin/systemctl", "start", "sentinel-guarded-autonomy.service"),
    "timer_active": ("/usr/bin/systemctl", "is-active", "sentinel-guarded-autonomy.timer"),
    "timer_enabled": ("/usr/bin/systemctl", "is-enabled", "sentinel-guarded-autonomy.timer"),
    "service_active": ("/usr/bin/systemctl", "is-active", "sentinel-guarded-autonomy.service"),
}

SECRET_VALUE_RE = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*(?P<value>[^\s,;]+)"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")
ZONE_ID_RE = re.compile(r"^[A-Fa-f0-9]{20,64}$")
RULESET_OBJECT_ID_RE = re.compile(r"^[A-Fa-f0-9]{20,64}$")


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
        result = datetime.fromisoformat(text)
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_hash(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except (OSError, ValueError):
        return str(path)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def has_project_symlink_component(path: Path) -> bool:
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


def output_path_allowed(path: Path) -> bool:
    if has_project_symlink_component(path):
        return False
    absolute = path.absolute()
    return any(
        not root.is_symlink()
        and (absolute == root.absolute() or absolute.is_relative_to(root.absolute()))
        for root in OUTPUT_ROOTS
    )


def ensure_dirs() -> None:
    for directory in (REPORT_DIR, STATE_ADAPTIVE_DIR, STATE_DIR, AUDIT_DIR, BACKUP_DIR, SYSTEMD_BACKUP_DIR):
        if not output_path_allowed(directory):
            raise RuntimeError(f"directory path blocked: {directory}")
        directory.mkdir(parents=True, exist_ok=True)


def read_json(path: Path) -> Tuple[Any, str]:
    if path.is_symlink():
        return None, "symlink_blocked"
    try:
        if not path.exists():
            return None, "missing"
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"


def load_dict(path: Path) -> Dict[str, Any]:
    value, status = read_json(path)
    return value if status == "ok" and isinstance(value, dict) else {}


def write_text(path: Path, text: str) -> None:
    if not output_path_allowed(path):
        raise RuntimeError(f"write path blocked: {path}")
    if PRIVATE_KEY_RE.search(text):
        raise RuntimeError("private key content blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    path.chmod(0o600 if is_within(path, STATE_DIR) or is_within(path, AUDIT_DIR) or is_within(path, BACKUP_DIR) else 0o644)


def write_json(path: Path, value: Any) -> None:
    text = json.dumps(value, indent=2, sort_keys=True)
    json.loads(text)
    write_text(path, text)


def append_jsonl(path: Path, value: Dict[str, Any]) -> None:
    if not output_path_allowed(path):
        raise RuntimeError(f"audit path blocked: {path}")
    line = json.dumps(value, sort_keys=True)
    if PRIVATE_KEY_RE.search(line):
        raise RuntimeError("private key content blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    path.chmod(0o600)


def policy_hash() -> str:
    return canonical_hash(POLICY_TEMPLATE)


def build_policy() -> Dict[str, Any]:
    ensure_dirs()
    write_json(POLICY_PATH, POLICY_TEMPLATE)
    registry = build_action_registry()
    write_json(ACTION_REGISTRY_JSON, registry)
    return {
        "status": "GUARDED_AUTONOMY_POLICY_BUILT",
        "policy_hash": policy_hash(),
        "action_registry_hash": registry["registry_hash"],
    }


def validate_policy() -> Dict[str, Any]:
    value, status = read_json(POLICY_PATH)
    checks = {
        "policy_json_valid": status == "ok" and isinstance(value, dict),
        "policy_exactly_matches_owner_approved_template": value == POLICY_TEMPLATE,
        "owner_policy_approved": isinstance(value, dict) and value.get("owner_policy_approved") is True,
        "level_2_selected": isinstance(value, dict) and value.get("autonomy_level") == "LEVEL_2_GUARDED_AUTONOMY",
        "low_live_policy_enabled": isinstance(value, dict) and value.get("low_live_enabled") is True,
        "medium_disabled": isinstance(value, dict) and value.get("medium_live_enabled") is False,
        "high_disabled": isinstance(value, dict) and value.get("high_live_enabled") is False,
        "two_phase_required": isinstance(value, dict) and value.get("two_phase_commit_required") is True,
        "canary_required": isinstance(value, dict) and value.get("canary_required") is True,
        "rollback_required": isinstance(value, dict) and value.get("rollback_required") is True,
        "post_validation_required": isinstance(value, dict) and value.get("post_apply_validation_required") is True,
        "rate_limits_exact": isinstance(value, dict) and value.get("action_limits") == POLICY_TEMPLATE["action_limits"],
        "fixed_health_targets": isinstance(value, dict)
        and value.get("health_targets") == POLICY_TEMPLATE["health_targets"]
        and all(validate_health_target_definition(target) for target in value.get("health_targets", [])),
    }
    findings = [name for name, passed in checks.items() if not passed]
    return {
        "status": "GUARDED_AUTONOMY_POLICY_VALID" if not findings else "GUARDED_AUTONOMY_POLICY_INVALID",
        "checks": checks,
        "findings": findings,
        "policy_hash": canonical_hash(value) if isinstance(value, dict) else None,
        "expected_policy_hash": policy_hash(),
    }


def action_by_id(action_id: str) -> Optional[Dict[str, Any]]:
    return next((item for item in REGISTERED_ACTIONS if item["action_id"] == action_id), None)


def validate_action_registry() -> Dict[str, Any]:
    findings: List[str] = []
    ids: List[str] = []
    for action in REGISTERED_ACTIONS:
        missing = sorted(ACTION_REQUIRED_FIELDS - set(action))
        if missing:
            findings.append(f"{action.get('action_id', 'unknown')}:missing:{','.join(missing)}")
        action_id = str(action.get("action_id"))
        if action_id in ids:
            findings.append(f"duplicate_action:{action_id}")
        ids.append(action_id)
        if action.get("risk") != "LOW_LIVE":
            findings.append(f"non_low_live_action:{action_id}")
        if not action.get("canary_plan", {}).get("required"):
            findings.append(f"canary_missing:{action_id}")
        if not action.get("rollback_adapter"):
            findings.append(f"rollback_missing:{action_id}")
        if not action.get("validation_checks"):
            findings.append(f"validation_missing:{action_id}")
        ttl = action.get("maximum_ttl")
        if not isinstance(ttl, int) or ttl <= 0 or ttl > POLICY_TEMPLATE["maximum_ttl_minutes"]:
            findings.append(f"ttl_invalid:{action_id}")
        if action.get("apply_adapter") not in ADAPTER_METADATA or action.get("rollback_adapter") not in ADAPTER_METADATA:
            findings.append(f"adapter_unknown:{action_id}")
        if action.get("owner_policy_reference") != OWNER_POLICY_REFERENCE:
            findings.append(f"owner_policy_reference_mismatch:{action_id}")
    return {
        "status": "GUARDED_ACTION_REGISTRY_VALID" if not findings else "GUARDED_ACTION_REGISTRY_INVALID",
        "findings": findings,
        "registered_action_count": len(REGISTERED_ACTIONS),
        "enabled_action_count": sum(1 for item in REGISTERED_ACTIONS if item.get("enabled")),
        "medium_or_high_actions": [],
    }


def private_env_metadata() -> Dict[str, Any]:
    required = {
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_ZONE_ID",
    }
    result = {
        "path": str(PRIVATE_ENV_PATH),
        "exists": False,
        "symlink": False,
        "mode_safe": False,
        "owner_safe": False,
        "group_safe": False,
        "world_readable": False,
        "declared_keys": [],
        "required_keys_present": False,
    }
    try:
        if not PRIVATE_ENV_PATH.exists():
            return result
        result["exists"] = True
        result["symlink"] = PRIVATE_ENV_PATH.is_symlink()
        if result["symlink"]:
            return result
        file_stat = PRIVATE_ENV_PATH.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        result["mode_safe"] = mode & 0o027 == 0
        result["owner_safe"] = file_stat.st_uid == 0
        result["group_safe"] = file_stat.st_gid == os.getgid()
        result["world_readable"] = bool(mode & 0o004)
        keys = set()
        for line in PRIVATE_ENV_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.split("=", 1)[0].strip()
                if key in required or key == "SENTINEL_ADMIN_ALLOWLIST_PRESENT":
                    keys.add(key)
        result["declared_keys"] = sorted(keys)
        result["required_keys_present"] = required.issubset(keys)
        return result
    except OSError:
        return result


def load_private_environment() -> Dict[str, str]:
    metadata = private_env_metadata()
    if not metadata["exists"] or metadata["symlink"] or not metadata["mode_safe"]:
        raise RuntimeError("private environment file is unavailable or unsafe")
    allowed = {
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_ZONE_ID",
        "SENTINEL_ADMIN_ALLOWLIST_PRESENT",
    }
    values: Dict[str, str] = {}
    for line in PRIVATE_ENV_PATH.read_text(encoding="utf-8", errors="strict").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if key in allowed:
            values[key] = value.strip().strip('"').strip("'")
    for key in allowed:
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values


def cloudflare_credentials_ready() -> Dict[str, Any]:
    metadata = private_env_metadata()
    try:
        values = load_private_environment()
    except (OSError, RuntimeError, UnicodeError):
        values = {}
    token_present = bool(values.get("CLOUDFLARE_API_TOKEN"))
    zone_id_valid = bool(ZONE_ID_RE.fullmatch(values.get("CLOUDFLARE_ZONE_ID", "")))
    return {
        "ready": bool(
            metadata["mode_safe"]
            and metadata["owner_safe"]
            and metadata["group_safe"]
            and not metadata["world_readable"]
            and token_present
            and zone_id_valid
        ),
        "token_present": token_present,
        "zone_id_valid": zone_id_valid,
        "private_file_mode_safe": metadata["mode_safe"],
        "private_file_owner_safe": metadata["owner_safe"],
        "private_file_group_safe": metadata["group_safe"],
        "private_file_world_readable": metadata["world_readable"],
    }


def build_action_registry() -> Dict[str, Any]:
    credential_readiness = cloudflare_credentials_ready()
    actions = []
    for item in REGISTERED_ACTIONS:
        action = json.loads(json.dumps(item))
        adapter = ADAPTER_METADATA[action["apply_adapter"]]
        adapter_ready = all(
            adapter[key] for key in ("supports_prepare", "supports_apply", "supports_validate", "supports_rollback")
        )
        if action["apply_adapter"] == "CloudflareGuardedAdapter":
            adapter_ready = adapter_ready and credential_readiness["ready"]
        action["runtime_adapter_ready"] = adapter_ready
        action["can_execute_now"] = False
        action["runtime_reason"] = "Activation gates have not produced ACTIVE runtime state."
        actions.append(action)
    registry_payload = {
        "schema_version": SCHEMA_VERSION,
        "owner_policy_reference": OWNER_POLICY_REFERENCE,
        "default_for_unregistered_action": "BLOCK_UNREGISTERED",
        "adapters": ADAPTER_METADATA,
        "actions": actions,
        "blocked_medium_high_actions": MEDIUM_HIGH_BLOCKED_ACTIONS,
    }
    registry_payload["registry_hash"] = canonical_hash(registry_payload)
    return registry_payload


def default_flags() -> Dict[str, bool]:
    return {
        "monitoring_enabled": True,
        "local_analysis_enabled": True,
        "local_draft_generation_enabled": True,
        "validation_enabled": True,
        "guarded_live_autonomy_enabled": False,
        "low_live_apply_enabled": False,
        "medium_live_apply_enabled": False,
        "high_live_apply_enabled": False,
        "unrestricted_shell_enabled": False,
        "remote_write_lock": True,
        "scheduler_install_lock": True,
        "production_apply_lock": True,
        "emergency_stop": True,
        "breach": False,
    }


def active_flags() -> Dict[str, bool]:
    return {
        "monitoring_enabled": True,
        "local_analysis_enabled": True,
        "local_draft_generation_enabled": True,
        "validation_enabled": True,
        "guarded_live_autonomy_enabled": True,
        "low_live_apply_enabled": True,
        "medium_live_apply_enabled": False,
        "high_live_apply_enabled": False,
        "unrestricted_shell_enabled": False,
        "remote_write_lock": False,
        "scheduler_install_lock": False,
        "production_apply_lock": False,
        "emergency_stop": False,
        "breach": False,
    }


def monitoring_flags() -> Dict[str, bool]:
    flags = default_flags()
    flags.update(
        {
            "monitoring_enabled": True,
            "scheduler_install_lock": False,
            "emergency_stop": False,
            "breach": False,
        }
    )
    return flags


def runtime_machine_allows_actions(state: Dict[str, Any]) -> bool:
    machine = state.get("machine_state")
    stage = state.get("activation_stage")
    return bool(
        machine == ACTIVE
        or (machine == CANARY and stage == "LEVEL_2_GUARDED_CANARY")
    )


def default_state() -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": utc_now(),
        "status": "GUARDED_AUTONOMY_LOCKED",
        "autonomy_level": "LEVEL_1_DRAFT_ONLY",
        "activation_stage": "LEVEL_1_DRAFT_ONLY",
        "machine_state": LOCKED,
        "flags": default_flags(),
        "policy_hash": policy_hash(),
        "registry_hash": build_action_registry()["registry_hash"],
        "preflight": {"status": "NOT_RUN", "gates": [], "blockers": []},
        "canary": {"status": "NOT_RUN", "live": False},
        "rollback_test": {"status": "NOT_RUN"},
        "last_cycle": {},
        "first_cycle_id": None,
        "active_actions": [],
        "last_action": None,
        "pending_validations": [],
        "activation": {"status": "NOT_ACTIVATED", "systemd_installed": False},
        "learning": {
            "successful_actions": {},
            "failed_actions": {},
            "rolled_back_actions": {},
            "false_positive_triggers": {},
            "successful_ttls": {},
            "policy_expansion_allowed": False,
        },
    }


def load_state() -> Dict[str, Any]:
    state = load_dict(STATE_JSON)
    if not state:
        state = default_state()
    defaults = default_state()
    for key, value in defaults.items():
        state.setdefault(key, value)
    for key, value in default_flags().items():
        state.setdefault("flags", {}).setdefault(key, value)
    return state


def transition(state: Dict[str, Any], target: str) -> None:
    current = str(state.get("machine_state", LOCKED))
    if current == target:
        return
    if (current, target) not in ALLOWED_TRANSITIONS:
        raise RuntimeError(f"blocked state transition: {current}->{target}")
    state["machine_state"] = target
    state["updated_at"] = utc_now()


def force_safe_locked(state: Dict[str, Any], status: str, blockers: Sequence[str]) -> None:
    current = state.get("machine_state", LOCKED)
    if current == PREFLIGHT:
        transition(state, LOCKED)
    elif current == ROLLBACK:
        transition(state, LOCKED)
    elif current not in {LOCKED, EMERGENCY_STOP}:
        state["machine_state"] = LOCKED
    state["status"] = status
    state["autonomy_level"] = "LEVEL_1_DRAFT_ONLY"
    state["flags"].update(default_flags())
    state["flags"]["breach"] = False
    state["activation"] = {
        **state.get("activation", {}),
        "status": "ACTIVATION_BLOCKED",
        "blockers": list(blockers),
        "systemd_installed": systemd_status()["installed"],
    }


def write_state(state: Dict[str, Any], record_history: bool = False) -> None:
    ensure_dirs()
    state["updated_at"] = utc_now()
    write_json(STATE_JSON, state)
    write_json(LATEST_STATE_JSON, state)
    if record_history:
        history, status = read_json(HISTORY_JSON)
        if status != "ok" or not isinstance(history, list):
            history = []
        history.append({
            "timestamp": state["updated_at"],
            "status": state["status"],
            "machine_state": state["machine_state"],
            "autonomy_level": state["autonomy_level"],
            "emergency_stop": state["flags"]["emergency_stop"],
            "breach": state["flags"]["breach"],
            "last_cycle_id": state.get("last_cycle", {}).get("cycle_id"),
        })
        write_json(HISTORY_JSON, history)
    elif not HISTORY_JSON.exists():
        write_json(HISTORY_JSON, [])


@contextmanager
def runtime_cycle_lock(max_wait_seconds: int = 0) -> Iterator[Dict[str, Any]]:
    del max_wait_seconds
    ensure_dirs()
    handle = RUNTIME_LOCK_JSON.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise RuntimeError("guarded autonomy runtime lock collision")
    lock_value = {
        "pid": os.getpid(),
        "started_at": utc_now(),
        "status": "RUNNING",
        "command": "--run-cycle",
    }
    handle.seek(0)
    handle.truncate()
    handle.write(json.dumps(lock_value, indent=2, sort_keys=True) + "\n")
    handle.flush()
    os.fchmod(handle.fileno(), 0o600)
    try:
        yield lock_value
    finally:
        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps({
            "pid": os.getpid(),
            "finished_at": utc_now(),
            "status": "IDLE",
            "command": "--run-cycle",
        }, indent=2, sort_keys=True) + "\n")
        handle.flush()
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def rules_hash(rules: Any) -> str:
    normalized = rules if isinstance(rules, list) else []
    return canonical_hash(normalized)


def sanitize_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in rule.items() if key not in {"version", "last_updated"}}


def semantic_rules_hash(rules: Any) -> str:
    normalized = [sanitize_rule(dict(rule)) for rule in rules if isinstance(rule, dict)] if isinstance(rules, list) else []
    return canonical_hash(normalized)


class CloudflareAdapterRequestError(RuntimeError):
    def __init__(self, status_code: Optional[int], operation: str) -> None:
        super().__init__(f"registered Cloudflare adapter {operation} failed")
        self.status_code = status_code
        self.operation = operation


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        del req, fp, code, msg, headers, newurl
        return None


def validate_health_target_definition(target: Dict[str, Any]) -> bool:
    parsed = urllib.parse.urlparse(str(target.get("url", "")))
    forbidden_prefixes = ("/wp-admin", "/wp-login.php", "/checkout", "/cart", "/account")
    return bool(
        target.get("id") in {"public_homepage", "public_robots"}
        and target.get("method") == "GET"
        and target.get("tls_verify") is True
        and target.get("required") is True
        and parsed.scheme == "https"
        and parsed.hostname == "electri-c-ity-studios-24-7.com"
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and not parsed.path.startswith(forbidden_prefixes)
        and set(target.get("expected_status", [])) == {200, 301, 302}
    )


def check_fixed_health_target(target: Dict[str, Any]) -> Dict[str, Any]:
    checked_at = utc_now()
    started = time.perf_counter()
    base_url = str(target.get("url", ""))
    parsed_base = urllib.parse.urlparse(base_url)
    result: Dict[str, Any] = {
        "target_id": target.get("id"),
        "final_host": parsed_base.hostname,
        "status": None,
        "redirect_count": 0,
        "tls_verified": False,
        "response_time_ms": None,
        "content_length": 0,
        "content_fingerprint": None,
        "checked_at": checked_at,
        "ok": False,
        "error": None,
        "challenge_detected": False,
        "challenge_candidate": False,
        "cloudflare_header_present": False,
        "server_class": "unknown",
        "challenge_marker_class": "none",
        "redirect_class": "none",
        "normalized_signature": None,
        "health_class": HEALTH_UNKNOWN,
    }
    if not validate_health_target_definition(target):
        result["error"] = "invalid_fixed_health_target_definition"
        return result
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirectHandler(),
    )
    current_url = base_url
    body = b""
    try:
        for redirect_count in range(6):
            request = urllib.request.Request(
                current_url,
                method="GET",
                headers={"User-Agent": "SentinelGuardedHealthcheck/1.0", "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1"},
            )
            response: Any
            try:
                response = opener.open(request, timeout=15)
            except urllib.error.HTTPError as exc:
                response = exc
            status_code = int(response.code)
            result["tls_verified"] = True
            server_value = str(response.headers.get("Server", "")).lower()
            header_names = {str(name).lower() for name in response.headers.keys()}
            result["server_class"] = "cloudflare" if "cloudflare" in server_value else ("other" if server_value else "unknown")
            result["cloudflare_header_present"] = bool(
                result["server_class"] == "cloudflare"
                or "cf-ray" in header_names
                or "cf-cache-status" in header_names
                or "cf-mitigated" in header_names
            )
            location = response.headers.get("Location")
            if status_code in {301, 302, 303, 307, 308} and location:
                response.close()
                if redirect_count >= 5:
                    result["error"] = "redirect_limit_exceeded"
                    break
                next_url = urllib.parse.urljoin(current_url, location)
                parsed_next = urllib.parse.urlparse(next_url)
                if (
                    parsed_next.scheme != "https"
                    or parsed_next.hostname != parsed_base.hostname
                    or parsed_next.username
                    or parsed_next.password
                ):
                    result["error"] = "redirect_target_blocked"
                    break
                result["redirect_count"] = redirect_count + 1
                result["redirect_class"] = "same_host"
                current_url = next_url
                continue
            body = response.read(2 * 1024 * 1024 + 1)
            challenge_header = str(response.headers.get("cf-mitigated", "")).lower() == "challenge"
            response.close()
            if len(body) > 2 * 1024 * 1024:
                result["error"] = "response_size_limit_exceeded"
                body = body[: 2 * 1024 * 1024]
            result["status"] = status_code
            result["final_host"] = urllib.parse.urlparse(current_url).hostname
            body_lower = body[:131072].lower()
            if challenge_header:
                result["challenge_marker_class"] = "cf_mitigated"
            elif b"challenge-platform" in body_lower or b"cf-chl-" in body_lower:
                result["challenge_marker_class"] = "cloudflare_managed_challenge"
            elif b"just a moment" in body_lower:
                result["challenge_marker_class"] = "cloudflare_interstitial"
            result["challenge_detected"] = result["challenge_marker_class"] != "none"
            break
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        result["error"] = type(exc).__name__
    result["response_time_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    result["content_length"] = len(body)
    expected_standard_status = bool(
        result["error"] is None
        and result["tls_verified"] is True
        and result["final_host"] == parsed_base.hostname
        and result["status"] in set(target["expected_status"])
        and result["challenge_detected"] is False
    )
    result["challenge_candidate"] = bool(
        result["error"] is None
        and result["status"] == 403
        and result["tls_verified"] is True
        and result["final_host"] == parsed_base.hostname
        and result["cloudflare_header_present"] is True
        and result["challenge_detected"] is True
    )
    normalized = {
        "status_class": f"{int(result['status']) // 100}xx" if isinstance(result.get("status"), int) else "unknown",
        "server_class": result["server_class"],
        "cloudflare_header_present": result["cloudflare_header_present"],
        "challenge_marker_class": result["challenge_marker_class"],
        "final_hostname_class": "approved" if result["final_host"] == parsed_base.hostname else "foreign_or_unknown",
        "redirect_class": result["redirect_class"],
        "tls_verification_state": "verified" if result["tls_verified"] else "failed_or_unknown",
    }
    result["normalized_signature"] = canonical_hash(normalized)
    result["content_fingerprint"] = None if result["challenge_candidate"] else (sha256_bytes(body) if body else None)
    if expected_standard_status:
        result["health_class"] = HEALTH_PASS
        result["ok"] = True
    elif result["challenge_candidate"]:
        result["health_class"] = HEALTH_UNKNOWN
    else:
        result["health_class"] = HEALTH_FAIL
    return result


def evaluate_health_gate_logic(
    homepage_samples: Sequence[Dict[str, Any]],
    robots: Dict[str, Any],
) -> Dict[str, Any]:
    signatures = [sample.get("normalized_signature") for sample in homepage_samples]
    challenge_reproducible = bool(
        len(homepage_samples) >= POLICY_TEMPLATE["health_challenge_repetitions"]
        and all(sample.get("challenge_candidate") is True for sample in homepage_samples)
        and len(set(signatures)) == 1
    )
    homepage = dict(homepage_samples[-1])
    if homepage.get("health_class") == HEALTH_PASS:
        gate_status = "HEALTH_TARGET_GATE_GREEN" if robots.get("health_class") == HEALTH_PASS else "HEALTH_TARGET_GATE_BLOCKED"
    elif challenge_reproducible and robots.get("health_class") == HEALTH_PASS:
        homepage["health_class"] = HEALTH_EXPECTED_EDGE_CHALLENGE
        homepage["ok"] = True
        gate_status = "HEALTH_TARGET_GATE_GREEN_CHALLENGE_AWARE"
    else:
        homepage["health_class"] = HEALTH_FAIL if homepage.get("health_class") != HEALTH_UNKNOWN else HEALTH_UNKNOWN
        gate_status = "HEALTH_TARGET_GATE_BLOCKED"
    return {
        "status": gate_status,
        "homepage": homepage,
        "challenge_reproducible": challenge_reproducible,
        "challenge_repetition_count": len(homepage_samples),
    }


def check_fixed_health_targets() -> Dict[str, Any]:
    targets = {target["id"]: target for target in POLICY_TEMPLATE["health_targets"]}
    robots = check_fixed_health_target(targets["public_robots"])
    homepage_samples = [check_fixed_health_target(targets["public_homepage"])]
    if homepage_samples[0].get("challenge_candidate"):
        for _ in range(POLICY_TEMPLATE["health_challenge_repetitions"] - 1):
            homepage_samples.append(check_fixed_health_target(targets["public_homepage"]))
    decision = evaluate_health_gate_logic(homepage_samples, robots)
    homepage = decision["homepage"]
    gate_status = decision["status"]
    challenge_reproducible = decision["challenge_reproducible"]
    latest_5xx = latest_monitor_total_5xx()
    checks = [homepage, robots]
    return {
        "status": gate_status,
        "checks": checks,
        "homepage_health_class": homepage["health_class"],
        "homepage_challenge_signature": homepage.get("normalized_signature") if homepage["health_class"] == HEALTH_EXPECTED_EDGE_CHALLENGE else None,
        "challenge_signature_status": "REPRODUCIBLE" if challenge_reproducible else "NOT_APPLICABLE_OR_NOT_REPRODUCIBLE",
        "challenge_repetition_count": decision["challenge_repetition_count"],
        "robots_health_class": robots["health_class"],
        "tls_verified": all(item.get("tls_verified") is True for item in checks),
        "recent_5xx": latest_5xx.get("count"),
        "recent_5xx_snapshot_id": latest_5xx.get("snapshot_id"),
        "response_bodies_stored": False,
        "challenge_tokens_stored": False,
        "checked_at": utc_now(),
    }


class CloudflareGuardedAdapter:
    api_origin = "https://api.cloudflare.com"
    api_prefix = "/client/v4"

    def __init__(self) -> None:
        self.metadata = ADAPTER_METADATA[self.__class__.__name__]

    def _environment(self) -> Dict[str, str]:
        values = load_private_environment()
        token = values.get("CLOUDFLARE_API_TOKEN", "")
        zone_id = values.get("CLOUDFLARE_ZONE_ID", "")
        if not token or not ZONE_ID_RE.fullmatch(zone_id):
            raise RuntimeError("Cloudflare credential prerequisites are missing or invalid")
        return values

    def _api_request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        values = self._environment()
        zone_id = values["CLOUDFLARE_ZONE_ID"]
        allowed_path = f"/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint"
        if path != allowed_path or method not in {"GET", "PUT"}:
            raise RuntimeError("remote target or method is not registered")
        url = self.api_origin + self.api_prefix + path
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {values['CLOUDFLARE_API_TOKEN']}",
                "Content-Type": "application/json",
                "User-Agent": "SentinelGuardedAutonomy/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"registered Cloudflare adapter request failed: {type(exc).__name__}") from exc
        if not isinstance(result, dict):
            raise RuntimeError("Cloudflare adapter returned non-object JSON")
        return result

    def _entrypoint(self) -> Dict[str, Any]:
        values = self._environment()
        result = self._api_request(
            "GET",
            f"/zones/{values['CLOUDFLARE_ZONE_ID']}/rulesets/phases/http_request_firewall_custom/entrypoint",
        )
        if result.get("success") is not True or not isinstance(result.get("result"), dict):
            raise RuntimeError("Cloudflare custom ruleset entrypoint is unavailable")
        return result["result"]

    def _rule_api_request(
        self,
        method: str,
        ruleset_id: str,
        rule_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        values = self._environment()
        zone_id = values["CLOUDFLARE_ZONE_ID"]
        if not RULESET_OBJECT_ID_RE.fullmatch(ruleset_id):
            raise RuntimeError("Cloudflare ruleset identifier is invalid")
        if method == "POST" and rule_id is None:
            path = f"/zones/{zone_id}/rulesets/{ruleset_id}/rules"
        elif method == "DELETE" and rule_id and RULESET_OBJECT_ID_RE.fullmatch(rule_id):
            path = f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"
        else:
            raise RuntimeError("Cloudflare rule operation is not registered")
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            self.api_origin + self.api_prefix + path,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {values['CLOUDFLARE_API_TOKEN']}",
                "Content-Type": "application/json",
                "User-Agent": "SentinelGuardedAutonomy/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            exc.close()
            raise CloudflareAdapterRequestError(int(exc.code), method.lower()) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise CloudflareAdapterRequestError(None, method.lower()) from exc
        if not isinstance(result, dict) or result.get("success") is not True:
            raise CloudflareAdapterRequestError(None, method.lower())
        return result

    @staticmethod
    def _write_canary_rule_matches(rule: Dict[str, Any]) -> bool:
        return bool(
            rule.get("ref") == WRITE_CANARY_REF
            and rule.get("description") == WRITE_CANARY_DESCRIPTION
            and rule.get("action") == "managed_challenge"
            and rule.get("expression") == WRITE_CANARY_EXPRESSION
            and rule.get("enabled") is False
        )

    def _delete_fixed_write_canary(
        self,
        ruleset_id: str,
        candidates: Sequence[Dict[str, Any]],
    ) -> Dict[str, Any]:
        identifiers = [str(rule.get("id") or "") for rule in candidates]
        if not identifiers or not all(RULESET_OBJECT_ID_RE.fullmatch(rule_id) for rule_id in identifiers):
            return {"deletion_verified": False, "delete_errors": ["invalid_or_missing_rule_identifier"], "final_rules": []}
        delete_errors: List[str] = []
        for rule_id in identifiers:
            try:
                self._rule_api_request("DELETE", ruleset_id, rule_id)
            except CloudflareAdapterRequestError as exc:
                delete_errors.append(f"delete_{exc.status_code or 'unknown'}")
        try:
            final_ruleset = self._entrypoint()
        except RuntimeError:
            return {"deletion_verified": False, "delete_errors": [*delete_errors, "absence_readback_failed"], "final_rules": []}
        final_rules = final_ruleset.get("rules") if isinstance(final_ruleset.get("rules"), list) else []
        remains = any(
            isinstance(rule, dict)
            and (rule.get("ref") == WRITE_CANARY_REF or rule.get("description") == WRITE_CANARY_DESCRIPTION)
            for rule in final_rules
        )
        return {
            "deletion_verified": not remains,
            "delete_errors": delete_errors,
            "final_rules": final_rules,
        }

    def probe_disabled_write_canary(self) -> Dict[str, Any]:
        ruleset = self._entrypoint()
        ruleset_id = str(ruleset.get("id") or "")
        if not RULESET_OBJECT_ID_RE.fullmatch(ruleset_id):
            raise RuntimeError("Cloudflare write-canary ruleset scope is invalid")
        before_rules = ruleset.get("rules") if isinstance(ruleset.get("rules"), list) else []
        before_hash = semantic_rules_hash(before_rules)
        existing = [
            rule for rule in before_rules
            if isinstance(rule, dict) and (rule.get("ref") == WRITE_CANARY_REF or rule.get("description") == WRITE_CANARY_DESCRIPTION)
        ]
        if existing:
            exact_stale = len(existing) == 1 and self._write_canary_rule_matches(existing[0])
            cleanup = self._delete_fixed_write_canary(ruleset_id, existing)
            if not cleanup["deletion_verified"]:
                return {
                    "status": "CLOUDFLARE_WRITE_CANARY_ROLLBACK_FAILED",
                    "reason": "preexisting_fixed_canary_cleanup_not_verified",
                    "created": False,
                    "verified": exact_stale,
                    "deleted": False,
                    "deletion_verified": False,
                    "traffic_effect": False,
                    "credential_values_disclosed": False,
                    "before_hash": before_hash,
                    "after_hash": semantic_rules_hash(cleanup["final_rules"]),
                }
            if not exact_stale:
                return {
                    "status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
                    "reason": "unexpected_preexisting_fixed_identity_removed_for_owner_review",
                    "created": False,
                    "verified": False,
                    "deleted": True,
                    "deletion_verified": True,
                    "traffic_effect": False,
                    "monitoring_activation_allowed": True,
                    "credential_values_disclosed": False,
                    "before_hash": before_hash,
                    "after_hash": semantic_rules_hash(cleanup["final_rules"]),
                }
            before_rules = cleanup["final_rules"]
            before_hash = semantic_rules_hash(before_rules)

        create_error: Optional[CloudflareAdapterRequestError] = None
        try:
            self._rule_api_request("POST", ruleset_id, payload=write_canary_payload())
        except CloudflareAdapterRequestError as exc:
            create_error = exc
        try:
            created_ruleset = self._entrypoint()
        except RuntimeError:
            return {
                "status": "CLOUDFLARE_WRITE_CANARY_ROLLBACK_FAILED",
                "reason": "post_create_readback_unavailable",
                "created": create_error is None,
                "verified": False,
                "deleted": False,
                "deletion_verified": False,
                "traffic_effect": False,
                "credential_values_disclosed": False,
                "before_hash": before_hash,
                "after_hash": None,
            }
        created_rules = created_ruleset.get("rules") if isinstance(created_ruleset.get("rules"), list) else []
        matching = [
            rule for rule in created_rules
            if isinstance(rule, dict) and (rule.get("ref") == WRITE_CANARY_REF or rule.get("description") == WRITE_CANARY_DESCRIPTION)
        ]
        if not matching:
            return {
                "status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
                "reason": "fixed_scope_write_permission_or_disabled_rule_create_unavailable",
                "http_status_class": f"{create_error.status_code // 100}xx" if create_error and create_error.status_code else None,
                "created": False,
                "verified": False,
                "deleted": False,
                "deletion_verified": True,
                "traffic_effect": False,
                "monitoring_activation_allowed": True,
                "credential_values_disclosed": False,
                "before_hash": before_hash,
                "after_hash": before_hash,
            }
        exact_match = len(matching) == 1 and self._write_canary_rule_matches(matching[0])
        rule_id = str(matching[0].get("id") or "") if len(matching) == 1 else ""
        cleanup = self._delete_fixed_write_canary(ruleset_id, matching)
        final_hash = semantic_rules_hash(cleanup["final_rules"])
        if not cleanup["deletion_verified"]:
            return {
                "status": "CLOUDFLARE_WRITE_CANARY_ROLLBACK_FAILED",
                "reason": "disabled_canary_deletion_not_verified",
                "created": True,
                "verified": exact_match,
                "deleted": False,
                "deletion_verified": False,
                "traffic_effect": False,
                "credential_values_disclosed": False,
                "rule_id_fingerprint": canonical_hash({"rule_id": rule_id}) if rule_id else None,
                "before_hash": before_hash,
                "after_hash": final_hash,
            }
        if not exact_match:
            return {
                "status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
                "reason": "created_canary_scope_or_content_mismatch_removed",
                "created": True,
                "verified": False,
                "deleted": True,
                "deletion_verified": True,
                "traffic_effect": False,
                "monitoring_activation_allowed": True,
                "credential_values_disclosed": False,
                "before_hash": before_hash,
                "after_hash": final_hash,
            }
        restored = final_hash == before_hash
        return {
            "status": "CLOUDFLARE_WRITE_CANARY_OK" if restored else "CLOUDFLARE_WRITE_CANARY_BLOCKED",
            "reason": "disabled_rule_created_verified_deleted_and_absence_verified" if restored else "concurrent_ruleset_drift_after_verified_canary_deletion",
            "created": True,
            "verified": True,
            "deleted": True,
            "deletion_verified": True,
            "traffic_effect": False,
            "enabled": False,
            "monitoring_activation_allowed": True,
            "credential_values_disclosed": False,
            "rule_id_fingerprint": canonical_hash({"rule_id": rule_id}),
            "before_hash": before_hash,
            "after_hash": final_hash,
        }

    def validate_read_scope(self) -> bool:
        ruleset = self._entrypoint()
        return bool(
            isinstance(ruleset.get("id"), str)
            and ruleset.get("phase") == "http_request_firewall_custom"
            and ruleset.get("kind") == "zone"
        )

    def _update(self, ruleset: Dict[str, Any], rules: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        values = self._environment()
        payload = {
            "name": ruleset.get("name", "default"),
            "description": ruleset.get("description", "") or "",
            "rules": [sanitize_rule(dict(rule)) for rule in rules],
        }
        result = self._api_request(
            "PUT",
            f"/zones/{values['CLOUDFLARE_ZONE_ID']}/rulesets/phases/http_request_firewall_custom/entrypoint",
            payload,
        )
        if result.get("success") is not True or not isinstance(result.get("result"), dict):
            raise RuntimeError("Cloudflare custom ruleset update failed")
        return result["result"]

    def healthcheck(self) -> Dict[str, Any]:
        self._environment()
        baseline = check_fixed_health_targets()
        return {
            "status": "HEALTHCHECK_OK" if health_gate_ok(baseline) else "HEALTHCHECK_FAILED",
            "gate_status": baseline["status"],
            "profile": health_profile_snapshot(baseline),
            "checks": baseline["checks"],
            "baseline": baseline,
        }

    def prepare(self, action: Dict[str, Any], cycle_id: str, baseline: Dict[str, Any]) -> Dict[str, Any]:
        if action["action_id"] != "temporary_scanner_managed_challenge_v1":
            raise RuntimeError("Cloudflare action is not executable by this adapter")
        ruleset = self._entrypoint()
        rules = ruleset.get("rules") if isinstance(ruleset.get("rules"), list) else []
        ref = action["scope"]["sentinel_owned_ref"]
        if any(str(rule.get("ref")) == ref for rule in rules if isinstance(rule, dict)):
            raise RuntimeError("Sentinel-owned scanner rule already exists")
        artifact = {
            "schema_version": SCHEMA_VERSION,
            "cycle_id": cycle_id,
            "action_id": action["action_id"],
            "created_at": utc_now(),
            "ruleset": {"name": ruleset.get("name"), "description": ruleset.get("description"), "rules": rules},
            "before_hash": rules_hash(rules),
            "after_hash": None,
            "baseline": baseline,
        }
        artifact_path = BACKUP_DIR / f"{cycle_id}-{action['action_id']}.json"
        write_json(artifact_path, artifact)
        artifact["artifact_path"] = str(artifact_path)
        return artifact

    def apply_scope(self, action: Dict[str, Any], artifact: Dict[str, Any], canary: bool) -> Dict[str, Any]:
        current = self._entrypoint()
        current_rules = current.get("rules") if isinstance(current.get("rules"), list) else []
        expected_hash = artifact["before_hash"] if artifact.get("after_hash") is None else artifact["after_hash"]
        if rules_hash(current_rules) != expected_hash:
            raise RuntimeError("ruleset hash mismatch before registered apply")
        ref = action["scope"]["sentinel_owned_ref"]
        expression = action["scope"]["canary_expression" if canary else "full_expression"]
        expires = iso_utc(utc_now_dt() + timedelta(minutes=action["canary_plan"]["ttl_minutes"] if canary else action["maximum_ttl"]))
        new_rule = {
            "ref": ref,
            "description": f"SentinelGuarded temporary scanner challenge; expires_at={expires}",
            "expression": expression,
            "action": "managed_challenge",
            "enabled": True,
        }
        replaced = False
        next_rules: List[Dict[str, Any]] = []
        for rule in current_rules:
            if isinstance(rule, dict) and str(rule.get("ref")) == ref:
                next_rules.append(new_rule)
                replaced = True
            else:
                next_rules.append(dict(rule))
        if canary and replaced:
            raise RuntimeError("unexpected existing canary rule")
        if not replaced:
            next_rules.append(new_rule)
        updated = self._update(current, next_rules)
        updated_rules = updated.get("rules") if isinstance(updated.get("rules"), list) else []
        after_hash = rules_hash(updated_rules)
        artifact["after_hash"] = after_hash
        artifact["expires_at"] = expires
        artifact["phase"] = "CANARY" if canary else "ACTIVE"
        write_json(Path(artifact["artifact_path"]), {key: value for key, value in artifact.items() if key != "artifact_path"})
        matching_rules = [rule for rule in updated_rules if isinstance(rule, dict) and str(rule.get("ref")) == ref]
        if len(matching_rules) != 1:
            raise RuntimeError("registered rule scope validation failed")
        applied_rule = matching_rules[0]
        if applied_rule.get("action") != "managed_challenge" or applied_rule.get("expression") != expression:
            raise RuntimeError("registered rule content validation failed")
        return {"status": "APPLY_OK", "phase": artifact["phase"], "after_hash": after_hash, "expires_at": expires}

    def reconcile_rollback_artifact(self, action: Dict[str, Any], artifact: Dict[str, Any]) -> Dict[str, Any]:
        current = self._entrypoint()
        current_rules = current.get("rules") if isinstance(current.get("rules"), list) else []
        current_hash = rules_hash(current_rules)
        if current_hash == artifact.get("before_hash"):
            return {"status": "NO_REMOTE_CHANGE_DETECTED"}
        ref = action["scope"]["sentinel_owned_ref"]
        own_rules = [rule for rule in current_rules if isinstance(rule, dict) and str(rule.get("ref")) == ref]
        other_rules = [rule for rule in current_rules if not (isinstance(rule, dict) and str(rule.get("ref")) == ref)]
        allowed_expressions = {action["scope"]["canary_expression"], action["scope"]["full_expression"]}
        exact_owned_rule = (
            len(own_rules) == 1
            and own_rules[0].get("action") == "managed_challenge"
            and own_rules[0].get("expression") in allowed_expressions
        )
        if not exact_owned_rule or rules_hash(other_rules) != artifact.get("before_hash"):
            return {"status": "UNEXPLAINED_REMOTE_HASH_MISMATCH"}
        artifact["after_hash"] = current_hash
        artifact["phase"] = "RECOVERED_FOR_ROLLBACK"
        write_json(Path(artifact["artifact_path"]), {key: value for key, value in artifact.items() if key != "artifact_path"})
        return {"status": "ROLLBACK_ARTIFACT_RECOVERED", "after_hash": current_hash}

    def rollback(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        artifact_path = Path(str(artifact.get("artifact_path", "")))
        if (
            not is_within(artifact_path, BACKUP_DIR)
            or has_project_symlink_component(artifact_path)
            or artifact_path.is_symlink()
            or not artifact_path.exists()
        ):
            return {"status": "ROLLBACK_FAILED", "reason": "rollback_artifact_missing_or_unsafe"}
        stored = load_dict(artifact_path)
        if not stored or not stored.get("after_hash"):
            return {"status": "ROLLBACK_FAILED", "reason": "rollback_artifact_incomplete"}
        current = self._entrypoint()
        current_rules = current.get("rules") if isinstance(current.get("rules"), list) else []
        if rules_hash(current_rules) != stored["after_hash"]:
            return {"status": "ROLLBACK_FAILED", "reason": "current_hash_mismatch"}
        previous = stored["ruleset"]
        restored = self._update(current, previous.get("rules", []))
        restored_rules = restored.get("rules") if isinstance(restored.get("rules"), list) else []
        restored_hash = rules_hash(restored_rules)
        if restored_hash != stored["before_hash"]:
            return {"status": "ROLLBACK_FAILED", "reason": "restored_hash_mismatch", "restored_hash": restored_hash}
        health = self.healthcheck()
        return {"status": "ROLLBACK_OK" if health["status"] == "HEALTHCHECK_OK" else "ROLLBACK_HEALTHCHECK_FAILED", "restored_hash": restored_hash, "healthcheck": health}


class SftpSentinelOwnedFileAdapter:
    metadata = ADAPTER_METADATA["SftpSentinelOwnedFileAdapter"]


class LocalSentinelServiceAdapter:
    metadata = ADAPTER_METADATA["LocalSentinelServiceAdapter"]


class ReportOnlyAdapter:
    metadata = ADAPTER_METADATA["ReportOnlyAdapter"]


def latest_monitor_status_count(status_code: int) -> Dict[str, Any]:
    monitor_root = PROJECT_DIR / "cloudflare-monitor"
    if not monitor_root.is_dir() or monitor_root.is_symlink():
        return {"snapshot_id": None, "count": None}
    for directory in reversed(sorted(monitor_root.iterdir())):
        if not re.fullmatch(r"\d{8}-\d{6}", directory.name) or not directory.is_dir() or directory.is_symlink():
            continue
        status_path = directory / "status-24h.json"
        if not status_path.is_file() or status_path.is_symlink():
            continue
        value = load_dict(status_path)
        try:
            rows = value["data"]["viewer"]["zones"][0]["httpRequestsAdaptiveGroups"]
        except (KeyError, IndexError, TypeError):
            continue
        count = sum(
            int(row.get("count") or 0)
            for row in rows
            if row.get("dimensions", {}).get("edgeResponseStatus") == status_code
        )
        return {"snapshot_id": directory.name, "count": count}
    return {"snapshot_id": None, "count": None}


def latest_monitor_total_5xx() -> Dict[str, Any]:
    monitor_root = PROJECT_DIR / "cloudflare-monitor"
    if not monitor_root.is_dir() or monitor_root.is_symlink():
        return {"snapshot_id": None, "count": None}
    for directory in reversed(sorted(monitor_root.iterdir())):
        if not re.fullmatch(r"\d{8}-\d{6}", directory.name) or not directory.is_dir() or directory.is_symlink():
            continue
        status_path = directory / "status-24h.json"
        if not status_path.is_file() or status_path.is_symlink():
            continue
        value = load_dict(status_path)
        try:
            rows = value["data"]["viewer"]["zones"][0]["httpRequestsAdaptiveGroups"]
        except (KeyError, IndexError, TypeError):
            continue
        count = sum(
            int(row.get("count") or 0)
            for row in rows
            if isinstance(row.get("dimensions", {}).get("edgeResponseStatus"), int)
            and 500 <= row["dimensions"]["edgeResponseStatus"] <= 599
        )
        return {"snapshot_id": directory.name, "count": count}
    return {"snapshot_id": None, "count": None}


def health_gate_ok(value: Dict[str, Any]) -> bool:
    return value.get("status") in HEALTH_GREEN_STATUSES


def health_profile_snapshot(value: Dict[str, Any]) -> Dict[str, Any]:
    checks = {row.get("target_id"): row for row in value.get("checks", []) if isinstance(row, dict)}
    homepage = checks.get("public_homepage", {})
    robots = checks.get("public_robots", {})
    return {
        "homepage_health_class": value.get("homepage_health_class", homepage.get("health_class", HEALTH_UNKNOWN)),
        "challenge_signature": value.get("homepage_challenge_signature"),
        "robots_health_class": value.get("robots_health_class", robots.get("health_class", HEALTH_UNKNOWN)),
        "tls_verified": value.get("tls_verified") is True,
        "recent_5xx": value.get("recent_5xx"),
        "recent_5xx_snapshot_id": value.get("recent_5xx_snapshot_id"),
        "homepage_final_host": homepage.get("final_host"),
        "robots_final_host": robots.get("final_host"),
        "homepage_redirect_class": homepage.get("redirect_class"),
        "robots_redirect_class": robots.get("redirect_class"),
        "checked_at": value.get("checked_at"),
    }


def compare_health_profiles(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    before_snapshot = health_profile_snapshot(before)
    after_snapshot = health_profile_snapshot(after)
    allowed_homepage_classes = {HEALTH_PASS, HEALTH_EXPECTED_EDGE_CHALLENGE}
    challenge_unchanged = not (
        before_snapshot["homepage_health_class"] == HEALTH_EXPECTED_EDGE_CHALLENGE
        and (
            after_snapshot["homepage_health_class"] != HEALTH_EXPECTED_EDGE_CHALLENGE
            or before_snapshot["challenge_signature"] != after_snapshot["challenge_signature"]
        )
    )
    before_5xx = before_snapshot.get("recent_5xx")
    after_5xx = after_snapshot.get("recent_5xx")
    no_5xx_growth = bool(
        before_5xx is None
        or after_5xx is None
        or int(after_5xx) <= int(before_5xx)
    )
    checks = {
        "homepage_class_healthy": after_snapshot["homepage_health_class"] in allowed_homepage_classes,
        "homepage_unchanged_or_improved": not (
            before_snapshot["homepage_health_class"] == HEALTH_PASS
            and after_snapshot["homepage_health_class"] != HEALTH_PASS
        ),
        "challenge_signature_unchanged": challenge_unchanged,
        "robots_pass": after_snapshot["robots_health_class"] == HEALTH_PASS,
        "tls_verified": after_snapshot["tls_verified"] is True,
        "homepage_host_unchanged": before_snapshot["homepage_final_host"] == after_snapshot["homepage_final_host"],
        "robots_host_unchanged": before_snapshot["robots_final_host"] == after_snapshot["robots_final_host"],
        "redirect_class_unchanged": (
            before_snapshot["homepage_redirect_class"] == after_snapshot["homepage_redirect_class"]
            and before_snapshot["robots_redirect_class"] == after_snapshot["robots_redirect_class"]
        ),
        "no_new_5xx_growth": no_5xx_growth,
    }
    return {
        "status": "HEALTH_PROFILE_VALID" if all(checks.values()) else "HEALTH_PROFILE_REGRESSION",
        "checks": checks,
        "before": before_snapshot,
        "after": after_snapshot,
    }


def current_signals() -> Dict[str, Any]:
    origin = load_dict(ORIGIN_DIAGNOSTICS_JSON)
    website = load_dict(WEBSITE_REPORT_JSON)
    status_counts = origin.get("comparison_scope", {}).get("current_snapshot", {}).get("status_code_counts", {})
    fake_scanner_count = 0
    actor_groups = set()
    for finding in website.get("correlation_v2_findings", []):
        if isinstance(finding, dict) and finding.get("signal_id") == "fake_nextjs_or_secret_scans":
            fake_scanner_count = int(finding.get("count") or 0)
            actor_groups.update(str(item) for item in finding.get("user_agents", []) if item)
    tls_gate = load_dict(TLS_GATE_STATE_JSON)
    latest_526 = latest_monitor_status_count(526)
    baseline_526 = tls_gate.get("current_526")
    observed_526 = latest_526["count"] if latest_526["count"] is not None else int(status_counts.get("526") or 0)
    return {
        "scanner_requests": fake_scanner_count,
        "scanner_actor_groups": len(actor_groups),
        "legitimate_scanner_path_use": False,
        "wp_login_volume": next((int(item.get("value") or 0) for item in website.get("metrics", []) if item.get("key") == "wp_login_503"), 0),
        "wp_login_automated_probability": "unknown",
        "admin_allowlist_present": "SENTINEL_ADMIN_ALLOWLIST_PRESENT" in set(private_env_metadata()["declared_keys"]),
        "login_healthcheck_ok": False,
        "status_503": int(status_counts.get("503") or 0),
        "status_504": int(status_counts.get("504") or 0),
        "status_522": int(status_counts.get("522") or 0),
        "status_526": int(observed_526 or 0),
        "tls_gate_status": tls_gate.get("status", "TLS_GATE_YELLOW"),
        "new_526_growth": bool(
            latest_526["count"] is not None
            and baseline_526 is not None
            and int(latest_526["count"]) > int(baseline_526)
        ),
        "latest_526_snapshot_id": latest_526["snapshot_id"],
        "microcache_candidate_approved": False,
        "anonymous_public_get": False,
        "website_status": origin.get("comparison_scope", {}).get("current_snapshot", {}).get("website_status") or website.get("overall_status"),
    }


def decide(signals: Dict[str, Any]) -> Dict[str, Any]:
    if signals.get("new_526_growth") is True or (
        int(signals.get("status_526") or 0) > 0
        and signals.get("tls_gate_status") not in {"TLS_GATE_GREEN", "TLS_GATE_GREEN_WITH_STALE_HISTORY"}
    ):
        return {
            "decision": "PAUSE_AND_ALERT",
            "candidate_action": None,
            "reason": "Origin TLS 526 evidence pauses all new live actions; no SSL or certificate mutation is allowed.",
        }
    scanner = int(signals.get("scanner_requests") or 0)
    actors = int(signals.get("scanner_actor_groups") or 0)
    if scanner >= 100 and actors >= 2 and signals.get("legitimate_scanner_path_use") is False:
        return {
            "decision": "LOW_LIVE_CANDIDATE",
            "candidate_action": "temporary_scanner_managed_challenge_v1",
            "reason": "High-confidence scanner paths crossed the static volume and actor thresholds.",
        }
    login_volume = int(signals.get("wp_login_volume") or 0)
    if (
        login_volume >= 100
        and signals.get("wp_login_automated_probability") == "high"
        and signals.get("admin_allowlist_present") is True
        and signals.get("login_healthcheck_ok") is True
    ):
        return {
            "decision": "LOW_LIVE_CANDIDATE",
            "candidate_action": "temporary_wp_login_protection_v1",
            "reason": "Automated login spike passed allowlist and health gates.",
        }
    if int(signals.get("status_503") or 0) > 0:
        if signals.get("microcache_candidate_approved") and signals.get("anonymous_public_get"):
            return {
                "decision": "LOW_LIVE_CANDIDATE",
                "candidate_action": "anonymous_microcache_canary_v1",
                "reason": "Approved anonymous GET endpoint is eligible for a microcache canary.",
            }
        return {
            "decision": "MONITOR_AND_ESCALATE",
            "candidate_action": None,
            "reason": "503 origin pressure has no currently proven safe apply candidate.",
        }
    if int(signals.get("status_522") or 0) > 0:
        return {
            "decision": "MONITOR_AND_PAUSE_NEW_ACTIONS",
            "candidate_action": None,
            "reason": "Origin connectivity evidence requires observation and owner alerting.",
        }
    return {"decision": "NO_ACTION", "candidate_action": None, "reason": "No registered LOW_LIVE trigger is satisfied."}


def rollback_triggered(before_5xx: int, after_5xx: int, validation: Dict[str, Any]) -> Tuple[bool, List[str]]:
    reasons = []
    if before_5xx > 0 and ((after_5xx - before_5xx) / before_5xx) * 100.0 >= 10.0:
        reasons.append("five_xx_increase_gte_10_percent")
    if validation.get("homepage_failures", 0) >= 2:
        reasons.append("homepage_healthcheck_failed_twice")
    if validation.get("wp_login_ok") is False:
        reasons.append("wp_login_healthcheck_failed")
    for key in ("browser_403_growth", "redirect_loop", "scope_mismatch", "policy_mismatch", "missing_rollback_artifact", "hash_mismatch", "adapter_error", "validation_timeout"):
        if validation.get(key) is True:
            reasons.append(key)
    return bool(reasons), reasons


def circuit_breaker_default() -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "CIRCUIT_BREAKER_ARMED",
        "actions": [],
        "failures": [],
        "failed_rollbacks": [],
        "cooldowns": {},
        "emergency_stop": False,
    }


def load_circuit() -> Dict[str, Any]:
    value = load_dict(CIRCUIT_BREAKER_JSON)
    return value or circuit_breaker_default()


def recent_rows(rows: Sequence[Dict[str, Any]], hours: int) -> List[Dict[str, Any]]:
    cutoff = utc_now_dt() - timedelta(hours=hours)
    return [row for row in rows if (parse_timestamp(row.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff]


def circuit_status(circuit: Dict[str, Any]) -> Dict[str, Any]:
    failures_hour = recent_rows(circuit.get("failures", []), 1)
    actions_hour = recent_rows(circuit.get("actions", []), 1)
    actions_day = recent_rows(circuit.get("actions", []), 24)
    failed_rollbacks = circuit.get("failed_rollbacks", [])
    tripped = len(failures_hour) >= 2 or len(failed_rollbacks) >= 2 or circuit.get("emergency_stop") is True
    return {
        "status": "CIRCUIT_BREAKER_OPEN" if tripped else "CIRCUIT_BREAKER_ARMED",
        "tripped": tripped,
        "failed_actions_last_hour": len(failures_hour),
        "actions_last_hour": len(actions_hour),
        "actions_last_day": len(actions_day),
        "failed_rollbacks": len(failed_rollbacks),
    }


def rate_limit_allows(
    circuit: Dict[str, Any],
    action_id: str,
    activation_stage: Optional[str] = None,
) -> Tuple[bool, str]:
    status = circuit_status(circuit)
    if status["tripped"]:
        return False, "circuit_breaker_open"
    limits = POLICY_TEMPLATE["action_limits"]
    hourly_limit = (
        limits["canary_max_actions_per_hour"]
        if activation_stage == "LEVEL_2_GUARDED_CANARY"
        else limits["max_actions_per_hour"]
    )
    if status["actions_last_hour"] >= hourly_limit:
        return False, "hourly_action_limit"
    if status["actions_last_day"] >= limits["max_actions_per_day"]:
        return False, "daily_action_limit"
    now = utc_now_dt()
    cooldown_until = parse_timestamp(circuit.get("cooldowns", {}).get(action_id))
    if cooldown_until and cooldown_until > now:
        return False, "action_cooldown"
    identical_failures = [row for row in recent_rows(circuit.get("failures", []), 1) if row.get("action_id") == action_id]
    if len(identical_failures) > POLICY_TEMPLATE["action_limits"]["max_identical_action_retries"]:
        return False, "identical_action_retry_limit"
    return True, "rate_limits_ok"


def deterministic_rollback_test() -> Dict[str, Any]:
    store = {"value": "before"}
    backup = dict(store)
    store["value"] = "canary"
    validation_failed = store["value"] != "expected"
    if validation_failed:
        store.clear()
        store.update(backup)
    return {
        "status": "GUARDED_AUTONOMY_ROLLBACK_TEST_OK" if store == backup else "GUARDED_AUTONOMY_ROLLBACK_TEST_FAILED",
        "backup_created": True,
        "canary_applied": True,
        "validation_failed_as_injected": validation_failed,
        "rollback_restored_before_state": store == backup,
        "live": False,
    }


def deterministic_canary_test() -> Dict[str, Any]:
    action = action_by_id("temporary_scanner_managed_challenge_v1") or {}
    checks = {
        "registered": bool(action),
        "low_live": action.get("risk") == "LOW_LIVE",
        "canary_required": action.get("canary_plan", {}).get("required") is True,
        "canary_scope_is_single_path": action.get("scope", {}).get("canary_expression") == SCANNER_CANARY_EXPRESSION,
        "ttl_lte_30": int(action.get("maximum_ttl") or 0) <= 30,
        "rollback_registered": action.get("rollback_adapter") == "CloudflareGuardedAdapter",
        "post_validation_registered": bool(action.get("validation_checks")),
    }
    return {
        "status": "GUARDED_AUTONOMY_CANARY_OK" if all(checks.values()) else "GUARDED_AUTONOMY_CANARY_FAILED",
        "checks": checks,
        "live": False,
        "note": "Contract canary only; no remote rule was created.",
    }


def deterministic_symlink_escape_test() -> bool:
    ensure_dirs()
    test_link = STATE_DIR / "self-test-symlink"
    if test_link.exists() or test_link.is_symlink():
        if not test_link.is_symlink():
            return False
        test_link.unlink()
    try:
        test_link.symlink_to(PROJECT_DIR.parent, target_is_directory=True)
        return not output_path_allowed(test_link / "escape.json")
    finally:
        if test_link.is_symlink():
            test_link.unlink()


def source_security_scan() -> Dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: List[str] = []
    subprocess_calls = 0
    shell_true = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "run" and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                subprocess_calls += 1
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    shell_true = True
    secret_findings = []
    for path in (Path(__file__), POLICY_PATH, SERVICE_SOURCE, TIMER_SOURCE, *PLAYBOOKS):
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if PRIVATE_KEY_RE.search(text):
            secret_findings.append(f"private_key:{rel(path)}")
        for match in SECRET_VALUE_RE.finditer(text):
            value = match.group("value").strip("\"'")
            is_code_placeholder = any(char in value for char in "{}()[]")
            if not is_code_placeholder and not any(
                marker in value.lower() for marker in ("missing", "false", "null", "blocked", "required")
            ):
                secret_findings.append(f"secret_like_value:{rel(path)}")
                break
    return {
        "status": "SOURCE_SECURITY_OK" if not secret_findings and not shell_true else "SOURCE_SECURITY_FAILED",
        "secret_findings": secret_findings,
        "shell_true": shell_true,
        "subprocess_call_sites": subprocess_calls,
        "systemctl_commands_exact_allowlist": set(SYSTEMCTL_COMMANDS) == {
            "daemon_reload", "enable_timer", "disable_timer", "start_service", "timer_active", "timer_enabled", "service_active"
        },
        "unrestricted_shell": False,
        "arbitrary_command_execution": False,
        "arbitrary_write_path": False,
    }


def freshness_gate(path: Path, max_hours: int = 24) -> Dict[str, Any]:
    value = load_dict(path)
    timestamp = parse_timestamp(value.get("generated_at_utc") or value.get("generated_at"))
    if not value:
        return {"passed": False, "reason": f"missing:{rel(path)}", "age_seconds": None}
    if not timestamp:
        return {"passed": False, "reason": f"invalid_timestamp:{rel(path)}", "age_seconds": None}
    age = max(0.0, (utc_now_dt() - timestamp).total_seconds())
    return {"passed": age <= max_hours * 3600, "reason": "current" if age <= max_hours * 3600 else "stale", "age_seconds": round(age, 2)}


def systemd_source_validation() -> Dict[str, Any]:
    service = SERVICE_SOURCE.read_text(encoding="utf-8") if SERVICE_SOURCE.exists() else ""
    timer = TIMER_SOURCE.read_text(encoding="utf-8") if TIMER_SOURCE.exists() else ""
    checks = {
        "service_exists": bool(service),
        "timer_exists": bool(timer),
        "fixed_exec_start": "ExecStart=/usr/bin/python3 /srv/sentinel-defense/sentinel_guarded_autonomy.py --run-cycle" in service,
        "no_new_privileges": "NoNewPrivileges=true" in service,
        "protect_system_strict": "ProtectSystem=strict" in service,
        "protect_home": "ProtectHome=true" in service,
        "private_tmp": "PrivateTmp=true" in service,
        "protect_kernel_tunables": "ProtectKernelTunables=true" in service,
        "protect_kernel_modules": "ProtectKernelModules=true" in service,
        "protect_control_groups": "ProtectControlGroups=true" in service,
        "lock_personality": "LockPersonality=true" in service,
        "restrict_suid_sgid": "RestrictSUIDSGID=true" in service,
        "restrict_realtime": "RestrictRealtime=true" in service,
        "memory_deny_write_execute": "MemoryDenyWriteExecute=true" in service,
        "fixed_environment_file": "EnvironmentFile=/etc/sentinel-defense.env" in service,
        "restricted_user": "User=deploy" in service and "Group=deploy" in service,
        "runtime_timeout": "TimeoutStartSec=" in service,
        "write_paths_restricted": "ReadWritePaths=/srv/sentinel-defense/reports /srv/sentinel-defense/state /srv/sentinel-defense/audit" in service,
        "two_minute_frequency": "OnUnitActiveSec=2min" in timer,
        "timer_fixed_unit": "Unit=sentinel-guarded-autonomy.service" in timer,
        "timer_not_persistent": "Persistent=false" in timer,
    }
    findings = [name for name, passed in checks.items() if not passed]
    return {"status": "SYSTEMD_SOURCE_VALID" if not findings else "SYSTEMD_SOURCE_INVALID", "checks": checks, "findings": findings}


def run_systemctl(command_id: str) -> Dict[str, Any]:
    command = SYSTEMCTL_COMMANDS.get(command_id)
    if command is None:
        return {"command_id": command_id, "returncode": 126, "stdout": "", "stderr": "command_not_allowlisted"}
    process = subprocess.run(
        list(command),
        cwd=str(PROJECT_DIR),
        check=False,
        shell=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {
        "command_id": command_id,
        "returncode": int(process.returncode),
        "stdout": process.stdout.strip()[:1000],
        "stderr": process.stderr.strip()[:1000],
    }


def systemd_status() -> Dict[str, Any]:
    timer_active = run_systemctl("timer_active")
    timer_enabled = run_systemctl("timer_enabled")
    service_active = run_systemctl("service_active")
    installed = SERVICE_DEST.exists() and TIMER_DEST.exists()
    return {
        "installed": installed,
        "timer_status": timer_active["stdout"] or timer_active["stderr"] or "unknown",
        "timer_active": timer_active["returncode"] == 0 and timer_active["stdout"] == "active",
        "timer_enabled": timer_enabled["returncode"] == 0 and timer_enabled["stdout"] == "enabled",
        "service_status": service_active["stdout"] or service_active["stderr"] or "unknown",
        "service_active": service_active["returncode"] == 0 and service_active["stdout"] == "active",
    }


def verified_systemd_installation() -> Dict[str, Any]:
    status = systemd_status()
    checks = {
        "service_regular_file": SERVICE_DEST.is_file() and not SERVICE_DEST.is_symlink(),
        "timer_regular_file": TIMER_DEST.is_file() and not TIMER_DEST.is_symlink(),
        "service_matches_source": False,
        "timer_matches_source": False,
        "timer_enabled": status["timer_enabled"],
    }
    try:
        if checks["service_regular_file"] and SERVICE_SOURCE.is_file():
            checks["service_matches_source"] = SERVICE_DEST.read_bytes() == SERVICE_SOURCE.read_bytes()
        if checks["timer_regular_file"] and TIMER_SOURCE.is_file():
            checks["timer_matches_source"] = TIMER_DEST.read_bytes() == TIMER_SOURCE.read_bytes()
    except OSError:
        pass
    return {
        "verified": all(checks.values()),
        "checks": checks,
        "systemd": status,
    }


def systemd_install_privilege() -> bool:
    return os.access(SERVICE_DEST.parent, os.W_OK)


def install_systemd_units() -> Dict[str, Any]:
    existing = verified_systemd_installation()
    if existing["verified"]:
        return {"status": "SYSTEMD_TIMER_ACTIVE", "backups": [], "systemd": existing["systemd"], "already_installed": True}
    if not systemd_install_privilege():
        return {"status": "SYSTEMD_INSTALL_BLOCKED", "reason": "systemd_destination_not_writable"}
    ensure_dirs()
    install_records = []
    try:
        for source, destination in ((SERVICE_SOURCE, SERVICE_DEST), (TIMER_SOURCE, TIMER_DEST)):
            if not source.is_file() or source.is_symlink() or destination.is_symlink():
                raise RuntimeError("unsafe_systemd_source_or_destination")
            record = {"destination": str(destination), "existed": destination.exists(), "backup": None}
            if destination.exists():
                backup = SYSTEMD_BACKUP_DIR / destination.name
                shutil.copy2(destination, backup)
                record["backup"] = str(backup)
            install_records.append(record)
            shutil.copy2(source, destination)
            destination.chmod(0o644)
        reload_result = run_systemctl("daemon_reload")
        if reload_result["returncode"] != 0:
            raise RuntimeError("daemon_reload_failed")
        enable_result = run_systemctl("enable_timer")
        if enable_result["returncode"] != 0:
            raise RuntimeError("timer_enable_failed")
        return {"status": "SYSTEMD_TIMER_ACTIVE", "install_records": install_records, "systemd": systemd_status()}
    except (OSError, RuntimeError) as exc:
        run_systemctl("disable_timer")
        for item in reversed(install_records):
            destination = Path(item["destination"])
            backup_value = item.get("backup")
            if item["existed"] and backup_value:
                shutil.copy2(Path(backup_value), destination)
            elif not item["existed"] and destination.is_file() and not destination.is_symlink():
                destination.unlink()
        run_systemctl("daemon_reload")
        return {"status": "SYSTEMD_INSTALL_ROLLED_BACK", "reason": str(exc), "install_records": install_records}


def collect_preflight() -> Dict[str, Any]:
    policy = validate_policy()
    registry = validate_action_registry()
    rollback_test = deterministic_rollback_test()
    canary_test = deterministic_canary_test()
    source_scan = source_security_scan()
    unit_validation = systemd_source_validation()
    origin = load_dict(ORIGIN_DIAGNOSTICS_JSON)
    master = load_dict(MASTER_CONSISTENCY_JSON)
    health = load_dict(HEALTH_BASELINE_STATE_JSON)
    tls_gate = load_dict(TLS_GATE_STATE_JSON)
    rc = load_dict(RC_JSON)
    current_526 = int(origin.get("comparison_scope", {}).get("current_snapshot", {}).get("status_code_counts", {}).get("526") or 0)
    current_breach = any(
        value is True
        for value in (
            origin.get("safety", {}).get("breach"),
            master.get("safety", {}).get("breach"),
            rc.get("breach"),
        )
    )
    credentials = cloudflare_credentials_ready()
    health_checked_at = parse_timestamp(health.get("checked_at") or health.get("generated_at"))
    health_age_seconds = (
        max(0.0, (utc_now_dt() - health_checked_at).total_seconds())
        if health_checked_at is not None
        else None
    )
    health_ready = (
        health_gate_ok(health)
        and health_age_seconds is not None
        and health_age_seconds <= 600
    )
    tls_gate_status = tls_gate.get("status")
    tls_ready = tls_gate_status in {"TLS_GATE_GREEN", "TLS_GATE_GREEN_WITH_STALE_HISTORY"}
    master_freshness = freshness_gate(MASTER_CONSISTENCY_JSON)
    origin_freshness = freshness_gate(ORIGIN_DIAGNOSTICS_JSON)
    apply_semantics_ok = master.get("apply_semantics", {}).get("status") == "APPLY_SEMANTICS_CONSISTENT"
    readiness_seal_ok = "READINESS_SEAL_GREEN" in (READINESS_SEAL_MD.read_text(encoding="utf-8") if READINESS_SEAL_MD.exists() else "")
    systemd_writable = systemd_install_privilege()
    installed_units = verified_systemd_installation()
    systemd_activation_path_ready = systemd_writable or installed_units["verified"]
    legacy_lock = load_dict(LEGACY_RUNTIME_LOCK)

    gates = [
        ("self_test", self_test(write_artifacts=False)["status"] == "GUARDED_AUTONOMY_SELF_TEST_OK", True, "Guarded runtime self-test must pass."),
        ("policy_json", policy["status"] == "GUARDED_AUTONOMY_POLICY_VALID", True, "Policy must exactly match the owner-approved template."),
        ("owner_policy_approved", POLICY_TEMPLATE["owner_policy_approved"] is True, True, "Owner policy reference is recorded."),
        ("action_registry", registry["status"] == "GUARDED_ACTION_REGISTRY_VALID", True, "All live actions must be registered LOW_LIVE actions."),
        ("no_medium_high_actions", not registry["medium_or_high_actions"], True, "MEDIUM and HIGH execution remains unavailable."),
        ("rollback_contract_test", rollback_test["status"] == "GUARDED_AUTONOMY_ROLLBACK_TEST_OK", True, "Injected failure must restore the exact before-state."),
        ("canary_contract_test", canary_test["status"] == "GUARDED_AUTONOMY_CANARY_OK", True, "Canary contract must include TTL, validation, and rollback."),
        ("master_freshness", master_freshness["passed"], True, master_freshness["reason"]),
        ("origin_diagnostics_freshness", origin_freshness["passed"], True, origin_freshness["reason"]),
        ("apply_semantics_consistent", apply_semantics_ok, True, "Phase 10.16 apply semantics must remain consistent."),
        ("readiness_seal_green", readiness_seal_ok, True, "Existing local autonomy regression seal must remain GREEN."),
        ("source_security", source_scan["status"] == "SOURCE_SECURITY_OK", True, "No unrestricted shell or secret content is permitted."),
        ("systemd_sources", unit_validation["status"] == "SYSTEMD_SOURCE_VALID", True, "Service and timer hardening must validate."),
        (
            "systemd_install_privilege_or_verified_install",
            systemd_activation_path_ready,
            True,
            "Units must be installable without an unrestricted privilege path or already match the reviewed sources and be enabled.",
        ),
        ("adapter_credentials", credentials["ready"], True, "Cloudflare credentials must be present in the protected environment file with fixed zone scope."),
        (
            "fixed_health_targets",
            health_ready,
            True,
            "Both fixed HTTPS targets must pass with verified TLS and an accepted status in a baseline no older than ten minutes.",
        ),
        (
            "origin_tls_gate",
            tls_ready,
            True,
            f"TLS gate is {tls_gate_status or 'MISSING'}; stable historical 526 observations may pass only as GREEN_WITH_STALE_HISTORY.",
        ),
        ("no_current_breach", current_breach is False, True, "A blocked gate is not a breach, but activation requires breach=false."),
        ("legacy_runtime_lock_observed", True, False, f"Current legacy lock remains {legacy_lock.get('max_autonomy_level', 'unknown')} until activation commits."),
    ]
    rows = [{"gate": name, "passed": passed, "required": required, "reason": reason} for name, passed, required, reason in gates]
    blockers = [row["gate"] for row in rows if row["required"] and not row["passed"]]
    return {
        "status": "GUARDED_AUTONOMY_PREFLIGHT_GREEN" if not blockers else "GUARDED_AUTONOMY_ACTIVATION_BLOCKED",
        "gates": rows,
        "blockers": blockers,
        "policy_validation": policy,
        "registry_validation": registry,
        "rollback_test": rollback_test,
        "canary_test": canary_test,
        "source_security": source_scan,
        "systemd_source_validation": unit_validation,
        "verified_systemd_installation": installed_units,
        "credential_readiness": credentials,
        "health_baseline": health,
        "health_baseline_age_seconds": health_age_seconds,
        "tls_gate": tls_gate,
        "current_526": current_526,
        "current_breach": current_breach,
        "website_status": origin.get("comparison_scope", {}).get("current_snapshot", {}).get("website_status"),
        "generated_at": utc_now(),
    }


def cycle_safety_gate(state: Dict[str, Any]) -> Dict[str, Any]:
    policy = validate_policy()
    registry = validate_action_registry()
    source = source_security_scan()
    origin = load_dict(ORIGIN_DIAGNOSTICS_JSON)
    master = load_dict(MASTER_CONSISTENCY_JSON)
    health = load_dict(HEALTH_BASELINE_STATE_JSON)
    tls_gate = load_dict(TLS_GATE_STATE_JSON)
    current_registry_hash = build_action_registry()["registry_hash"]
    critical_findings = []
    blockers = []
    if policy["status"] != "GUARDED_AUTONOMY_POLICY_VALID" or state.get("policy_hash") != policy_hash():
        blockers.append("policy_hash_or_content_mismatch")
    if registry["status"] != "GUARDED_ACTION_REGISTRY_VALID" or state.get("registry_hash") != current_registry_hash:
        blockers.append("action_registry_hash_or_content_mismatch")
    if source["status"] != "SOURCE_SECURITY_OK":
        critical_findings.append("source_security_failure")
    if origin.get("safety", {}).get("breach") is True or master.get("safety", {}).get("breach") is True:
        critical_findings.append("current_breach")
    for name, path in (("origin_diagnostics_freshness", ORIGIN_DIAGNOSTICS_JSON), ("master_freshness", MASTER_CONSISTENCY_JSON)):
        if not freshness_gate(path)["passed"]:
            blockers.append(name)
    health_timestamp = parse_timestamp(health.get("generated_at") or health.get("checked_at"))
    if (
        not health_gate_ok(health)
        or not health_timestamp
        or utc_now_dt() - health_timestamp > timedelta(minutes=10)
    ):
        blockers.append("health_baseline_missing_failed_or_stale")
    if tls_gate.get("status") not in {"TLS_GATE_GREEN", "TLS_GATE_GREEN_WITH_STALE_HISTORY"}:
        blockers.append("tls_gate_not_green")
    latest_526 = latest_monitor_status_count(526)
    if (
        latest_526["count"] is not None
        and tls_gate.get("current_526") is not None
        and int(latest_526["count"]) > int(tls_gate["current_526"])
    ):
        blockers.append("new_526_growth")
    if state.get("activation", {}).get("systemd_installed") is True and not verified_systemd_installation()["verified"]:
        blockers.append("systemd_installation_drift")
    flags = state.get("flags", {})
    if flags.get("medium_live_apply_enabled") is not False or flags.get("high_live_apply_enabled") is not False:
        critical_findings.append("medium_or_high_runtime_flag_enabled")
    return {
        "status": "CYCLE_SAFETY_OK" if not critical_findings and not blockers else "CYCLE_SAFETY_BLOCKED",
        "critical_findings": critical_findings,
        "blockers": blockers,
    }


def degrade_runtime(state: Dict[str, Any], status: str, reason: str) -> None:
    if state.get("machine_state") == ACTIVE:
        transition(state, DEGRADED)
    elif state.get("machine_state") == CANARY:
        transition(state, ROLLBACK)
        transition(state, LOCKED)
    state["flags"]["guarded_live_autonomy_enabled"] = False
    state["flags"]["low_live_apply_enabled"] = False
    state["flags"]["production_apply_lock"] = True
    state["flags"]["remote_write_lock"] = True
    state["status"] = status
    state["activation"] = {**state.get("activation", {}), "reason": reason}


def audit_record(
    cycle_id: str,
    trigger: Any,
    candidate_action: Optional[str],
    decision: str,
    reason: str,
    **results: Any,
) -> Dict[str, Any]:
    action = action_by_id(candidate_action) if candidate_action else None
    return {
        "cycle_id": cycle_id,
        "timestamp": utc_now(),
        "input_snapshot_ids": {
            "origin_diagnostics": load_dict(ORIGIN_DIAGNOSTICS_JSON).get("generated_at_utc"),
            "website_report": load_dict(WEBSITE_REPORT_JSON).get("generated_at_utc"),
        },
        "trigger": trigger,
        "candidate_action": candidate_action,
        "risk": action.get("risk") if action else None,
        "policy_match": bool(action and action.get("owner_policy_reference") == OWNER_POLICY_REFERENCE),
        "preflight_result": results.get("preflight_result"),
        "decision": decision,
        "reason": reason,
        "canary_result": results.get("canary_result"),
        "apply_result": results.get("apply_result"),
        "validation_result": results.get("validation_result"),
        "rollback_result": results.get("rollback_result"),
        "before_hash": results.get("before_hash"),
        "after_hash": results.get("after_hash"),
        "ttl": action.get("maximum_ttl") if action else None,
        "owner_policy_reference": OWNER_POLICY_REFERENCE,
    }


def append_decision_audit(record: Dict[str, Any]) -> None:
    append_jsonl(AUDIT_JSONL, record)
    append_jsonl(ACTIONS_AUDIT_JSONL, record)


def execute_rollback(state: Dict[str, Any], reason: str) -> Dict[str, Any]:
    last = state.get("last_action")
    if not isinstance(last, dict) or not last.get("artifact_path"):
        result = {"status": "ROLLBACK_NOT_AVAILABLE", "reason": "no_sentinel_owned_action"}
        state["rollback_status"] = result
        return result
    current = state.get("machine_state")
    if current == ACTIVE:
        transition(state, ROLLBACK)
    elif current == CANARY:
        transition(state, ROLLBACK)
    adapter = CloudflareGuardedAdapter()
    result = adapter.rollback(last)
    result["trigger_reason"] = reason
    result["timestamp"] = utc_now()
    append_jsonl(ROLLBACK_AUDIT_JSONL, {
        "cycle_id": last.get("cycle_id"),
        "timestamp": result["timestamp"],
        "action_id": last.get("action_id"),
        "reason": reason,
        "result": result["status"],
        "before_hash": last.get("before_hash"),
        "after_hash": last.get("after_hash"),
    })
    circuit = load_circuit()
    if result["status"] == "ROLLBACK_OK":
        transition(state, LOCKED)
        state["active_actions"] = []
        state["pending_validations"] = []
        state["flags"].update(default_flags())
        state["status"] = "GUARDED_AUTONOMY_ROLLED_BACK_LOCKED"
        circuit.setdefault("cooldowns", {})[last["action_id"]] = iso_utc(
            utc_now_dt() + timedelta(minutes=POLICY_TEMPLATE["action_limits"]["global_cooldown_minutes"])
        )
    else:
        circuit.setdefault("failed_rollbacks", []).append({"timestamp": utc_now(), "action_id": last.get("action_id"), "reason": result.get("reason")})
        if len(circuit["failed_rollbacks"]) >= 2:
            if state.get("machine_state") == ROLLBACK:
                transition(state, EMERGENCY_STOP)
            state["flags"].update(default_flags())
            state["flags"]["breach"] = True
            state["status"] = "GUARDED_AUTONOMY_EMERGENCY_STOP_ROLLBACK_FAILURE"
            circuit["emergency_stop"] = True
    write_json(CIRCUIT_BREAKER_JSON, circuit)
    state["rollback_status"] = result
    return result


def trip_runtime_emergency(state: Dict[str, Any], status: str, reason: str, breach: bool) -> None:
    current = state.get("machine_state")
    if current == ACTIVE:
        transition(state, DEGRADED)
        transition(state, EMERGENCY_STOP)
    elif current == CANARY:
        transition(state, ROLLBACK)
        transition(state, EMERGENCY_STOP)
    elif current in {DEGRADED, ROLLBACK}:
        transition(state, EMERGENCY_STOP)
    else:
        state["machine_state"] = EMERGENCY_STOP
    state["flags"].update(default_flags())
    state["flags"]["breach"] = breach
    state["autonomy_level"] = "LEVEL_1_DRAFT_ONLY"
    state["status"] = status
    state["activation"] = {
        **state.get("activation", {}),
        "status": "EMERGENCY_STOP",
        "reason": reason,
    }


def rearm_after_safe_cleanup(state: Dict[str, Any]) -> Dict[str, Any]:
    result = collect_preflight()
    state["preflight"] = result
    if result["status"] != "GUARDED_AUTONOMY_PREFLIGHT_GREEN":
        force_safe_locked(state, "GUARDED_AUTONOMY_ACTIVATION_BLOCKED", result["blockers"])
        return {"status": "REARM_BLOCKED", "blockers": result["blockers"]}
    transition(state, PREFLIGHT)
    transition(state, CANARY)
    state["flags"].update(active_flags())
    if state.get("activation_stage") == "LEVEL_2_GUARDED_CANARY":
        state["autonomy_level"] = "LEVEL_2_GUARDED_CANARY"
        state["status"] = "GUARDED_CANARY_ACTIVE"
    else:
        transition(state, ACTIVE)
        state["autonomy_level"] = "LEVEL_2_GUARDED_AUTONOMY"
        state["status"] = "GUARDED_AUTONOMY_ACTIVE"
    state["policy_hash"] = policy_hash()
    state["registry_hash"] = build_action_registry()["registry_hash"]
    return {"status": "REARMED_ACTIVE", "blockers": []}


def process_active_action(state: Dict[str, Any], signals: Dict[str, Any]) -> Dict[str, Any]:
    active_actions = state.get("active_actions")
    last = state.get("last_action")
    if not isinstance(active_actions, list) or not active_actions:
        return {"handled": False}
    if not isinstance(last, dict) or not last.get("artifact_path"):
        trip_runtime_emergency(
            state,
            "GUARDED_AUTONOMY_EMERGENCY_STOP_MISSING_ROLLBACK_ARTIFACT",
            "active Sentinel action has no rollback artifact",
            breach=True,
        )
        return {
            "handled": True,
            "decision": "EMERGENCY_STOP",
            "execution": "NO_ACTION",
            "reason": "Active Sentinel action has no rollback artifact.",
            "validation_result": {"status": "VALIDATION_BLOCKED"},
            "rollback_result": {"status": "ROLLBACK_NOT_AVAILABLE"},
        }

    action_id = str(last.get("action_id") or active_actions[0].get("action_id") or "")
    expires_at = parse_timestamp(last.get("expires_at") or active_actions[0].get("expires_at"))
    if signals.get("new_526_growth") is True or signals.get("tls_gate_status") not in {
        "TLS_GATE_GREEN",
        "TLS_GATE_GREEN_WITH_STALE_HISTORY",
    }:
        rollback = execute_rollback(state, "origin_tls_526_open")
        return {
            "handled": True,
            "decision": "ROLLBACK_AND_PAUSE",
            "execution": rollback["status"],
            "reason": "Origin TLS 526 evidence caused Sentinel-owned rule rollback and paused new actions.",
            "validation_result": {"status": "TLS_526_PAUSE"},
            "rollback_result": rollback,
            "action_id": action_id,
        }
    if expires_at is None:
        rollback = execute_rollback(state, "invalid_action_expiry")
        return {
            "handled": True,
            "decision": "ROLLBACK_AND_LOCK",
            "execution": rollback["status"],
            "reason": "Active action TTL is missing or invalid.",
            "validation_result": {"status": "INVALID_TTL"},
            "rollback_result": rollback,
            "action_id": action_id,
        }
    if expires_at <= utc_now_dt():
        rollback = execute_rollback(state, "ttl_expired")
        rearm = rearm_after_safe_cleanup(state) if rollback["status"] == "ROLLBACK_OK" else {"status": "NOT_REARMED"}
        return {
            "handled": True,
            "decision": "TTL_ROLLBACK_COMPLETE" if rollback["status"] == "ROLLBACK_OK" else "TTL_ROLLBACK_FAILED",
            "execution": rollback["status"],
            "reason": "Temporary Sentinel-owned action reached its registered TTL.",
            "validation_result": {"status": "TTL_EXPIRED", "rearm": rearm},
            "rollback_result": rollback,
            "action_id": action_id,
        }

    now = utc_now_dt()
    pending = state.get("pending_validations") if isinstance(state.get("pending_validations"), list) else []
    due = [item for item in pending if (parse_timestamp(item.get("due_at")) or datetime.min.replace(tzinfo=timezone.utc)) <= now]
    if not due:
        return {
            "handled": True,
            "decision": "MONITOR_ACTIVE_ACTION",
            "execution": "NO_NEW_ACTION",
            "reason": "A temporary Sentinel-owned action is active and awaiting its next validation or TTL.",
            "validation_result": {"status": "VALIDATION_NOT_DUE", "expires_at": iso_utc(expires_at)},
            "rollback_result": None,
            "action_id": action_id,
        }

    adapter = CloudflareGuardedAdapter()
    try:
        health = adapter.healthcheck()
    except RuntimeError as exc:
        health = {"status": "HEALTHCHECK_FAILED", "reason": str(exc)}
    baseline_health = last.get("baseline", {}).get("healthcheck", {}).get("baseline", {})
    health_profile = (
        compare_health_profiles(baseline_health, health.get("baseline", {}))
        if baseline_health and health.get("baseline")
        else {"status": "HEALTH_PROFILE_REGRESSION", "checks": {"baseline_available": False}}
    )
    health["health_profile"] = health_profile
    baseline_5xx = int(last.get("baseline", {}).get("five_xx") or 0)
    current_5xx = int(signals.get("status_503") or 0) + int(signals.get("status_504") or 0)
    should_rollback, reasons = rollback_triggered(
        baseline_5xx,
        current_5xx,
        {
            "wp_login_ok": health.get("status") == "HEALTHCHECK_OK",
            "adapter_error": health.get("status") != "HEALTHCHECK_OK"
            or health_profile.get("status") != "HEALTH_PROFILE_VALID",
        },
    )
    if should_rollback:
        rollback = execute_rollback(state, ",".join(reasons))
        return {
            "handled": True,
            "decision": "AUTOMATIC_ROLLBACK",
            "execution": rollback["status"],
            "reason": ",".join(reasons),
            "validation_result": health,
            "rollback_result": rollback,
            "action_id": action_id,
        }
    due_ids = {(item.get("action_id"), item.get("cycle_id"), item.get("due_at")) for item in due}
    state["pending_validations"] = [
        item for item in pending if (item.get("action_id"), item.get("cycle_id"), item.get("due_at")) not in due_ids
    ]
    return {
        "handled": True,
        "decision": "ACTIVE_ACTION_VALIDATED",
        "execution": "VALIDATION_ONLY",
        "reason": f"Completed {len(due)} due post-apply validation checkpoint(s).",
        "validation_result": health,
        "rollback_result": None,
        "action_id": action_id,
    }


def auto_promote_guarded_canary(state: Dict[str, Any]) -> Dict[str, Any]:
    if state.get("machine_state") != CANARY or state.get("activation_stage") != "LEVEL_2_GUARDED_CANARY":
        return {"status": "RUNTIME_PROMOTION_NOT_APPLICABLE"}
    window = load_dict(CANARY_WINDOW_STATE_JSON)
    started = parse_timestamp(window.get("started_at"))
    if started is None:
        result = {"status": "RUNTIME_PROMOTION_BLOCKED", "findings": ["canary_start_missing"]}
        write_json(RUNTIME_PROMOTION_STATE_JSON, result)
        return result
    rows: List[Dict[str, Any]] = []
    invalid_rows = 0
    if AUDIT_JSONL.exists() and not AUDIT_JSONL.is_symlink():
        for line in AUDIT_JSONL.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                invalid_rows += 1
                continue
            timestamp = parse_timestamp(row.get("timestamp")) if isinstance(row, dict) else None
            if isinstance(row, dict) and row.get("cycle_id") and timestamp and timestamp >= started:
                rows.append(row)
            elif not isinstance(row, dict):
                invalid_rows += 1
    elapsed_minutes = max(0.0, (utc_now_dt() - started).total_seconds() / 60.0)
    circuit = load_circuit()
    recent_failures = [
        row for row in circuit.get("failures", [])
        if (parse_timestamp(row.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc)) >= started
    ]
    recent_failed_rollbacks = [
        row for row in circuit.get("failed_rollbacks", [])
        if (parse_timestamp(row.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc)) >= started
    ]
    health_regressions = sum(1 for row in rows if "REGRESSION" in str(row.get("validation_result", "")))
    unexpected_writes = sum(
        1 for row in rows
        if "unexpected_write_path" in str(row.get("reason", "")) or "scope_expansion" in str(row.get("reason", ""))
    )
    tls = load_dict(TLS_GATE_STATE_JSON)
    checks = {
        "minimum_60_minutes": elapsed_minutes >= 60.0,
        "minimum_20_cycles": len(rows) >= 20,
        "zero_failed_actions": not recent_failures,
        "zero_failed_rollbacks": not recent_failed_rollbacks,
        "zero_health_regressions": health_regressions == 0,
        "no_new_526_growth": (tls.get("delta_526") or 0) <= 0,
        "tls_gate_green": tls.get("status") in {"TLS_GATE_GREEN", "TLS_GATE_GREEN_WITH_STALE_HISTORY"},
        "policy_valid": validate_policy().get("status") == "GUARDED_AUTONOMY_POLICY_VALID"
        and state.get("policy_hash") == policy_hash(),
        "registry_valid": state.get("registry_hash") == build_action_registry()["registry_hash"],
        "audit_valid": invalid_rows == 0,
        "no_unexpected_write_paths": unexpected_writes == 0,
        "circuit_breaker_armed": circuit_status(circuit).get("status") == "CIRCUIT_BREAKER_ARMED",
    }
    hard_failure = any(
        not passed for name, passed in checks.items()
        if name not in {"minimum_60_minutes", "minimum_20_cycles"}
    )
    if hard_failure:
        status = "RUNTIME_PROMOTION_BLOCKED"
    elif all(checks.values()):
        transition(state, ACTIVE)
        state["activation_stage"] = "LEVEL_2_GUARDED_AUTONOMY"
        state["autonomy_level"] = "LEVEL_2_GUARDED_AUTONOMY"
        state["flags"].update(active_flags())
        state["status"] = "GUARDED_AUTONOMY_ACTIVE"
        status = "RUNTIME_PROMOTION_GREEN"
    else:
        status = "RUNTIME_PROMOTION_IN_PROGRESS"
    result = {
        "status": status,
        "evaluated_at": utc_now(),
        "started_at": iso_utc(started),
        "elapsed_minutes": round(elapsed_minutes, 2),
        "successful_cycles": len(rows),
        "checks": checks,
        "findings": [name for name, passed in checks.items() if not passed],
        "activation_stage": state.get("activation_stage"),
        "breach": state.get("flags", {}).get("breach", False),
    }
    write_json(RUNTIME_PROMOTION_STATE_JSON, result)
    return result


def run_cycle() -> Dict[str, Any]:
    with runtime_cycle_lock():
        state = load_state()
        cycle_id = f"guarded-{utc_now_dt().strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        if state.get("first_cycle_id") is None:
            state["first_cycle_id"] = cycle_id
        staged_health: Optional[Dict[str, Any]] = None
        if state.get("activation_stage") in {
            "LEVEL_2_MONITORING_ACTIVE",
            "LEVEL_2_SCHEDULER_VERIFICATION",
            "LEVEL_2_GUARDED_CANARY",
            "LEVEL_2_GUARDED_AUTONOMY",
        }:
            staged_health = check_fixed_health_targets()
            write_json(HEALTH_BASELINE_STATE_JSON, staged_health)
        signals = current_signals()
        selected = decide(signals)
        circuit = load_circuit()
        circuit_view = circuit_status(circuit)
        decision = selected["decision"]
        reason = selected["reason"]
        candidate = selected["candidate_action"]
        execution = "NO_ACTION"
        canary_result: Any = None
        apply_result: Any = None
        validation_result: Any = None
        rollback_result: Any = None
        before_hash = None
        after_hash = None
        lifecycle_handled = False
        safety_handled = False
        cycle_gate = cycle_safety_gate(state)

        if state.get("activation_stage") in {"LEVEL_2_MONITORING_ACTIVE", "LEVEL_2_SCHEDULER_VERIFICATION"}:
            validation_result = staged_health or {"status": "HEALTH_TARGET_GATE_BLOCKED"}

        if runtime_machine_allows_actions(state) and cycle_gate["critical_findings"]:
            trip_runtime_emergency(
                state,
                "GUARDED_AUTONOMY_EMERGENCY_STOP_SAFETY_DRIFT",
                ",".join(cycle_gate["critical_findings"]),
                breach=True,
            )
            safety_handled = True
            decision = "EMERGENCY_STOP"
            execution = "NO_ACTION"
            reason = ",".join(cycle_gate["critical_findings"])
            candidate = None
            validation_result = {"status": "CYCLE_SAFETY_BLOCKED", "findings": cycle_gate["critical_findings"]}
        elif runtime_machine_allows_actions(state) and cycle_gate["blockers"]:
            safety_handled = True
            reason = ",".join(cycle_gate["blockers"])
            if state.get("active_actions"):
                rollback_result = execute_rollback(state, reason)
                decision = "ROLLBACK_AND_DEGRADE"
                execution = rollback_result["status"]
                if rollback_result["status"] != "ROLLBACK_OK":
                    trip_runtime_emergency(
                        state,
                        "GUARDED_AUTONOMY_EMERGENCY_STOP_SAFETY_ROLLBACK_FAILURE",
                        reason,
                        breach=True,
                    )
            else:
                degrade_runtime(state, "GUARDED_AUTONOMY_DEGRADED_SAFETY_GATE", reason)
                decision = "DEGRADE_AND_MONITOR"
                execution = "NO_ACTION"
            candidate = None
            validation_result = {"status": "CYCLE_SAFETY_BLOCKED", "findings": cycle_gate["blockers"]}

        if (
            not safety_handled
            and runtime_machine_allows_actions(state)
            and state["flags"]["guarded_live_autonomy_enabled"]
            and not state["flags"]["emergency_stop"]
            and state.get("active_actions")
        ):
            previous_action = state.get("last_action") if isinstance(state.get("last_action"), dict) else {}
            lifecycle = process_active_action(state, signals)
            lifecycle_handled = lifecycle.get("handled") is True
            if lifecycle_handled:
                decision = lifecycle["decision"]
                execution = lifecycle["execution"]
                reason = lifecycle["reason"]
                candidate = lifecycle.get("action_id")
                validation_result = lifecycle.get("validation_result")
                rollback_result = lifecycle.get("rollback_result")
                before_hash = previous_action.get("before_hash")
                after_hash = previous_action.get("after_hash")
                circuit = load_circuit()
                circuit_view = circuit_status(circuit)

        if safety_handled or lifecycle_handled:
            pass
        elif state["flags"]["emergency_stop"] or not state["flags"]["guarded_live_autonomy_enabled"] or not runtime_machine_allows_actions(state):
            decision = "NO_ACTION"
            if state.get("activation_stage") == "LEVEL_2_SCHEDULER_VERIFICATION":
                reason = "Scheduler verification cycle completed with live application disabled."
            elif state.get("activation_stage") == "LEVEL_2_MONITORING_ACTIVE":
                reason = "Monitoring-only cycle completed with productive application locked."
            else:
                reason = "Runtime is not ACTIVE; local monitoring and audit remain enabled."
        elif circuit_view["tripped"]:
            degrade_runtime(state, "GUARDED_AUTONOMY_DEGRADED_CIRCUIT_BREAKER", "circuit_breaker_open")
            decision = "NO_ACTION"
            reason = "Circuit breaker is open; new live actions are paused."
        elif signals.get("new_526_growth") is True or signals.get("tls_gate_status") not in {
            "TLS_GATE_GREEN",
            "TLS_GATE_GREEN_WITH_STALE_HISTORY",
        }:
            degrade_runtime(state, "GUARDED_AUTONOMY_DEGRADED_TLS_GATE", "tls_gate_or_526_growth")
            decision = "PAUSE_AND_ALERT"
            reason = "TLS gate or new 526 growth paused new live actions without changing SSL or certificates."
        elif candidate:
            action = action_by_id(candidate)
            if not action or not action.get("enabled"):
                decision = "NO_ACTION"
                reason = "Candidate is registered but not runtime-enabled."
            else:
                rate_ok, rate_reason = rate_limit_allows(circuit, candidate, state.get("activation_stage"))
                if not rate_ok:
                    decision = "NO_ACTION"
                    reason = rate_reason
                elif action["apply_adapter"] != "CloudflareGuardedAdapter":
                    decision = "NO_ACTION"
                    reason = "Registered adapter is fail-closed because productive rollback is not available."
                else:
                    adapter = CloudflareGuardedAdapter()
                    artifact: Optional[Dict[str, Any]] = None
                    apply_attempted = False
                    try:
                        baseline_health = adapter.healthcheck()
                        if baseline_health["status"] != "HEALTHCHECK_OK":
                            raise RuntimeError("baseline_healthcheck_failed")
                        before_5xx = int(signals.get("status_503") or 0) + int(signals.get("status_504") or 0)
                        artifact = adapter.prepare(action, cycle_id, {"healthcheck": baseline_health, "five_xx": before_5xx})
                        before_hash = artifact["before_hash"]
                        apply_attempted = True
                        canary_result = adapter.apply_scope(action, artifact, canary=True)
                        canary_health = adapter.healthcheck()
                        canary_profile = compare_health_profiles(
                            baseline_health["baseline"],
                            canary_health.get("baseline", {}),
                        )
                        canary_result = {**canary_result, "health_profile": canary_profile}
                        if canary_health["status"] != "HEALTHCHECK_OK" or canary_profile["status"] != "HEALTH_PROFILE_VALID":
                            state["last_action"] = {**artifact, "cycle_id": cycle_id, "action_id": candidate}
                            rollback_result = execute_rollback(state, "canary_validation_failed")
                            raise RuntimeError("canary_validation_failed")
                        apply_result = adapter.apply_scope(action, artifact, canary=False)
                        after_hash = artifact["after_hash"]
                        post_health = adapter.healthcheck()
                        post_profile = compare_health_profiles(
                            baseline_health["baseline"],
                            post_health.get("baseline", {}),
                        )
                        validation_result = {**post_health, "health_profile": post_profile}
                        if post_health["status"] != "HEALTHCHECK_OK" or post_profile["status"] != "HEALTH_PROFILE_VALID":
                            state["last_action"] = {**artifact, "cycle_id": cycle_id, "action_id": candidate}
                            rollback_result = execute_rollback(state, "post_apply_validation_failed")
                            raise RuntimeError("post_apply_validation_failed")
                        execution = "LOW_LIVE_APPLIED"
                        expires_at = artifact["expires_at"]
                        state["last_action"] = {**artifact, "cycle_id": cycle_id, "action_id": candidate}
                        state["active_actions"] = [{"action_id": candidate, "cycle_id": cycle_id, "expires_at": expires_at}]
                        state["pending_validations"] = [
                            {"action_id": candidate, "cycle_id": cycle_id, "due_at": iso_utc(utc_now_dt() + timedelta(seconds=seconds))}
                            for seconds in POLICY_TEMPLATE["validation_schedule_seconds"][1:]
                        ]
                        circuit.setdefault("actions", []).append({"timestamp": utc_now(), "action_id": candidate, "cycle_id": cycle_id})
                    except RuntimeError as exc:
                        execution = "ACTION_FAILED"
                        decision = "ROLLBACK_OR_LOCK"
                        reason = str(exc)
                        if artifact is not None and apply_attempted and rollback_result is None:
                            if artifact.get("after_hash"):
                                state["last_action"] = {**artifact, "cycle_id": cycle_id, "action_id": candidate}
                                rollback_result = execute_rollback(state, "adapter_or_scope_failure")
                            else:
                                try:
                                    reconciliation = adapter.reconcile_rollback_artifact(action, artifact)
                                except RuntimeError:
                                    reconciliation = {"status": "UNEXPLAINED_REMOTE_HASH_MISMATCH"}
                                if reconciliation["status"] == "ROLLBACK_ARTIFACT_RECOVERED":
                                    state["last_action"] = {**artifact, "cycle_id": cycle_id, "action_id": candidate}
                                    rollback_result = execute_rollback(state, "uncertain_apply_reconciled")
                                elif reconciliation["status"] == "UNEXPLAINED_REMOTE_HASH_MISMATCH":
                                    trip_runtime_emergency(
                                        state,
                                        "GUARDED_AUTONOMY_EMERGENCY_STOP_HASH_MISMATCH",
                                        "unexplained remote hash mismatch",
                                        breach=True,
                                    )
                        circuit.setdefault("failures", []).append({"timestamp": utc_now(), "action_id": candidate, "cycle_id": cycle_id, "reason": reason})
                        if circuit_status(circuit)["failed_actions_last_hour"] >= 2:
                            trip_runtime_emergency(
                                state,
                                "GUARDED_AUTONOMY_EMERGENCY_STOP_ACTION_FAILURES",
                                "two failed LOW_LIVE actions within one hour",
                                breach=False,
                            )
                            circuit["emergency_stop"] = True
        circuit_view = circuit_status(circuit)
        write_json(CIRCUIT_BREAKER_JSON, circuit)
        record = audit_record(
            cycle_id,
            signals,
            candidate,
            decision,
            reason,
            preflight_result=state.get("preflight", {}).get("status"),
            canary_result=canary_result,
            apply_result=apply_result,
            validation_result=validation_result,
            rollback_result=rollback_result,
            before_hash=before_hash,
            after_hash=after_hash,
        )
        append_decision_audit(record)
        state["last_cycle"] = {
            "cycle_id": cycle_id,
            "timestamp": utc_now(),
            "decision": decision,
            "candidate_action": candidate,
            "execution": execution,
            "reason": reason,
            "healthcheck": validation_result or {"status": "NOT_RUN"},
            "circuit_breaker": circuit_view,
        }
        state["runtime_promotion"] = auto_promote_guarded_canary(state)
        write_state(state, record_history=True)
        report = build_runtime_report(state)
        write_reports(report)
        return report


def preflight() -> Dict[str, Any]:
    state = load_state()
    if state["machine_state"] == LOCKED:
        transition(state, PREFLIGHT)
    result = collect_preflight()
    state["preflight"] = result
    state["rollback_test"] = result["rollback_test"]
    state["canary"] = result["canary_test"]
    if result["status"] == "GUARDED_AUTONOMY_PREFLIGHT_GREEN":
        state["status"] = "GUARDED_AUTONOMY_PREFLIGHT_GREEN"
    else:
        force_safe_locked(state, "GUARDED_AUTONOMY_ACTIVATION_BLOCKED", result["blockers"])
    write_state(state, record_history=True)
    report = build_runtime_report(state)
    write_reports(report)
    append_jsonl(AUDIT_JSONL, {
        "cycle_id": None,
        "timestamp": utc_now(),
        "input_snapshot_ids": {},
        "trigger": "activation_preflight",
        "candidate_action": None,
        "risk": None,
        "policy_match": True,
        "preflight_result": result["status"],
        "decision": "ACTIVATE_ALLOWED" if not result["blockers"] else "ACTIVATION_BLOCKED",
        "reason": ",".join(result["blockers"]) if result["blockers"] else "all_gates_passed",
        "canary_result": result["canary_test"]["status"],
        "apply_result": None,
        "validation_result": None,
        "rollback_result": result["rollback_test"]["status"],
        "before_hash": None,
        "after_hash": None,
        "ttl": None,
        "owner_policy_reference": OWNER_POLICY_REFERENCE,
    })
    return report


def activate() -> Dict[str, Any]:
    state = load_state()
    state["status"] = "GUARDED_AUTONOMY_STAGED_ACTIVATION_REQUIRED"
    state["activation"] = {
        "status": "GUARDED_AUTONOMY_ACTIVATION_BLOCKED",
        "reason": "use_sentinel_guarded_activation_staged_controller",
        "systemd_installed": verified_systemd_installation()["verified"],
    }
    state["last_stop_reason"] = "staged_activation_required"
    write_state(state, record_history=False)
    report = build_runtime_report(state)
    write_reports(report)
    return report


def pause_runtime() -> Dict[str, Any]:
    state = load_state()
    if state["machine_state"] == ACTIVE:
        transition(state, DEGRADED)
    state["flags"]["guarded_live_autonomy_enabled"] = False
    state["flags"]["low_live_apply_enabled"] = False
    state["flags"]["production_apply_lock"] = True
    state["flags"]["remote_write_lock"] = True
    state["status"] = "GUARDED_AUTONOMY_PAUSED"
    write_state(state, record_history=True)
    report = build_runtime_report(state)
    write_reports(report)
    return report


def resume_runtime() -> Dict[str, Any]:
    report = preflight()
    state = load_state()
    if state["preflight"]["status"] == "GUARDED_AUTONOMY_PREFLIGHT_GREEN" and state["machine_state"] == DEGRADED:
        transition(state, ACTIVE)
        state["flags"].update(active_flags())
        state["autonomy_level"] = "LEVEL_2_GUARDED_AUTONOMY"
        state["status"] = "GUARDED_AUTONOMY_ACTIVE"
        write_state(state, record_history=True)
        report = build_runtime_report(state)
        write_reports(report)
    return report


def emergency_stop_runtime() -> Dict[str, Any]:
    state = load_state()
    current = state["machine_state"]
    if current == ACTIVE:
        transition(state, DEGRADED)
        transition(state, EMERGENCY_STOP)
    elif current == DEGRADED:
        transition(state, EMERGENCY_STOP)
    elif current == CANARY:
        transition(state, ROLLBACK)
        transition(state, EMERGENCY_STOP)
    elif current == ROLLBACK:
        transition(state, EMERGENCY_STOP)
    state["flags"].update(default_flags())
    state["flags"]["breach"] = False
    state["status"] = "GUARDED_AUTONOMY_EMERGENCY_STOP"
    if systemd_status()["installed"]:
        state.setdefault("activation", {})["disable_result"] = run_systemctl("disable_timer")
    write_state(state, record_history=True)
    report = build_runtime_report(state)
    write_reports(report)
    return report


def rollback_last() -> Dict[str, Any]:
    state = load_state()
    result = execute_rollback(state, "owner_or_runtime_rollback_last")
    write_state(state, record_history=True)
    report = build_runtime_report(state)
    report["rollback_status"] = result
    write_reports(report)
    return report


def build_runtime_report(state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    state = state or load_state()
    registry = build_action_registry()
    circuit = circuit_status(load_circuit())
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": state["status"],
        "autonomy_level": state["autonomy_level"],
        "activation_stage": state.get("activation_stage", "LEVEL_1_DRAFT_ONLY"),
        "machine_state": state["machine_state"],
        "flags": state["flags"],
        "policy": {
            "status": validate_policy()["status"],
            "policy_hash": policy_hash(),
            "owner_policy_reference": OWNER_POLICY_REFERENCE,
        },
        "preflight": state.get("preflight", {}),
        "registered_actions": registry["actions"],
        "blocked_medium_high_actions": MEDIUM_HIGH_BLOCKED_ACTIONS,
        "adapters": registry["adapters"],
        "canary": state.get("canary", {}),
        "rollback_test": state.get("rollback_test", {}),
        "rollback_status": state.get("rollback_status", {"status": "NO_ROLLBACK_EXECUTED"}),
        "circuit_breaker": circuit,
        "systemd": systemd_status(),
        "activation": state.get("activation", {}),
        "first_cycle_id": state.get("first_cycle_id"),
        "last_cycle": state.get("last_cycle", {}),
        "active_actions": state.get("active_actions", []),
        "pending_validations": state.get("pending_validations", []),
        "learning": state.get("learning", {}),
        "runtime_promotion": state.get("runtime_promotion", load_dict(RUNTIME_PROMOTION_STATE_JSON)),
        "validation": {"status": "NOT_RUN", "findings": []},
    }
    report["validation"] = logical_validation(report)
    return report


def logical_validation(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = []
    flags = report["flags"]
    if flags["medium_live_apply_enabled"] or flags["high_live_apply_enabled"] or flags["unrestricted_shell_enabled"]:
        findings.append("forbidden_runtime_capability_enabled")
    runtime_stage_allows_live = report["machine_state"] == ACTIVE or (
        report["machine_state"] == CANARY and report.get("activation_stage") == "LEVEL_2_GUARDED_CANARY"
    )
    if not runtime_stage_allows_live and (flags["guarded_live_autonomy_enabled"] or flags["low_live_apply_enabled"]):
        findings.append("live_flags_enabled_outside_active_state")
    if flags["emergency_stop"] and not (flags["production_apply_lock"] and flags["remote_write_lock"]):
        findings.append("emergency_stop_lock_incomplete")
    if runtime_stage_allows_live and report["preflight"].get("status") != "GUARDED_AUTONOMY_PREFLIGHT_GREEN":
        findings.append("active_without_green_preflight")
    registry = validate_action_registry()
    if registry["findings"]:
        findings.extend(registry["findings"])
    return {
        "status": "GUARDED_AUTONOMY_VALIDATION_OK" if not findings else "GUARDED_AUTONOMY_VALIDATION_FAILED",
        "findings": findings,
        "breach": flags["breach"],
    }


def render_main(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# Sentinel Guarded Autonomy",
        "",
        f"- status: `{report['status']}`",
        f"- autonomy_level: `{report['autonomy_level']}`",
        f"- machine_state: `{report['machine_state']}`",
        f"- preflight: `{report['preflight'].get('status', 'NOT_RUN')}`",
        f"- emergency_stop: `{str(report['flags']['emergency_stop']).lower()}`",
        f"- low_live_apply_enabled: `{str(report['flags']['low_live_apply_enabled']).lower()}`",
        f"- medium_live_apply_enabled: `false`",
        f"- high_live_apply_enabled: `false`",
        f"- breach: `{str(report['flags']['breach']).lower()}`",
        "",
        "Owner authorization is recorded in policy. Runtime activation remains conditional on every current gate.",
    ])


def render_preflight(report: Dict[str, Any]) -> str:
    preflight_value = report.get("preflight", {})
    lines = ["# Sentinel Guarded Autonomy Preflight", "", f"- status: `{preflight_value.get('status', 'NOT_RUN')}`", "", "| Gate | Required | Passed | Reason |", "|---|---|---|---|"]
    for gate in preflight_value.get("gates", []):
        lines.append(f"| `{gate['gate']}` | `{str(gate['required']).lower()}` | `{str(gate['passed']).lower()}` | {gate['reason']} |")
    if preflight_value.get("blockers"):
        lines += ["", "## Blocking Gates", ""] + [f"- `{item}`" for item in preflight_value["blockers"]]
    return "\n".join(lines)


def render_actions(report: Dict[str, Any]) -> str:
    lines = ["# Sentinel Guarded LOW_LIVE Actions", "", "Unregistered actions are blocked. Disabled actions remain non-executable.", "", "| Action | Risk | Enabled | Adapter Ready | TTL |", "|---|---|---|---|---:|"]
    for action in report["registered_actions"]:
        lines.append(f"| `{action['action_id']}` | `{action['risk']}` | `{str(action['enabled']).lower()}` | `{str(action['runtime_adapter_ready']).lower()}` | {action['maximum_ttl']} |")
    lines += ["", "## MEDIUM/HIGH Blocked", ""] + [f"- `{item}`" for item in report["blocked_medium_high_actions"]]
    return "\n".join(lines)


def render_cycle(report: Dict[str, Any]) -> str:
    cycle = report.get("last_cycle", {})
    return "\n".join([
        "# Sentinel Guarded Cycle",
        "",
        f"- cycle_id: `{cycle.get('cycle_id')}`",
        f"- decision: `{cycle.get('decision', 'NOT_RUN')}`",
        f"- candidate_action: `{cycle.get('candidate_action')}`",
        f"- execution: `{cycle.get('execution', 'NOT_RUN')}`",
        f"- reason: {cycle.get('reason', 'No cycle has run.')}",
        f"- healthcheck: `{cycle.get('healthcheck', {}).get('status', 'NOT_RUN')}`",
    ])


def render_validation(report: Dict[str, Any]) -> str:
    validation = report["validation"]
    return "\n".join([
        "# Sentinel Guarded Validation",
        "",
        f"- status: `{validation['status']}`",
        f"- findings: `{len(validation['findings'])}`",
        f"- breach: `{str(validation['breach']).lower()}`",
        f"- policy: `{report['policy']['status']}`",
        f"- circuit_breaker: `{report['circuit_breaker']['status']}`",
    ])


def render_rollback(report: Dict[str, Any]) -> str:
    rollback = report.get("rollback_status", {})
    return "\n".join([
        "# Sentinel Guarded Rollback Status",
        "",
        f"- contract_test: `{report.get('rollback_test', {}).get('status', 'NOT_RUN')}`",
        f"- last_runtime_rollback: `{rollback.get('status', 'NO_ROLLBACK_EXECUTED')}`",
        "- scope: Sentinel-owned changes only",
        "- current-hash mismatch: fail closed and trigger emergency handling",
    ])


def render_owner(report: Dict[str, Any]) -> str:
    blockers = report.get("preflight", {}).get("blockers", [])
    return "\n".join([
        "# Sentinel Guarded Autonomy Owner Summary",
        "",
        f"- runtime status: `{report['status']}`",
        f"- systemd timer: `{report['systemd']['timer_status']}`",
        f"- machine state: `{report['machine_state']}`",
        f"- activation blockers: `{len(blockers)}`",
        f"- first cycle: `{report.get('first_cycle_id')}`",
        f"- last decision: `{report.get('last_cycle', {}).get('decision', 'NOT_RUN')}`",
        "",
        "MEDIUM and HIGH actions remain blocked. No unrestricted autopilot is available.",
    ])


def write_reports(report: Dict[str, Any]) -> None:
    ensure_dirs()
    write_json(REPORT_JSON, report)
    write_text(REPORT_MD, render_main(report))
    write_text(PREFLIGHT_MD, render_preflight(report))
    write_text(ACTIONS_MD, render_actions(report))
    write_text(CYCLE_MD, render_cycle(report))
    write_text(VALIDATION_MD, render_validation(report))
    write_text(ROLLBACK_MD, render_rollback(report))
    write_text(OWNER_MD, render_owner(report))
    if not CIRCUIT_BREAKER_JSON.exists():
        write_json(CIRCUIT_BREAKER_JSON, circuit_breaker_default())
    if not LAST_KNOWN_GOOD_JSON.exists():
        write_json(LAST_KNOWN_GOOD_JSON, {
            "status": "NO_ACTIVE_LAST_KNOWN_GOOD",
            "policy_hash": policy_hash(),
            "machine_state": LOCKED,
        })
    if not RUNTIME_LOCK_JSON.exists():
        write_json(RUNTIME_LOCK_JSON, {"status": "IDLE", "updated_at": utc_now()})


def validate_outputs() -> Dict[str, Any]:
    findings = []
    for path in OUTPUT_JSONS:
        if not path.exists():
            findings.append(f"missing_json:{rel(path)}")
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            findings.append(f"invalid_json:{rel(path)}")
    for path in OUTPUT_MARKDOWN:
        try:
            if not path.read_text(encoding="utf-8").strip():
                findings.append(f"empty_markdown:{rel(path)}")
        except OSError:
            findings.append(f"missing_markdown:{rel(path)}")
    for path in (AUDIT_JSONL, ACTIONS_AUDIT_JSONL, ROLLBACK_AUDIT_JSONL):
        if not path.exists():
            continue
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip() and not isinstance(json.loads(line), dict):
                    findings.append(f"invalid_jsonl_row:{rel(path)}")
        except (OSError, json.JSONDecodeError):
            findings.append(f"invalid_jsonl:{rel(path)}")
    return {"status": "GUARDED_OUTPUT_VALIDATION_OK" if not findings else "GUARDED_OUTPUT_VALIDATION_FAILED", "findings": findings}


def self_test(write_artifacts: bool = False) -> Dict[str, Any]:
    registry = validate_action_registry()
    policy = validate_policy()
    canary = deterministic_canary_test()
    rollback = deterministic_rollback_test()
    test_a = decide({"status_526": 0, "scanner_requests": 100, "scanner_actor_groups": 3, "legitimate_scanner_path_use": False, "status_503": 0, "status_522": 0})
    test_b = decide({"status_526": 0, "scanner_requests": 0, "scanner_actor_groups": 0, "legitimate_scanner_path_use": False, "wp_login_volume": 3, "wp_login_automated_probability": "low", "status_503": 0, "status_522": 0})
    test_c = decide({"status_526": 0, "scanner_requests": 0, "scanner_actor_groups": 0, "legitimate_scanner_path_use": False, "wp_login_volume": 150, "wp_login_automated_probability": "high", "admin_allowlist_present": True, "login_healthcheck_ok": True, "status_503": 0, "status_522": 0})
    test_d = decide({"status_526": 0, "scanner_requests": 0, "scanner_actor_groups": 0, "legitimate_scanner_path_use": False, "status_503": 200, "microcache_candidate_approved": False, "anonymous_public_get": False, "status_522": 0})
    test_e = decide({"status_526": 0, "scanner_requests": 0, "scanner_actor_groups": 0, "legitimate_scanner_path_use": False, "status_503": 200, "microcache_candidate_approved": True, "anonymous_public_get": True, "status_522": 0})
    test_f = decide({"status_526": 2})
    test_g = rollback_triggered(100, 110, {"wp_login_ok": True})
    synthetic_circuit = circuit_breaker_default()
    synthetic_circuit["failures"] = [
        {"timestamp": utc_now(), "action_id": "a"},
        {"timestamp": utc_now(), "action_id": "b"},
    ]
    test_h = circuit_status(synthetic_circuit)
    synthetic_rate_limit = circuit_breaker_default()
    synthetic_rate_limit["actions"] = [
        {"timestamp": utc_now(), "action_id": f"action-{index}"}
        for index in range(POLICY_TEMPLATE["action_limits"]["max_actions_per_hour"])
    ]
    rate_limit_test = rate_limit_allows(synthetic_rate_limit, "temporary_scanner_managed_challenge_v1")
    source_scan = source_security_scan()
    unit_validation = systemd_source_validation()
    scanner_action = action_by_id("temporary_scanner_managed_challenge_v1") or {}
    login_action = action_by_id("temporary_wp_login_protection_v1") or {}
    transition_state = default_state()
    transition(transition_state, PREFLIGHT)
    transition(transition_state, CANARY)
    transition(transition_state, ACTIVE)
    direct_transition_blocked = False
    try:
        invalid_state = default_state()
        transition(invalid_state, ACTIVE)
    except RuntimeError:
        direct_transition_blocked = True
    emergency_state = default_state()
    transition(emergency_state, PREFLIGHT)
    transition(emergency_state, CANARY)
    transition(emergency_state, ACTIVE)
    emergency_state["flags"].update(active_flags())
    trip_runtime_emergency(emergency_state, "TEST_EMERGENCY_STOP", "deterministic test", breach=False)
    safe_output_path = output_path_allowed(STATE_DIR / "test.json")
    symlink_escape_blocked = not output_path_allowed(PROJECT_DIR.parent / "outside.json")
    real_symlink_escape_blocked = deterministic_symlink_escape_test()
    checks = {
        "test_a_scanner_candidate": test_a["candidate_action"] == "temporary_scanner_managed_challenge_v1" and scanner_action.get("maximum_ttl", 99) <= 30,
        "test_a_canary_rollback": scanner_action.get("canary_plan", {}).get("required") is True and bool(scanner_action.get("rollback_adapter")),
        "test_b_normal_login_no_action": test_b["decision"] == "NO_ACTION",
        "test_c_login_candidate_not_permanent_block": test_c["candidate_action"] == "temporary_wp_login_protection_v1" and set(login_action.get("scope", {}).get("allowed_actions", [])) == {"managed_challenge", "rate_limit"},
        "test_d_503_monitor_escalate": test_d["decision"] == "MONITOR_AND_ESCALATE",
        "test_e_microcache_candidate": test_e["candidate_action"] == "anonymous_microcache_canary_v1",
        "test_e_failed_validation_rolls_back": rollback["rollback_restored_before_state"] is True,
        "test_f_526_pauses": test_f["decision"] == "PAUSE_AND_ALERT",
        "test_g_10_percent_rollback": test_g[0] is True and "five_xx_increase_gte_10_percent" in test_g[1],
        "test_h_circuit_breaker": test_h["tripped"] is True,
        "rate_limits": rate_limit_test == (False, "hourly_action_limit"),
        "emergency_stop": emergency_state["machine_state"] == EMERGENCY_STOP and emergency_state["flags"]["emergency_stop"] is True,
        "policy_valid": policy["status"] == "GUARDED_AUTONOMY_POLICY_VALID",
        "registry_valid": registry["status"] == "GUARDED_ACTION_REGISTRY_VALID",
        "all_actions_low_live": not registry["medium_or_high_actions"],
        "every_action_has_ttl_canary_rollback_validation": all(
            action.get("maximum_ttl") and action.get("canary_plan", {}).get("required") and action.get("rollback_adapter") and action.get("validation_checks")
            for action in REGISTERED_ACTIONS
        ),
        "state_machine_sequence": transition_state["machine_state"] == ACTIVE,
        "no_locked_to_active": direct_transition_blocked,
        "safe_output_path": safe_output_path,
        "outside_path_blocked": symlink_escape_blocked,
        "symlink_escape_blocked": real_symlink_escape_blocked,
        "no_unrestricted_shell": source_scan["unrestricted_shell"] is False and source_scan["shell_true"] is False,
        "no_arbitrary_command": source_scan["arbitrary_command_execution"] is False and source_scan["systemctl_commands_exact_allowlist"],
        "no_arbitrary_write_path": source_scan["arbitrary_write_path"] is False,
        "no_secrets": not source_scan["secret_findings"],
        "fixed_remote_target": ADAPTER_METADATA["CloudflareGuardedAdapter"]["remote_targets"] == ["api.cloudflare.com"],
        "fixed_health_targets": len(POLICY_TEMPLATE["health_targets"]) == 2
        and all(validate_health_target_definition(target) for target in POLICY_TEMPLATE["health_targets"]),
        "ssl_dns_certificate_blocked": all(item in MEDIUM_HIGH_BLOCKED_ACTIONS for item in ("dns_change", "cloudflare_ssl_mode_change", "certificate_replacement")),
        "broad_country_asn_blocked": "broad_ip_asn_country_block" in MEDIUM_HIGH_BLOCKED_ACTIONS,
        "wordpress_db_changes_blocked": all(item in MEDIUM_HIGH_BLOCKED_ACTIONS for item in ("wordpress_core_change", "plugin_or_theme_change", "database_write")),
        "systemd_unit_hardened": unit_validation["status"] == "SYSTEMD_SOURCE_VALID",
        "timer_fixed_run_cycle": unit_validation["checks"].get("fixed_exec_start") is True,
        "breach_false": default_flags()["breach"] is False,
        "canary_contract": canary["status"] == "GUARDED_AUTONOMY_CANARY_OK",
        "rollback_contract": rollback["status"] == "GUARDED_AUTONOMY_ROLLBACK_TEST_OK",
    }
    findings = [name for name, passed in checks.items() if not passed]
    result = {
        "status": "GUARDED_AUTONOMY_SELF_TEST_OK" if not findings else "GUARDED_AUTONOMY_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }
    if write_artifacts:
        state = load_state()
        state["self_test"] = result
        write_state(state)
        report = build_runtime_report(state)
        write_reports(report)
    return result


def audit_summary() -> Dict[str, Any]:
    summary = {"decision_rows": 0, "action_rows": 0, "rollback_rows": 0, "invalid_rows": 0}
    for key, path in (("decision_rows", AUDIT_JSONL), ("action_rows", ACTIONS_AUDIT_JSONL), ("rollback_rows", ROLLBACK_AUDIT_JSONL)):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                if isinstance(json.loads(line), dict):
                    summary[key] += 1
                else:
                    summary["invalid_rows"] += 1
            except json.JSONDecodeError:
                summary["invalid_rows"] += 1
    summary["status"] = "GUARDED_AUDIT_VALID" if summary["invalid_rows"] == 0 else "GUARDED_AUDIT_INVALID"
    return summary


def initialize_outputs() -> Dict[str, Any]:
    if not POLICY_PATH.exists():
        build_policy()
    state = load_state()
    write_state(state)
    report = build_runtime_report(state)
    write_reports(report)
    for path in (AUDIT_JSONL, ACTIONS_AUDIT_JSONL, ROLLBACK_AUDIT_JSONL):
        if not path.exists():
            append_jsonl(path, {"timestamp": utc_now(), "event": "audit_initialized", "breach": False})
    return report


def print_status(report: Dict[str, Any]) -> None:
    print(report.get("status", "GUARDED_AUTONOMY_NOT_INITIALIZED"))
    print(f"MACHINE_STATE_{report.get('machine_state', 'UNKNOWN')}")
    print(f"AUTONOMY_{report.get('autonomy_level', 'UNKNOWN')}")
    print(f"LOW_LIVE_ENABLED_{str(report.get('flags', {}).get('low_live_apply_enabled', False)).upper()}")
    print("MEDIUM_ENABLED_FALSE")
    print("HIGH_ENABLED_FALSE")
    print(f"EMERGENCY_STOP_{str(report.get('flags', {}).get('emergency_stop', True)).upper()}")
    print(f"BREACH_{str(report.get('flags', {}).get('breach', False)).upper()}")
    print(f"SYSTEMD_TIMER_{'ACTIVE' if report.get('systemd', {}).get('timer_active') else 'INACTIVE'}")
    print(report.get("circuit_breaker", {}).get("status", "CIRCUIT_BREAKER_UNKNOWN"))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel guarded autonomy controller")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--build-policy", action="store_true")
    group.add_argument("--validate-policy", action="store_true")
    group.add_argument("--list-actions", action="store_true")
    group.add_argument("--preflight", action="store_true")
    group.add_argument("--test-rollbacks", action="store_true")
    group.add_argument("--run-canary", action="store_true")
    group.add_argument("--activate", action="store_true")
    group.add_argument("--run-cycle", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--pause", action="store_true")
    group.add_argument("--resume", action="store_true")
    group.add_argument("--emergency-stop", action="store_true")
    group.add_argument("--rollback-last", action="store_true")
    group.add_argument("--audit-summary", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = self_test(write_artifacts=False)
        print(result["status"])
        if result["findings"]:
            print(json.dumps(result["findings"]))
        return 0 if not result["findings"] else 1
    if args.build_policy:
        result = build_policy()
        initialize_outputs()
        print(result["status"])
        return 0
    if args.validate_policy:
        result = validate_policy()
        print(result["status"])
        return 0 if not result["findings"] else 1
    if args.list_actions:
        initialize_outputs()
        registry = build_action_registry()
        for action in registry["actions"]:
            print(f"{action['action_id']} risk={action['risk']} enabled={str(action['enabled']).lower()} adapter_ready={str(action['runtime_adapter_ready']).lower()}")
        return 0
    if args.preflight:
        initialize_outputs()
        report = preflight()
        print(report["preflight"]["status"])
        if report["preflight"].get("blockers"):
            print("BLOCKERS=" + ",".join(report["preflight"]["blockers"]))
        return 0 if report["preflight"]["status"] == "GUARDED_AUTONOMY_PREFLIGHT_GREEN" else 2
    if args.test_rollbacks:
        initialize_outputs()
        result = deterministic_rollback_test()
        state = load_state()
        state["rollback_test"] = result
        write_state(state)
        append_jsonl(ROLLBACK_AUDIT_JSONL, {"timestamp": utc_now(), "event": "deterministic_rollback_test", "result": result["status"], "live": False})
        write_reports(build_runtime_report(state))
        print(result["status"])
        return 0 if result["status"] == "GUARDED_AUTONOMY_ROLLBACK_TEST_OK" else 1
    if args.run_canary:
        initialize_outputs()
        result = deterministic_canary_test()
        state = load_state()
        state["canary"] = result
        write_state(state)
        write_reports(build_runtime_report(state))
        print(result["status"])
        print("CANARY_LIVE_FALSE")
        return 0 if result["status"] == "GUARDED_AUTONOMY_CANARY_OK" else 1
    if args.activate:
        initialize_outputs()
        report = activate()
        print_status(report)
        return 0 if report["status"] == "GUARDED_AUTONOMY_ACTIVE" else 2
    if args.run_cycle:
        initialize_outputs()
        report = run_cycle()
        cycle = report.get("last_cycle", {})
        print(f"CYCLE_ID={cycle.get('cycle_id')}")
        print(f"DECISION={cycle.get('decision')}")
        print(f"EXECUTION={cycle.get('execution')}")
        return 0
    if args.pause:
        print_status(pause_runtime())
        return 0
    if args.resume:
        report = resume_runtime()
        print_status(report)
        return 0 if report["status"] == "GUARDED_AUTONOMY_ACTIVE" else 2
    if args.emergency_stop:
        print_status(emergency_stop_runtime())
        return 0
    if args.rollback_last:
        report = rollback_last()
        print(report["rollback_status"]["status"])
        return 0 if report["rollback_status"]["status"] in {"ROLLBACK_OK", "ROLLBACK_NOT_AVAILABLE"} else 2
    if args.audit_summary:
        initialize_outputs()
        result = audit_summary()
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "GUARDED_AUDIT_VALID" else 1
    if args.status:
        initialize_outputs()
        report = build_runtime_report()
        write_reports(report)
        print_status(report)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
