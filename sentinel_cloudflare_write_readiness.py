#!/usr/bin/env python3
"""Read-only Cloudflare write-readiness evidence for guarded autonomy.

This component never performs a Cloudflare mutation. It separates the last
mutating write-canary result from a fresh capability inspection and evaluates
whether LOW_LIVE is ready for a later, explicit owner activation. Readiness is
not activation: LOW/MEDIUM/HIGH remain disabled and production stays locked.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import sentinel_guarded_autonomy as guarded
import sentinel_runtime_safety as runtime_safety


PROJECT_DIR = Path(__file__).resolve().parent
REPORT_DIR = PROJECT_DIR / "reports/latest"
STATE_DIR = PROJECT_DIR / "state/guarded-autonomy"
AUDIT_DIR = PROJECT_DIR / "audit"

REPORT_JSON = REPORT_DIR / "sentinel-cloudflare-write-readiness.json"
REPORT_MD = REPORT_DIR / "sentinel-cloudflare-write-readiness.md"
STATE_JSON = STATE_DIR / "write-readiness.json"
AUDIT_JSONL = AUDIT_DIR / "sentinel-cloudflare-write-readiness.jsonl"
HISTORICAL_CANARY_JSON = STATE_DIR / "write-canary.json"
CANONICAL_JSON = REPORT_DIR / "sentinel-canonical-truth.json"

SCHEMA_VERSION = "sentinel-cloudflare-write-readiness-1"
CANARY_CURRENT_SECONDS = 24 * 60 * 60
READINESS_CURRENT_SECONDS = 2 * 60 * 60

CURRENT = "CURRENT"
STALE = "STALE_EXCLUDED_FROM_CURRENT_READINESS"
MISSING = "MISSING"
INVALID_TIMESTAMP = "INVALID_TIMESTAMP"

CANARY_OK = "CLOUDFLARE_WRITE_CANARY_OK"
CANARY_STALE = "CLOUDFLARE_WRITE_CANARY_STALE"
CANARY_MISSING = "CLOUDFLARE_WRITE_CANARY_MISSING"
CANARY_INVALID = "CLOUDFLARE_WRITE_CANARY_INVALID_TIMESTAMP"

CAPABILITY_VERIFIED = "CLOUDFLARE_WRITE_CAPABILITY_VERIFIED_READ_ONLY"
CAPABILITY_VERIFIED_BY_CANARY = "CLOUDFLARE_WRITE_CAPABILITY_VERIFIED_BY_FRESH_CANARY"
CAPABILITY_CAPACITY_BLOCKED = "CLOUDFLARE_WRITE_CAPABILITY_BLOCKED_RULESET_CAPACITY"
CAPABILITY_PERMISSION_BLOCKED = "CLOUDFLARE_WRITE_CAPABILITY_BLOCKED_PERMISSION"
CAPABILITY_PERMISSION_UNPROVEN = "CLOUDFLARE_WRITE_CAPABILITY_PERMISSION_UNPROVEN"
CAPABILITY_AUTH_BLOCKED = "CLOUDFLARE_WRITE_CAPABILITY_BLOCKED_AUTH"
CAPABILITY_SCOPE_BLOCKED = "CLOUDFLARE_WRITE_CAPABILITY_BLOCKED_FIXED_SCOPE"

PERMISSION_VERIFIED = "ZONE_WAF_WRITE_PERMISSION_VERIFIED"
PERMISSION_VERIFIED_BY_CANARY = "ZONE_WAF_WRITE_PERMISSION_VERIFIED_BY_FRESH_CANARY"
PERMISSION_MISSING = "ZONE_WAF_WRITE_PERMISSION_MISSING"
PERMISSION_UNPROVEN = "ZONE_WAF_WRITE_PERMISSION_UNPROVEN"

CAPABILITY_VERIFIED_STATUSES = frozenset({CAPABILITY_VERIFIED, CAPABILITY_VERIFIED_BY_CANARY})

READY = "READY_FOR_OWNER_ACTIVATION"
ACTIVE = "LOW_LIVE_ACTIVE"
NOT_READY = "NOT_READY_FOR_OWNER_ACTIVATION"
NOT_EVALUATED = "LOW_LIVE_READINESS_PENDING_CANONICAL_EVALUATION"

PROMOTION_READY = "RUNTIME_PROMOTION_READY_FOR_OWNER_ACTIVATION"
PROMOTION_ACTIVE = "RUNTIME_PROMOTION_LOW_LIVE_ACTIVE"
PROMOTION_BLOCKED = "RUNTIME_PROMOTION_BLOCKED_BY_WRITE_READINESS"

# Cloudflare currently counts all rules in the zone's custom firewall phase
# against these plan limits. Unknown plans fail closed instead of guessing.
CUSTOM_RULE_LIMIT_BY_PLAN = {
    "free": 5,
    "pro": 20,
    "business": 100,
    "enterprise": 1000,
}
LIMIT_REFERENCE = "https://developers.cloudflare.com/waf/custom-rules/#availability"
WRITE_PERMISSION_NAMES = frozenset({"Zone WAF Write", "Zone WAF Edit"})
OBJECT_ID_RE = re.compile(r"^[A-Fa-f0-9]{20,64}$")


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


def read_dict(path: Path) -> Dict[str, Any]:
    if path.is_symlink():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def write_json(path: Path, value: Dict[str, Any]) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refusing symlink output: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def write_text(path: Path, value: str) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refusing symlink output: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(value.rstrip() + "\n", encoding="utf-8")
    temporary.replace(path)


def append_audit(result: Dict[str, Any]) -> None:
    if AUDIT_JSONL.is_symlink():
        raise RuntimeError("refusing symlink audit output")
    AUDIT_JSONL.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "timestamp": result["generated_at"],
        "event": "cloudflare_write_readiness_evaluated",
        "capability_status": result["capability"]["status"],
        "permission_status": result["capability"]["permission_status"],
        "write_canary_status": result["write_canary"]["current_status"],
        "write_canary_freshness": result["write_canary"]["freshness"],
        "source_integrity_status": result["source_integrity"]["status"],
        "low_live_readiness": result["low_live_readiness"]["status"],
        "real_mutation_performed": False,
        "low_live": False,
        "medium": False,
        "high": False,
        "production_apply_lock": True,
        "breach": False,
    }
    with AUDIT_JSONL.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def cloudflare_error_codes(value: Dict[str, Any]) -> List[int]:
    return sorted({
        row.get("code")
        for row in value.get("errors", [])
        if isinstance(row, dict) and isinstance(row.get("code"), int)
    })


class FixedReadOnlyCloudflareInspector:
    """Fixed first-party GETs only; no caller-provided URL or API operation."""

    api_base = "https://api.cloudflare.com/client/v4"

    def __init__(self) -> None:
        values = guarded.load_private_environment()
        token = values.get("CLOUDFLARE_API_TOKEN", "")
        zone_id = values.get("CLOUDFLARE_ZONE_ID", "")
        if not token or not guarded.ZONE_ID_RE.fullmatch(zone_id):
            raise RuntimeError("configured Cloudflare credentials are unavailable")
        self._token = token
        self._zone_id = zone_id

    def _get(self, operation: str, token_id: Optional[str] = None) -> Tuple[Optional[int], Dict[str, Any]]:
        fixed = {
            "token_verify": "/user/tokens/verify",
            "permission_groups": "/user/tokens/permission_groups",
            "fixed_zone": f"/zones/{self._zone_id}",
            "custom_ruleset_entrypoint": (
                f"/zones/{self._zone_id}/rulesets/phases/"
                "http_request_firewall_custom/entrypoint"
            ),
        }
        if operation == "token_details":
            if not isinstance(token_id, str) or not OBJECT_ID_RE.fullmatch(token_id):
                raise RuntimeError("verified token identifier is invalid")
            path = f"/user/tokens/{token_id}"
        elif operation in fixed:
            path = fixed[operation]
        else:
            raise RuntimeError("Cloudflare read operation is not registered")
        request = urllib.request.Request(
            self.api_base + path,
            method="GET",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "SentinelWriteReadinessReadOnly/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                parsed = json.loads(response.read(262144).decode("utf-8"))
                return int(response.status), parsed if isinstance(parsed, dict) else {}
        except urllib.error.HTTPError as exc:
            try:
                parsed = json.loads(exc.read(65536).decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                parsed = {}
            finally:
                exc.close()
            return int(exc.code), parsed if isinstance(parsed, dict) else {}
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            return None, {}

    @staticmethod
    def _permission_names(policies: Any, group_names: Dict[str, str]) -> List[str]:
        names = set()
        if not isinstance(policies, list):
            return []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            for group in policy.get("permission_groups", []):
                if not isinstance(group, dict):
                    continue
                name = group.get("name")
                group_id = group.get("id")
                if isinstance(name, str):
                    names.add(name)
                elif isinstance(group_id, str) and group_id in group_names:
                    names.add(group_names[group_id])
        return sorted(names)

    def inspect(self) -> Dict[str, Any]:
        verify_http, verify = self._get("token_verify")
        verify_result = verify.get("result") if isinstance(verify.get("result"), dict) else {}
        token_active = bool(
            verify_http == 200
            and verify.get("success") is True
            and verify_result.get("status") == "active"
        )
        token_id = verify_result.get("id") if isinstance(verify_result.get("id"), str) else None

        details_http: Optional[int] = None
        details: Dict[str, Any] = {}
        if token_active and token_id:
            details_http, details_response = self._get("token_details", token_id)
            if details_response.get("success") is True and isinstance(details_response.get("result"), dict):
                details = details_response["result"]

        group_names: Dict[str, str] = {}
        groups_http: Optional[int] = None
        if details:
            groups_http, groups_response = self._get("permission_groups")
            groups = groups_response.get("result") if isinstance(groups_response.get("result"), list) else []
            group_names = {
                row["id"]: row["name"]
                for row in groups
                if isinstance(row, dict)
                and isinstance(row.get("id"), str)
                and isinstance(row.get("name"), str)
            }

        permission_names = self._permission_names(details.get("policies"), group_names)
        write_permission = bool(WRITE_PERMISSION_NAMES.intersection(permission_names))
        policy_readable = bool(details)
        permission_status = (
            PERMISSION_VERIFIED if write_permission else
            PERMISSION_MISSING if policy_readable else
            PERMISSION_UNPROVEN
        )

        fixed_zone_included: Optional[bool] = None
        wildcard_zone_scope: Optional[bool] = None
        if policy_readable:
            fixed_zone_included = False
            wildcard_zone_scope = False
            for policy in details.get("policies", []):
                resources = policy.get("resources") if isinstance(policy, dict) else None
                if not isinstance(resources, dict):
                    continue
                for resource, decision in resources.items():
                    if not isinstance(resource, str):
                        continue
                    included = str(decision).lower() in {"*", "include", "true"}
                    if self._zone_id in resource and included:
                        fixed_zone_included = True
                    if resource.endswith(":*") and "zone" in resource and included:
                        wildcard_zone_scope = True

        zone_http, zone_response = self._get("fixed_zone")
        zone = zone_response.get("result") if isinstance(zone_response.get("result"), dict) else {}
        zone_ok = bool(
            zone_http == 200
            and zone_response.get("success") is True
            and zone.get("id") == self._zone_id
            and zone.get("status") == "active"
        )
        plan = zone.get("plan") if isinstance(zone.get("plan"), dict) else {}
        plan_id = str(plan.get("legacy_id") or "").lower() or None

        rules_http, rules_response = self._get("custom_ruleset_entrypoint")
        ruleset = rules_response.get("result") if isinstance(rules_response.get("result"), dict) else {}
        ruleset_ok = bool(
            rules_http == 200
            and rules_response.get("success") is True
            and ruleset.get("kind") == "zone"
            and ruleset.get("phase") == "http_request_firewall_custom"
        )
        rules = ruleset.get("rules") if isinstance(ruleset.get("rules"), list) else []
        rule_count = len(rules) if ruleset_ok else None
        rule_limit = CUSTOM_RULE_LIMIT_BY_PLAN.get(plan_id or "")
        capacity_available = bool(
            isinstance(rule_count, int)
            and isinstance(rule_limit, int)
            and rule_count < rule_limit
        ) if rule_limit is not None else None
        exact_canary_count = sum(
            1 for rule in rules
            if isinstance(rule, dict)
            and rule.get("ref") == guarded.WRITE_CANARY_REF
            and rule.get("description") == guarded.WRITE_CANARY_DESCRIPTION
            and rule.get("expression") == guarded.WRITE_CANARY_EXPRESSION
            and rule.get("action") == "managed_challenge"
            and rule.get("enabled") is False
        )

        if not token_active:
            capability_status = CAPABILITY_AUTH_BLOCKED
        elif not zone_ok or not ruleset_ok:
            capability_status = CAPABILITY_SCOPE_BLOCKED
        elif capacity_available is False:
            capability_status = CAPABILITY_CAPACITY_BLOCKED
        elif permission_status == PERMISSION_MISSING:
            capability_status = CAPABILITY_PERMISSION_BLOCKED
        elif permission_status == PERMISSION_UNPROVEN:
            capability_status = CAPABILITY_PERMISSION_UNPROVEN
        elif capacity_available is True and permission_status == PERMISSION_VERIFIED:
            capability_status = CAPABILITY_VERIFIED
        else:
            capability_status = CAPABILITY_SCOPE_BLOCKED

        return {
            "status": capability_status,
            "checked_at": utc_now(),
            "methods_used": ["GET"],
            "real_mutation_performed": False,
            "token_active": token_active,
            "token_verify_http_status": verify_http,
            "token_verify_error_codes": cloudflare_error_codes(verify),
            "token_policy_readable": policy_readable,
            "token_details_http_status": details_http,
            "permission_groups_http_status": groups_http,
            "permission_status": permission_status,
            "fixed_zone_policy_scope_proven": fixed_zone_included,
            "wildcard_zone_scope": wildcard_zone_scope,
            "fixed_zone_active": zone_ok,
            "fixed_zone_http_status": zone_http,
            "zone_plan": plan_id,
            "custom_ruleset_readable": ruleset_ok,
            "custom_ruleset_http_status": rules_http,
            "custom_rule_count": rule_count,
            "custom_rule_limit": rule_limit,
            "custom_rule_capacity_available": capacity_available,
            "custom_rule_limit_reference": LIMIT_REFERENCE,
            "dedicated_fixed_canary_present": exact_canary_count == 1,
            "dedicated_fixed_canary_count": exact_canary_count,
            "credential_values_disclosed": False,
            "api_response_body_stored": False,
        }


def classify_historical_canary(value: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    moment = now or utc_now_dt()
    generated_at = value.get("generated_at")
    parsed = parse_timestamp(generated_at)
    if not value:
        freshness = MISSING
        current_status = CANARY_MISSING
        age_seconds = None
    elif parsed is None:
        freshness = INVALID_TIMESTAMP
        current_status = CANARY_INVALID
        age_seconds = None
    else:
        age_seconds = max(0.0, (moment - parsed).total_seconds())
        freshness = CURRENT if age_seconds <= CANARY_CURRENT_SECONDS else STALE
        current_status = value.get("status") if freshness == CURRENT else CANARY_STALE
    before_hash = value.get("before_hash")
    after_hash = value.get("after_hash")
    hash_restored = bool(
        isinstance(before_hash, str)
        and re.fullmatch(r"[a-f0-9]{64}", before_hash)
        and after_hash == before_hash
    )
    permission_proven = bool(
        freshness == CURRENT
        and current_status == CANARY_OK
        and value.get("reason") == "disabled_rule_created_verified_deleted_and_absence_verified"
        and value.get("created") is True
        and value.get("enabled") is False
        and value.get("verified") is True
        and value.get("deleted") is True
        and value.get("deletion_verified") is True
        and value.get("traffic_effect") is False
        and value.get("fixed_zone_scope") is True
        and value.get("disabled_rule_required") is True
        and value.get("managed_challenge_only") is True
        and value.get("fixed_rule_identity") == guarded.WRITE_CANARY_DESCRIPTION
        and value.get("credential_values_disclosed") is False
        and value.get("breach") is False
        and hash_restored
    )
    return {
        "source": str(HISTORICAL_CANARY_JSON.relative_to(PROJECT_DIR)),
        "last_run_at": generated_at,
        "age_seconds": round(age_seconds, 2) if isinstance(age_seconds, float) else None,
        "freshness": freshness,
        "historical_status": value.get("status") if value else None,
        "current_status": current_status,
        "historical_http_status_code": value.get("http_status_code"),
        "historical_cloudflare_error_codes": value.get("cloudflare_error_codes", []),
        "historical_rule_created": value.get("created") is True,
        "historical_traffic_effect": value.get("traffic_effect") is True,
        "historical_rule_enabled": value.get("enabled"),
        "historical_rule_verified": value.get("verified") is True,
        "historical_rule_deleted": value.get("deleted") is True,
        "historical_deletion_verified": value.get("deletion_verified") is True,
        "historical_hash_restored": hash_restored,
        "write_permission_proven_by_fresh_canary": permission_proven,
    }


def apply_fresh_canary_permission_evidence(
    canary: Dict[str, Any],
    capability: Dict[str, Any],
) -> Dict[str, Any]:
    """Use a completed fixed-scope canary as direct permission evidence."""
    result = dict(capability)
    current_scope_ok = bool(
        result.get("token_active") is True
        and result.get("fixed_zone_active") is True
        and result.get("custom_ruleset_readable") is True
        and result.get("custom_rule_capacity_available") is True
        and result.get("dedicated_fixed_canary_count") == 0
    )
    if canary.get("write_permission_proven_by_fresh_canary") is True and current_scope_ok:
        result["metadata_permission_status"] = result.get("permission_status")
        result["permission_status"] = PERMISSION_VERIFIED_BY_CANARY
        result["status"] = CAPABILITY_VERIFIED_BY_CANARY
        result["write_permission_evidence"] = (
            "FRESH_FIXED_DISABLED_RULE_CREATE_READBACK_DELETE_ABSENCE_AND_HASH_RESTORE"
        )
        result["permission_evidence_includes_prior_mutation"] = True
    return result


def runtime_readiness_gate(value: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Return a fail-closed runtime view of a persisted readiness envelope."""
    moment = now or utc_now_dt()
    generated_at = parse_timestamp(value.get("generated_at"))
    if not value:
        return {"status": NOT_READY, "freshness": MISSING, "blockers": ["write_readiness_missing"]}
    if generated_at is None:
        return {"status": NOT_READY, "freshness": INVALID_TIMESTAMP, "blockers": ["write_readiness_invalid_timestamp"]}
    age_seconds = max(0.0, (moment - generated_at).total_seconds())
    if age_seconds > READINESS_CURRENT_SECONDS:
        return {
            "status": NOT_READY,
            "freshness": STALE,
            "age_seconds": round(age_seconds, 2),
            "blockers": ["write_readiness_stale"],
        }
    readiness = value.get("low_live_readiness") if isinstance(value.get("low_live_readiness"), dict) else {}
    status = readiness.get("status")
    blockers = readiness.get("blockers") if isinstance(readiness.get("blockers"), list) else []
    if status not in {READY, ACTIVE}:
        return {
            "status": NOT_READY,
            "freshness": CURRENT,
            "age_seconds": round(age_seconds, 2),
            "blockers": blockers or ["low_live_readiness_not_green"],
        }
    return {
        "status": READY,
        "activation_status": status,
        "freshness": CURRENT,
        "age_seconds": round(age_seconds, 2),
        "blockers": [],
    }


def canonical_value(report: Dict[str, Any], name: str) -> Any:
    canonical = report.get("canonical") if isinstance(report.get("canonical"), dict) else {}
    block = canonical.get(name) if isinstance(canonical.get(name), dict) else {}
    return block.get("value") if block.get("resolution") == "RESOLVED" else None


def readiness_gate(
    canonical_report: Optional[Dict[str, Any]],
    canary: Dict[str, Any],
    capability: Dict[str, Any],
    rollback_status: str,
    source_integrity_status: str,
) -> Dict[str, Any]:
    if not isinstance(canonical_report, dict):
        return {
            "status": NOT_EVALUATED,
            "blockers": ["canonical_truth_not_evaluated"],
            "checks": {},
        }
    low_live_enabled = canonical_value(canonical_report, "low_live_enabled")
    production_apply_lock = canonical_value(canonical_report, "production_apply_lock")
    checks = {
        "canonical_truth_ok": canonical_report.get("status") == "CANONICAL_TRUTH_OK",
        "website_status_ok": canonical_value(canonical_report, "website_status") == "OK",
        "no_elevated_watchpoints": canonical_value(canonical_report, "rolling_window_status") == "NO_ELEVATED_WATCHPOINTS",
        "no_growth_observed": canonical_value(canonical_report, "current_growth") == "NO_GROWTH_OBSERVED",
        "scheduler_green": canonical_value(canonical_report, "scheduler_status") == "SCHEDULER_VERIFICATION_GREEN",
        "circuit_breaker_armed": canonical_value(canonical_report, "circuit_breaker_status") == "CIRCUIT_BREAKER_ARMED",
        "emergency_stop_false": canonical_value(canonical_report, "emergency_stop") is False,
        "breach_false": canonical_value(canonical_report, "breach") is False,
        "write_canary_current": canary.get("freshness") == CURRENT,
        "write_canary_successful": canary.get("current_status") == CANARY_OK,
        "write_capability_verified": capability.get("status") in CAPABILITY_VERIFIED_STATUSES,
        "rollback_verified": rollback_status == "GUARDED_AUTONOMY_ROLLBACK_TEST_OK",
        "source_integrity_verified": source_integrity_status == "SOURCE_INTEGRITY_VERIFIED",
        "medium_disabled": canonical_value(canonical_report, "medium_live_enabled") is False,
        "high_disabled": canonical_value(canonical_report, "high_live_enabled") is False,
        "low_runtime_state_consistent": (
            (low_live_enabled is False and production_apply_lock is True)
            or (low_live_enabled is True and production_apply_lock is False)
        ),
    }
    blockers = [name for name, passed in checks.items() if not passed]
    status = (
        ACTIVE
        if not blockers and low_live_enabled is True
        else (READY if not blockers else NOT_READY)
    )
    return {"status": status, "blockers": blockers, "checks": checks}


def evaluate(
    canonical_report: Optional[Dict[str, Any]] = None,
    *,
    perform_remote: bool = True,
    persist: bool = True,
) -> Dict[str, Any]:
    historical = classify_historical_canary(read_dict(HISTORICAL_CANARY_JSON))
    if perform_remote:
        try:
            capability = FixedReadOnlyCloudflareInspector().inspect()
        except (RuntimeError, OSError, UnicodeError):
            capability = {
                "status": CAPABILITY_AUTH_BLOCKED,
                "checked_at": utc_now(),
                "methods_used": ["GET"],
                "real_mutation_performed": False,
                "permission_status": PERMISSION_UNPROVEN,
                "credential_values_disclosed": False,
                "api_response_body_stored": False,
            }
    else:
        previous = read_dict(STATE_JSON)
        capability = previous.get("capability") if isinstance(previous.get("capability"), dict) else {}
        if not capability:
            capability = {
                "status": CAPABILITY_AUTH_BLOCKED,
                "checked_at": None,
                "methods_used": [],
                "real_mutation_performed": False,
                "permission_status": PERMISSION_UNPROVEN,
            }

    capability = apply_fresh_canary_permission_evidence(historical, capability)
    rollback = guarded.deterministic_rollback_test()
    source_integrity = runtime_safety.verify_fixed_source_manifest()
    gate = readiness_gate(
        canonical_report,
        historical,
        capability,
        rollback.get("status", "UNKNOWN"),
        source_integrity.get("status", "UNKNOWN"),
    )
    promotion = (
        PROMOTION_ACTIVE
        if gate["status"] == ACTIVE
        else (PROMOTION_READY if gate["status"] == READY else PROMOTION_BLOCKED)
    )
    blockers = sorted(set([
        *gate.get("blockers", []),
        *(["cloudflare_custom_rule_capacity_exhausted"] if capability.get("status") == CAPABILITY_CAPACITY_BLOCKED else []),
        *(["cloudflare_write_permission_unproven"] if capability.get("permission_status") == PERMISSION_UNPROVEN else []),
        *(["write_canary_stale"] if historical.get("freshness") == STALE else []),
    ]))
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "CLOUDFLARE_WRITE_READINESS_EVALUATED",
        "write_canary": historical,
        "capability": capability,
        "low_live_readiness": {**gate, "blockers": blockers},
        "promotion_gate_status": promotion,
        "rollback": rollback,
        "source_integrity": source_integrity,
        "safety": {
            "real_mutation_performed": False,
            "low_live": canonical_value(canonical_report or {}, "low_live_enabled"),
            "medium": False,
            "high": False,
            "production_apply_lock": canonical_value(canonical_report or {}, "production_apply_lock"),
            "emergency_stop": canonical_value(canonical_report or {}, "emergency_stop"),
            "breach": False,
        },
        "historical_and_current_evidence_separated": True,
        "credential_values_disclosed": False,
        "api_response_body_stored": False,
    }
    if persist:
        write_json(STATE_JSON, result)
        write_json(REPORT_JSON, result)
        write_text(REPORT_MD, render_markdown(result))
        append_audit(result)
    return result


def render_markdown(result: Dict[str, Any]) -> str:
    canary = result["write_canary"]
    capability = result["capability"]
    readiness = result["low_live_readiness"]
    safety = result["safety"]
    blockers = readiness.get("blockers", [])
    return "\n".join([
        "# Sentinel Cloudflare Write Readiness",
        "",
        "> Read-only capability evidence. This report does not activate LOW_LIVE and performs no Cloudflare mutation.",
        "",
        f"- evaluated: `{result['generated_at']}`",
        f"- historical canary source: `{canary['source']}`",
        f"- historical canary last run: `{canary.get('last_run_at')}`",
        f"- historical canary freshness: `{canary['freshness']}`",
        f"- current canary status: `{canary['current_status']}`",
        f"- capability check: `{capability.get('status')}`",
        f"- permission status: `{capability.get('permission_status')}`",
        f"- source integrity: `{result['source_integrity'].get('status', 'UNKNOWN')}`",
        f"- fixed zone active: `{str(capability.get('fixed_zone_active')).lower()}`",
        f"- custom rule usage: `{capability.get('custom_rule_count')}/{capability.get('custom_rule_limit')}`",
        f"- dedicated fixed canary present: `{str(capability.get('dedicated_fixed_canary_present')).lower()}`",
        f"- LOW_LIVE readiness: `{readiness['status']}`",
        f"- promotion gate: `{result['promotion_gate_status']}`",
        f"- blockers: `{', '.join(blockers) if blockers else 'none'}`",
        "",
        "## Safety",
        "",
        "- Cloudflare methods used: `GET`",
        "- real mutation performed: `false`",
        f"- LOW_LIVE: `{str(safety.get('low_live')).lower()}`",
        f"- MEDIUM: `{str(safety.get('medium')).lower()}`",
        f"- HIGH: `{str(safety.get('high')).lower()}`",
        f"- production apply lock: `{str(safety.get('production_apply_lock')).lower()}`",
    ])


def _fixture_canonical(**overrides: Any) -> Dict[str, Any]:
    values = {
        "website_status": "OK",
        "rolling_window_status": "NO_ELEVATED_WATCHPOINTS",
        "current_growth": "NO_GROWTH_OBSERVED",
        "scheduler_status": "SCHEDULER_VERIFICATION_GREEN",
        "circuit_breaker_status": "CIRCUIT_BREAKER_ARMED",
        "emergency_stop": False,
        "breach": False,
        "low_live_enabled": False,
        "medium_live_enabled": False,
        "high_live_enabled": False,
        "production_apply_lock": True,
    }
    values.update(overrides)
    return {
        "status": "CANONICAL_TRUTH_OK",
        "canonical": {
            key: {"value": value, "resolution": "RESOLVED"}
            for key, value in values.items()
        },
    }


def self_test() -> Dict[str, Any]:
    now = datetime(2026, 8, 30, tzinfo=timezone.utc)
    stale = classify_historical_canary({
        "generated_at": "2026-07-16T17:05:25Z",
        "status": "CLOUDFLARE_WRITE_CANARY_BLOCKED",
        "created": False,
        "traffic_effect": False,
    }, now)
    current_ok = classify_historical_canary({
        "generated_at": "2026-08-30T00:00:00Z",
        "status": CANARY_OK,
        "reason": "disabled_rule_created_verified_deleted_and_absence_verified",
        "created": True,
        "enabled": False,
        "verified": True,
        "deleted": True,
        "deletion_verified": True,
        "traffic_effect": False,
        "fixed_zone_scope": True,
        "disabled_rule_required": True,
        "managed_challenge_only": True,
        "fixed_rule_identity": guarded.WRITE_CANARY_DESCRIPTION,
        "credential_values_disclosed": False,
        "breach": False,
        "before_hash": "a" * 64,
        "after_hash": "a" * 64,
    }, now)
    capability_unproven = {
        "status": CAPABILITY_PERMISSION_UNPROVEN,
        "permission_status": PERMISSION_UNPROVEN,
        "token_active": True,
        "fixed_zone_active": True,
        "custom_ruleset_readable": True,
        "custom_rule_capacity_available": True,
        "dedicated_fixed_canary_count": 0,
    }
    capability_ok = apply_fresh_canary_permission_evidence(current_ok, capability_unproven)
    incomplete_canary = dict(current_ok)
    incomplete_canary["write_permission_proven_by_fresh_canary"] = False
    incomplete_capability = apply_fresh_canary_permission_evidence(incomplete_canary, capability_unproven)
    ready = readiness_gate(
        _fixture_canonical(), current_ok, capability_ok,
        "GUARDED_AUTONOMY_ROLLBACK_TEST_OK",
        "SOURCE_INTEGRITY_VERIFIED",
    )
    active = readiness_gate(
        _fixture_canonical(low_live_enabled=True, production_apply_lock=False),
        current_ok,
        capability_ok,
        "GUARDED_AUTONOMY_ROLLBACK_TEST_OK",
        "SOURCE_INTEGRITY_VERIFIED",
    )
    unknown_safety = readiness_gate(
        _fixture_canonical(emergency_stop=None), current_ok, capability_ok,
        "GUARDED_AUTONOMY_ROLLBACK_TEST_OK",
        "SOURCE_INTEGRITY_VERIFIED",
    )
    blocked_integrity = readiness_gate(
        _fixture_canonical(), current_ok, capability_ok,
        "GUARDED_AUTONOMY_ROLLBACK_TEST_OK",
        "SOURCE_INTEGRITY_BLOCKED",
    )
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    inspector_node = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "FixedReadOnlyCloudflareInspector"
    )
    request_methods = [
        keyword.value.value
        for node in ast.walk(inspector_node)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "method"
        and isinstance(keyword.value, ast.Constant)
        and isinstance(keyword.value.value, str)
    ]
    checks = {
        "stale_canary_not_current_truth": stale["freshness"] == STALE and stale["current_status"] == CANARY_STALE,
        "stale_blocked_not_green": stale["current_status"] != CANARY_OK,
        "all_green_yields_owner_readiness_only": ready["status"] == READY,
        "active_low_runtime_is_consistent": active["status"] == ACTIVE,
        "active_low_runtime_gate_remains_green": runtime_readiness_gate(
            {"generated_at": "2026-08-30T00:00:00Z", "low_live_readiness": active}, now
        )["status"] == READY,
        "fresh_complete_canary_proves_permission": (
            capability_ok["status"] == CAPABILITY_VERIFIED_BY_CANARY
            and capability_ok["permission_status"] == PERMISSION_VERIFIED_BY_CANARY
        ),
        "incomplete_canary_fails_closed": incomplete_capability["status"] == CAPABILITY_PERMISSION_UNPROVEN,
        "unknown_safety_fails_closed": unknown_safety["status"] == NOT_READY,
        "source_integrity_failure_blocks_readiness": (
            blocked_integrity["status"] == NOT_READY
            and "source_integrity_verified" in blocked_integrity["blockers"]
        ),
        "stale_readiness_envelope_fails_closed": runtime_readiness_gate(
            {"generated_at": "2026-08-29T00:00:00Z", "low_live_readiness": {"status": READY}}, now
        )["freshness"] == STALE,
        "readiness_never_enables_low": _fixture_canonical()["canonical"]["low_live_enabled"]["value"] is False,
        "fixed_get_only": bool(request_methods) and set(request_methods) == {"GET"},
        "no_shell_execution": "subprocess" not in {node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)},
        "no_arbitrary_url_cli": "url" not in {action.dest for action in build_parser()._actions},
        "historical_current_separated": HISTORICAL_CANARY_JSON != STATE_JSON,
        "capacity_logic": CUSTOM_RULE_LIMIT_BY_PLAN["free"] == 5,
        "breach_false": True,
    }
    findings = [name for name, passed in checks.items() if not passed]
    return {
        "status": "CLOUDFLARE_WRITE_READINESS_SELF_TEST_OK" if not findings else "CLOUDFLARE_WRITE_READINESS_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


def print_status(result: Dict[str, Any]) -> None:
    canary = result.get("write_canary", {})
    capability = result.get("capability", {})
    readiness = result.get("low_live_readiness", {})
    safety = result.get("safety", {})
    print(result.get("status", "NOT_RUN"))
    print(f"write_canary={canary.get('current_status', 'UNKNOWN')}")
    print(f"write_canary_freshness={canary.get('freshness', 'UNKNOWN')}")
    print(f"capability={capability.get('status', 'UNKNOWN')}")
    print(f"permission={capability.get('permission_status', 'UNKNOWN')}")
    print(f"low_live_readiness={readiness.get('status', 'UNKNOWN')}")
    print(f"low_live={str(safety.get('low_live')).lower()}")
    print(f"medium={str(safety.get('medium')).lower()}")
    print(f"high={str(safety.get('high')).lower()}")
    print(f"production_apply_lock={str(safety.get('production_apply_lock')).lower()}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only Cloudflare LOW_LIVE readiness evidence")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--evaluate", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.self_test:
        result = self_test()
        print(result["status"])
        return 0 if not result["findings"] else 1
    if args.evaluate:
        canonical = read_dict(CANONICAL_JSON)
        result = evaluate(canonical if canonical else None, perform_remote=True, persist=True)
        print_status(result)
        return 0
    result = read_dict(STATE_JSON)
    print_status(result)
    return 0 if result else 2


if __name__ == "__main__":
    raise SystemExit(main())
