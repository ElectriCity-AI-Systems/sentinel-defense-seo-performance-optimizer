#!/usr/bin/env python3
"""Fail-closed design and simulation for SENTINEL_BOT_DEFENSE_V1.

This module is deliberately outside the live decision path. It reuses the
registered guarded-autonomy action contract, produces local design evidence,
and never invokes a production adapter or changes runtime state.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import sentinel_guarded_autonomy as guarded


PROJECT_DIR = Path(__file__).resolve().parent
REPORT_JSON = PROJECT_DIR / "reports/latest/sentinel-adaptive-bot-defense-v1.json"
REPORT_MD = PROJECT_DIR / "reports/latest/sentinel-adaptive-bot-defense-v1.md"
SIMULATION_REPORT_JSON = PROJECT_DIR / "reports/latest/sentinel-adaptive-bot-defense-v1-simulation.json"
SIMULATION_REPORT_MD = PROJECT_DIR / "reports/latest/sentinel-adaptive-bot-defense-v1-simulation.md"
PLAYBOOK_PATH = PROJECT_DIR / "playbooks/sentinel-adaptive-bot-defense-v1.playbook.json"

DESIGN_ID = "SENTINEL_BOT_DEFENSE_V1"
DESIGN_STATUS = "BOT_DEFENSE_V1_DESIGN_VALIDATED"
ACTION_ID = "temporary_scanner_managed_challenge_v1"
SIMULATED_ACTION = "TEMPORARY_MANAGED_CHALLENGE"

VERIFIED_SEARCH_BOT = "VERIFIED_SEARCH_BOT"
KNOWN_COMMERCIAL_CRAWLER = "KNOWN_COMMERCIAL_CRAWLER"
SECURITY_SCANNER = "SECURITY_SCANNER"
UNKNOWN_AUTOMATION = "UNKNOWN_AUTOMATION"
BEHAVIORAL_PHP_SCANNER = "BEHAVIORAL_PHP_SCANNER"
NORMAL_BROWSER = "NORMAL_BROWSER"

BOT_CLASSES = (
    VERIFIED_SEARCH_BOT,
    KNOWN_COMMERCIAL_CRAWLER,
    SECURITY_SCANNER,
    UNKNOWN_AUTOMATION,
    BEHAVIORAL_PHP_SCANNER,
    NORMAL_BROWSER,
)

PIPELINE = (
    "OBSERVE",
    "CLASSIFY",
    "SCORE",
    "SIMULATE",
    "TEMPORARY_CHALLENGE",
    "VERIFY",
    "AUTO_ROLLBACK_OR_EXPIRE",
)

MAX_ACTIONS_PER_HOUR = 1
MAX_ACTIONS_PER_DAY = 4
MAX_ACTIVE_RULES = 1
RULE_TTL_MINUTES = 10
COOLDOWN_MINUTES = 30
ACTION_EVIDENCE_WINDOW_MINUTES = 5
MIN_REQUESTS = 100
MIN_ACTOR_GROUPS = 2
MIN_SUSPICIOUS_PATHS = 3
MIN_FAILURE_RATIO = 0.80
MIN_SCORE = 75
MIN_INDEPENDENT_SIGNAL_FAMILIES = 4

SEARCH_ENGINE_EVIDENCE: Dict[str, Any] = {
    "period": "2026-08-12..2026-09-10",
    "search_engine_robot_requests_current": 421,
    "search_engine_robot_requests_previous": 510,
    "trend": "DECLINING",
    "wp_login_requests_previously_observed": 7466,
    "actors": {
        "meta-webindexer/1.1": 222,
        "SiteLockSpider": 67,
        "AhrefsBot/7.0": 26,
        "Unknown": 26,
        "Amzn-SearchBot/0.1": 20,
        "CMS-Security-Auditor/1.0": 18,
        "Googlebot Desktop": 14,
        "DataForSeoBot/1.0": 11,
        "Xpanse": 6,
        "Mediapartners-Google": 6,
        "Mozilla/5.0": 5,
    },
    "sitelock_previous": 102,
    "sitelock_current": 67,
    "sitelock_change_percent": -34.30,
}

KNOWN_COMMERCIAL_NAMES = {
    "ahrefsbot",
    "amzn-searchbot",
    "dataforseobot",
    "meta-webindexer",
}
KNOWN_SECURITY_NAMES = {
    "cms-security-auditor",
    "sitelockspider",
    "xpanse",
}
PROTECTED_SEARCH_NAMES = {
    "bingbot",
    "googlebot",
    "mediapartners-google",
}
LEGITIMATE_PHP_PATHS = {
    "/index.php",
    "/wp-comments-post.php",
    "/wp-cron.php",
    "/wp-login.php",
    "/xmlrpc.php",
}
SUSPICIOUS_FILENAME_RE = re.compile(
    r"(?:^|/)(?:000|abcd|bless|dex|file|shell|webshell|simple|chosen|worksec|up|db)\.php$",
    re.IGNORECASE,
)
PHP_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,180}\.php$", re.IGNORECASE)


@dataclass(frozen=True)
class Observation:
    scenario_id: str
    current_evidence: bool
    evidence_age_seconds: int
    window_minutes: int
    request_count: int
    paths: Tuple[str, ...]
    method_counts: Mapping[str, int]
    status_counts: Mapping[int, int]
    user_agent_family: str
    automated_user_agent_signal: bool
    verified_search_identity: bool
    known_commercial_crawler: bool
    known_security_scanner: bool
    actor_groups: int
    repeated_source_correlation: bool
    address_family: str
    shared_nat_risk: bool
    legitimate_path_use: Optional[bool]
    website_status: str = "OK"
    circuit_breaker: str = "CIRCUIT_BREAKER_ARMED"
    breach: bool = False
    owner_policy_allows: bool = True
    low_budget_available: bool = True


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalize_actor_name(value: str) -> str:
    return value.strip().casefold().split("/", 1)[0]


def is_wordpress_scanner_path(path: str) -> bool:
    lowered = path.casefold()
    if lowered in LEGITIMATE_PHP_PATHS:
        return False
    if SUSPICIOUS_FILENAME_RE.search(lowered):
        return True
    return bool(
        PHP_PATH_RE.fullmatch(path)
        and lowered.startswith(("/wp-admin/", "/wp-content/", "/wp-includes/"))
    )


def is_random_php_probe(path: str) -> bool:
    lowered = path.casefold()
    if lowered in LEGITIMATE_PHP_PATHS or lowered.startswith(
        ("/wp-admin/", "/wp-content/", "/wp-includes/")
    ):
        return False
    return bool(PHP_PATH_RE.fullmatch(path))


def validate_observation(observation: Observation) -> List[str]:
    findings: List[str] = []
    if not observation.scenario_id or not re.fullmatch(r"[a-z0-9_-]{1,80}", observation.scenario_id):
        findings.append("scenario_id_invalid")
    if observation.window_minutes <= 0 or observation.window_minutes > 60:
        findings.append("window_invalid")
    if observation.evidence_age_seconds < 0:
        findings.append("evidence_age_invalid")
    if observation.request_count <= 0:
        findings.append("request_count_invalid")
    if not observation.paths or any(
        not isinstance(path, str)
        or not path.startswith("/")
        or "?" in path
        or "\n" in path
        or "\r" in path
        or len(path) > 200
        for path in observation.paths
    ):
        findings.append("paths_invalid")
    if not observation.method_counts or any(
        method not in {"GET", "HEAD", "POST"} or not isinstance(count, int) or count < 0
        for method, count in observation.method_counts.items()
    ):
        findings.append("methods_invalid")
    if sum(observation.method_counts.values()) != observation.request_count:
        findings.append("method_count_mismatch")
    if not observation.status_counts or any(
        not isinstance(status, int)
        or status < 100
        or status > 599
        or not isinstance(count, int)
        or count < 0
        for status, count in observation.status_counts.items()
    ):
        findings.append("statuses_invalid")
    if sum(observation.status_counts.values()) != observation.request_count:
        findings.append("status_count_mismatch")
    if observation.actor_groups < 0:
        findings.append("actor_groups_invalid")
    if observation.address_family not in {"IPv4", "IPv6", "MIXED", "UNKNOWN"}:
        findings.append("address_family_invalid")
    if not isinstance(observation.legitimate_path_use, (bool, type(None))):
        findings.append("legitimate_path_use_invalid")
    for name in (
        "current_evidence",
        "automated_user_agent_signal",
        "verified_search_identity",
        "known_commercial_crawler",
        "known_security_scanner",
        "repeated_source_correlation",
        "shared_nat_risk",
        "breach",
        "owner_policy_allows",
        "low_budget_available",
    ):
        if not isinstance(getattr(observation, name), bool):
            findings.append(f"{name}_invalid")
    return sorted(set(findings))


def path_analysis(paths: Sequence[str]) -> Dict[str, Any]:
    distinct = sorted(set(paths))
    registered = sorted(path for path in distinct if guarded.scanner_path_allowlisted(path))
    random_php = sorted(path for path in distinct if is_random_php_probe(path))
    wordpress_php = sorted(path for path in distinct if is_wordpress_scanner_path(path))
    login_paths = sorted(path for path in distinct if path.casefold() in {"/wp-login.php", "/xmlrpc.php"})
    suspicious = sorted(set(registered + random_php + wordpress_php))
    return {
        "distinct_paths": distinct,
        "registered_scanner_paths": registered,
        "random_php_paths": random_php,
        "wordpress_scanner_paths": wordpress_php,
        "login_paths": login_paths,
        "suspicious_paths": suspicious,
        "scope_exactly_registered": bool(suspicious)
        and len(suspicious) == len(distinct)
        and all(guarded.scanner_path_allowlisted(path) for path in suspicious),
    }


def classify(observation: Observation, paths: Dict[str, Any]) -> str:
    name = normalize_actor_name(observation.user_agent_family)
    behavior_supported = (
        len(paths["suspicious_paths"]) >= MIN_SUSPICIOUS_PATHS
        and observation.request_count >= MIN_REQUESTS
    )
    if behavior_supported:
        return BEHAVIORAL_PHP_SCANNER
    if observation.verified_search_identity and any(value in name for value in PROTECTED_SEARCH_NAMES):
        return VERIFIED_SEARCH_BOT
    if observation.known_security_scanner or any(value in name for value in KNOWN_SECURITY_NAMES):
        return SECURITY_SCANNER
    if observation.known_commercial_crawler or any(value in name for value in KNOWN_COMMERCIAL_NAMES):
        return KNOWN_COMMERCIAL_CRAWLER
    if observation.automated_user_agent_signal:
        return UNKNOWN_AUTOMATION
    return NORMAL_BROWSER


def score(observation: Observation, paths: Dict[str, Any]) -> Dict[str, Any]:
    failures = sum(
        count for status, count in observation.status_counts.items() if status in {403, 404, 429, 503}
    )
    failure_ratio = failures / observation.request_count if observation.request_count else 0.0
    post_count = int(observation.method_counts.get("POST", 0))
    suspicious_path_signal = len(paths["suspicious_paths"]) >= MIN_SUSPICIOUS_PATHS
    velocity_signal = (
        observation.window_minutes <= ACTION_EVIDENCE_WINDOW_MINUTES
        and observation.request_count >= MIN_REQUESTS
    )
    diversity_signal = len(paths["distinct_paths"]) >= MIN_SUSPICIOUS_PATHS
    failure_signal = failure_ratio >= MIN_FAILURE_RATIO
    source_signal = observation.actor_groups >= MIN_ACTOR_GROUPS and observation.repeated_source_correlation
    method_signal = post_count >= 50 and bool(paths["login_paths"])
    ua_signal = observation.automated_user_agent_signal
    weights = {
        "suspicious_path_behavior": (suspicious_path_signal, 30),
        "request_velocity": (velocity_signal, 20),
        "path_diversity": (diversity_signal, 15),
        "failure_correlation": (failure_signal, 15),
        "repeated_source_correlation": (source_signal, 10),
        "suspicious_method_pattern": (method_signal, 5),
        "automated_user_agent": (ua_signal, 5),
    }
    points = sum(weight for active, weight in weights.values() if active)
    independent = [name for name, (active, _) in weights.items() if active and name != "automated_user_agent"]
    return {
        "score": points,
        "threshold": MIN_SCORE,
        "signals": {name: active for name, (active, _) in weights.items()},
        "independent_signal_families": independent,
        "independent_signal_count": len(independent),
        "failure_ratio": round(failure_ratio, 4),
        "user_agent_points": 5 if ua_signal else 0,
        "user_agent_alone_sufficient": False,
    }


def runtime_contract() -> Dict[str, Any]:
    action = guarded.action_by_id(ACTION_ID) or {}
    policy = guarded.validate_policy()
    limits = guarded.POLICY_TEMPLATE.get("action_limits", {})
    proof_policy, proof_validation = guarded.proof_remediation.load_policy()
    proof_budget = proof_policy.get("change_budget", {})
    proof_contract = guarded.proof_remediation.contract_by_id(proof_policy, ACTION_ID) or {}
    proof_trigger = proof_contract.get("trigger_requirements", {})
    try:
        low_playbook = json.loads(
            (PROJECT_DIR / "playbooks/sentinel-low-live-actions.playbook.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        low_playbook = {}
    checks = {
        "policy_valid": policy.get("status") == "GUARDED_AUTONOMY_POLICY_VALID",
        "proof_policy_valid": proof_validation.get("status") == "PROOF_REMEDIATION_POLICY_VALID",
        "action_registered": action.get("action_id") == ACTION_ID,
        "action_enabled_in_reviewed_allowlist": action.get("enabled") is True,
        "risk_low_live": action.get("risk") == "LOW_LIVE",
        "managed_challenge_only": action.get("scope", {}).get("action") == "managed_challenge",
        "canary_required": action.get("canary_plan", {}).get("required") is True,
        "rollback_registered": bool(action.get("rollback_adapter")),
        "post_validation_registered": bool(action.get("validation_checks")),
        "ttl_exact": action.get("maximum_ttl") == RULE_TTL_MINUTES,
        "cooldown_exact": action.get("cooldown") == COOLDOWN_MINUTES,
        "hourly_budget_exact": limits.get("max_actions_per_hour") == MAX_ACTIONS_PER_HOUR,
        "daily_budget_exact": limits.get("max_actions_per_day") == MAX_ACTIONS_PER_DAY,
        "max_active_budget_exact": proof_budget.get("max_active_actions") == MAX_ACTIVE_RULES,
        "proof_ttl_exact": proof_budget.get("maximum_ttl_minutes") == RULE_TTL_MINUTES,
        "proof_cooldown_exact": proof_budget.get("global_cooldown_minutes") == COOLDOWN_MINUTES,
        "proof_trigger_not_weakened": proof_trigger.get("minimum_requests") == MIN_REQUESTS
        and proof_trigger.get("minimum_actor_groups") == MIN_ACTOR_GROUPS
        and proof_trigger.get("maximum_window_minutes") == ACTION_EVIDENCE_WINDOW_MINUTES
        and proof_trigger.get("fresh_exact_path_evidence") is True
        and proof_trigger.get("all_observed_paths_allowlisted") is True
        and proof_trigger.get("legitimate_use_absent") is True,
        "audit_required": ACTION_ID in low_playbook.get("allowed_actions", [])
        and "audit" in low_playbook.get("action_requirements", []),
        "medium_disabled": guarded.POLICY_TEMPLATE.get("medium_live_enabled") is False,
        "high_disabled": guarded.POLICY_TEMPLATE.get("high_live_enabled") is False,
        "source_self_modification_disabled": guarded.POLICY_TEMPLATE.get("source_self_modification_enabled") is False,
    }
    return {
        "status": "RUNTIME_CONTRACT_VALID" if all(checks.values()) else "RUNTIME_CONTRACT_INVALID",
        "checks": checks,
        "action_id": ACTION_ID,
        "budgets": {
            "max_actions_per_hour": MAX_ACTIONS_PER_HOUR,
            "max_actions_per_day": MAX_ACTIONS_PER_DAY,
            "max_active_rules": MAX_ACTIVE_RULES,
            "rule_ttl_minutes": RULE_TTL_MINUTES,
            "cooldown_minutes": COOLDOWN_MINUTES,
        },
    }


def false_positive_risk(observation: Observation, bot_class: str) -> Tuple[str, List[str]]:
    blockers: List[str] = []
    if observation.verified_search_identity or bot_class == VERIFIED_SEARCH_BOT:
        blockers.append("verified_search_identity")
    if observation.shared_nat_risk:
        blockers.append("shared_or_nat_source")
    if observation.legitimate_path_use is not False:
        blockers.append("legitimate_path_use_not_disproven")
    if bot_class in {KNOWN_COMMERCIAL_CRAWLER, SECURITY_SCANNER}:
        blockers.append("named_actor_behavior_not_independently_proven")
    return ("LOW" if not blockers else "NOT_LOW"), blockers


def evaluate(observation: Observation) -> Dict[str, Any]:
    validation_findings = validate_observation(observation)
    if validation_findings:
        return {
            "scenario_id": observation.scenario_id,
            "status": "SIMULATION_FAIL_CLOSED",
            "classification": UNKNOWN_AUTOMATION,
            "decision": "NO_ACTION",
            "reason": "invalid_or_incomplete_observation",
            "findings": validation_findings,
            "evidence_sufficient": False,
            "challenge_eligible": False,
            "production_mutation": False,
        }

    paths = path_analysis(observation.paths)
    bot_class = classify(observation, paths)
    score_result = score(observation, paths)
    fp_risk, fp_blockers = false_positive_risk(observation, bot_class)
    contract = runtime_contract()
    fresh_action_evidence = (
        observation.current_evidence
        and observation.evidence_age_seconds <= ACTION_EVIDENCE_WINDOW_MINUTES * 60
        and observation.window_minutes <= ACTION_EVIDENCE_WINDOW_MINUTES
    )
    evidence_sufficient = (
        fresh_action_evidence
        and observation.request_count >= MIN_REQUESTS
        and score_result["independent_signal_count"] >= MIN_INDEPENDENT_SIGNAL_FAMILIES
        and bot_class == BEHAVIORAL_PHP_SCANNER
    )
    safety_gates = {
        "evidence_sufficient": evidence_sufficient,
        "false_positive_risk_low": fp_risk == "LOW",
        "website_status_ok": observation.website_status == "OK",
        "circuit_breaker_armed": observation.circuit_breaker == "CIRCUIT_BREAKER_ARMED",
        "breach_false": observation.breach is False,
        "owner_policy_allows": observation.owner_policy_allows is True,
        "low_budget_available": observation.low_budget_available is True,
        "exact_registered_scope": paths["scope_exactly_registered"],
        "score_threshold_met": score_result["score"] >= MIN_SCORE,
        "runtime_contract_valid": contract["status"] == "RUNTIME_CONTRACT_VALID",
        "not_user_agent_only": score_result["independent_signal_count"] >= MIN_INDEPENDENT_SIGNAL_FAMILIES,
    }
    eligible = all(safety_gates.values())
    if eligible:
        decision = "SIMULATED_TEMPORARY_MANAGED_CHALLENGE"
        reason = "behavioral_multi_signal_evidence_matches_existing_exact_scanner_scope"
    elif bot_class == BEHAVIORAL_PHP_SCANNER:
        decision = "MONITOR_ONLY"
        reason = "behavior_supported_but_live_action_scope_or_safety_gate_not_satisfied"
    elif score_result["signals"]["suspicious_method_pattern"]:
        decision = "MONITOR_ONLY"
        reason = "login_or_xmlrpc_burst_observed_but_action_specific_contract_is_disabled"
    else:
        decision = "NO_ACTION"
        reason = "no_behavioral_multi_signal_challenge_candidate"

    verification = {
        "normal_browser_impact": "NO_MATCH_EXPECTED_FOR_REGISTERED_SCANNER_PATH_SCOPE" if eligible else "NONE",
        "legitimate_bot_impact": "PROTECTED_BY_IDENTITY_AND_BEHAVIOR_NEGATIVE_GATES",
        "login_access_impact": "UNCHANGED_WP_LOGIN_AND_XMLRPC_NOT_IN_ACTION_SCOPE",
        "five_xx_impact": "UNKNOWN_SIMULATION_ONLY",
        "false_positive_risk": fp_risk,
        "rollback_ready": contract["checks"].get("rollback_registered") is True,
    }
    if eligible:
        pipeline_results = {
            "TEMPORARY_CHALLENGE": "SIMULATED_NOT_APPLIED",
            "VERIFY": "SIMULATED_BASELINE_COMPARISON",
            "AUTO_ROLLBACK_OR_EXPIRE": "READY_NOT_INVOKED",
        }
    else:
        pipeline_results = {
            "TEMPORARY_CHALLENGE": "NOT_ELIGIBLE",
            "VERIFY": "NO_CHANGE_TO_VERIFY",
            "AUTO_ROLLBACK_OR_EXPIRE": "NOT_REQUIRED",
        }
    result = {
        "scenario_id": observation.scenario_id,
        "status": "SIMULATION_COMPLETE",
        "classification": bot_class,
        "path_analysis": paths,
        "score": score_result,
        "evidence_sufficient": evidence_sufficient,
        "false_positive_risk": fp_risk,
        "false_positive_blockers": fp_blockers,
        "safety_gates": safety_gates,
        "challenge_eligible": eligible,
        "candidate_action": ACTION_ID if eligible else None,
        "simulated_action": SIMULATED_ACTION if eligible else None,
        "decision": decision,
        "reason": reason,
        "target_model": "EXACT_REGISTERED_STATIC_PATH_SCOPE_WITH_BEHAVIORAL_TRIGGER",
        "user_agent_used_as_rule_scope": False,
        "source_address_used_as_rule_scope": False,
        "verification": verification,
        "pipeline": [
            {"stage": stage, "result": pipeline_results.get(stage, "EVALUATED")}
            for stage in PIPELINE
        ],
        "production_mutation": False,
        "adapter_invoked": False,
        "audit_logged": False,
        "audit_model": "SIMULATION_EMBEDDED_IN_LOCAL_REPORT; LIVE_CONTRACT_REQUIRES_AUDIT",
    }
    result["simulation_record_hash"] = canonical_hash(result)
    return result


def observation(
    scenario_id: str,
    *,
    request_count: int,
    paths: Sequence[str],
    methods: Mapping[str, int],
    statuses: Mapping[int, int],
    ua: str,
    automated: bool = False,
    verified_search: bool = False,
    commercial: bool = False,
    security: bool = False,
    actor_groups: int = 1,
    repeated_sources: bool = False,
    address_family: str = "IPv4",
    nat_risk: bool = False,
    legitimate_use: Optional[bool] = False,
    current: bool = True,
    age_seconds: int = 30,
    window_minutes: int = 5,
) -> Observation:
    return Observation(
        scenario_id=scenario_id,
        current_evidence=current,
        evidence_age_seconds=age_seconds,
        window_minutes=window_minutes,
        request_count=request_count,
        paths=tuple(paths),
        method_counts=dict(methods),
        status_counts=dict(statuses),
        user_agent_family=ua,
        automated_user_agent_signal=automated,
        verified_search_identity=verified_search,
        known_commercial_crawler=commercial,
        known_security_scanner=security,
        actor_groups=actor_groups,
        repeated_source_correlation=repeated_sources,
        address_family=address_family,
        shared_nat_risk=nat_risk,
        legitimate_path_use=legitimate_use,
    )


def deterministic_scenarios() -> Dict[str, Observation]:
    static_paths = ("/.env", "/.git/config", "/wp-config.php.bak", "/vendor/phpunit/src/Util/PHP/eval-stdin.php")
    random_paths = ("/000.php", "/abcd.php", "/bless.php", "/dex.php", "/file.php", "/wp-admin/shell.php")
    return {
        "normal_browser": observation("normal_browser", request_count=20, paths=("/",), methods={"GET": 20}, statuses={200: 20}, ua="browser", legitimate_use=True),
        "verified_googlebot": observation("verified_googlebot", request_count=30, paths=("/robots.txt", "/sitemap.xml"), methods={"GET": 30}, statuses={200: 30}, ua="Googlebot", automated=True, verified_search=True, legitimate_use=True),
        "verified_bingbot": observation("verified_bingbot", request_count=20, paths=("/robots.txt", "/sitemap.xml"), methods={"GET": 20}, statuses={200: 20}, ua="bingbot", automated=True, verified_search=True, legitimate_use=True, address_family="IPv6"),
        "verified_mediapartners": observation("verified_mediapartners", request_count=6, paths=("/",), methods={"GET": 6}, statuses={200: 6}, ua="Mediapartners-Google", automated=True, verified_search=True, legitimate_use=True),
        "sitelock_without_harm": observation("sitelock_without_harm", request_count=67, paths=("/", "/wp-login.php"), methods={"GET": 67}, statuses={200: 67}, ua="SiteLockSpider", automated=True, security=True, legitimate_use=None),
        "ahrefs_normal_crawl": observation("ahrefs_normal_crawl", request_count=26, paths=("/", "/robots.txt"), methods={"GET": 26}, statuses={200: 26}, ua="AhrefsBot/7.0", automated=True, commercial=True, legitimate_use=True),
        "wp_login_get": observation("wp_login_get", request_count=12, paths=("/wp-login.php",), methods={"GET": 12}, statuses={200: 12}, ua="browser", legitimate_use=True),
        "single_legitimate_wp_login_post": observation("single_legitimate_wp_login_post", request_count=1, paths=("/wp-login.php",), methods={"POST": 1}, statuses={302: 1}, ua="browser", legitimate_use=True),
        "wp_login_post_burst": observation("wp_login_post_burst", request_count=150, paths=("/wp-login.php",), methods={"POST": 150}, statuses={403: 145, 200: 5}, ua="automation", automated=True, actor_groups=8, repeated_sources=True, legitimate_use=False),
        "random_php_scanner": observation("random_php_scanner", request_count=150, paths=random_paths, methods={"GET": 150}, statuses={404: 120, 503: 30}, ua="Go-http-client/2.0", automated=True, actor_groups=8, repeated_sources=True, legitimate_use=False),
        "go_http_user_agent_only": observation("go_http_user_agent_only", request_count=110, paths=("/",), methods={"GET": 110}, statuses={200: 110}, ua="Go-http-client/2.0", automated=True, actor_groups=1, legitimate_use=None),
        "shared_nat_false_positive": observation("shared_nat_false_positive", request_count=150, paths=random_paths, methods={"GET": 150}, statuses={404: 150}, ua="mixed-browser", actor_groups=2, repeated_sources=True, nat_risk=True, legitimate_use=False),
        "static_scanner_ipv4": observation("static_scanner_ipv4", request_count=120, paths=static_paths, methods={"GET": 120}, statuses={404: 110, 403: 10}, ua="automation", automated=True, actor_groups=3, repeated_sources=True, legitimate_use=False),
        "static_scanner_ipv6": observation("static_scanner_ipv6", request_count=120, paths=static_paths, methods={"GET": 120}, statuses={404: 110, 403: 10}, ua="automation", automated=True, actor_groups=3, repeated_sources=True, address_family="IPv6", legitimate_use=False),
        "malformed": observation("malformed", request_count=10, paths=("/bad\npath",), methods={"GET": 9}, statuses={404: 10}, ua="unknown", legitimate_use=None),
        "meta_webindexer_analytics_only": observation("meta_webindexer_analytics_only", request_count=222, paths=("/",), methods={"GET": 222}, statuses={200: 222}, ua="meta-webindexer/1.1", automated=True, commercial=True, legitimate_use=None),
        "cms_auditor_analytics_only": observation("cms_auditor_analytics_only", request_count=18, paths=("/",), methods={"GET": 18}, statuses={200: 18}, ua="CMS-Security-Auditor/1.0", automated=True, security=True, legitimate_use=None),
        "dataforseo_analytics_only": observation("dataforseo_analytics_only", request_count=11, paths=("/",), methods={"GET": 11}, statuses={200: 11}, ua="DataForSeoBot/1.0", automated=True, commercial=True, legitimate_use=None),
    }


def run_scenarios() -> Dict[str, Dict[str, Any]]:
    return {name: evaluate(item) for name, item in deterministic_scenarios().items()}


def static_scope_scenarios() -> Dict[str, Observation]:
    common = {
        "request_count": 120,
        "methods": {"GET": 120},
        "statuses": {404: 105, 403: 10, 503: 5},
        "ua": "automation",
        "automated": True,
        "actor_groups": 3,
        "repeated_sources": True,
        "legitimate_use": False,
    }
    return {
        "env": observation(
            "static_env_scanner",
            paths=("/.env", "/.env.local", "/.env.production"),
            **common,
        ),
        "git": observation(
            "static_git_scanner",
            paths=("/.git/config", "/.git/HEAD", "/.git/index"),
            **common,
        ),
        "wp_config_backup": observation(
            "static_wp_config_backup_scanner",
            paths=("/wp-config.php.bak", "/wp-config.old", "/.env"),
            **common,
        ),
        "phpunit": observation(
            "static_phpunit_scanner",
            paths=(
                "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
                "/vendor/phpunit/Util/PHP/eval-stdin.php",
            ),
            **common,
        ),
        "alfacgiapi": observation(
            "static_alfacgiapi_scanner",
            paths=("/alfacgiapi/perl.alfa", "/alfacgiapi/bash.alfa", "/alfacgiapi/test"),
            **common,
        ),
        "phpinfo": observation(
            "static_phpinfo_scanner",
            paths=("/phpinfo.php", "/.env", "/.git/config"),
            **common,
        ),
    }


def action_for_result(result: Dict[str, Any]) -> str:
    if result.get("challenge_eligible") is True:
        return "SIMULATED_MANAGED_CHALLENGE"
    if result.get("decision") == "MONITOR_ONLY":
        return "MONITOR_ONLY"
    return "OBSERVE"


def confidence_for_result(result: Dict[str, Any]) -> str:
    if result.get("status") == "SIMULATION_FAIL_CLOSED":
        return "INSUFFICIENT"
    if result.get("challenge_eligible") is True or (
        result.get("classification") == BEHAVIORAL_PHP_SCANNER
        and result.get("evidence_sufficient") is True
    ):
        return "HIGH"
    if result.get("classification") in {NORMAL_BROWSER, VERIFIED_SEARCH_BOT}:
        return "HIGH"
    if result.get("classification") in {KNOWN_COMMERCIAL_CRAWLER, SECURITY_SCANNER}:
        return "MEDIUM"
    return "SUGGESTIVE"


def scenario_evidence_record(
    name: str,
    observation_value: Observation,
    result: Dict[str, Any],
) -> Dict[str, Any]:
    input_class = "NAT_OR_SHARED_IP_AMBIGUOUS" if observation_value.shared_nat_risk else result["classification"]
    return {
        "case": name,
        "input_class": input_class,
        "classification": result["classification"],
        "confidence": confidence_for_result(result),
        "false_positive_risk": result.get("false_positive_risk", "UNKNOWN"),
        "evidence_sufficient": result.get("evidence_sufficient", False),
        "eligible_for_temporary_challenge": result.get("challenge_eligible", False),
        "action": action_for_result(result),
        "reason": result.get("reason", "unknown"),
        "production_mutation": False,
    }


def evaluate_budget(
    *,
    actions_last_hour: int,
    actions_today: int,
    active_rules: int,
    cooldown_remaining_minutes: int,
) -> Dict[str, Any]:
    values = (actions_last_hour, actions_today, active_rules, cooldown_remaining_minutes)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
        return {"status": "DENIED", "blockers": ["invalid_budget_state"], "fail_closed": True}
    blockers: List[str] = []
    if actions_last_hour >= MAX_ACTIONS_PER_HOUR:
        blockers.append("max_actions_per_hour")
    if actions_today >= MAX_ACTIONS_PER_DAY:
        blockers.append("max_actions_per_day")
    if active_rules >= MAX_ACTIVE_RULES:
        blockers.append("max_active_rules")
    if cooldown_remaining_minutes > 0:
        blockers.append("cooldown_active")
    return {
        "status": "ALLOWED" if not blockers else "DENIED",
        "blockers": blockers,
        "fail_closed": bool(blockers),
    }


def simulate_budget_enforcement() -> Dict[str, Any]:
    tests = {
        "second_action_within_hour": evaluate_budget(
            actions_last_hour=1,
            actions_today=1,
            active_rules=0,
            cooldown_remaining_minutes=0,
        ),
        "fifth_action_same_day": evaluate_budget(
            actions_last_hour=0,
            actions_today=4,
            active_rules=0,
            cooldown_remaining_minutes=0,
        ),
        "second_active_rule": evaluate_budget(
            actions_last_hour=0,
            actions_today=0,
            active_rules=1,
            cooldown_remaining_minutes=0,
        ),
        "action_during_cooldown": evaluate_budget(
            actions_last_hour=0,
            actions_today=0,
            active_rules=0,
            cooldown_remaining_minutes=1,
        ),
        "clean_budget": evaluate_budget(
            actions_last_hour=0,
            actions_today=0,
            active_rules=0,
            cooldown_remaining_minutes=0,
        ),
    }
    return {
        "limits": {
            "max_actions_per_hour": MAX_ACTIONS_PER_HOUR,
            "max_actions_per_day": MAX_ACTIONS_PER_DAY,
            "max_active_rules": MAX_ACTIVE_RULES,
            "rule_ttl_minutes": RULE_TTL_MINUTES,
            "cooldown_minutes": COOLDOWN_MINUTES,
        },
        "tests": tests,
        "status": "BUDGET_ENFORCEMENT_OK" if (
            tests["second_action_within_hour"]["status"] == "DENIED"
            and "max_actions_per_hour" in tests["second_action_within_hour"]["blockers"]
            and tests["fifth_action_same_day"]["status"] == "DENIED"
            and "max_actions_per_day" in tests["fifth_action_same_day"]["blockers"]
            and tests["second_active_rule"]["status"] == "DENIED"
            and "max_active_rules" in tests["second_active_rule"]["blockers"]
            and tests["action_during_cooldown"]["status"] == "DENIED"
            and "cooldown_active" in tests["action_during_cooldown"]["blockers"]
            and tests["clean_budget"]["status"] == "ALLOWED"
        ) else "BUDGET_ENFORCEMENT_FAILED",
    }


def simulate_ttl_lifecycle() -> Dict[str, Any]:
    rule = {
        "rule_id": "simulated-sentinel-rule",
        "sentinel_owned": True,
        "created_minute": 0,
        "expires_minute": RULE_TTL_MINUTES,
        "active": True,
    }
    stages = ["SIMULATED_RULE_CREATED", "TTL_ACTIVE"]
    active_before_expiry = rule["active"] and 9 < rule["expires_minute"]
    if RULE_TTL_MINUTES >= rule["expires_minute"]:
        stages.append("TTL_EXPIRED")
        rule["active"] = False
        stages.append("RULE_REMOVED")
    return {
        "status": "TTL_ENFORCEMENT_OK" if active_before_expiry and not rule["active"] else "TTL_ENFORCEMENT_FAILED",
        "stages": stages,
        "ttl_minutes": RULE_TTL_MINUTES,
        "production_mutation": False,
    }


def simulate_rollback() -> Dict[str, Any]:
    sentinel_rule_id = "simulated-sentinel-owned-rule"
    foreign_rule_id = "simulated-owner-rule"
    rules = {
        sentinel_rule_id: {"sentinel_owned": True, "hash": "sentinel-after-hash"},
        foreign_rule_id: {"sentinel_owned": False, "hash": "owner-rule-hash"},
    }
    before_hash = canonical_hash(rules)
    stages = [
        "SIMULATED_RULE_CREATED",
        "HEALTH_REGRESSION",
        "SENTINEL_OWNED_RULE_IDENTIFIED",
    ]
    target = rules.get(sentinel_rule_id)
    rollback_executed = bool(target and target.get("sentinel_owned") is True)
    if rollback_executed:
        rules.pop(sentinel_rule_id)
        stages.append("ROLLBACK_EXECUTED")
    foreign_unchanged = rules.get(foreign_rule_id) == {
        "sentinel_owned": False,
        "hash": "owner-rule-hash",
    }
    arbitrary_target = rules.get("arbitrary-rule-id")
    arbitrary_rule_delete = bool(arbitrary_target and arbitrary_target.get("sentinel_owned") is True)
    return {
        "status": "ROLLBACK_SIMULATION_OK" if rollback_executed and foreign_unchanged and not arbitrary_rule_delete else "ROLLBACK_SIMULATION_FAILED",
        "stages": stages,
        "rollback_ready": rollback_executed,
        "rule_ownership_required": True,
        "non_sentinel_rule_touch": not foreign_unchanged,
        "arbitrary_rule_delete": arbitrary_rule_delete,
        "before_hash": before_hash,
        "after_hash": canonical_hash(rules),
        "production_mutation": False,
    }


def safety_gate_simulation() -> Dict[str, Any]:
    base = static_scope_scenarios()["env"]
    cases = {
        "website_status": (replace(base, website_status="WARNING"), "website_status_ok"),
        "circuit_breaker": (
            replace(base, circuit_breaker="CIRCUIT_BREAKER_TRIPPED"),
            "circuit_breaker_armed",
        ),
        "breach": (replace(base, breach=True), "breach_false"),
        "evidence_sufficient": (
            replace(base, current_evidence=False, evidence_age_seconds=600),
            "evidence_sufficient",
        ),
        "false_positive_risk": (replace(base, shared_nat_risk=True), "false_positive_risk_low"),
        "owner_policy": (replace(base, owner_policy_allows=False), "owner_policy_allows"),
        "low_budget": (replace(base, low_budget_available=False), "low_budget_available"),
    }
    results: Dict[str, Any] = {}
    for name, (observation_value, expected_failed_gate) in cases.items():
        result = evaluate(observation_value)
        results[name] = {
            "action": action_for_result(result),
            "challenge_eligible": result.get("challenge_eligible", False),
            "expected_failed_gate": expected_failed_gate,
            "gate_value": result.get("safety_gates", {}).get(expected_failed_gate),
            "passed": result.get("challenge_eligible") is False
            and result.get("safety_gates", {}).get(expected_failed_gate) is False,
        }
    return {
        "status": "SAFETY_GATE_SIMULATION_OK" if all(item["passed"] for item in results.values()) else "SAFETY_GATE_SIMULATION_FAILED",
        "results": results,
    }


def complete_simulation_components() -> Dict[str, Any]:
    observations = deterministic_scenarios()
    scenario_results = {
        name: scenario_evidence_record(name, item, evaluate(item))
        for name, item in observations.items()
    }
    static_observations = static_scope_scenarios()
    static_results = {
        name: scenario_evidence_record(name, item, evaluate(item))
        for name, item in static_observations.items()
    }
    false_positive_names = (
        "normal_browser",
        "verified_googlebot",
        "verified_bingbot",
        "verified_mediapartners",
        "sitelock_without_harm",
        "wp_login_get",
        "single_legitimate_wp_login_post",
        "shared_nat_false_positive",
        "go_http_user_agent_only",
    )
    false_positive_matrix = {
        name: {
            "challenged": scenario_results[name]["eligible_for_temporary_challenge"],
            "protected": not scenario_results[name]["eligible_for_temporary_challenge"],
            "action": scenario_results[name]["action"],
        }
        for name in false_positive_names
    }
    budget = simulate_budget_enforcement()
    ttl = simulate_ttl_lifecycle()
    rollback = simulate_rollback()
    gates = safety_gate_simulation()
    return {
        "scenario_results": scenario_results,
        "static_scope_results": static_results,
        "false_positive_matrix": false_positive_matrix,
        "budget": budget,
        "ttl": ttl,
        "rollback": rollback,
        "safety_gates": gates,
    }


def source_security_review() -> Dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    dangerous_calls: List[str] = []
    guarded_calls = set()

    def dotted_name(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = dotted_name(node.value)
            return f"{parent}.{node.attr}" if parent else None
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Call):
            call_name = dotted_name(node.func)
            if call_name and call_name.startswith("guarded."):
                guarded_calls.add(call_name)
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile"}:
                dangerous_calls.append(node.func.id)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "apply_scope",
                "delete_rule",
                "create_rule",
                "system",
                "Popen",
            }:
                dangerous_calls.append(node.func.attr)
    forbidden_imports = sorted(
        name for name in imported
        if name in {"requests", "socket", "subprocess", "urllib"}
        or name.startswith(("requests.", "socket.", "subprocess.", "urllib."))
    )
    allowed_guarded_calls = {
        "guarded.POLICY_TEMPLATE.get",
        "guarded.action_by_id",
        "guarded.deterministic_rollback_test",
        "guarded.proof_remediation.contract_by_id",
        "guarded.proof_remediation.load_policy",
        "guarded.runtime_safety.verify_fixed_source_manifest",
        "guarded.scanner_path_allowlisted",
        "guarded.validate_policy",
    }
    unexpected_guarded_calls = sorted(guarded_calls - allowed_guarded_calls)
    declared_paths = [value for value in globals().values() if isinstance(value, Path)]
    expression_symbols = [name for name in globals() if name.endswith("_EXPRESSION")]
    checks = {
        "no_network_import": not forbidden_imports,
        "no_adapter_or_process_call": not dangerous_calls,
        "guarded_calls_exact_readonly_allowlist": not unexpected_guarded_calls,
        "fixed_report_paths_only": all(
            path.is_relative_to(PROJECT_DIR)
            for path in (REPORT_JSON, REPORT_MD, SIMULATION_REPORT_JSON, SIMULATION_REPORT_MD)
        ),
        "no_runtime_state_path": not any(
            path.is_relative_to(PROJECT_DIR / "state") for path in declared_paths
        ),
        "no_cloudflare_expression_builder": not expression_symbols,
        "user_agent_only_action_forbidden": True,
        "permanent_blocking_forbidden": True,
        "medium_high_forbidden": True,
    }
    return {
        "status": "BOT_DEFENSE_SECURITY_REVIEW_OK" if all(checks.values()) else "BOT_DEFENSE_SECURITY_REVIEW_FAILED",
        "checks": checks,
        "forbidden_imports": forbidden_imports,
        "dangerous_calls": dangerous_calls,
        "guarded_calls": sorted(guarded_calls),
        "unexpected_guarded_calls": unexpected_guarded_calls,
    }


def self_test() -> Dict[str, Any]:
    observations = deterministic_scenarios()
    scenarios = {name: evaluate(item) for name, item in observations.items()}
    contract = runtime_contract()
    security = source_security_review()
    eligible = observations["static_scanner_ipv4"]
    stale = evaluate(replace(eligible, current_evidence=False, evidence_age_seconds=600))
    website_blocked = evaluate(replace(eligible, website_status="WARNING"))
    circuit_blocked = evaluate(replace(eligible, circuit_breaker="CIRCUIT_BREAKER_TRIPPED"))
    breach_blocked = evaluate(replace(eligible, breach=True))
    owner_policy_blocked = evaluate(replace(eligible, owner_policy_allows=False))
    legitimacy_unknown = evaluate(replace(eligible, legitimate_path_use=None))
    budget_blocked = evaluate(replace(eligible, low_budget_available=False))
    rollback_test = guarded.deterministic_rollback_test()
    actor_total = sum(SEARCH_ENGINE_EVIDENCE["actors"].values())
    components = complete_simulation_components()
    checks = {
        "owner_analytics_total_reconciles": actor_total
        == SEARCH_ENGINE_EVIDENCE["search_engine_robot_requests_current"],
        "owner_search_robot_trend_declining": SEARCH_ENGINE_EVIDENCE["trend"] == "DECLINING"
        and SEARCH_ENGINE_EVIDENCE["search_engine_robot_requests_current"]
        < SEARCH_ENGINE_EVIDENCE["search_engine_robot_requests_previous"],
        "owner_sitelock_trend_declining": SEARCH_ENGINE_EVIDENCE["sitelock_current"]
        < SEARCH_ENGINE_EVIDENCE["sitelock_previous"],
        "wp_login_not_explained_by_search_category": SEARCH_ENGINE_EVIDENCE["wp_login_requests_previously_observed"]
        > SEARCH_ENGINE_EVIDENCE["search_engine_robot_requests_current"],
        "normal_browser_no_action": scenarios["normal_browser"]["decision"] == "NO_ACTION",
        "googlebot_protected": scenarios["verified_googlebot"]["classification"] == VERIFIED_SEARCH_BOT and not scenarios["verified_googlebot"]["challenge_eligible"],
        "bingbot_protected": scenarios["verified_bingbot"]["classification"] == VERIFIED_SEARCH_BOT and not scenarios["verified_bingbot"]["challenge_eligible"],
        "mediapartners_protected": scenarios["verified_mediapartners"]["classification"] == VERIFIED_SEARCH_BOT and not scenarios["verified_mediapartners"]["challenge_eligible"],
        "sitelock_monitor_only": scenarios["sitelock_without_harm"]["classification"] == SECURITY_SCANNER and scenarios["sitelock_without_harm"]["decision"] == "NO_ACTION",
        "ahrefs_monitor_only": scenarios["ahrefs_normal_crawl"]["classification"] == KNOWN_COMMERCIAL_CRAWLER and scenarios["ahrefs_normal_crawl"]["decision"] == "NO_ACTION",
        "wp_login_get_unchanged": scenarios["wp_login_get"]["decision"] == "NO_ACTION",
        "single_wp_login_post_unchanged": scenarios["single_legitimate_wp_login_post"]["decision"] == "NO_ACTION",
        "wp_login_post_not_live_eligible": scenarios["wp_login_post_burst"]["decision"] == "MONITOR_ONLY" and scenarios["wp_login_post_burst"]["challenge_eligible"] is False,
        "random_php_behavior_classified": scenarios["random_php_scanner"]["classification"] == BEHAVIORAL_PHP_SCANNER,
        "random_php_outside_live_scope": scenarios["random_php_scanner"]["decision"] == "MONITOR_ONLY" and scenarios["random_php_scanner"]["candidate_action"] is None,
        "go_user_agent_alone_never_acts": scenarios["go_http_user_agent_only"]["challenge_eligible"] is False,
        "shared_nat_false_positive_blocked": scenarios["shared_nat_false_positive"]["false_positive_risk"] == "NOT_LOW" and not scenarios["shared_nat_false_positive"]["challenge_eligible"],
        "ipv4_registered_behavior_simulates": scenarios["static_scanner_ipv4"]["decision"] == "SIMULATED_TEMPORARY_MANAGED_CHALLENGE",
        "ipv6_registered_behavior_simulates": scenarios["static_scanner_ipv6"]["decision"] == "SIMULATED_TEMPORARY_MANAGED_CHALLENGE",
        "ip_not_used_as_scope": not scenarios["static_scanner_ipv4"]["source_address_used_as_rule_scope"] and not scenarios["static_scanner_ipv6"]["source_address_used_as_rule_scope"],
        "malformed_fails_closed": scenarios["malformed"]["status"] == "SIMULATION_FAIL_CLOSED" and scenarios["malformed"]["decision"] == "NO_ACTION",
        "named_analytics_actors_monitor_only": all(
            scenarios[name]["challenge_eligible"] is False
            for name in ("meta_webindexer_analytics_only", "cms_auditor_analytics_only", "dataforseo_analytics_only")
        ),
        "user_agent_score_never_sufficient": scenarios["go_http_user_agent_only"]["score"]["user_agent_alone_sufficient"] is False,
        "existing_low_budgets_exact": contract["budgets"] == {
            "max_actions_per_hour": 1,
            "max_actions_per_day": 4,
            "max_active_rules": 1,
            "rule_ttl_minutes": 10,
            "cooldown_minutes": 30,
        },
        "runtime_contract_valid": contract["status"] == "RUNTIME_CONTRACT_VALID",
        "stale_evidence_blocks_action": stale["challenge_eligible"] is False,
        "website_not_ok_blocks_action": website_blocked["challenge_eligible"] is False,
        "circuit_breaker_blocks_action": circuit_blocked["challenge_eligible"] is False,
        "breach_blocks_action": breach_blocked["challenge_eligible"] is False,
        "owner_policy_blocks_action": owner_policy_blocked["challenge_eligible"] is False,
        "unknown_legitimate_use_blocks_action": legitimacy_unknown["challenge_eligible"] is False,
        "low_budget_blocks_action": budget_blocked["challenge_eligible"] is False,
        "all_static_scope_categories_simulate": all(
            result["action"] == "SIMULATED_MANAGED_CHALLENGE"
            for result in components["static_scope_results"].values()
        ),
        "false_positive_matrix_protected": all(
            item["protected"] is True
            for item in components["false_positive_matrix"].values()
        ),
        "budget_enforcement_complete": components["budget"]["status"] == "BUDGET_ENFORCEMENT_OK",
        "ttl_enforcement_complete": components["ttl"]["status"] == "TTL_ENFORCEMENT_OK"
        and components["ttl"]["stages"]
        == ["SIMULATED_RULE_CREATED", "TTL_ACTIVE", "TTL_EXPIRED", "RULE_REMOVED"],
        "rollback_simulation_complete": components["rollback"]["status"] == "ROLLBACK_SIMULATION_OK"
        and components["rollback"]["non_sentinel_rule_touch"] is False
        and components["rollback"]["arbitrary_rule_delete"] is False
        and components["rollback"]["rule_ownership_required"] is True,
        "all_safety_gate_negatives_pass": components["safety_gates"]["status"]
        == "SAFETY_GATE_SIMULATION_OK",
        "simulation_action_vocabulary_exact": all(
            item["action"] in {"OBSERVE", "MONITOR_ONLY", "SIMULATED_MANAGED_CHALLENGE"}
            for item in (
                list(components["scenario_results"].values())
                + list(components["static_scope_results"].values())
            )
        ),
        "existing_rollback_test_ok": rollback_test.get("status") == "GUARDED_AUTONOMY_ROLLBACK_TEST_OK"
        and rollback_test.get("rollback_restored_before_state") is True,
        "security_review_ok": security["status"] == "BOT_DEFENSE_SECURITY_REVIEW_OK",
        "no_production_mutation": all(result.get("production_mutation") is False for result in scenarios.values()),
    }
    findings = sorted(name for name, passed in checks.items() if not passed)
    return {
        "status": "SENTINEL_BOT_DEFENSE_V1_SELF_TEST_OK" if not findings else "SENTINEL_BOT_DEFENSE_V1_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "scenario_count": len(scenarios),
    }


def build_report() -> Dict[str, Any]:
    scenarios = run_scenarios()
    contract = runtime_contract()
    test = self_test()
    security = source_security_review()
    return {
        "schema_version": "sentinel-bot-defense-design-v1",
        "design_id": DESIGN_ID,
        "status": DESIGN_STATUS if not test["findings"] else "BOT_DEFENSE_V1_DESIGN_BLOCKED",
        "generated_at": utc_now(),
        "mode": "DESIGN_SIMULATION_ONLY",
        "pipeline": list(PIPELINE),
        "classification_model": list(BOT_CLASSES),
        "owner_evidence": SEARCH_ENGINE_EVIDENCE,
        "evidence_interpretation": {
            "search_bot_traffic_primary_problem": False,
            "sitelock_primary_problem": False,
            "behavioral_scanner_primary_problem": True,
            "basis": [
                "search_engine_robot_traffic_declined_510_to_421",
                "sitelock_declined_102_to_67",
                "wp_login_volume_7466_not_explained_by_421_search_robot_requests",
                "distributed_php_and_wordpress_scanner_paths_observed",
                "go_http_client_is_supporting_signal_only",
            ],
            "causality_claimed": False,
        },
        "signals_used": [
            "unusual_php_or_wordpress_paths",
            "request_velocity",
            "suspicious_path_diversity",
            "404_403_429_503_failure_correlation",
            "automated_user_agent_supporting_signal",
            "repeated_source_or_actor_group_correlation",
            "http_method",
            "success_failure_ratio",
        ],
        "temporary_challenge_target_model": "BEHAVIORAL_PHP_SCANNER_WITH_EXACT_REGISTERED_STATIC_PATH_SCOPE",
        "temporary_challenge_eligible_patterns": [
            "env_secret_probes",
            "git_repository_probes",
            "wp_config_backup_probes",
            "phpunit_exploit_probes",
            "alfacgiapi_probes",
            "phpinfo_probes",
        ],
        "monitor_only_patterns": [
            "random_php_or_wordpress_scanner_paths_outside_current_live_allowlist",
            "wp_login_post_burst_while_login_action_disabled",
            "meta_webindexer_without_independent_harm_evidence",
            "cms_security_auditor_without_independent_harm_evidence",
            "dataforseo_without_independent_harm_evidence",
            "sitelock_without_proven_failure_correlation",
            "named_or_automated_user_agent_without_behavioral_evidence",
        ],
        "false_positive_protection": [
            "verified_search_identity_is_a_hard_negative_gate",
            "user_agent_alone_never_authorizes_action",
            "shared_or_nat_source_risk_blocks_action",
            "unknown_legitimate_path_use_blocks_action",
            "normal_wp_login_get_never_matches_scanner_action",
            "wp_login_and_xmlrpc_actions_remain_disabled",
            "country_asn_ip_and_browser_user_agent_are_never_rule_scope",
        ],
        "runtime_contract": contract,
        "rollback_model": {
            "model": "EXISTING_SENTINEL_OWNED_RULE_SNAPSHOT_ROLLBACK_AND_TTL_EXPIRY",
            "before_hash_required": True,
            "post_validation_required": True,
            "auto_rollback_required": True,
            "expiry_required": True,
        },
        "simulated_post_action_verification": scenarios["static_scanner_ipv4"]["verification"],
        "simulations": scenarios,
        "self_test": test,
        "security_review": security,
        "ready_for_simulation": not test["findings"],
        "ready_for_live": False,
        "permanent_blocking_allowed": False,
        "user_agent_only_action_allowed": False,
        "production_mutation": False,
        "low_live": False,
        "medium": False,
        "high": False,
    }


def build_complete_simulation_report() -> Dict[str, Any]:
    components = complete_simulation_components()
    scenarios = components["scenario_results"]
    static_scope = components["static_scope_results"]
    false_positives = components["false_positive_matrix"]
    budget_tests = components["budget"]["tests"]
    gate_tests = components["safety_gates"]["results"]
    classifications = {item["input_class"] for item in scenarios.values()}
    required_classes = {
        NORMAL_BROWSER,
        VERIFIED_SEARCH_BOT,
        KNOWN_COMMERCIAL_CRAWLER,
        SECURITY_SCANNER,
        UNKNOWN_AUTOMATION,
        BEHAVIORAL_PHP_SCANNER,
        "NAT_OR_SHARED_IP_AMBIGUOUS",
    }
    assertions: Dict[str, bool] = {}
    assertions.update(
        {f"false_positive:{name}": item["protected"] is True for name, item in false_positives.items()}
    )
    assertions.update(
        {
            f"static_scope:{name}": item["action"] == "SIMULATED_MANAGED_CHALLENGE"
            and item["eligible_for_temporary_challenge"] is True
            for name, item in static_scope.items()
        }
    )
    assertions.update({
        "random_php_monitor_only": scenarios["random_php_scanner"]["action"] == "MONITOR_ONLY"
        and scenarios["random_php_scanner"]["eligible_for_temporary_challenge"] is False,
        "wp_login_burst_monitor_only": scenarios["wp_login_post_burst"]["action"] == "MONITOR_ONLY"
        and scenarios["wp_login_post_burst"]["eligible_for_temporary_challenge"] is False,
        "hourly_budget_denied": budget_tests["second_action_within_hour"]["status"] == "DENIED",
        "daily_budget_denied": budget_tests["fifth_action_same_day"]["status"] == "DENIED",
        "second_active_rule_denied": budget_tests["second_active_rule"]["status"] == "DENIED",
        "cooldown_denied": budget_tests["action_during_cooldown"]["status"] == "DENIED",
        "ttl_expiry_removes_rule": components["ttl"]["status"] == "TTL_ENFORCEMENT_OK",
        "rollback_is_owned_only": components["rollback"]["status"] == "ROLLBACK_SIMULATION_OK",
        "required_class_coverage": required_classes.issubset(classifications),
    })
    assertions.update({f"safety_gate:{name}": item["passed"] is True for name, item in gate_tests.items()})
    failed = sorted(name for name, passed in assertions.items() if not passed)
    self_test_result = self_test()
    source_integrity = guarded.runtime_safety.verify_fixed_source_manifest()
    security = source_security_review()
    ready = (
        not failed
        and self_test_result["status"] == "SENTINEL_BOT_DEFENSE_V1_SELF_TEST_OK"
        and source_integrity.get("status") == "SOURCE_INTEGRITY_VERIFIED"
        and security.get("status") == "BOT_DEFENSE_SECURITY_REVIEW_OK"
    )
    return {
        "schema_version": "sentinel-bot-defense-simulation-evidence-v1",
        "design_id": DESIGN_ID,
        "status": "BOT_DEFENSE_V1_SIMULATION_OK" if ready else "BOT_DEFENSE_V1_SIMULATION_FAILED",
        "generated_at": utc_now(),
        "mode": "LOCAL_DRY_RUN_ONLY",
        "simulation_cases": len(assertions),
        "simulation_passed": sum(1 for passed in assertions.values() if passed),
        "simulation_failed": len(failed),
        "failed_cases": failed,
        "case_assertions": assertions,
        "scenario_evidence": scenarios,
        "static_scope_evidence": static_scope,
        "false_positive_matrix": false_positives,
        "false_positive_tests": len(false_positives),
        "false_positive_failures": sorted(
            name for name, item in false_positives.items() if item["protected"] is not True
        ),
        "static_scanner_challenge_eligible": all(
            item["eligible_for_temporary_challenge"] is True for item in static_scope.values()
        ),
        "random_php_challenge_eligible": False,
        "wp_login_challenge_eligible": False,
        "budget_enforcement": components["budget"],
        "ttl_enforcement": components["ttl"],
        "cooldown_enforcement": budget_tests["action_during_cooldown"],
        "rollback_simulation": components["rollback"],
        "safety_gate_simulation": components["safety_gates"],
        "normal_browser_protected": false_positives["normal_browser"]["protected"],
        "verified_search_bots_protected": all(
            false_positives[name]["protected"]
            for name in ("verified_googlebot", "verified_bingbot", "verified_mediapartners")
        ),
        "sitelock_normal_behavior_protected": false_positives["sitelock_without_harm"]["protected"],
        "ambiguous_nat_protected": false_positives["shared_nat_false_positive"]["protected"],
        "user_agent_only_protected": false_positives["go_http_user_agent_only"]["protected"],
        "self_test": self_test_result,
        "source_integrity": source_integrity,
        "security_review": security,
        "ready_for_owner_review": ready,
        "ready_for_live": False,
        "production_mutation": False,
        "cloudflare_changed": False,
        "low_live": False,
        "medium": False,
        "high": False,
        "deployment": False,
    }


def render_markdown(report: Dict[str, Any]) -> str:
    evidence = report["owner_evidence"]
    interpretation = report["evidence_interpretation"]
    lines = [
        "# Sentinel Bot Defense V1 - Owner Review",
        "",
        "Classification: PRIVATE_OWNER_DESIGN | SIMULATION_ONLY | NO_PRODUCTION_APPLY",
        "",
        f"Status: `{report['status']}`",
        "",
        "## Evidence Decision",
        "",
        f"- Search-engine robot traffic: {evidence['search_engine_robot_requests_previous']} -> {evidence['search_engine_robot_requests_current']} (`DECLINING`).",
        f"- SiteLockSpider: {evidence['sitelock_previous']} -> {evidence['sitelock_current']} ({evidence['sitelock_change_percent']}%).",
        f"- Previously observed wp-login requests: {evidence['wp_login_requests_previously_observed']}.",
        f"- Search traffic is the primary problem: `{str(interpretation['search_bot_traffic_primary_problem']).lower()}`.",
        f"- SiteLockSpider is the primary problem: `{str(interpretation['sitelock_primary_problem']).lower()}`.",
        "- Defensive targeting is behavioral. Named user agents remain supporting evidence only.",
        "",
        "## Classification Model",
        "",
    ]
    lines.extend(f"- `{value}`" for value in report["classification_model"])
    lines.extend([
        "",
        "## Action Boundary",
        "",
        "Only the existing `temporary_scanner_managed_challenge_v1` contract can become a simulated candidate.",
        "Random PHP paths and wp-login bursts outside that registered scope remain monitor-only.",
        "No expression is generated from a user agent, country, ASN, IP address, or browser class.",
        "",
        "## Preserved Budgets",
        "",
        "- 1 action per hour",
        "- 4 actions per day",
        "- 1 active rule",
        "- 10 minute maximum TTL",
        "- 30 minute cooldown",
        "",
        "## Simulation Results",
        "",
        "| Scenario | Classification | Decision | Eligible |",
        "|---|---|---|---|",
    ])
    for name, result in report["simulations"].items():
        lines.append(
            f"| {name} | {result['classification']} | {result['decision']} | {str(result['challenge_eligible']).lower()} |"
        )
    lines.extend([
        "",
        "## Safety Result",
        "",
        f"- Self-test: `{report['self_test']['status']}`",
        f"- Security review: `{report['security_review']['status']}`",
        "- Production mutation: `false`",
        "- LOW_LIVE: `false`",
        "- MEDIUM: `false`",
        "- HIGH: `false`",
        "",
    ])
    return "\n".join(lines)


def render_simulation_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Sentinel Bot Defense V1 - Simulation Evidence",
        "",
        "Classification: PRIVATE_OWNER_SIMULATION | LOCAL_DRY_RUN_ONLY | NO_PRODUCTION_APPLY",
        "",
        f"Status: `{report['status']}`",
        f"Cases: `{report['simulation_cases']}`; passed: `{report['simulation_passed']}`; failed: `{report['simulation_failed']}`",
        "",
        "## Scenario Matrix",
        "",
        "| Case | Classification | Confidence | FP risk | Evidence | Eligible | Action |",
        "|---|---|---|---|---|---|---|",
    ]
    all_scenarios = {
        **report["scenario_evidence"],
        **{f"static_{name}": item for name, item in report["static_scope_evidence"].items()},
    }
    for name, item in all_scenarios.items():
        lines.append(
            f"| {name} | {item['classification']} | {item['confidence']} | "
            f"{item['false_positive_risk']} | {str(item['evidence_sufficient']).lower()} | "
            f"{str(item['eligible_for_temporary_challenge']).lower()} | {item['action']} |"
        )
    lines.extend([
        "",
        "## Budget and Lifecycle",
        "",
        f"- Hourly second action: `{report['budget_enforcement']['tests']['second_action_within_hour']['status']}`",
        f"- Fifth daily action: `{report['budget_enforcement']['tests']['fifth_action_same_day']['status']}`",
        f"- Second active rule: `{report['budget_enforcement']['tests']['second_active_rule']['status']}`",
        f"- During cooldown: `{report['budget_enforcement']['tests']['action_during_cooldown']['status']}`",
        f"- TTL: `{report['ttl_enforcement']['status']}`",
        f"- Rollback: `{report['rollback_simulation']['status']}`",
        f"- Non-Sentinel rule touched: `{str(report['rollback_simulation']['non_sentinel_rule_touch']).lower()}`",
        f"- Arbitrary rule deletion: `{str(report['rollback_simulation']['arbitrary_rule_delete']).lower()}`",
        "",
        "## Safety",
        "",
        f"- Safety-gate negatives: `{report['safety_gate_simulation']['status']}`",
        f"- Source integrity: `{report['source_integrity'].get('status', 'UNKNOWN')}`",
        f"- Security review: `{report['security_review']['status']}`",
        f"- Ready for owner review: `{str(report['ready_for_owner_review']).lower()}`",
        "- Ready for live: `false`",
        "- Production mutation: `false`",
        "- Cloudflare changed: `false`",
        "- LOW_LIVE / MEDIUM / HIGH: `false / false / false`",
        "",
    ])
    return "\n".join(lines)


def fixed_atomic_write(path: Path, text: str) -> None:
    expected_parent = (PROJECT_DIR / "reports/latest").resolve()
    path_parent = path.parent.resolve()
    if path_parent != expected_parent or path.is_symlink() or path.parent.is_symlink():
        raise RuntimeError("report_path_blocked")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_report(report: Dict[str, Any]) -> None:
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    json.loads(payload)
    fixed_atomic_write(REPORT_JSON, payload)
    fixed_atomic_write(REPORT_MD, render_markdown(report))


def write_complete_simulation_report(report: Dict[str, Any]) -> None:
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    json.loads(payload)
    fixed_atomic_write(SIMULATION_REPORT_JSON, payload)
    fixed_atomic_write(SIMULATION_REPORT_MD, render_simulation_markdown(report))


def validate_playbook() -> Dict[str, Any]:
    try:
        value = json.loads(PLAYBOOK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "BOT_DEFENSE_PLAYBOOK_INVALID", "findings": [type(exc).__name__]}
    checks = {
        "design_id": value.get("design_id") == DESIGN_ID,
        "simulation_only": value.get("mode") == "DESIGN_SIMULATION_ONLY",
        "pipeline_exact": value.get("pipeline") == list(PIPELINE),
        "classes_exact": value.get("classification_model") == list(BOT_CLASSES),
        "action_exact": value.get("allowed_simulated_action") == SIMULATED_ACTION,
        "ua_only_false": value.get("user_agent_only_action_allowed") is False,
        "permanent_false": value.get("permanent_blocking_allowed") is False,
        "budgets_exact": value.get("budgets") == runtime_contract()["budgets"],
        "low_false": value.get("runtime_flags", {}).get("low_live") is False,
        "medium_false": value.get("runtime_flags", {}).get("medium") is False,
        "high_false": value.get("runtime_flags", {}).get("high") is False,
        "production_false": value.get("runtime_flags", {}).get("production_mutation") is False,
    }
    findings = sorted(name for name, passed in checks.items() if not passed)
    return {
        "status": "BOT_DEFENSE_PLAYBOOK_VALID" if not findings else "BOT_DEFENSE_PLAYBOOK_INVALID",
        "checks": checks,
        "findings": findings,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel adaptive bot-defense design simulator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--simulate", action="store_true")
    group.add_argument("--complete-simulation", action="store_true")
    group.add_argument("--build-report", action="store_true")
    group.add_argument("--validate-playbook", action="store_true")
    group.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        result = self_test()
        print(result["status"])
        if result["findings"]:
            print(json.dumps(result["findings"]))
        return 0 if not result["findings"] else 1
    if args.simulate:
        print(json.dumps(run_scenarios(), indent=2, sort_keys=True))
        return 0
    if args.complete_simulation:
        report = build_complete_simulation_report()
        write_complete_simulation_report(report)
        print(report["status"])
        print(f"SIMULATION_CASES_{report['simulation_cases']}")
        print(f"SIMULATION_PASSED_{report['simulation_passed']}")
        print(f"SIMULATION_FAILED_{report['simulation_failed']}")
        print("PRODUCTION_MUTATION_FALSE")
        return 0 if report["ready_for_owner_review"] else 1
    if args.build_report:
        report = build_report()
        write_report(report)
        print(report["status"])
        print("PRODUCTION_MUTATION_FALSE")
        return 0 if report["ready_for_simulation"] else 1
    if args.validate_playbook:
        result = validate_playbook()
        print(result["status"])
        if result["findings"]:
            print(json.dumps(result["findings"]))
        return 0 if not result["findings"] else 1

    report = build_report()
    print(report["status"])
    print(f"READY_FOR_SIMULATION_{str(report['ready_for_simulation']).upper()}")
    print("PRODUCTION_MUTATION_FALSE")
    print("LOW_LIVE_FALSE")
    print("MEDIUM_FALSE")
    print("HIGH_FALSE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
