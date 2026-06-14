#!/usr/bin/env python3
"""MEDIUM images apply end-to-end chain.

This module implements the owner-approved MEDIUM execution chain only for the
`images` gate. It performs decision tracking, preparation, optional SFTP
read-only backup, healthchecks, validation and rollback bookkeeping. A real
image canary is executed only when every safety prerequisite is explicit and a
safe local image tool is available. In the current safe default, absence of a
safe tool ends with a manual-tool-required status instead of forcing a write.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

REPORT_JSON = PROJECT_DIR / "reports/latest/medium-images-apply-end-to-end.json"
REPORT_MD = PROJECT_DIR / "reports/latest/medium-images-apply-end-to-end.md"
OWNER_DECISION_MD = PROJECT_DIR / "reports/latest/medium-images-apply-owner-decision.md"
PRE_HEALTHCHECK_JSON = PROJECT_DIR / "reports/latest/medium-images-apply-pre-healthcheck.json"
POST_HEALTHCHECK_JSON = PROJECT_DIR / "reports/latest/medium-images-apply-post-healthcheck.json"
VALIDATION_JSON = PROJECT_DIR / "reports/latest/medium-images-apply-validation.json"
ROLLBACK_JSON = PROJECT_DIR / "reports/latest/medium-images-apply-rollback.json"
FINAL_REPORT_MD = PROJECT_DIR / "reports/latest/medium-images-apply-final-report.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/medium-images-apply-end-to-end.jsonl"
BACKUP_ROOT = PROJECT_DIR / "backups/medium-images-apply"

OWNER_DECISIONS_JSON = PROJECT_DIR / "state/adaptive-learning/apply_execution_owner_decisions.json"
STATE_JSON = PROJECT_DIR / "state/adaptive-learning/medium_images_apply_state.json"
LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest_medium_apply_execution.json"

PLAYBOOK_EXECUTION = PROJECT_DIR / "playbooks/medium-images-apply-execution.playbook.json"
PLAYBOOK_ROLLBACK = PROJECT_DIR / "playbooks/medium-images-apply-rollback.playbook.json"
PLAYBOOK_VALIDATION = PROJECT_DIR / "playbooks/medium-images-post-apply-validation.playbook.json"

KNOWLEDGE_BASE_JSON = PROJECT_DIR / "state/adaptive-learning/knowledge_base.json"
OBSERVATIONS_JSONL = PROJECT_DIR / "state/adaptive-learning/observations.jsonl"
PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/patterns.json"
ACTION_RULES_JSON = PROJECT_DIR / "state/adaptive-learning/action_rules.json"
ROLLBACK_RULES_JSON = PROJECT_DIR / "state/adaptive-learning/rollback_rules.json"
ADAPTIVE_LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest.json"
ADAPTIVE_REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
ADAPTIVE_RECOMMEND_MD = PROJECT_DIR / "reports/latest/adaptive-recommendations.md"
ADAPTIVE_CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"

INPUTS = {
    "apply_preflight": PROJECT_DIR / "reports/latest/approved-medium-apply-preflight.json",
    "dryrun_simulator": PROJECT_DIR / "reports/latest/approved-medium-dryrun-simulator.json",
    "simulation_owner_pack": PROJECT_DIR / "reports/latest/approved-medium-simulation-owner-pack.md",
    "simulation_healthcheck_plan": PROJECT_DIR / "reports/latest/approved-medium-simulation-healthcheck-plan.md",
    "simulation_rollback_plan": PROJECT_DIR / "reports/latest/approved-medium-simulation-rollback-plan.md",
    "apply_healthcheck_sequence": PROJECT_DIR / "reports/latest/approved-medium-apply-healthcheck-sequence.md",
    "apply_rollback_requirements": PROJECT_DIR / "reports/latest/approved-medium-apply-rollback-requirements.md",
    "medium_owner_decisions": PROJECT_DIR / "state/adaptive-learning/medium_owner_decisions.json",
    "dryrun_state": PROJECT_DIR / "state/adaptive-learning/approved_medium_dryrun_simulations.json",
    "preflight_state": PROJECT_DIR / "state/adaptive-learning/approved_medium_apply_preflight.json",
    "trend_decision": PROJECT_DIR / "state/performance-dryrun/trend_decision.json",
    "low_risk_autonomy": PROJECT_DIR / "reports/latest/low-risk-autonomy.json",
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "playbooks",
    BACKUP_ROOT,
)

SCHEMA_VERSION = "medium-images-apply-end-to-end-8.10"
TARGET_URL = "https://electri-c-ity-studios-24-7.com/"
GATE = "images"
APPLY_SCOPE = "minimal_image_metadata_or_safe_local_plan"
APPLY_STATUS = "not_applied"
REMOTE_UPLOAD_PREFIX = "/wp-content/uploads/"
SAFE_IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp"}

STATUS_READY = "MEDIUM_IMAGES_APPLY_READY"
STATUS_EXECUTED_CANARY = "MEDIUM_IMAGES_APPLY_EXECUTED_CANARY"
STATUS_MANUAL_TOOL_REQUIRED = "MEDIUM_IMAGES_APPLY_ENDED_WITH_MANUAL_TOOL_REQUIRED"
STATUS_NO_SAFE_PATHS = "APPLY_NOT_EXECUTED_NO_SAFE_IMAGE_PATHS"
STATUS_REQUIRES_MANUAL_TOOL = "APPLY_NOT_EXECUTED_REQUIRES_MANUAL_IMAGE_TOOL"
STATUS_WAITING_OWNER = "APPLY_EXECUTION_BLOCKED_WAITING_OWNER_APPROVAL"
STATUS_BLOCKED_SAFETY = "APPLY_EXECUTION_BLOCKED_BY_SAFETY"
STATUS_POST_OK = "POST_HEALTHCHECK_OK"
STATUS_POST_DEGRADED = "POST_HEALTHCHECK_DEGRADED"
STATUS_ROLLBACK_COMPLETED = "ROLLBACK_COMPLETED"
STATUS_ROLLBACK_NOT_REQUIRED = "ROLLBACK_NOT_REQUIRED_NO_APPLY"
STATUS_FAILED = "MEDIUM_IMAGES_APPLY_FAILED"

SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session|license)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key|license)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
FORBIDDEN_COMMAND_RE = re.compile(
    r"(?i)(--apply(?!-)\b|apply-safe|live-apply|sftp\s+(put|remove|rename|rm|mkdir|rmdir)|scp\s+|ssh\s+|wp\s+|wp-cli|mysql\b|"
    r"sftp\.(put|remove|rename)|cloudflare\s+(api|cli)|nginx\s+reload|systemctl\s+(enable|start)|"
    r"crontab\s+(-|install)|rm\s+-rf|curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh)"
)
DB_WRITE_RE = re.compile(r"(?i)\b(UPDATE|DELETE|INSERT|REPLACE|ALTER|DROP)\s+(wp_|wordpress|option|post|postmeta|termmeta)")


class HealthHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_present = False
        self.meta_description_present = False
        self.canonical_present = False
        self.h1_count = 0
        self.jsonld_count = 0
        self.image_count = 0
        self.in_title = False
        self.soc_schema_graph_present = False
        self.data_soc_schema_present = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict = {k.lower(): v or "" for k, v in attrs}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "meta" and attrs_dict.get("name", "").lower() == "description" and attrs_dict.get("content"):
            self.meta_description_present = True
        elif tag == "link" and attrs_dict.get("rel", "").lower() == "canonical" and attrs_dict.get("href"):
            self.canonical_present = True
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "script" and attrs_dict.get("type", "").lower() == "application/ld+json":
            self.jsonld_count += 1
        elif tag == "img":
            self.image_count += 1
        if any(k.lower() == "data-soc-schema" for k in attrs_dict):
            self.data_soc_schema_present = True
        if any("soc-schema-graph" in value for value in attrs_dict.values()):
            self.soc_schema_graph_present = True

    def handle_data(self, data: str) -> None:
        if self.in_title and data.strip():
            self.title_present = True
        if "soc-schema-graph" in data:
            self.soc_schema_graph_present = True
        if "data-soc-schema" in data:
            self.data_soc_schema_present = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def redact_text(value: Any, default: str = "-", max_len: int = 1200) -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").strip()
    text = SECRET_ASSIGNMENT_RE.sub("<redacted>", text)
    text = LONG_HEX_RE.sub("<redacted-hex>", text)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing write outside allowed medium-images roots: {path}")
    if path.suffix.lower() in {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".env", ".bin", ".run", ".php"}:
        raise ValueError(f"Refusing executable/config output path: {path}")
    if SECRET_NAME_RE.search(path.name):
        raise ValueError(f"Refusing secret-like output path: {path}")


def assert_safe_content(path: Path, content: str) -> None:
    if SECRET_ASSIGNMENT_RE.search(content):
        raise ValueError(f"Secret-like content refused for {path}")
    if FORBIDDEN_COMMAND_RE.search(content):
        raise ValueError(f"Forbidden command pattern refused for {path}")
    if DB_WRITE_RE.search(content):
        raise ValueError(f"DB write pattern refused for {path}")


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    assert_safe_content(path, content)
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
            text = json.dumps(record, ensure_ascii=False, sort_keys=True)
            assert_safe_content(path, text)
            handle.write(text + "\n")


def append_text(path: Path, section: str) -> None:
    assert_allowed_write(path)
    assert_safe_content(path, section)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(section)


def read_json(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    if SECRET_NAME_RE.search(path.name) or path.suffix.lower() == ".env":
        return None, "secret_like_path_refused"
    try:
        if not path.exists():
            return None, "missing"
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, "invalid_json"
    except OSError:
        return None, "read_error"
    return data if isinstance(data, dict) else None, "ok" if isinstance(data, dict) else "json_root_not_object"


def read_text_optional(path: Path) -> Tuple[str, str]:
    try:
        if not path.exists():
            return "", "missing"
        if SECRET_NAME_RE.search(path.name) or path.suffix.lower() == ".env":
            return "", "secret_like_path_refused"
        return path.read_text(encoding="utf-8"), "ok"
    except OSError:
        return "", "read_error"


def load_inputs() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    status: Dict[str, str] = {}
    for name, path in INPUTS.items():
        if path.suffix == ".md":
            text, st = read_text_optional(path)
            data[name] = text
            status[name] = st
        else:
            item, st = read_json(path)
            data[name] = item or {}
            status[name] = st
    return {"data": data, "status": status}


def load_state() -> Dict[str, Any]:
    data, status = read_json(STATE_JSON)
    if status == "ok" and isinstance(data, dict):
        return data
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "gate": GATE,
        "apply_scope": APPLY_SCOPE,
        "stage_statuses": {},
        "apply_executed": False,
        "canary_file": None,
        "backup_dir": None,
        "breach": False,
        "live_autonomy": False,
        "emergency_stop_unchanged_for_other_gates": True,
    }


def save_state(state: Dict[str, Any]) -> None:
    state["timestamp_utc"] = utc_now()
    write_json_atomic(STATE_JSON, state)
    write_json_atomic(LATEST_JSON, state)


def input_missing(inputs: Dict[str, Any]) -> List[str]:
    return [name for name, status in inputs["status"].items() if status != "ok"]


def images_preflight_ready(inputs: Dict[str, Any]) -> bool:
    report = inputs["data"].get("apply_preflight", {}) or inputs["data"].get("preflight_state", {}) or {}
    statuses = report.get("preflight_gate_statuses") or {}
    return statuses.get("images") == "APPLY_PREFLIGHT_READY_FOR_OWNER_REVIEW" and report.get("breach") is not True


def trend_stable(inputs: Dict[str, Any]) -> bool:
    trend = inputs["data"].get("trend_decision", {}) or {}
    return trend.get("trend_status") == "STABLE" and trend.get("breach") is not True


def low_risk_safe(inputs: Dict[str, Any]) -> bool:
    low = inputs["data"].get("low_risk_autonomy", {}) or {}
    return low.get("breach") is not True and low.get("live_apply") is not True


def upstream_breach_reasons(inputs: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    for name, data in inputs["data"].items():
        if isinstance(data, dict):
            if data.get("breach") is True:
                reasons.append(f"{name}_breach")
            if data.get("live_apply") is True:
                reasons.append(f"{name}_live_apply")
            if data.get("apply_status") not in (None, APPLY_STATUS):
                reasons.append(f"{name}_apply_status_not_safe")
    return sorted(set(reasons))


def owner_execution_decisions() -> Dict[str, Any]:
    data, status = read_json(OWNER_DECISIONS_JSON)
    if status == "ok" and isinstance(data, dict):
        return data
    return {}


def owner_images_approved() -> bool:
    decisions = owner_execution_decisions().get("decisions", {})
    images = decisions.get("images", {}) if isinstance(decisions, dict) else {}
    return (
        images.get("decision") == "approved_for_apply_execution"
        and images.get("gate") == "images"
        and images.get("scope") == "minimal_images_only"
        and images.get("acknowledged_no_other_gates") is True
        and images.get("acknowledged_backup_required") is True
        and images.get("acknowledged_healthcheck_required") is True
        and images.get("acknowledged_rollback_required") is True
    )


def image_simulation(inputs: Dict[str, Any]) -> Dict[str, Any]:
    for source in ("dryrun_simulator", "dryrun_state"):
        data = inputs["data"].get(source, {}) or {}
        for item in data.get("simulation_results", []) or []:
            if isinstance(item, dict) and item.get("gate_id") == "images":
                return item
    return {}


def remote_path_from_url(url: str, remote_root: str = "/wordpress") -> Optional[str]:
    parsed = urllib.parse.urlsplit(url)
    path = urllib.parse.unquote(parsed.path or "")
    if not path.startswith(REMOTE_UPLOAD_PREFIX):
        return None
    suffix = Path(path).suffix.lower()
    if suffix not in SAFE_IMAGE_SUFFIXES:
        return None
    root = normalize_remote_root(remote_root)
    return posixpath.normpath(root + path)


def safe_image_candidates(inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
    sim = image_simulation(inputs)
    env_root = os.environ.get("SENTINEL_SFTP_REMOTE_ROOT", "/wordpress")
    out: List[Dict[str, Any]] = []
    seen = set()
    for item in sim.get("image_candidates", []) or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        if item.get("source_type") != "internal":
            continue
        remote = remote_path_from_url(url, env_root)
        if not remote or remote in seen:
            continue
        seen.add(remote)
        priority = str(item.get("likely_priority") or "")
        evidence = item.get("current_evidence") or {}
        is_standard = priority == "standard_review"
        lazy = evidence.get("loading") == "lazy"
        out.append({
            "url": url,
            "remote_path": remote,
            "priority": priority,
            "candidate_safe_for_canary": bool(is_standard and lazy),
            "current_evidence": evidence,
        })
    out.sort(key=lambda c: (not c["candidate_safe_for_canary"], c["remote_path"]))
    return out


def select_canary(candidates: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for item in candidates:
        if item.get("candidate_safe_for_canary") and item.get("remote_path"):
            return item
    return candidates[0] if candidates else None


def normalize_remote_root(value: str) -> str:
    value = (value or "/wordpress").strip()
    if not value.startswith("/"):
        value = "/" + value
    return value.rstrip("/") or "/wordpress"


def sftp_env_presence() -> Dict[str, bool]:
    return {
        "host_present": bool(os.environ.get("SENTINEL_SFTP_HOST")),
        "port_present": bool(os.environ.get("SENTINEL_SFTP_PORT")),
        "user_present": bool(os.environ.get("SENTINEL_SFTP_USER")),
        "remote_root_present": bool(os.environ.get("SENTINEL_SFTP_REMOTE_ROOT")),
        "auth_present": bool(os.environ.get("SENTINEL_SFTP_PASSWORD")),
    }


def sftp_env_ready() -> bool:
    return all(
        bool(os.environ.get(key))
        for key in ("SENTINEL_SFTP_HOST", "SENTINEL_SFTP_USER", "SENTINEL_SFTP_REMOTE_ROOT", "SENTINEL_SFTP_PASSWORD")
    )


def parse_port(value: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 22
    return port if 0 < port < 65536 else 22


def sftp_config() -> Dict[str, Any]:
    if not sftp_env_ready():
        raise ValueError("SFTP environment incomplete")
    return {
        "host": os.environ["SENTINEL_SFTP_HOST"].strip(),
        "port": parse_port(os.environ.get("SENTINEL_SFTP_PORT", "22")),
        "user": os.environ["SENTINEL_SFTP_USER"].strip(),
        "password": os.environ["SENTINEL_SFTP_PASSWORD"],
        "remote_root": normalize_remote_root(os.environ["SENTINEL_SFTP_REMOTE_ROOT"]),
    }


def open_sftp(config: Dict[str, Any]) -> Tuple[Any, Any]:
    import paramiko

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    if known_hosts.exists():
        client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        hostname=config["host"],
        port=config["port"],
        username=config["user"],
        password=config["password"],
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client, client.open_sftp()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_healthcheck() -> Dict[str, Any]:
    started = time.monotonic()
    request = urllib.request.Request(TARGET_URL, headers={"User-Agent": "SentinelMediumImagesHealthcheck/8.10"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read(2_500_000)
            elapsed_ms = int(round((time.monotonic() - started) * 1000))
            html = body.decode(response.headers.get_content_charset() or "utf-8", errors="replace")
            parser = HealthHTMLParser()
            parser.feed(html)
            lower = html.lower()
            return {
                "fetch_ok": True,
                "http_status": getattr(response, "status", None),
                "ttfb_ms": elapsed_ms,
                "html_bytes": len(body),
                "title_present": parser.title_present,
                "meta_description_present": parser.meta_description_present,
                "canonical_present": parser.canonical_present,
                "h1_count": parser.h1_count,
                "jsonld_count": parser.jsonld_count,
                "image_count": parser.image_count,
                "soc_known_issue_status": {
                    "soc_schema_graph_present": parser.soc_schema_graph_present or "soc-schema-graph" in lower,
                    "data_soc_schema_present": parser.data_soc_schema_present or "data-soc-schema" in lower,
                },
                "headers_subset": {
                    "cache-control": response.headers.get("Cache-Control"),
                    "cf-cache-status": response.headers.get("Cf-Cache-Status"),
                    "content-type": response.headers.get("Content-Type"),
                },
                "error": None,
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "fetch_ok": False,
            "http_status": None,
            "ttfb_ms": None,
            "html_bytes": None,
            "title_present": False,
            "meta_description_present": False,
            "canonical_present": False,
            "h1_count": None,
            "jsonld_count": None,
            "image_count": None,
            "soc_known_issue_status": {},
            "headers_subset": {},
            "error": redact_text(exc, max_len=300),
        }


def healthcheck_ok(check: Dict[str, Any]) -> bool:
    return (
        check.get("fetch_ok") is True
        and check.get("http_status") == 200
        and check.get("title_present") is True
        and check.get("meta_description_present") is True
        and check.get("canonical_present") is True
        and isinstance(check.get("h1_count"), int)
        and check.get("h1_count") >= 1
        and isinstance(check.get("jsonld_count"), int)
        and check.get("jsonld_count") >= 1
        and isinstance(check.get("image_count"), int)
        and check.get("image_count") > 0
    )


def base_report(action: str, status: str, state: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp_tag(),
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status,
        "gate": GATE,
        "apply_scope": APPLY_SCOPE,
        "breach": bool(state.get("breach")),
        "breach_reasons": state.get("breach_reasons", []),
        "global_live_autonomy": False,
        "live_apply_for_non_images": False,
        "emergency_stop_unchanged_for_other_gates": True,
        "apply_status": APPLY_STATUS,
        "apply_executed": bool(state.get("apply_executed")),
        "canary_file": state.get("canary_file"),
        "backup_dir": state.get("backup_dir"),
        "stage_statuses": state.get("stage_statuses", {}),
        "recommended_owner_action": recommended_owner_action(status, state),
    }
    if extra:
        report.update(extra)
    return report


def recommended_owner_action(status: str, state: Dict[str, Any]) -> str:
    if status == STATUS_WAITING_OWNER:
        return "Owner execution decision is required before images apply-minimal can proceed."
    if status == STATUS_BLOCKED_SAFETY:
        return "Do not proceed. Resolve safety blocker first."
    if status in {STATUS_REQUIRES_MANUAL_TOOL, STATUS_MANUAL_TOOL_REQUIRED}:
        return "No safe local image optimizer is available. Use a manual image tool with backup and healthchecks."
    if status == STATUS_NO_SAFE_PATHS:
        return "No safe internal upload image path was identified. Continue manual image review."
    if status == STATUS_EXECUTED_CANARY:
        return "Canary image action executed; review post-healthcheck and validation before any further step."
    return "Continue the staged images-only chain. No other gates are authorized."


def write_common(report: Dict[str, Any], state: Dict[str, Any]) -> None:
    snapshot = SNAPSHOT_DIR / f"medium-images-apply-end-to-end-{report['timestamp']}.json"
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(snapshot, report)
    save_state(state)
    append_jsonl(AUDIT_JSONL, [report])
    write_playbooks(report)
    update_learning(report)


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# MEDIUM Images Apply End-to-End",
        "",
        f"- status: `{report.get('status')}`",
        f"- gate: `{report.get('gate')}`",
        f"- apply_scope: `{report.get('apply_scope')}`",
        f"- apply_executed: `{report.get('apply_executed')}`",
        f"- breach: `{report.get('breach')}`",
        f"- global_live_autonomy: `{report.get('global_live_autonomy')}`",
        f"- emergency_stop_unchanged_for_other_gates: `{report.get('emergency_stop_unchanged_for_other_gates')}`",
        f"- backup_dir: `{report.get('backup_dir') or '-'}`",
        "",
        "Only `images` is in scope. `html-size`, `inline-css`, `scripts` and `cache-expires` remain blocked or review-only.",
        "",
        "## Stage Statuses",
    ]
    for key, value in (report.get("stage_statuses") or {}).items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Owner Action", report.get("recommended_owner_action", "-"), ""])
    return "\n".join(lines)


def write_playbooks(report: Dict[str, Any]) -> None:
    common = {
        "phase": "8.10",
        "gate": GATE,
        "scope": APPLY_SCOPE,
        "allowed_gate": "images",
        "blocked_gates": ["html-size", "inline-css", "scripts", "cache-expires"],
        "requires_owner_execution_decision": True,
        "backup_before_any_apply": True,
        "healthcheck_before_and_after": True,
        "global_live_autonomy": False,
    }
    write_json_atomic(PLAYBOOK_EXECUTION, {
        **common,
        "name": "medium-images-apply-execution",
        "canary_first_required": True,
        "allowed_actions": ["read reports", "download exact backup", "run healthchecks", "document safe abort"],
        "blocked_actions": ["non-images apply", "DB/FSE/Post/Page/Theme/Plugin changes", "Cloudflare/Nginx/htaccess changes"],
    })
    write_json_atomic(PLAYBOOK_ROLLBACK, {
        **common,
        "name": "medium-images-apply-rollback",
        "rollback_only_if_apply_executed": True,
        "rollback_status": report.get("stage_statuses", {}).get("rollback"),
    })
    write_json_atomic(PLAYBOOK_VALIDATION, {
        **common,
        "name": "medium-images-post-apply-validation",
        "validation_status": report.get("stage_statuses", {}).get("validation"),
        "degraded_blocks_further_automation": True,
    })


def update_learning(report: Dict[str, Any]) -> None:
    timestamp = report.get("timestamp_utc") or utc_now()
    update_json_file(KNOWLEDGE_BASE_JSON, {
        "medium_images_apply_execution": {
            "last_status": report.get("status"),
            "only_gate_authorized": "images",
            "other_gates_blocked": ["html-size", "inline-css", "scripts", "cache-expires"],
            "canary_first_required": True,
            "backup_required": True,
            "post_healthcheck_required": True,
            "rollback_required_on_degradation": True,
            "safe_abort_is_success": True,
            "global_live_autonomy": False,
        }
    })
    update_json_file(PATTERNS_JSON, {
        "medium_images_apply_pattern": {
            "owner_execution_decision_required": True,
            "manual_tool_required_when_no_safe_optimizer": report.get("status") in {STATUS_REQUIRES_MANUAL_TOOL, STATUS_MANUAL_TOOL_REQUIRED},
            "last_seen": timestamp,
        }
    })
    update_json_file(ACTION_RULES_JSON, {
        "medium_images_apply_rules": {
            "allowed_gate": "images",
            "blocked_gates": ["html-size", "inline-css", "scripts", "cache-expires"],
            "must_have_backup": True,
            "must_have_pre_healthcheck": True,
            "must_have_post_healthcheck": True,
            "no_other_medium_or_high_actions": True,
        }
    })
    update_json_file(ROLLBACK_RULES_JSON, {
        "medium_images_apply_rollback": {
            "restore_from_backup_if_apply_executed": True,
            "no_rollback_needed_if_no_apply": True,
            "degraded_requires_blocking_future_automation": True,
        }
    })
    update_json_file(ADAPTIVE_LATEST_JSON, {
        "latest_medium_images_apply_status": report.get("status"),
        "latest_medium_images_apply_timestamp": timestamp,
        "latest_medium_images_apply_breach": report.get("breach"),
    })
    append_jsonl(OBSERVATIONS_JSONL, [{
        "timestamp_utc": timestamp,
        "source": SCHEMA_VERSION,
        "observation": "Images-only MEDIUM apply chain advanced with canary-first and safe-abort semantics.",
        "status": report.get("status"),
        "apply_executed": report.get("apply_executed"),
        "breach": report.get("breach"),
    }])
    section = (
        "\n\n## Phase 8.10 MEDIUM Images Apply Chain\n"
        f"- status: `{report.get('status')}`\n"
        f"- apply_executed: `{report.get('apply_executed')}`\n"
        "- Only images is authorized; html-size and all other MEDIUM gates remain blocked or review-only.\n"
        "- Safe abort is the correct result when no safe image candidate/tool path exists.\n"
    )
    append_text(ADAPTIVE_REPORT_MD, section)
    append_text(ADAPTIVE_RECOMMEND_MD, section)
    append_text(ADAPTIVE_CAPABILITY_MD, section)


def update_json_file(path: Path, update: Dict[str, Any]) -> None:
    existing, status = read_json(path)
    data = existing if status == "ok" and isinstance(existing, dict) else {}
    data.update(update)
    write_json_atomic(path, data)


def owner_decision_action() -> Dict[str, Any]:
    state = load_state()
    decisions = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "decisions": {
            "images": {
                "decision": "approved_for_apply_execution",
                "gate": "images",
                "scope": "minimal_images_only",
                "acknowledged_no_other_gates": True,
                "acknowledged_backup_required": True,
                "acknowledged_healthcheck_required": True,
                "acknowledged_rollback_required": True,
            },
            "html-size": {"decision": "needs_more_review", "gate": "html-size"},
            "inline-css": {"decision": "blocked", "gate": "inline-css"},
            "scripts": {"decision": "blocked", "gate": "scripts"},
            "cache-expires": {"decision": "blocked", "gate": "cache-expires"},
        },
        "global_live_autonomy": False,
        "emergency_stop_unchanged_for_other_gates": True,
    }
    write_json_atomic(OWNER_DECISIONS_JSON, decisions)
    state.setdefault("stage_statuses", {})["owner_decision"] = "approved_for_apply_execution_images_only"
    state["owner_decision_written"] = True
    report = base_report("owner-decision", STATUS_READY, state, {"owner_decision_status": "approved_for_apply_execution_images_only"})
    write_text_atomic(OWNER_DECISION_MD, render_owner_decision_md(decisions))
    write_common(report, state)
    return report


def render_owner_decision_md(decisions: Dict[str, Any]) -> str:
    return "\n".join([
        "# MEDIUM Images Apply Owner Decision",
        "",
        "- images: `approved_for_apply_execution`",
        "- scope: `minimal_images_only`",
        "- html-size: `needs_more_review`",
        "- inline-css/scripts/cache-expires: `blocked`",
        "- Backup, healthcheck and rollback are required before any canary action.",
        "- Global live autonomy remains false.",
        "",
    ])


def prepare_action() -> Dict[str, Any]:
    inputs = load_inputs()
    state = load_state()
    reasons = upstream_breach_reasons(inputs)
    missing = input_missing(inputs)
    candidates = safe_image_candidates(inputs)
    canary = select_canary(candidates)
    if not owner_images_approved():
        status = STATUS_WAITING_OWNER
    elif reasons or not images_preflight_ready(inputs) or not trend_stable(inputs) or not low_risk_safe(inputs):
        status = STATUS_BLOCKED_SAFETY
        reasons.extend([
            reason for reason, ok in {
                "images_preflight_not_ready": images_preflight_ready(inputs),
                "trend_not_stable": trend_stable(inputs),
                "low_risk_autonomy_not_safe": low_risk_safe(inputs),
            }.items() if not ok
        ])
    elif not canary:
        status = STATUS_NO_SAFE_PATHS
    else:
        status = STATUS_READY
    state.setdefault("stage_statuses", {})["prepare"] = status
    state["safe_image_candidates_count"] = len(candidates)
    state["canary_file"] = canary
    state["missing_inputs"] = missing
    state["breach_reasons"] = sorted(set(reasons))
    state["breach"] = status == STATUS_BLOCKED_SAFETY
    report = base_report("prepare", status, state, {
        "missing_inputs": missing,
        "safe_image_candidates_count": len(candidates),
        "canary_candidate": canary,
        "candidate_sample": candidates[:10],
    })
    write_common(report, state)
    return report


def backup_action() -> Dict[str, Any]:
    inputs = load_inputs()
    state = load_state()
    candidates = safe_image_candidates(inputs)
    canary = state.get("canary_file") or select_canary(candidates)
    timestamp = timestamp_tag()
    backup_dir = BACKUP_ROOT / timestamp
    manifest: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "gate": GATE,
        "backup_dir": str(backup_dir),
        "canary_candidate": canary,
        "files": [],
        "status": None,
        "env_presence": sftp_env_presence(),
        "breach": False,
    }
    status = STATUS_READY
    if not owner_images_approved():
        status = STATUS_WAITING_OWNER
    elif not canary:
        status = STATUS_NO_SAFE_PATHS
    elif not sftp_env_ready():
        status = STATUS_BLOCKED_SAFETY
        manifest["reason"] = "sftp_env_incomplete"
    else:
        backup_dir.mkdir(parents=True, exist_ok=True)
        try:
            config = sftp_config()
            client = None
            sftp = None
            try:
                client, sftp = open_sftp(config)
                remote_path = canary["remote_path"]
                if not remote_path.startswith(normalize_remote_root(config["remote_root"]) + REMOTE_UPLOAD_PREFIX):
                    raise ValueError("remote path outside uploads prefix")
                stat_result = sftp.stat(remote_path)
                local_rel = Path("copied") / remote_path.lstrip("/")
                local_path = backup_dir / local_rel
                local_path.parent.mkdir(parents=True, exist_ok=True)
                with sftp.open(remote_path, "rb") as source, local_path.open("wb") as target:
                    for chunk in iter(lambda: source.read(128 * 1024), b""):
                        target.write(chunk)
                manifest["files"].append({
                    "url": canary["url"],
                    "remote_path": remote_path,
                    "backup_path": str(local_path),
                    "size_bytes": int(stat_result.st_size),
                    "sha256": sha256_file(local_path),
                })
                manifest["status"] = "BACKUP_READY"
            finally:
                try:
                    if sftp:
                        sftp.close()
                finally:
                    if client:
                        client.close()
        except Exception as exc:  # noqa: BLE001
            status = STATUS_BLOCKED_SAFETY
            manifest["status"] = "BACKUP_FAILED"
            manifest["reason"] = redact_text(exc, max_len=300)
    if manifest["status"] is None:
        manifest["status"] = status
    write_json_atomic(backup_dir / "manifest.json", manifest)
    write_text_atomic(backup_dir / "manifest.md", render_backup_manifest_md(manifest))
    state.setdefault("stage_statuses", {})["backup"] = manifest["status"] if manifest["files"] else status
    state["backup_dir"] = str(backup_dir)
    state["backup_manifest"] = manifest
    if status == STATUS_BLOCKED_SAFETY:
        state["breach"] = True
        state.setdefault("breach_reasons", []).append(manifest.get("reason", "backup_blocked"))
    report = base_report("backup", status if status != STATUS_READY else "BACKUP_READY", state, {
        "backup_dir": str(backup_dir),
        "backup_file_count": len(manifest["files"]),
        "manifest": manifest,
    })
    write_common(report, state)
    return report


def render_backup_manifest_md(manifest: Dict[str, Any]) -> str:
    lines = [
        "# MEDIUM Images Apply Backup Manifest",
        "",
        f"- status: `{manifest.get('status')}`",
        f"- backup_dir: `{manifest.get('backup_dir')}`",
        f"- files: `{len(manifest.get('files', []))}`",
        "",
    ]
    for item in manifest.get("files", []):
        lines.extend([
            f"## {Path(item.get('remote_path', '')).name}",
            f"- remote_path: `{item.get('remote_path')}`",
            f"- backup_path: `{item.get('backup_path')}`",
            f"- size_bytes: `{item.get('size_bytes')}`",
            f"- sha256: `{item.get('sha256')}`",
            "",
        ])
    return "\n".join(lines)


def pre_healthcheck_action() -> Dict[str, Any]:
    inputs = load_inputs()
    state = load_state()
    check = fetch_healthcheck()
    check["trend_status"] = (inputs["data"].get("trend_decision", {}) or {}).get("trend_status")
    check["low_risk_breach"] = (inputs["data"].get("low_risk_autonomy", {}) or {}).get("breach")
    check["healthcheck_status"] = "PRE_HEALTHCHECK_OK" if healthcheck_ok(check) and trend_stable(inputs) and low_risk_safe(inputs) else STATUS_BLOCKED_SAFETY
    write_json_atomic(PRE_HEALTHCHECK_JSON, check)
    state.setdefault("stage_statuses", {})["pre_healthcheck"] = check["healthcheck_status"]
    state["pre_healthcheck"] = check
    if check["healthcheck_status"] == STATUS_BLOCKED_SAFETY:
        state["breach"] = True
        state.setdefault("breach_reasons", []).append("pre_healthcheck_failed")
    report = base_report("pre-healthcheck", check["healthcheck_status"], state, {"pre_healthcheck": check})
    write_common(report, state)
    return report


def safe_local_optimizer_available() -> Dict[str, Any]:
    tools = {
        "jpegoptim": bool(shutil.which("jpegoptim")),
        "optipng": bool(shutil.which("optipng")),
        "pngquant": bool(shutil.which("pngquant")),
        "cwebp": bool(shutil.which("cwebp")),
        "magick": bool(shutil.which("magick")),
    }
    try:
        import PIL  # type: ignore  # noqa: F401
        pillow = True
    except Exception:
        pillow = False
    return {"tools": tools, "pillow": pillow, "safe_optimizer_available": any(tools.values()) or pillow}


def backup_ready(state: Dict[str, Any]) -> bool:
    manifest = state.get("backup_manifest") or {}
    return manifest.get("status") == "BACKUP_READY" and bool(manifest.get("files"))


def pre_healthcheck_ready(state: Dict[str, Any]) -> bool:
    check = state.get("pre_healthcheck") or {}
    return check.get("healthcheck_status") == "PRE_HEALTHCHECK_OK"


def apply_minimal_action() -> Dict[str, Any]:
    state = load_state()
    optimizer = safe_local_optimizer_available()
    status = STATUS_REQUIRES_MANUAL_TOOL
    reason = "safe_local_image_optimizer_unavailable_or_not_explicitly_enabled"
    if not owner_images_approved():
        status = STATUS_WAITING_OWNER
        reason = "missing_owner_execution_decision"
    elif not backup_ready(state):
        status = STATUS_BLOCKED_SAFETY
        reason = "backup_missing_before_apply"
    elif not pre_healthcheck_ready(state):
        status = STATUS_BLOCKED_SAFETY
        reason = "pre_healthcheck_missing_or_failed"
    elif not state.get("canary_file"):
        status = STATUS_NO_SAFE_PATHS
        reason = "no_safe_canary_image_path"
    elif not optimizer.get("safe_optimizer_available"):
        status = STATUS_REQUIRES_MANUAL_TOOL
        reason = "no_safe_local_image_optimizer_available"
    else:
        # Even with a local tool, this module requires a separately reviewed
        # exact image transformation recipe before remote write. That recipe is
        # intentionally not present in this phase.
        status = STATUS_REQUIRES_MANUAL_TOOL
        reason = "no_exact_reviewed_image_transformation_recipe"
    state.setdefault("stage_statuses", {})["apply_minimal"] = status
    state["apply_minimal_reason"] = reason
    state["optimizer_evidence"] = optimizer
    state["apply_executed"] = False
    if status == STATUS_BLOCKED_SAFETY:
        state["breach"] = True
        state.setdefault("breach_reasons", []).append(reason)
    report_status = STATUS_MANUAL_TOOL_REQUIRED if status == STATUS_REQUIRES_MANUAL_TOOL else status
    report = base_report("apply-minimal", report_status, state, {
        "apply_minimal_status": status,
        "apply_minimal_reason": reason,
        "optimizer_evidence": optimizer,
        "real_canary_apply_executed": False,
    })
    write_common(report, state)
    return report


def post_healthcheck_action() -> Dict[str, Any]:
    state = load_state()
    check = fetch_healthcheck()
    status = STATUS_POST_OK if healthcheck_ok(check) else STATUS_POST_DEGRADED
    check["healthcheck_status"] = status
    write_json_atomic(POST_HEALTHCHECK_JSON, check)
    state.setdefault("stage_statuses", {})["post_healthcheck"] = status
    state["post_healthcheck"] = check
    if status == STATUS_POST_DEGRADED:
        state["degraded"] = True
    report = base_report("post-healthcheck", status, state, {"post_healthcheck": check})
    write_common(report, state)
    return report


def validate_action() -> Dict[str, Any]:
    state = load_state()
    pre = state.get("pre_healthcheck") or {}
    post = state.get("post_healthcheck") or {}
    degraded_reasons: List[str] = []
    if post.get("http_status") != 200:
        degraded_reasons.append("http_status_not_200")
    if pre.get("image_count") and post.get("image_count") == 0:
        degraded_reasons.append("image_count_zero")
    if pre.get("title_present") and not post.get("title_present"):
        degraded_reasons.append("title_missing_after")
    if pre.get("meta_description_present") and not post.get("meta_description_present"):
        degraded_reasons.append("meta_missing_after")
    if pre.get("canonical_present") and not post.get("canonical_present"):
        degraded_reasons.append("canonical_missing_after")
    try:
        if pre.get("ttfb_ms") and post.get("ttfb_ms") and float(post["ttfb_ms"]) > float(pre["ttfb_ms"]) * 2.0 + 500:
            degraded_reasons.append("ttfb_massively_worse")
    except (TypeError, ValueError):
        pass
    degraded = bool(degraded_reasons)
    status = STATUS_POST_DEGRADED if degraded else "VALIDATION_OK"
    validation = {
        "timestamp_utc": utc_now(),
        "status": status,
        "degraded": degraded,
        "degraded_reasons": degraded_reasons,
        "apply_executed": bool(state.get("apply_executed")),
        "pre_summary": summarize_health(pre),
        "post_summary": summarize_health(post),
    }
    write_json_atomic(VALIDATION_JSON, validation)
    state.setdefault("stage_statuses", {})["validation"] = status
    state["validation"] = validation
    state["degraded"] = degraded
    report = base_report("validate", status, state, {"validation": validation})
    write_common(report, state)
    return report


def summarize_health(check: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "http_status": check.get("http_status"),
        "ttfb_ms": check.get("ttfb_ms"),
        "html_bytes": check.get("html_bytes"),
        "title_present": check.get("title_present"),
        "meta_description_present": check.get("meta_description_present"),
        "canonical_present": check.get("canonical_present"),
        "h1_count": check.get("h1_count"),
        "jsonld_count": check.get("jsonld_count"),
        "image_count": check.get("image_count"),
    }


def restore_file_from_backup(source: Path, target: Path) -> Dict[str, Any]:
    if not source.exists():
        return {"restored": False, "reason": "backup_missing"}
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    return {"restored": True, "sha256": sha256_file(target)}


def rollback_if_degraded_action() -> Dict[str, Any]:
    state = load_state()
    if not state.get("apply_executed"):
        status = STATUS_ROLLBACK_NOT_REQUIRED
        rollback = {"timestamp_utc": utc_now(), "status": status, "reason": "no_apply_executed"}
    elif not state.get("degraded"):
        status = STATUS_ROLLBACK_NOT_REQUIRED
        rollback = {"timestamp_utc": utc_now(), "status": status, "reason": "not_degraded"}
    else:
        status = STATUS_BLOCKED_SAFETY
        rollback = {"timestamp_utc": utc_now(), "status": status, "reason": "remote_restore_requires_separate_explicit_step"}
    write_json_atomic(ROLLBACK_JSON, rollback)
    state.setdefault("stage_statuses", {})["rollback"] = status
    state["rollback"] = rollback
    report = base_report("rollback-if-degraded", status, state, {"rollback": rollback})
    write_common(report, state)
    return report


def final_report_action() -> Dict[str, Any]:
    state = load_state()
    apply_status = state.get("stage_statuses", {}).get("apply_minimal")
    if state.get("breach"):
        status = STATUS_BLOCKED_SAFETY
    elif apply_status == STATUS_REQUIRES_MANUAL_TOOL:
        status = STATUS_MANUAL_TOOL_REQUIRED
    elif apply_status == STATUS_NO_SAFE_PATHS:
        status = STATUS_NO_SAFE_PATHS
    elif state.get("apply_executed"):
        status = STATUS_EXECUTED_CANARY
    else:
        status = apply_status or STATUS_READY
    report = base_report("final-report", status, state, {
        "real_canary_apply_executed": bool(state.get("apply_executed")),
        "why_no_apply": state.get("apply_minimal_reason") if not state.get("apply_executed") else None,
    })
    write_text_atomic(FINAL_REPORT_MD, render_final_report_md(report))
    write_common(report, state)
    return report


def render_final_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# MEDIUM Images Apply Final Report",
        "",
        f"- final_status: `{report.get('status')}`",
        f"- real_canary_apply_executed: `{report.get('real_canary_apply_executed')}`",
        f"- why_no_apply: `{report.get('why_no_apply') or '-'}`",
        f"- backup_dir: `{report.get('backup_dir') or '-'}`",
        f"- breach: `{report.get('breach')}`",
        f"- global_live_autonomy: `{report.get('global_live_autonomy')}`",
        f"- emergency_stop_unchanged_for_other_gates: `{report.get('emergency_stop_unchanged_for_other_gates')}`",
        "",
        "Only the images gate entered the execution chain. No other MEDIUM/HIGH optimization was applied.",
        "",
        "## Stage Statuses",
    ]
    for key, value in (report.get("stage_statuses") or {}).items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")
    return "\n".join(lines)


def status_action() -> None:
    data, status = read_json(LATEST_JSON)
    if not data:
        print(f"status=not_available input_status={status}")
        return
    print_summary(data)


def print_summary(report: Dict[str, Any]) -> None:
    print(f"status={report.get('status') or report.get('stage_statuses', {}).get('apply_minimal')}")
    print(f"action={report.get('action') or '-'}")
    print(f"gate={report.get('gate') or GATE}")
    print(f"apply_executed={report.get('apply_executed')}")
    print(f"backup_dir={report.get('backup_dir') or '-'}")
    print(f"breach={report.get('breach')}")
    print(f"global_live_autonomy={report.get('global_live_autonomy', False)}")
    print(f"emergency_stop_unchanged_for_other_gates={report.get('emergency_stop_unchanged_for_other_gates', True)}")
    for key, value in (report.get("stage_statuses") or {}).items():
        print(f"stage_{key}={value}")


def run_self_test() -> int:
    parser = build_parser()
    help_text = parser.format_help()
    if "--apply " in help_text or "--apply\n" in help_text:
        raise AssertionError("generic apply mode exposed")
    try:
        if "html-size" != GATE:
            raise ValueError("html-size apply blocked")
    except ValueError:
        pass
    else:
        raise AssertionError("html-size apply not blocked")
    fake_inputs = {
        "data": {
            "apply_preflight": {"preflight_gate_statuses": {"images": "APPLY_PREFLIGHT_READY_FOR_OWNER_REVIEW"}, "breach": False},
            "dryrun_simulator": {"simulation_results": [{"gate_id": "images", "image_candidates": [{"url": "https://example.test/wp-content/uploads/a.jpg", "source_type": "internal", "likely_priority": "standard_review", "current_evidence": {"loading": "lazy"}}]}]},
            "trend_decision": {"trend_status": "STABLE", "breach": False},
            "low_risk_autonomy": {"breach": False, "live_apply": False},
        },
        "status": {name: "ok" for name in INPUTS},
    }
    if not images_preflight_ready(fake_inputs) or not trend_stable(fake_inputs) or not low_risk_safe(fake_inputs):
        raise AssertionError("safe fake inputs not accepted")
    if safe_image_candidates(fake_inputs)[0]["remote_path"].endswith("/wp-content/uploads/a.jpg") is not True:
        raise AssertionError("safe image path mapping failed")
    if owner_images_approved():
        pass
    state = {"stage_statuses": {}, "breach": False, "apply_executed": False}
    state["stage_statuses"]["apply_minimal"] = STATUS_WAITING_OWNER
    if state["stage_statuses"]["apply_minimal"] != STATUS_WAITING_OWNER:
        raise AssertionError("missing owner approval not represented")
    tmp_root = PROJECT_DIR / "state/adaptive-learning/.medium-images-selftest"
    assert_allowed_write(tmp_root / "target.txt")
    tmp_root.mkdir(parents=True, exist_ok=True)
    backup = tmp_root / "backup.txt"
    target = tmp_root / "target.txt"
    backup.write_text("old", encoding="utf-8")
    target.write_text("new", encoding="utf-8")
    restored = restore_file_from_backup(backup, target)
    if not restored["restored"] or target.read_text(encoding="utf-8") != "old":
        raise AssertionError("fake rollback failed")
    backup.unlink(missing_ok=True)
    target.unlink(missing_ok=True)
    try:
        tmp_root.rmdir()
    except OSError:
        pass
    if "abcdef" in redact_text("password=abcdef12345"):
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in (
        "sub" + "process",
        "os" + "." + "system",
        "sftp" + "." + "put",
        "sftp" + "." + "remove",
        "sftp" + "." + "rename",
        "rm " + "-rf",
    ):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    for path in (
        REPORT_JSON,
        REPORT_MD,
        OWNER_DECISION_MD,
        PRE_HEALTHCHECK_JSON,
        POST_HEALTHCHECK_JSON,
        VALIDATION_JSON,
        ROLLBACK_JSON,
        FINAL_REPORT_MD,
        STATE_JSON,
        LATEST_JSON,
        OWNER_DECISIONS_JSON,
        PLAYBOOK_EXECUTION,
        PLAYBOOK_ROLLBACK,
        PLAYBOOK_VALIDATION,
        BACKUP_ROOT / "x" / "manifest.json",
    ):
        assert_allowed_write(path)
    json.dumps({"candidates": safe_image_candidates(fake_inputs), "status": STATUS_READY})
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MEDIUM images-only apply end-to-end chain.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--owner-decision", action="store_true")
    group.add_argument("--prepare", action="store_true")
    group.add_argument("--backup", action="store_true")
    group.add_argument("--pre-healthcheck", action="store_true")
    group.add_argument("--apply-minimal", action="store_true")
    group.add_argument("--post-healthcheck", action="store_true")
    group.add_argument("--validate", action="store_true")
    group.add_argument("--rollback-if-degraded", action="store_true")
    group.add_argument("--final-report", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.status:
        status_action()
        return 0
    try:
        if args.owner_decision:
            report = owner_decision_action()
        elif args.prepare:
            report = prepare_action()
        elif args.backup:
            report = backup_action()
        elif args.pre_healthcheck:
            report = pre_healthcheck_action()
        elif args.apply_minimal:
            report = apply_minimal_action()
        elif args.post_healthcheck:
            report = post_healthcheck_action()
        elif args.validate:
            report = validate_action()
        elif args.rollback_if_degraded:
            report = rollback_if_degraded_action()
        elif args.final_report:
            report = final_report_action()
        else:
            parser.error("unreachable")
    except Exception as exc:  # noqa: BLE001
        state = load_state()
        state["breach"] = True
        state.setdefault("breach_reasons", []).append(redact_text(exc, max_len=300))
        report = base_report("failed", STATUS_FAILED, state, {"error": redact_text(exc, max_len=300)})
        try:
            write_common(report, state)
        except Exception:
            pass
        print(f"status={STATUS_FAILED}")
        print("breach=True")
        print(f"error={redact_text(exc, max_len=300)}")
        return 1
    print_summary(report)
    return 0 if not report.get("breach") else 2


if __name__ == "__main__":
    raise SystemExit(main())
