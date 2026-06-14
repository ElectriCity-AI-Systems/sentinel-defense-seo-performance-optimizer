#!/usr/bin/env python3
"""MEDIUM Images New Canary Recipe Execution (Phase 8.13).

Images-only canary recipe gate for one exact WebP upload file. The module can
prepare and validate a local optimized canary, and it uploads only when the
single allowed remote path, backup hash, tooling, pre-healthcheck and savings
threshold are all satisfied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
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

ALLOWED_REMOTE_PATH = "/wordpress/wp-content/uploads/2025/11/Bildschirmfoto-vom-2025-11-26-15-21-16-1-scaled.webp"
ALLOWED_IMAGE_URL = "https://electri-c-ity-studios-24-7.com/wp-content/uploads/2025/11/Bildschirmfoto-vom-2025-11-26-15-21-16-1-scaled.webp"
PREVIOUS_FAILED_REMOTE = "/wordpress/wp-content/uploads/2023/08/Acid-Love-Cover-Art-1-2.webp"
TARGET_URL = "https://electri-c-ity-studios-24-7.com/"

REPORT_JSON = PROJECT_DIR / "reports/latest/medium-images-new-canary-execution.json"
REPORT_MD = PROJECT_DIR / "reports/latest/medium-images-new-canary-execution.md"
PRE_HEALTHCHECK_JSON = PROJECT_DIR / "reports/latest/medium-images-new-canary-pre-upload-healthcheck.json"
POST_HEALTHCHECK_JSON = PROJECT_DIR / "reports/latest/medium-images-new-canary-post-upload-healthcheck.json"
VALIDATION_JSON = PROJECT_DIR / "reports/latest/medium-images-new-canary-validation.json"
ROLLBACK_JSON = PROJECT_DIR / "reports/latest/medium-images-new-canary-rollback.json"
FINAL_REPORT_MD = PROJECT_DIR / "reports/latest/medium-images-new-canary-final-report.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/medium-images-new-canary-execution.jsonl"

STATE_JSON = PROJECT_DIR / "state/adaptive-learning/medium_images_new_canary_execution_state.json"
LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest_medium_images_new_canary_execution.json"
OWNER_DECISIONS_JSON = PROJECT_DIR / "state/adaptive-learning/apply_execution_owner_decisions.json"
APPLY_STATE_JSON = PROJECT_DIR / "state/adaptive-learning/medium_images_apply_state.json"
LOW_RISK_JSON = PROJECT_DIR / "reports/latest/low-risk-autonomy.json"
NEXT_CANARY_JSON = PROJECT_DIR / "state/adaptive-learning/latest_medium_images_next_canary.json"
TREND_DECISION_JSON = PROJECT_DIR / "state/performance-dryrun/trend_decision.json"

CANARY_ROOT = PROJECT_DIR / "backups/medium-images-new-canary-execution"

PLAYBOOK_RECIPE = PROJECT_DIR / "playbooks/medium-images-new-canary-execution.playbook.json"
PLAYBOOK_ROLLBACK = PROJECT_DIR / "playbooks/medium-images-new-canary-rollback.playbook.json"
PLAYBOOK_VALIDATION = PROJECT_DIR / "playbooks/medium-images-new-canary-validation.playbook.json"

KNOWLEDGE_BASE_JSON = PROJECT_DIR / "state/adaptive-learning/knowledge_base.json"
OBSERVATIONS_JSONL = PROJECT_DIR / "state/adaptive-learning/observations.jsonl"
PATTERNS_JSON = PROJECT_DIR / "state/adaptive-learning/patterns.json"
ACTION_RULES_JSON = PROJECT_DIR / "state/adaptive-learning/action_rules.json"
ROLLBACK_RULES_JSON = PROJECT_DIR / "state/adaptive-learning/rollback_rules.json"
ADAPTIVE_LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest.json"
ADAPTIVE_REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
ADAPTIVE_RECOMMEND_MD = PROJECT_DIR / "reports/latest/adaptive-recommendations.md"
ADAPTIVE_CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "playbooks",
    CANARY_ROOT,
)

SCHEMA_VERSION = "medium-images-new-canary-execution-8.13"

STATUS_TOOLING_FAILED = "MEDIUM_IMAGES_NEW_CANARY_TOOLING_FAILED"
STATUS_READY = "MEDIUM_IMAGES_NEW_CANARY_READY"
STATUS_LOCAL_OPTIMIZED = "MEDIUM_IMAGES_NEW_CANARY_LOCAL_OPTIMIZED"
STATUS_UPLOAD_EXECUTED = "MEDIUM_IMAGES_NEW_CANARY_UPLOAD_EXECUTED"
STATUS_UPLOAD_SKIPPED_NOT_BENEFICIAL = "MEDIUM_IMAGES_NEW_CANARY_UPLOAD_SKIPPED_NOT_BENEFICIAL"
STATUS_UPLOAD_BLOCKED = "MEDIUM_IMAGES_NEW_CANARY_UPLOAD_BLOCKED_BY_SAFETY"
STATUS_VALIDATION_OK = "MEDIUM_IMAGES_NEW_CANARY_VALIDATION_OK"
STATUS_VALIDATION_DEGRADED = "MEDIUM_IMAGES_NEW_CANARY_VALIDATION_DEGRADED"
STATUS_ROLLBACK_COMPLETED = "ROLLBACK_COMPLETED"
STATUS_ROLLBACK_NOT_REQUIRED = "ROLLBACK_NOT_REQUIRED"
STATUS_FAILED = "MEDIUM_IMAGES_NEW_CANARY_FAILED"

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


class HealthParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_present = False
        self.meta_description_present = False
        self.canonical_present = False
        self.h1_count = 0
        self.jsonld_count = 0
        self.image_count = 0
        self.target_image_present = False
        self.in_title = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
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
            combined = " ".join(attrs_dict.values())
            if "Bildschirmfoto-vom-2025-11-26-15-21-16-1-scaled.webp" in combined:
                self.target_image_present = True

    def handle_data(self, data: str) -> None:
        if self.in_title and data.strip():
            self.title_present = True

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
        raise ValueError(f"Refusing write outside allowed canary roots: {path}")
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


def load_state() -> Dict[str, Any]:
    state, status = read_json(STATE_JSON)
    if status == "ok" and isinstance(state, dict):
        state = clear_optional_learning_errors(state)
        return state
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "gate": "images",
        "allowed_remote_path": ALLOWED_REMOTE_PATH,
        "upload_executed": False,
        "breach": False,
        "stage_statuses": {},
        "global_live_autonomy": False,
        "emergency_stop_unchanged_for_other_gates": True,
    }


def clear_optional_learning_errors(state: Dict[str, Any]) -> Dict[str, Any]:
    reasons = state.get("breach_reasons") or []
    if state.get("breach") is True and reasons and all(
        "Permission denied" in str(reason) and "adaptive-" in str(reason)
        for reason in reasons
    ):
        state["breach"] = False
        state["breach_reasons"] = []
    return state


def save_state(state: Dict[str, Any]) -> None:
    state["timestamp_utc"] = utc_now()
    write_json_atomic(STATE_JSON, state)
    write_json_atomic(LATEST_JSON, state)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_exact_allowed_remote_path(path: str) -> bool:
    return posixpath.normpath(path or "") == ALLOWED_REMOTE_PATH


def owner_decision_ok() -> bool:
    data, status = read_json(OWNER_DECISIONS_JSON)
    if status != "ok" or not isinstance(data, dict):
        return False
    images = (data.get("decisions") or {}).get("images", {})
    others = data.get("decisions") or {}
    return (
        images.get("decision") == "approved_for_apply_execution"
        and images.get("gate") == "images"
        and images.get("scope") == "minimal_images_only"
        and images.get("acknowledged_no_other_gates") is True
        and images.get("acknowledged_backup_required") is True
        and images.get("acknowledged_healthcheck_required") is True
        and images.get("acknowledged_rollback_required") is True
        and (others.get("html-size", {}) or {}).get("decision") != "approved_for_apply_execution"
        and (others.get("inline-css", {}) or {}).get("decision") != "approved_for_apply_execution"
        and (others.get("scripts", {}) or {}).get("decision") != "approved_for_apply_execution"
        and (others.get("cache-expires", {}) or {}).get("decision") != "approved_for_apply_execution"
    )


def selected_candidate_ok() -> Dict[str, Any]:
    data, status = read_json(NEXT_CANARY_JSON)
    if status != "ok" or not isinstance(data, dict):
        return {"ok": False, "reason": f"next_canary_input_{status}"}
    candidates = data.get("candidates") or []
    selected = next((item for item in candidates if item.get("selected_candidate") is True), None)
    if not isinstance(selected, dict):
        return {"ok": False, "reason": "no_selected_candidate"}
    if selected.get("remote_path") != ALLOWED_REMOTE_PATH:
        return {"ok": False, "reason": "selected_remote_path_mismatch", "selected_remote_path": selected.get("remote_path")}
    if selected.get("url") != ALLOWED_IMAGE_URL:
        return {"ok": False, "reason": "selected_url_mismatch", "selected_url": selected.get("url")}
    if selected.get("is_previous_failed_candidate") is True or selected.get("remote_path") == PREVIOUS_FAILED_REMOTE:
        return {"ok": False, "reason": "previous_failed_candidate_blocked"}
    if selected.get("blocked") is True:
        return {"ok": False, "reason": "selected_candidate_marked_blocked", "blocked_reason": selected.get("blocked_reason")}
    return {
        "ok": True,
        "candidate": {
            "url": selected.get("url"),
            "remote_path": selected.get("remote_path"),
            "format": selected.get("format"),
            "size_bytes": selected.get("size_bytes"),
            "likely_position": selected.get("likely_position"),
            "estimated_savings_low": selected.get("estimated_savings_low"),
            "estimated_savings_high": selected.get("estimated_savings_high"),
        },
    }


def command_exists(name: str) -> Optional[str]:
    return shutil.which(name)


def tooling_status() -> Dict[str, Any]:
    tools = {name: command_exists(name) for name in ("cwebp", "dwebp", "webpinfo")}
    minimal = bool(tools["cwebp"] and tools["dwebp"] and tools["webpinfo"])
    return {
        "tools_present": {name: bool(path) for name, path in tools.items()},
        "minimal_tooling_ok": minimal,
        "direct_webp_recipe": False,
        "decode_encode_recipe_available": bool(tools["dwebp"] and tools["cwebp"] and tools["webpinfo"]),
        "tooling_status": STATUS_READY if minimal else STATUS_TOOLING_FAILED,
    }


def run_tool(args: List[str], timeout: int = 90) -> Dict[str, Any]:
    try:
        result = subprocess.run(args, shell=False, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": redact_text(result.stdout, max_len=800),
            "stderr": redact_text(result.stderr, max_len=800),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "returncode": None, "stdout": "", "stderr": redact_text(exc, max_len=300)}


def webpinfo(path: Path) -> Dict[str, Any]:
    if not command_exists("webpinfo"):
        return {"ok": False, "reason": "webpinfo_missing"}
    result = run_tool(["webpinfo", str(path)])
    text = "\n".join([result.get("stdout", ""), result.get("stderr", "")])
    width = parse_int_after(text, "Width:")
    height = parse_int_after(text, "Height:")
    return {
        "ok": bool(result["ok"] and "No error detected" in text),
        "width": width,
        "height": height,
        "size_bytes": path.stat().st_size if path.exists() else None,
        "returncode": result.get("returncode"),
    }


def parse_int_after(text: str, label: str) -> Optional[int]:
    for line in text.splitlines():
        if label in line:
            try:
                return int(line.split(label, 1)[1].strip().split()[0])
            except (IndexError, ValueError):
                return None
    return None


def new_work_dir() -> Path:
    path = CANARY_ROOT / timestamp_tag()
    path.mkdir(parents=True, exist_ok=True)
    return path


def current_work_dir(state: Dict[str, Any]) -> Path:
    existing = state.get("work_dir")
    if existing:
        path = Path(existing)
        path.mkdir(parents=True, exist_ok=True)
        return path
    path = new_work_dir()
    state["work_dir"] = str(path)
    return path


def fetch_home_healthcheck() -> Dict[str, Any]:
    started = time.monotonic()
    request = urllib.request.Request(TARGET_URL, headers={"User-Agent": "SentinelImagesCanaryHealthcheck/8.13"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read(2_500_000)
            html = body.decode(response.headers.get_content_charset() or "utf-8", errors="replace")
            parser = HealthParser()
            parser.feed(html)
            return {
                "fetch_ok": True,
                "http_status": getattr(response, "status", None),
                "ttfb_ms": int(round((time.monotonic() - started) * 1000)),
                "html_bytes": len(body),
                "title_present": parser.title_present,
                "meta_description_present": parser.meta_description_present,
                "canonical_present": parser.canonical_present,
                "h1_count": parser.h1_count,
                "jsonld_count": parser.jsonld_count,
                "image_count": parser.image_count,
                "target_image_present": parser.target_image_present or "Bildschirmfoto-vom-2025-11-26-15-21-16-1-scaled.webp" in html,
                "headers_subset": {
                    "cache-control": response.headers.get("Cache-Control"),
                    "cf-cache-status": response.headers.get("Cf-Cache-Status"),
                    "content-type": response.headers.get("Content-Type"),
                },
                "error": None,
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"fetch_ok": False, "http_status": None, "error": redact_text(exc, max_len=300)}


def fetch_image_healthcheck() -> Dict[str, Any]:
    request = urllib.request.Request(ALLOWED_IMAGE_URL, headers={"User-Agent": "SentinelImagesCanaryImageProbe/8.13"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read(256 * 1024)
            return {
                "fetch_ok": True,
                "http_status": getattr(response, "status", None),
                "sample_bytes": len(body),
                "content_type": response.headers.get("Content-Type"),
                "content_length": response.headers.get("Content-Length"),
                "error": None,
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"fetch_ok": False, "http_status": None, "error": redact_text(exc, max_len=300)}


def healthcheck_ok(check: Dict[str, Any]) -> bool:
    return (
        check.get("fetch_ok") is True
        and check.get("http_status") == 200
        and check.get("title_present") is True
        and check.get("meta_description_present") is True
        and check.get("canonical_present") is True
        and isinstance(check.get("h1_count"), int)
        and check["h1_count"] >= 1
        and isinstance(check.get("jsonld_count"), int)
        and check["jsonld_count"] >= 1
        and isinstance(check.get("image_count"), int)
        and check["image_count"] > 0
        and check.get("target_image_present") is True
    )


def low_risk_breach() -> bool:
    data, status = read_json(LOW_RISK_JSON)
    return status == "ok" and isinstance(data, dict) and data.get("breach") is True


def performance_trend_regression() -> bool:
    data, status = read_json(TREND_DECISION_JSON)
    if status != "ok" or not isinstance(data, dict):
        return False
    return data.get("trend_status") == "REGRESSION" or data.get("status") == "PERFORMANCE_TREND_ACCUMULATOR_REGRESSION" or data.get("breach") is True


def sftp_env_ready() -> bool:
    return all(
        bool(os.environ.get(key))
        for key in ("SENTINEL_SFTP_HOST", "SENTINEL_SFTP_USER", "SENTINEL_SFTP_REMOTE_ROOT", "SENTINEL_SFTP_PASSWORD")
    )


def sftp_env_presence() -> Dict[str, bool]:
    return {
        "host_present": bool(os.environ.get("SENTINEL_SFTP_HOST")),
        "port_present": bool(os.environ.get("SENTINEL_SFTP_PORT")),
        "user_present": bool(os.environ.get("SENTINEL_SFTP_USER")),
        "remote_root_present": bool(os.environ.get("SENTINEL_SFTP_REMOTE_ROOT")),
        "auth_present": bool(os.environ.get("SENTINEL_SFTP_PASSWORD")),
    }


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
        "remote_root": os.environ["SENTINEL_SFTP_REMOTE_ROOT"].strip().rstrip("/") or "/wordpress",
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


def download_remote_exact(local_path: Path) -> Dict[str, Any]:
    if not sftp_env_ready():
        return {"ok": False, "reason": "sftp_env_incomplete", "env_presence": sftp_env_presence()}
    config = sftp_config()
    if not is_exact_allowed_remote_path(ALLOWED_REMOTE_PATH):
        return {"ok": False, "reason": "remote_path_not_allowed"}
    client = None
    sftp = None
    try:
        client, sftp = open_sftp(config)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with sftp.open(ALLOWED_REMOTE_PATH, "rb") as source, local_path.open("wb") as target:
            for chunk in iter(lambda: source.read(128 * 1024), b""):
                target.write(chunk)
        return {"ok": True, "size_bytes": local_path.stat().st_size, "sha256": sha256_file(local_path)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": redact_text(exc, max_len=300)}
    finally:
        try:
            if sftp:
                sftp.close()
        finally:
            if client:
                client.close()


def upload_remote_exact(local_path: Path) -> Dict[str, Any]:
    if not sftp_env_ready():
        return {"ok": False, "reason": "sftp_env_incomplete", "env_presence": sftp_env_presence()}
    if not local_path.exists():
        return {"ok": False, "reason": "local_upload_file_missing"}
    if not is_exact_allowed_remote_path(ALLOWED_REMOTE_PATH):
        return {"ok": False, "reason": "remote_path_not_allowed"}
    config = sftp_config()
    client = None
    sftp = None
    try:
        client, sftp = open_sftp(config)
        with local_path.open("rb") as source, sftp.open(ALLOWED_REMOTE_PATH, "wb") as target:
            for chunk in iter(lambda: source.read(128 * 1024), b""):
                target.write(chunk)
        return {"ok": True, "remote_path": ALLOWED_REMOTE_PATH, "uploaded_sha256": sha256_file(local_path), "uploaded_size_bytes": local_path.stat().st_size}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": redact_text(exc, max_len=300)}
    finally:
        try:
            if sftp:
                sftp.close()
        finally:
            if client:
                client.close()


def base_report(action: str, status: str, state: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp_tag(),
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status,
        "gate": "images",
        "allowed_remote_path": ALLOWED_REMOTE_PATH,
        "upload_executed": bool(state.get("upload_executed")),
        "breach": bool(state.get("breach")),
        "breach_reasons": state.get("breach_reasons", []),
        "global_live_autonomy": False,
        "emergency_stop_unchanged_for_other_gates": True,
        "stage_statuses": state.get("stage_statuses", {}),
        "recommended_owner_action": recommended_owner_action(status, state),
    }
    if extra:
        report.update(extra)
    return report


def recommended_owner_action(status: str, state: Dict[str, Any]) -> str:
    if status == STATUS_TOOLING_FAILED:
        return "Install or provide cwebp and webpinfo before canary upload can be considered."
    if status == STATUS_UPLOAD_SKIPPED_NOT_BENEFICIAL:
        return "Do not upload. The optimized file does not meet the minimum 3 percent savings threshold."
    if status == STATUS_UPLOAD_EXECUTED:
        return "Review post-upload healthcheck and validation; rollback if degraded."
    if status == STATUS_VALIDATION_DEGRADED:
        return "Rollback the exact canary file from backup."
    if status == STATUS_UPLOAD_BLOCKED:
        return "Do not proceed. Resolve safety blocker first."
    return "Continue the images-only canary recipe stages. No other gate is authorized."


def write_common(report: Dict[str, Any], state: Dict[str, Any]) -> None:
    snapshot = SNAPSHOT_DIR / f"medium-images-new-canary-execution-{report['timestamp']}.json"
    state["last_status"] = report.get("status")
    state["last_action"] = report.get("action")
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(snapshot, report)
    save_state(state)
    append_jsonl(AUDIT_JSONL, [report])
    write_playbooks(report)
    update_learning(report)


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# MEDIUM Images Canary Recipe",
        "",
        f"- status: `{report.get('status')}`",
        f"- upload_executed: `{report.get('upload_executed')}`",
        f"- breach: `{report.get('breach')}`",
        f"- global_live_autonomy: `{report.get('global_live_autonomy')}`",
        f"- allowed_remote_path: `{report.get('allowed_remote_path')}`",
        "",
        "Only the single canary image path is in scope. Other gates remain blocked or review-only.",
        "",
        "## Stage Statuses",
    ]
    for key, value in (report.get("stage_statuses") or {}).items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Owner Action", report.get("recommended_owner_action", "-"), ""])
    return "\n".join(lines)


def write_playbooks(report: Dict[str, Any]) -> None:
    common = {
        "phase": "8.13",
        "gate": "images",
        "allowed_remote_path": ALLOWED_REMOTE_PATH,
        "blocked_gates": ["html-size", "inline-css", "scripts", "cache-expires"],
        "backup_sha256_required": "current_sftp_backup_sha256",
        "minimum_savings_percent": 3.0,
        "global_live_autonomy": False,
    }
    write_json_atomic(PLAYBOOK_RECIPE, {
        **common,
        "name": "medium-images-new-canary-execution",
        "allowed_actions": ["local WebP optimization", "exact-path upload only after all checks", "local reports"],
        "blocked_actions": ["other gates", "database writes", "content/template/code changes", "cache purge"],
    })
    write_json_atomic(PLAYBOOK_ROLLBACK, {
        **common,
        "name": "medium-images-new-canary-rollback",
        "rollback_remote_path": ALLOWED_REMOTE_PATH,
        "rollback_from_backup": "backups/medium-images-new-canary-execution/<timestamp>/original.webp",
    })
    write_json_atomic(PLAYBOOK_VALIDATION, {
        **common,
        "name": "medium-images-new-canary-validation",
        "validation_rules": ["homepage remains 200", "image count plausible", "target image reachable", "TTFB not massively worse"],
    })


def update_json_file(path: Path, update: Dict[str, Any]) -> None:
    existing, status = read_json(path)
    data = existing if status == "ok" and isinstance(existing, dict) else {}
    data.update(update)
    write_json_atomic(path, data)


def update_learning(report: Dict[str, Any]) -> None:
    timestamp = report.get("timestamp_utc") or utc_now()
    update_json_file(KNOWLEDGE_BASE_JSON, {
        "medium_images_new_canary_execution": {
            "last_status": report.get("status"),
            "single_allowed_remote_path": ALLOWED_REMOTE_PATH,
            "minimum_savings_percent": 3.0,
            "webpinfo_required": True,
            "rollback_exact_file_only": True,
            "global_live_autonomy": False,
            "safe_skip_when_not_beneficial": report.get("status") == STATUS_UPLOAD_SKIPPED_NOT_BENEFICIAL,
        }
    })
    update_json_file(PATTERNS_JSON, {
        "medium_images_new_canary_execution_pattern": {
            "single_file_canary": True,
            "threshold_blocks_upload": True,
            "last_seen": timestamp,
        }
    })
    update_json_file(ACTION_RULES_JSON, {
        "medium_images_new_canary_rules": {
            "allowed_remote_path": ALLOWED_REMOTE_PATH,
            "blocked_gates": ["html-size", "inline-css", "scripts", "cache-expires"],
            "requires_pre_healthcheck": True,
            "requires_backup_hash_match": True,
            "requires_savings_percent_at_least": 3.0,
        }
    })
    update_json_file(ROLLBACK_RULES_JSON, {
        "medium_images_new_canary_rollback": {
            "restore_exact_remote_path": ALLOWED_REMOTE_PATH,
            "backup_path": "state.backup.backup_path",
            "rollback_if_degraded": True,
        }
    })
    update_json_file(ADAPTIVE_LATEST_JSON, {
        "latest_medium_images_new_canary_status": report.get("status"),
        "latest_medium_images_new_canary_timestamp": timestamp,
        "latest_medium_images_new_canary_breach": report.get("breach"),
    })
    append_jsonl(OBSERVATIONS_JSONL, [{
        "timestamp_utc": timestamp,
        "source": SCHEMA_VERSION,
        "observation": "Images canary recipe stage evaluated exact WebP canary path with threshold-based upload control.",
        "status": report.get("status"),
        "upload_executed": report.get("upload_executed"),
        "breach": report.get("breach"),
    }])
    section = (
        "\n\n## Phase 8.13 MEDIUM Images Canary Recipe\n"
        f"- status: `{report.get('status')}`\n"
        f"- upload_executed: `{report.get('upload_executed')}`\n"
        "- Only the exact canary WebP file is in scope; all other gates remain blocked or review-only.\n"
        "- Upload is blocked when savings are below the minimum threshold or any safety gate fails.\n"
    )
    for path in (ADAPTIVE_REPORT_MD, ADAPTIVE_RECOMMEND_MD, ADAPTIVE_CAPABILITY_MD):
        try:
            append_text(path, section)
        except PermissionError:
            continue


def prepare_action() -> Dict[str, Any]:
    state = load_state()
    work_dir = current_work_dir(state)
    tooling = tooling_status()
    candidate = selected_candidate_ok()
    status = STATUS_READY
    reasons: List[str] = []
    if not owner_decision_ok():
        status = STATUS_UPLOAD_BLOCKED
        reasons.append("owner_execution_decision_not_images_only")
    if not candidate.get("ok"):
        status = STATUS_UPLOAD_BLOCKED
        reasons.append(candidate.get("reason") or "selected_candidate_invalid")
    if not tooling.get("minimal_tooling_ok"):
        status = STATUS_TOOLING_FAILED
        reasons.append("tooling_incomplete")
    if not is_exact_allowed_remote_path(ALLOWED_REMOTE_PATH):
        status = STATUS_UPLOAD_BLOCKED
        reasons.append("remote_path_not_exact_allowed")
    if ALLOWED_REMOTE_PATH == PREVIOUS_FAILED_REMOTE:
        status = STATUS_UPLOAD_BLOCKED
        reasons.append("previous_failed_candidate_blocked")
    state.setdefault("stage_statuses", {})["prepare"] = status
    state["work_dir"] = str(work_dir)
    state["tooling"] = tooling
    state["selected_candidate_check"] = candidate
    state["breach"] = status == STATUS_UPLOAD_BLOCKED
    state["breach_reasons"] = reasons
    report = base_report("prepare", status, state, {"tooling": tooling, "selected_candidate_check": candidate, "work_dir": str(work_dir), "block_reasons": reasons})
    write_common(report, state)
    return report


def backup_action() -> Dict[str, Any]:
    state = load_state()
    status = STATUS_READY
    reasons: List[str] = []
    if state.get("stage_statuses", {}).get("prepare") != STATUS_READY:
        status = STATUS_UPLOAD_BLOCKED
        reasons.append("prepare_not_ready")
    if not sftp_env_ready():
        status = STATUS_UPLOAD_BLOCKED
        reasons.append("sftp_env_incomplete")
    if not is_exact_allowed_remote_path(ALLOWED_REMOTE_PATH):
        status = STATUS_UPLOAD_BLOCKED
        reasons.append("remote_path_not_exact_allowed")
    work_dir = current_work_dir(state)
    original = work_dir / "original.webp"
    backup: Dict[str, Any] = {"ok": False, "reason": "backup_not_attempted", "backup_path": str(original)}
    if status == STATUS_READY:
        backup = download_remote_exact(original)
        backup["backup_path"] = str(original)
        if not backup.get("ok"):
            status = STATUS_UPLOAD_BLOCKED
            reasons.append("sftp_backup_failed")
        elif backup.get("size_bytes", 0) <= 0 or not backup.get("sha256"):
            status = STATUS_UPLOAD_BLOCKED
            reasons.append("backup_invalid")
    state["backup"] = backup
    state["original_path"] = str(original) if backup.get("ok") else state.get("original_path")
    state.setdefault("stage_statuses", {})["backup"] = "BACKUP_READY" if status == STATUS_READY else status
    if status == STATUS_UPLOAD_BLOCKED:
        state["breach"] = True
        state.setdefault("breach_reasons", []).extend(reasons)
    write_manifest(state)
    report = base_report("backup", state["stage_statuses"]["backup"], state, {"backup": backup, "block_reasons": reasons})
    write_common(report, state)
    return report


def current_work_dir(state: Dict[str, Any]) -> Path:
    if state.get("work_dir"):
        path = Path(state["work_dir"])
    else:
        path = CANARY_ROOT / timestamp_tag()
        state["work_dir"] = str(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_manifest(state: Dict[str, Any]) -> None:
    work_dir = current_work_dir(state)
    opt = state.get("optimization") or {}
    backup = state.get("backup") or {}
    manifest = {
        "timestamp": work_dir.name,
        "timestamp_utc": utc_now(),
        "remote_path": ALLOWED_REMOTE_PATH,
        "backup_path": backup.get("backup_path"),
        "original_size": opt.get("original_size") or backup.get("size_bytes"),
        "optimized_size": opt.get("optimized_size"),
        "savings_bytes": opt.get("savings_bytes"),
        "savings_percent": opt.get("savings_percent"),
        "original_sha256": backup.get("sha256"),
        "optimized_sha256": opt.get("optimized_sha256"),
        "upload_executed": bool(state.get("upload_executed")),
    }
    write_json_atomic(work_dir / "manifest.json", manifest)


def optimize_local_canary_action() -> Dict[str, Any]:
    state = load_state()
    tooling = state.get("tooling") or tooling_status()
    if not tooling.get("minimal_tooling_ok"):
        status = STATUS_TOOLING_FAILED
        state.setdefault("stage_statuses", {})["optimize_local"] = status
        report = base_report("optimize-local-canary", status, state, {"tooling": tooling})
        write_common(report, state)
        return report
    if state.get("stage_statuses", {}).get("backup") != "BACKUP_READY":
        status = STATUS_UPLOAD_BLOCKED
        state["breach"] = True
        state.setdefault("breach_reasons", []).append("backup_not_ready")
        state.setdefault("stage_statuses", {})["optimize_local"] = status
        report = base_report("optimize-local", status, state, {"reason": "backup_not_ready"})
        write_common(report, state)
        return report
    original = Path(state.get("original_path") or "")
    if not original.exists():
        status = STATUS_UPLOAD_BLOCKED
        state["breach"] = True
        state.setdefault("breach_reasons", []).append("original_canary_copy_missing")
        report = base_report("optimize-local", status, state, {"reason": "original_canary_copy_missing"})
        write_common(report, state)
        return report
    work_dir = current_work_dir(state)
    output = work_dir / "optimized.webp"
    before = webpinfo(original)
    temp_png = work_dir / "decoded.png"
    decode = run_tool(["dwebp", str(original), "-o", str(temp_png)])
    encode = run_tool(["cwebp", "-quiet", "-q", "82", "-m", "6", "-mt", str(temp_png), "-o", str(output)]) if decode.get("ok") else {"ok": False}
    direct = {"ok": bool(decode.get("ok") and encode.get("ok")), "decode": decode, "encode": encode}
    recipe = "dwebp_then_cwebp"
    after = webpinfo(output) if output.exists() else {"ok": False, "reason": "optimized_output_missing"}
    original_size = original.stat().st_size
    optimized_size = output.stat().st_size if output.exists() else 0
    savings_bytes = original_size - optimized_size
    savings_percent = round((savings_bytes / original_size) * 100, 3) if original_size else 0.0
    valid = bool(
        before.get("ok")
        and after.get("ok")
        and before.get("width") == after.get("width")
        and before.get("height") == after.get("height")
        and optimized_size > 0
        and optimized_size < original_size
    )
    upload_eligible = bool(valid and savings_percent >= 3.0)
    if not valid:
        status = STATUS_UPLOAD_BLOCKED
        state["breach"] = True
        state.setdefault("breach_reasons", []).append("optimized_output_invalid")
    elif not upload_eligible:
        status = STATUS_UPLOAD_SKIPPED_NOT_BENEFICIAL
    else:
        status = STATUS_LOCAL_OPTIMIZED
    optimization = {
        "recipe": recipe,
        "original_path": str(original),
        "optimized_path": str(output),
        "original_size": original_size,
        "optimized_size": optimized_size,
        "savings_bytes": savings_bytes,
        "savings_percent": savings_percent,
        "webpinfo_before": before,
        "webpinfo_after": after,
        "valid_output": valid,
        "upload_eligible": upload_eligible,
        "tool_result_ok": direct.get("ok"),
        "original_sha256": sha256_file(original),
        "optimized_sha256": sha256_file(output) if output.exists() else None,
    }
    state["optimization"] = optimization
    state.setdefault("stage_statuses", {})["optimize_local"] = status
    write_manifest(state)
    report = base_report("optimize-local", status, state, {"optimization": optimization})
    write_common(report, state)
    return report


def pre_upload_healthcheck_action() -> Dict[str, Any]:
    state = load_state()
    check = fetch_home_healthcheck()
    check["image_probe"] = fetch_image_healthcheck()
    check["low_risk_breach"] = low_risk_breach()
    check["performance_trend_regression"] = performance_trend_regression()
    check["healthcheck_status"] = "PRE_UPLOAD_HEALTHCHECK_OK" if healthcheck_ok(check) and check["image_probe"].get("http_status") == 200 and not check["low_risk_breach"] and not check["performance_trend_regression"] else STATUS_UPLOAD_BLOCKED
    write_json_atomic(PRE_HEALTHCHECK_JSON, check)
    state["pre_upload_healthcheck"] = check
    state.setdefault("stage_statuses", {})["pre_upload_healthcheck"] = check["healthcheck_status"]
    if check["healthcheck_status"] == STATUS_UPLOAD_BLOCKED:
        state["breach"] = True
        state.setdefault("breach_reasons", []).append("pre_upload_healthcheck_failed")
    report = base_report("pre-upload-healthcheck", check["healthcheck_status"], state, {"pre_upload_healthcheck": check})
    write_common(report, state)
    return report


def upload_canary_action() -> Dict[str, Any]:
    state = load_state()
    opt = state.get("optimization") or {}
    backup = state.get("backup") or {}
    status = STATUS_UPLOAD_BLOCKED
    reason = None
    upload_result: Dict[str, Any] = {}
    if not owner_decision_ok():
        reason = "owner_execution_decision_not_images_only"
    elif not backup.get("ok") or not backup.get("sha256") or not Path(backup.get("backup_path") or "").exists():
        reason = "backup_missing_or_invalid"
    elif not opt.get("valid_output"):
        reason = "optimized_output_invalid_or_missing"
    elif not opt.get("upload_eligible"):
        status = STATUS_UPLOAD_SKIPPED_NOT_BENEFICIAL
        reason = "savings_below_3_percent_or_not_smaller"
    elif (state.get("pre_upload_healthcheck") or {}).get("healthcheck_status") != "PRE_UPLOAD_HEALTHCHECK_OK":
        reason = "pre_upload_healthcheck_not_ok"
    elif not is_exact_allowed_remote_path(ALLOWED_REMOTE_PATH):
        reason = "remote_path_not_exact_allowed"
    elif not sftp_env_ready():
        reason = "sftp_env_incomplete"
    else:
        work_dir = current_work_dir(state)
        remote_before = work_dir / "remote-before-upload.webp"
        before = download_remote_exact(remote_before)
        if not before.get("ok"):
            reason = "remote_before_download_failed"
            upload_result["remote_before"] = before
        elif before.get("sha256") != backup.get("sha256"):
            reason = "remote_current_hash_differs_from_backup"
            upload_result["remote_before"] = before
        else:
            upload_result["remote_before"] = before
            upload = upload_remote_exact(Path(opt["optimized_path"]))
            upload_result["upload"] = upload
            if upload.get("ok"):
                remote_after = work_dir / "remote-after-upload.webp"
                after = download_remote_exact(remote_after)
                upload_result["remote_after"] = after
                status = STATUS_UPLOAD_EXECUTED if after.get("ok") and after.get("sha256") == upload.get("uploaded_sha256") else STATUS_UPLOAD_BLOCKED
                reason = None if status == STATUS_UPLOAD_EXECUTED else "remote_after_hash_mismatch"
            else:
                reason = upload.get("reason") or "upload_failed"
    state.setdefault("stage_statuses", {})["upload_canary"] = status
    state["upload_result"] = upload_result
    state["upload_executed"] = status == STATUS_UPLOAD_EXECUTED
    write_manifest(state)
    if status == STATUS_UPLOAD_BLOCKED:
        state["breach"] = True
        state.setdefault("breach_reasons", []).append(reason or "upload_blocked")
    report = base_report("upload-canary", status, state, {"upload_status": status, "upload_reason": reason, "upload_result": upload_result})
    write_common(report, state)
    return report


def post_upload_healthcheck_action() -> Dict[str, Any]:
    state = load_state()
    check = fetch_home_healthcheck()
    check["image_probe"] = fetch_image_healthcheck()
    ok = healthcheck_ok(check) and check["image_probe"].get("http_status") == 200
    check["healthcheck_status"] = "POST_UPLOAD_HEALTHCHECK_OK" if ok else STATUS_VALIDATION_DEGRADED
    write_json_atomic(POST_HEALTHCHECK_JSON, check)
    state["post_upload_healthcheck"] = check
    state.setdefault("stage_statuses", {})["post_upload_healthcheck"] = check["healthcheck_status"]
    report = base_report("post-upload-healthcheck", check["healthcheck_status"], state, {"post_upload_healthcheck": check})
    write_common(report, state)
    return report


def validate_canary_action() -> Dict[str, Any]:
    state = load_state()
    pre = state.get("pre_upload_healthcheck") or {}
    post = state.get("post_upload_healthcheck") or {}
    opt = state.get("optimization") or {}
    reasons: List[str] = []
    if post.get("http_status") != 200:
        reasons.append("homepage_not_200")
    if (post.get("image_probe") or {}).get("http_status") != 200:
        reasons.append("target_image_not_reachable")
    if post.get("image_count") == 0:
        reasons.append("image_count_zero")
    if pre.get("image_count") and post.get("image_count") and abs(int(post["image_count"]) - int(pre["image_count"])) > 2:
        reasons.append("image_count_changed_unexpectedly")
    if pre.get("html_bytes") and post.get("html_bytes") and int(post["html_bytes"]) > int(pre["html_bytes"]) * 1.15:
        reasons.append("html_massively_larger")
    if pre.get("ttfb_ms") and post.get("ttfb_ms") and float(post["ttfb_ms"]) > float(pre["ttfb_ms"]) * 2.0 + 500:
        reasons.append("ttfb_strongly_worse")
    degraded = bool(reasons)
    status = STATUS_VALIDATION_DEGRADED if degraded else STATUS_VALIDATION_OK
    validation = {
        "timestamp_utc": utc_now(),
        "status": status,
        "degraded": degraded,
        "degraded_reasons": reasons,
        "upload_executed": bool(state.get("upload_executed")),
        "original_size": opt.get("original_size"),
        "optimized_size": opt.get("optimized_size"),
        "savings_bytes": opt.get("savings_bytes"),
        "savings_percent": opt.get("savings_percent"),
        "pre_summary": summarize_health(pre),
        "post_summary": summarize_health(post),
    }
    write_json_atomic(VALIDATION_JSON, validation)
    state["validation"] = validation
    state["degraded"] = degraded
    state.setdefault("stage_statuses", {})["validate_canary"] = status
    report = base_report("validate-canary", status, state, {"validation": validation})
    write_common(report, state)
    return report


def summarize_health(check: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "http_status": check.get("http_status"),
        "ttfb_ms": check.get("ttfb_ms"),
        "html_bytes": check.get("html_bytes"),
        "image_count": check.get("image_count"),
        "jsonld_count": check.get("jsonld_count"),
        "target_image_present": check.get("target_image_present"),
        "image_probe_status": (check.get("image_probe") or {}).get("http_status"),
    }


def rollback_if_degraded_action() -> Dict[str, Any]:
    state = load_state()
    if not state.get("upload_executed"):
        status = STATUS_ROLLBACK_NOT_REQUIRED
        rollback = {"timestamp_utc": utc_now(), "status": status, "reason": "no_upload_executed"}
    elif not state.get("degraded"):
        status = STATUS_ROLLBACK_NOT_REQUIRED
        rollback = {"timestamp_utc": utc_now(), "status": status, "reason": "validation_not_degraded"}
    else:
        if not sftp_env_ready():
            status = STATUS_UPLOAD_BLOCKED
            rollback = {"timestamp_utc": utc_now(), "status": status, "reason": "sftp_env_incomplete"}
        else:
            backup = state.get("backup") or {}
            backup_path = Path(backup.get("backup_path") or "")
            if not backup_path.exists() or not backup.get("sha256"):
                upload = {"ok": False, "reason": "backup_missing_or_invalid"}
                remote_after = {}
                status = STATUS_UPLOAD_BLOCKED
            else:
                upload = upload_remote_exact(backup_path)
                remote_after = download_remote_exact(current_work_dir(state) / "remote-after-rollback.webp") if upload.get("ok") else {}
                status = STATUS_ROLLBACK_COMPLETED if remote_after.get("sha256") == backup.get("sha256") else STATUS_UPLOAD_BLOCKED
            rollback = {"timestamp_utc": utc_now(), "status": status, "restore_upload": upload, "remote_after": remote_after}
    write_json_atomic(ROLLBACK_JSON, rollback)
    state["rollback"] = rollback
    state.setdefault("stage_statuses", {})["rollback_if_degraded"] = status
    report = base_report("rollback-if-degraded", status, state, {"rollback": rollback})
    write_common(report, state)
    return report


def final_report_action() -> Dict[str, Any]:
    state = load_state()
    if state.get("breach"):
        status = STATUS_UPLOAD_BLOCKED
    elif state.get("upload_executed") and (state.get("validation") or {}).get("status") == STATUS_VALIDATION_OK:
        status = STATUS_UPLOAD_EXECUTED
    elif (state.get("optimization") or {}).get("upload_eligible") is False:
        status = STATUS_UPLOAD_SKIPPED_NOT_BENEFICIAL
    elif (state.get("tooling") or {}).get("minimal_tooling_ok") is False:
        status = STATUS_TOOLING_FAILED
    else:
        status = state.get("stage_statuses", {}).get("upload_canary") or STATUS_READY
    report = base_report("final-report", status, state, {
        "final_status": status,
        "original_size": (state.get("optimization") or {}).get("original_size"),
        "optimized_size": (state.get("optimization") or {}).get("optimized_size"),
        "savings_bytes": (state.get("optimization") or {}).get("savings_bytes"),
        "savings_percent": (state.get("optimization") or {}).get("savings_percent"),
        "why_no_upload": upload_skip_reason(state),
    })
    write_text_atomic(FINAL_REPORT_MD, render_final_report_md(report))
    write_common(report, state)
    return report


def upload_skip_reason(state: Dict[str, Any]) -> Optional[str]:
    if state.get("upload_executed"):
        return None
    if (state.get("optimization") or {}).get("upload_eligible") is False:
        return "optimized_savings_below_3_percent_or_not_beneficial"
    if (state.get("tooling") or {}).get("minimal_tooling_ok") is False:
        return "tooling_missing"
    return (state.get("stage_statuses") or {}).get("upload_canary")


def render_final_report_md(report: Dict[str, Any]) -> str:
    return "\n".join([
        "# MEDIUM Images Canary Final Report",
        "",
        f"- final_status: `{report.get('final_status')}`",
        f"- upload_executed: `{report.get('upload_executed')}`",
        f"- original_size: `{report.get('original_size')}`",
        f"- optimized_size: `{report.get('optimized_size')}`",
        f"- savings_bytes: `{report.get('savings_bytes')}`",
        f"- savings_percent: `{report.get('savings_percent')}`",
        f"- why_no_upload: `{report.get('why_no_upload') or '-'}`",
        f"- breach: `{report.get('breach')}`",
        f"- global_live_autonomy: `{report.get('global_live_autonomy')}`",
        f"- emergency_stop_unchanged_for_other_gates: `{report.get('emergency_stop_unchanged_for_other_gates')}`",
        "",
        "Only the exact canary WebP was considered. No other gate or file was changed.",
        "",
    ])


def status_action() -> None:
    data, status = read_json(LATEST_JSON)
    if not data:
        print(f"status=not_available input_status={status}")
        return
    print_summary(data)


def print_summary(report: Dict[str, Any]) -> None:
    print(f"status={report.get('status') or report.get('final_status') or report.get('last_status')}")
    print(f"action={report.get('action') or report.get('last_action') or '-'}")
    print(f"upload_executed={report.get('upload_executed')}")
    print(f"breach={report.get('breach')}")
    print(f"global_live_autonomy={report.get('global_live_autonomy', False)}")
    print(f"emergency_stop_unchanged_for_other_gates={report.get('emergency_stop_unchanged_for_other_gates', True)}")
    opt = report.get("optimization") or {}
    if not opt:
        state = load_state()
        opt = state.get("optimization") or {}
    if opt:
        print(f"original_size={opt.get('original_size')}")
        print(f"optimized_size={opt.get('optimized_size')}")
        print(f"savings_bytes={opt.get('savings_bytes')}")
        print(f"savings_percent={opt.get('savings_percent')}")
    for key, value in (report.get("stage_statuses") or {}).items():
        print(f"stage_{key}={value}")


def run_self_test() -> int:
    parser = build_parser()
    if "--apply " in parser.format_help() or "--apply\n" in parser.format_help():
        raise AssertionError("generic apply mode exposed")
    if is_exact_allowed_remote_path("/wordpress/wp-content/uploads/2023/08/other.webp"):
        raise AssertionError("unknown remote path accepted")
    if is_exact_allowed_remote_path(PREVIOUS_FAILED_REMOTE):
        raise AssertionError("previous failed Acid-Love candidate accepted")
    if not is_exact_allowed_remote_path(ALLOWED_REMOTE_PATH):
        raise AssertionError("allowed remote path rejected")
    fake_decision = {"decisions": {"images": {"decision": "pending_review"}}}
    if (fake_decision["decisions"]["images"]["decision"] == "approved_for_apply_execution"):
        raise AssertionError("missing owner decision not represented")
    missing_backup = {"ok": False, "sha256": None}
    if missing_backup["ok"]:
        raise AssertionError("missing backup not represented")
    fake_tooling = {"minimal_tooling_ok": False}
    if fake_tooling["minimal_tooling_ok"]:
        raise AssertionError("missing tooling not represented")
    original = 1000
    bigger = 1100
    small = 980
    if bigger < original:
        raise AssertionError("larger output accepted")
    if round(((original - small) / original) * 100, 3) >= 3.0:
        raise AssertionError("savings under threshold accepted")
    webp_fail = {"ok": False}
    if webp_fail["ok"]:
        raise AssertionError("webpinfo failure accepted")
    pre_fail = {"http_status": 500, "fetch_ok": True}
    if healthcheck_ok(pre_fail):
        raise AssertionError("bad pre healthcheck accepted")
    tmp = PROJECT_DIR / "state/adaptive-learning/.canary-selftest"
    tmp.mkdir(parents=True, exist_ok=True)
    src = tmp / "src.webp"
    dst = tmp / "dst.webp"
    src.write_bytes(b"old")
    dst.write_bytes(b"new")
    shutil.copyfile(src, dst)
    if dst.read_bytes() != b"old":
        raise AssertionError("local rollback model failed")
    src.unlink(missing_ok=True)
    dst.unlink(missing_ok=True)
    try:
        tmp.rmdir()
    except OSError:
        pass
    if "abcdef" in redact_text("password=abcdef12345"):
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in ("os" + "." + "system", "sftp" + "." + "remove", "sftp" + "." + "rename", "rm " + "-rf"):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    for path in (
        REPORT_JSON,
        REPORT_MD,
        PRE_HEALTHCHECK_JSON,
        POST_HEALTHCHECK_JSON,
        VALIDATION_JSON,
        ROLLBACK_JSON,
        FINAL_REPORT_MD,
        STATE_JSON,
        LATEST_JSON,
        PLAYBOOK_RECIPE,
        PLAYBOOK_ROLLBACK,
        PLAYBOOK_VALIDATION,
        CANARY_ROOT / "x" / "optimized.webp",
    ):
        assert_allowed_write(path)
    json.dumps({"status": STATUS_READY, "remote": ALLOWED_REMOTE_PATH})
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MEDIUM images new canary recipe execution.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--prepare", action="store_true")
    group.add_argument("--backup", action="store_true")
    group.add_argument("--optimize-local", action="store_true")
    group.add_argument("--pre-upload-healthcheck", action="store_true")
    group.add_argument("--upload-canary", action="store_true")
    group.add_argument("--post-upload-healthcheck", action="store_true")
    group.add_argument("--validate-canary", action="store_true")
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
        if args.prepare:
            report = prepare_action()
        elif args.backup:
            report = backup_action()
        elif args.optimize_local:
            report = optimize_local_canary_action()
        elif args.pre_upload_healthcheck:
            report = pre_upload_healthcheck_action()
        elif args.upload_canary:
            report = upload_canary_action()
        elif args.post_upload_healthcheck:
            report = post_upload_healthcheck_action()
        elif args.validate_canary:
            report = validate_canary_action()
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
