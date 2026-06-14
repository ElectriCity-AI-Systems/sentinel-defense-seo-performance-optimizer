#!/usr/bin/env python3
"""Owner-approved MEDIUM Dry-run Gates (Phase 8.1).

Prepares dry-run-only gates for MEDIUM-risk SEO/Performance actions. It never
applies changes, never deletes cache, never writes remote files, never changes
WordPress/DB/SFTP/Cloudflare/Nginx/.htaccess/FSE/Post/Theme/Plugin state, and
has no apply mode.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

REPORT_JSON = PROJECT_DIR / "reports/latest/medium-dryrun-gates.json"
REPORT_MD = PROJECT_DIR / "reports/latest/medium-dryrun-gates.md"
OWNER_PACK_MD = PROJECT_DIR / "reports/latest/medium-owner-review-pack.md"
STATE_JSON = PROJECT_DIR / "state/adaptive-learning/medium_gate_state.json"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/medium-dryrun-gates.jsonl"

PLAYBOOKS = {
    "cache-purge": PROJECT_DIR / "playbooks/medium-cache-purge-dryrun.playbook.json",
    "seo-plugin-settings": PROJECT_DIR / "playbooks/medium-seo-plugin-settings-review.playbook.json",
    "image-lazyload": PROJECT_DIR / "playbooks/medium-image-lazyload-dryrun.playbook.json",
    "sourcemap-wpo": PROJECT_DIR / "playbooks/medium-sourcemap-wpo-dryrun.playbook.json",
    "microcache-config": PROJECT_DIR / "playbooks/medium-microcache-config-review.playbook.json",
}

INPUTS = {
    "low_risk_autonomy": PROJECT_DIR / "reports/latest/low-risk-autonomy.json",
    "adaptive_recommendations": PROJECT_DIR / "reports/latest/adaptive-recommendations.json",
    "seo_safe_optimizer": PROJECT_DIR / "reports/latest/seo-safe-optimizer-report.json",
    "performance_safe_audit": PROJECT_DIR / "reports/latest/performance-safe-audit-report.json",
    "concrete_optimizer": PROJECT_DIR / "reports/latest/concrete-seo-performance-optimizer.json",
    "sourcemap_prevention": PROJECT_DIR / "reports/latest/sourcemap-prevention-report.json",
    "wpo_cache_soc_purge": PROJECT_DIR / "reports/latest/wpo-cache-soc-marker-purge.json",
    "ai_radio_timeout": PROJECT_DIR / "reports/latest/ai-radio-api-timeout-diagnosis.json",
    "ai_radio_microcache": PROJECT_DIR / "reports/latest/ai-radio-nowplaying-microcache-status.json",
    "master": PROJECT_DIR / "reports/latest/sentinel-master-report.json",
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "playbooks",
)

STATUS_OK = "MEDIUM_DRYRUN_GATES_OK"
STATUS_WARNINGS = "MEDIUM_DRYRUN_GATES_WARNINGS"
STATUS_BLOCKED = "MEDIUM_DRYRUN_GATES_BLOCKED_BY_SAFETY"
STATUS_FAILED = "MEDIUM_DRYRUN_GATES_FAILED"

RISK = "MEDIUM_REQUIRES_OWNER_APPROVAL"
APPLY_STATUS = "not_applied"
SCHEMA_VERSION = "medium-dryrun-gates-8.1"

GATES = ("cache-purge", "seo-plugin-settings", "image-lazyload", "sourcemap-wpo", "microcache-config")

SECRET_NAME_RE = re.compile(r"(?i)(secret|key|token|password|passwd|api[_-]?key|credential|authorization|cookie|session|license)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer|token|credential|session|"
    r"authorization|set-cookie|cookie|x-api-key|access[_-]?key|license)\b\s*[:=]\s*"
    r"[\"']?(?!false\b|true\b|null\b|none\b|not_applied\b|<redacted|-\b|0\b)"
    r"[A-Za-z0-9+/=_\-]{4,}"
)
LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
FORBIDDEN_COMMAND_RE = re.compile(
    r"(?i)(--apply\b|apply-safe|live-apply|sftp\s+(put|remove|rename|rm|mkdir|rmdir)|scp\s+|ssh\s+|wp\s+|wp-cli|mysql\b|"
    r"sftp\.(put|remove|rename)|cloudflare\s+(api|cli)|nginx\s+reload|systemctl\s+(enable|start)|"
    r"crontab\s+(-|install)|rm\s+-rf|curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh)"
)
DB_WRITE_RE = re.compile(r"(?i)\b(UPDATE|DELETE|INSERT|REPLACE|ALTER|DROP)\s+(wp_|wordpress|option|post|postmeta|termmeta)")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def redact_text(value: Any, default: str = "-", max_len: int = 1000) -> str:
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
        raise ValueError(f"Refusing write outside allowed medium dry-run roots: {path}")
    if path.suffix.lower() in {".sh", ".bash", ".zsh", ".service", ".timer", ".py", ".env", ".bin", ".run"}:
        raise ValueError(f"Refusing executable/install output: {path}")
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


def load_inputs() -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    status: Dict[str, str] = {}
    for name, path in INPUTS.items():
        item, st = read_json(path)
        data[name] = item or {}
        status[name] = st
    return {"data": data, "status": status}


def nested_get(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def gate_cache_purge(inputs: Dict[str, Any]) -> Dict[str, Any]:
    low = inputs["data"].get("low_risk_autonomy", {})
    purge = inputs["data"].get("wpo_cache_soc_purge", {})
    analysis = low.get("analysis") or {}
    return {
        "gate": "cache-purge",
        "risk": RISK,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "checks": {
            "known_cache_report_status": purge.get("status") or purge.get("removal_status") or "not_available",
            "previous_matched_cache_files_count": purge.get("matched_cache_files_count"),
            "previous_deleted_cache_files_count": purge.get("deleted_cache_files_count"),
            "soc_markers_visible": (analysis.get("soc_watch") or {}),
            "html_size_bytes": analysis.get("html_size_bytes"),
        },
        "would_change": False,
        "owner_review_required": True,
        "recommendation": "Prepare exact-prefix cache purge plan with backup and post-healthcheck only if Owner approves; do not purge now.",
        "healthcheck_plan": ["public HTML marker scan", "JSON-LD count compare", "cache header compare", "schema health score compare"],
    }


def gate_seo_plugin_settings(inputs: Dict[str, Any]) -> Dict[str, Any]:
    low = inputs["data"].get("low_risk_autonomy", {})
    seo = inputs["data"].get("seo_safe_optimizer", {})
    analysis = low.get("analysis") or {}
    return {
        "gate": "seo-plugin-settings",
        "risk": RISK,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "checks": {
            "seo_report_status": seo.get("status", "not_available"),
            "title_length": analysis.get("title_length"),
            "meta_description_length": analysis.get("meta_description_length"),
            "canonical_present": bool(analysis.get("canonical")),
            "robots_meta": analysis.get("robots_meta"),
            "og_title_present": bool((analysis.get("open_graph") or {}).get("title")),
            "twitter_card_present": bool((analysis.get("twitter") or {}).get("card")),
        },
        "would_change": False,
        "owner_review_required": True,
        "recommendation": "Core SEO fields are healthy; only prepare Owner copy/paste review for SEO plugin settings.",
        "healthcheck_plan": ["title/meta compare", "canonical compare", "OG/Twitter compare", "sitemap/robots read-only check"],
    }


def gate_image_lazyload(inputs: Dict[str, Any]) -> Dict[str, Any]:
    low = inputs["data"].get("low_risk_autonomy", {})
    perf = inputs["data"].get("performance_safe_audit", {})
    analysis = low.get("analysis") or {}
    image_count = int(analysis.get("image_count") or 0)
    lazy_count = int(analysis.get("lazy_image_count") or 0)
    return {
        "gate": "image-lazyload",
        "risk": RISK,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "checks": {
            "performance_report_status": perf.get("status", "not_available"),
            "image_count": image_count,
            "lazy_image_count": lazy_count,
            "non_lazy_image_estimate": max(0, image_count - lazy_count),
            "webp_hint_count": analysis.get("webp_hint_count"),
            "external_resource_host_count": analysis.get("external_resource_host_count"),
        },
        "would_change": False,
        "owner_review_required": True,
        "recommendation": "Prepare image width/height/lazyload review only; do not rewrite images or upload optimized files.",
        "healthcheck_plan": ["image count compare", "lazy count compare", "layout shift manual review", "performance score compare"],
    }


def gate_sourcemap_wpo(inputs: Dict[str, Any]) -> Dict[str, Any]:
    sm = inputs["data"].get("sourcemap_prevention", {})
    return {
        "gate": "sourcemap-wpo",
        "risk": RISK,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "checks": {
            "sourcemap_report_status": sm.get("status", "not_available"),
            "active_wpo_actions_count": sm.get("active_wpo_actions_count"),
            "already_remediated_count": sm.get("already_remediated_count"),
            "historical_window_remainder_count": sm.get("historical_window_remainder_count"),
            "wpo_minify_safe_to_apply": sm.get("wpo_minify_safe_to_apply"),
            "core_requires_review": sm.get("core_requires_review"),
        },
        "would_change": False,
        "owner_review_required": True,
        "recommendation": "Keep SourceMap/WPO changes dry-run only unless active WPO actions are confirmed and Owner approves.",
        "healthcheck_plan": ["sourceMappingURL existence check", "planned action count compare", "WPO-only scope review"],
    }


def gate_microcache_config(inputs: Dict[str, Any]) -> Dict[str, Any]:
    timeout = inputs["data"].get("ai_radio_timeout", {})
    micro = inputs["data"].get("ai_radio_microcache", {})
    master = inputs["data"].get("master", {})
    return {
        "gate": "microcache-config",
        "risk": RISK,
        "dryrun_status": "DRY_RUN_REVIEW_READY",
        "checks": {
            "timeout_status": timeout.get("status", "not_available"),
            "microcache_deployed": micro.get("microcache_deployed"),
            "local_validation": micro.get("local_validation"),
            "cache_header": micro.get("cache_header"),
            "nginx_cache_ttl_seconds": micro.get("nginx_cache_ttl_seconds"),
            "website_status": master.get("website_status"),
            "autonomy_cause": nested_get(master, ["master_critical_cause_snapshot", "critical_caused_by_autonomy"], False),
        },
        "would_change": False,
        "owner_review_required": True,
        "recommendation": "Continue observe-only for NowPlaying microcache and 24h 5xx/504 decay; do not change Nginx or Cloudflare here.",
        "healthcheck_plan": ["NowPlaying cache header compare", "5xx/504 rolling-window compare", "origin timeout trend compare"],
    }


GATE_BUILDERS = {
    "cache-purge": gate_cache_purge,
    "seo-plugin-settings": gate_seo_plugin_settings,
    "image-lazyload": gate_image_lazyload,
    "sourcemap-wpo": gate_sourcemap_wpo,
    "microcache-config": gate_microcache_config,
}


def build_playbook(gate: Dict[str, Any]) -> Dict[str, Any]:
    name = gate["gate"]
    return {
        "name": f"medium-{name}-dryrun",
        "purpose": f"Owner-approved MEDIUM dry-run gate for {name}; no live changes.",
        "risk": RISK,
        "owner_review_required": True,
        "dry_run_only": True,
        "triggers": ["Owner requests dry-run", "Adaptive recommendation references this gate"],
        "inputs": [str(path) for path in INPUTS.values()],
        "allowed_actions": ["read local reports", "count known candidates", "write report", "write snapshot", "write audit", "prepare owner review"],
        "blocked_actions": [
            "live apply",
            "SFTP write",
            "DB write",
            "cache purge",
            "Cloudflare change",
            "Nginx change",
            ".htaccess change",
            "FSE/Post/Page/Theme/Plugin edit",
        ],
        "healthcheck_plan": gate.get("healthcheck_plan", []),
        "rollback_requirements": ["No rollback needed for dry-run; any future action requires backup and Owner approval."],
        "output_reports": ["reports/latest/medium-dryrun-gates.json", "reports/latest/medium-dryrun-gates.md"],
        "disable_conditions": ["breach=true", "unexpected apply mode", "secret-like output", "forbidden command pattern"],
    }


def aggregate_status(gates: List[Dict[str, Any]], breach: bool, input_status: Dict[str, str]) -> str:
    if breach:
        return STATUS_BLOCKED
    if any(status not in {"ok", "missing"} for status in input_status.values()):
        return STATUS_WARNINGS
    if any(status == "missing" for status in input_status.values()):
        return STATUS_WARNINGS
    if not gates:
        return STATUS_WARNINGS
    return STATUS_OK


def build_bundle(action: str, gate_name: Optional[str] = None, write_owner_pack: bool = False) -> Dict[str, Any]:
    ts = timestamp_tag()
    inputs = load_inputs()
    if gate_name and gate_name not in GATE_BUILDERS:
        gates: List[Dict[str, Any]] = []
        breach = True
        reasons = [f"unknown gate: {gate_name}"]
    else:
        selected = [gate_name] if gate_name else list(GATES)
        gates = [GATE_BUILDERS[name](inputs) for name in selected if name]
        breach = False
        reasons: List[str] = []
    status = aggregate_status(gates, breach, inputs["status"])
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": ts,
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status,
        "breach": breach,
        "breach_reasons": reasons,
        "live_apply": False,
        "emergency_stop_unchanged": True,
        "apply_status": APPLY_STATUS,
        "gate_count": len(GATES),
        "selected_gate": gate_name,
        "dryrun_results_count": len(gates),
        "dryrun_results": gates,
        "risk_summary": dict(Counter(g["risk"] for g in gates)),
        "input_status": inputs["status"],
        "owner_review_pack_written": write_owner_pack,
        "recommended_next_step": "Owner may review MEDIUM dry-run evidence. Do not apply or install anything from this phase.",
    }
    return {"report": report, "playbooks": {gate["gate"]: build_playbook(gate) for gate in gates}}


def render_report_md(report: Dict[str, Any]) -> str:
    lines = [
        "# MEDIUM Dry-run Gates",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- Emergency stop unchanged: `{report.get('emergency_stop_unchanged')}`",
        f"- Selected gate: `{report.get('selected_gate') or 'all'}`",
        f"- Dry-run results: `{report.get('dryrun_results_count')}`",
        "",
    ]
    for gate in report.get("dryrun_results", []):
        lines.append(f"## {gate.get('gate')}")
        lines.append(f"- Risk: `{gate.get('risk')}`")
        lines.append(f"- Status: `{gate.get('dryrun_status')}`")
        lines.append(f"- Owner review required: `{gate.get('owner_review_required')}`")
        lines.append(f"- Would change: `{gate.get('would_change')}`")
        lines.append(f"- Recommendation: {gate.get('recommendation')}")
        lines.append("")
    return "\n".join(lines)


def render_owner_pack(report: Dict[str, Any]) -> str:
    lines = [
        "# MEDIUM Owner Review Pack",
        "",
        "This pack is dry-run only. It does not authorize apply, installation, cache purge, or remote writes.",
        "",
    ]
    for gate in report.get("dryrun_results", []):
        lines.append(f"## {gate.get('gate')}")
        lines.append(f"- Risk: `{gate.get('risk')}`")
        lines.append(f"- Recommendation: {gate.get('recommendation')}")
        lines.append("- Healthcheck plan:")
        for item in gate.get("healthcheck_plan", []):
            lines.append(f"  - {item}")
        lines.append("- Owner decision required before any future action.")
        lines.append("")
    return "\n".join(lines)


def write_outputs(bundle: Dict[str, Any], write_playbooks: bool = True, write_owner_pack: bool = False) -> None:
    report = bundle["report"]
    ts = str(report["timestamp"])
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(STATE_JSON, report)
    write_json_atomic(SNAPSHOT_DIR / f"medium-dryrun-gates-{ts}.json", report)
    if write_owner_pack:
        write_text_atomic(OWNER_PACK_MD, render_owner_pack(report))
    if write_playbooks:
        for gate_name, playbook in bundle["playbooks"].items():
            write_json_atomic(PLAYBOOKS[gate_name], playbook)
    append_jsonl(
        AUDIT_JSONL,
        [{
            "timestamp_utc": report.get("timestamp_utc"),
            "action": report.get("action"),
            "status": report.get("status"),
            "selected_gate": report.get("selected_gate"),
            "dryrun_results_count": report.get("dryrun_results_count"),
            "breach": report.get("breach"),
            "live_apply": report.get("live_apply"),
        }],
    )


def list_gates() -> Dict[str, Any]:
    bundle = build_bundle("list-gates")
    write_outputs(bundle, write_playbooks=True)
    return bundle


def dry_run(gate: str) -> Dict[str, Any]:
    bundle = build_bundle("dry-run", gate_name=gate)
    write_outputs(bundle, write_playbooks=True)
    return bundle


def owner_review_pack() -> Dict[str, Any]:
    bundle = build_bundle("owner-review-pack", write_owner_pack=True)
    write_outputs(bundle, write_playbooks=True, write_owner_pack=True)
    return bundle


def print_status() -> None:
    data, status = read_json(STATE_JSON)
    if not data:
        print(f"status=not_available input_status={status}")
        return
    print(f"status={data.get('status')}")
    print(f"breach={data.get('breach')}")
    print(f"live_apply={data.get('live_apply')}")
    print(f"emergency_stop_unchanged={data.get('emergency_stop_unchanged')}")
    print(f"dryrun_results_count={data.get('dryrun_results_count')}")
    for gate in data.get("dryrun_results", []):
        print(f"gate={gate.get('gate')} dryrun_status={gate.get('dryrun_status')} risk={gate.get('risk')}")


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    if set(GATE_BUILDERS) != set(GATES):
        raise AssertionError("gate registry mismatch")
    unknown = build_bundle("dry-run", gate_name="unknown")
    if not unknown["report"]["breach"]:
        raise AssertionError("unknown gate not blocked")
    sample = build_bundle("self-test", gate_name="cache-purge")
    if sample["report"]["dryrun_results"][0]["would_change"] is not False:
        raise AssertionError("dry-run gate would change state")
    if "abcdef" in redact_text("api_key=abcdef12345"):
        raise AssertionError("secret redaction failed")
    source = Path(__file__).read_text(encoding="utf-8")
    for token in ("sub" + "process", "os" + "." + "system", "." + "put(", "." + "remove(", "." + "rename(", "rm " + "-rf"):
        if token in source:
            raise AssertionError(f"forbidden implementation token found: {token}")
    for path in (REPORT_JSON, REPORT_MD, STATE_JSON, SNAPSHOT_DIR / "x.json", AUDIT_JSONL, PLAYBOOKS["cache-purge"]):
        assert_allowed_write(path)
    json.dumps(sample["report"])
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Owner-approved MEDIUM dry-run gates.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--list-gates", action="store_true")
    group.add_argument("--dry-run", choices=GATES)
    group.add_argument("--owner-review-pack", action="store_true")
    group.add_argument("--status", action="store_true")
    return parser


def print_summary(bundle: Dict[str, Any]) -> None:
    report = bundle["report"]
    print(f"status={report.get('status')}")
    print(f"selected_gate={report.get('selected_gate') or 'all'}")
    print(f"dryrun_results_count={report.get('dryrun_results_count')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop_unchanged={report.get('emergency_stop_unchanged')}")
    for gate in report.get("dryrun_results", []):
        print(f"gate={gate.get('gate')} dryrun_status={gate.get('dryrun_status')} risk={gate.get('risk')}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.status:
        print_status()
        return 0
    try:
        if args.list_gates:
            bundle = list_gates()
        elif args.dry_run:
            bundle = dry_run(args.dry_run)
        elif args.owner_review_pack:
            bundle = owner_review_pack()
        else:
            parser.error("unreachable")
    except Exception as exc:  # noqa: BLE001
        failed = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": timestamp_tag(),
            "timestamp_utc": utc_now(),
            "action": "failed",
            "status": STATUS_FAILED,
            "breach": True,
            "live_apply": False,
            "apply_status": APPLY_STATUS,
            "error": redact_text(exc),
        }
        write_json_atomic(REPORT_JSON, failed)
        write_text_atomic(REPORT_MD, "# MEDIUM Dry-run Gates\n\n- Status: `MEDIUM_DRYRUN_GATES_FAILED`\n")
        print(f"status={STATUS_FAILED}")
        print("breach=True")
        return 2
    print_summary(bundle)
    return 0 if not bundle["report"].get("breach") else 2


if __name__ == "__main__":
    sys.exit(main())
