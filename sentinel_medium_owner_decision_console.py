#!/usr/bin/env python3
"""MEDIUM Owner Decision Console (Phase 8.7).

Stores local Owner decisions for MEDIUM owner-review optimization gates. This
module only documents decisions. It has no apply mode and performs no
production changes.
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

REPORT_JSON = PROJECT_DIR / "reports/latest/medium-owner-decision-console.json"
REPORT_MD = PROJECT_DIR / "reports/latest/medium-owner-decision-console.md"
SUMMARY_MD = PROJECT_DIR / "reports/latest/medium-owner-decision-summary.md"
SNAPSHOT_DIR = PROJECT_DIR / "snapshots"
AUDIT_JSONL = PROJECT_DIR / "audit/medium-owner-decision-console.jsonl"
STATE_JSON = PROJECT_DIR / "state/adaptive-learning/medium_owner_decisions.json"
HISTORY_JSONL = PROJECT_DIR / "state/adaptive-learning/medium_owner_decisions_history.jsonl"
PLAYBOOK_JSON = PROJECT_DIR / "playbooks/medium-owner-decision-console.playbook.json"

KNOWLEDGE_BASE_JSON = PROJECT_DIR / "state/adaptive-learning/knowledge_base.json"
OBSERVATIONS_JSONL = PROJECT_DIR / "state/adaptive-learning/observations.jsonl"
ACTION_RULES_JSON = PROJECT_DIR / "state/adaptive-learning/action_rules.json"
ADAPTIVE_LATEST_JSON = PROJECT_DIR / "state/adaptive-learning/latest.json"
ADAPTIVE_REPORT_MD = PROJECT_DIR / "reports/latest/adaptive-learning-engine.md"
ADAPTIVE_CAPABILITY_MD = PROJECT_DIR / "reports/latest/adaptive-bot-capability-map.md"

INPUTS = {
    "medium_gates_report": PROJECT_DIR / "reports/latest/medium-owner-review-gates.json",
    "owner_pack": PROJECT_DIR / "reports/latest/medium-optimization-owner-pack.md",
    "healthcheck_plan": PROJECT_DIR / "reports/latest/medium-optimization-healthcheck-plan.md",
    "rollback_plan": PROJECT_DIR / "reports/latest/medium-optimization-rollback-plan.md",
    "latest_medium_gates": PROJECT_DIR / "state/adaptive-learning/latest_medium_gates.json",
    "medium_owner_review_gates": PROJECT_DIR / "state/adaptive-learning/medium_owner_review_gates.json",
}

ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "snapshots",
    PROJECT_DIR / "audit",
    PROJECT_DIR / "state/adaptive-learning",
    PROJECT_DIR / "playbooks",
)

STATUS_OK = "MEDIUM_OWNER_DECISION_CONSOLE_OK"
STATUS_WARNINGS = "MEDIUM_OWNER_DECISION_CONSOLE_WARNINGS"
STATUS_BLOCKED = "MEDIUM_OWNER_DECISION_CONSOLE_BLOCKED_BY_SAFETY"
STATUS_FAILED = "MEDIUM_OWNER_DECISION_CONSOLE_FAILED"

GATES = ("images", "inline-css", "scripts", "cache-expires", "html-size")
DECISIONS = ("pending_review", "approved_for_dry_run_only", "needs_more_review", "rejected", "blocked")
NEXT_STAGE = {
    "pending_review": "owner_review",
    "approved_for_dry_run_only": "dry_run_simulation_only",
    "needs_more_review": "manual_review_required",
    "rejected": "no_action",
    "blocked": "blocked",
}
APPLY_STATUS = "not_applied"
SCHEMA_VERSION = "medium-owner-decision-console-8.7"

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


def reject_secret_note(note: str) -> str:
    cleaned = redact_text(note, default="", max_len=500)
    if SECRET_ASSIGNMENT_RE.search(note) or LONG_HEX_RE.search(note):
        raise ValueError("Secret-like note refused")
    return cleaned


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(f"Refusing write outside allowed decision console roots: {path}")
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


def gate_catalog(inputs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    report = inputs["data"].get("medium_gates_report", {}) or inputs["data"].get("medium_owner_review_gates", {}) or {}
    gates = {gate.get("gate_id"): gate for gate in report.get("gates", []) if isinstance(gate, dict) and gate.get("gate_id")}
    for gate_id in GATES:
        gates.setdefault(gate_id, {
            "gate_id": gate_id,
            "risk_level": "MEDIUM_REQUIRES_OWNER_APPROVAL",
            "status": "not_available",
            "confidence_score": None,
            "evidence": {},
            "expected_benefit": "not_available",
            "exact_manual_review_steps": [],
            "pre_healthcheck": [],
            "post_healthcheck": [],
            "rollback_plan": [],
            "blocked_auto_actions": [],
        })
    return gates


def default_decision(gate_id: str) -> Dict[str, Any]:
    return {
        "gate_id": gate_id,
        "decision": "pending_review",
        "note": "",
        "updated_at": None,
        "next_allowed_stage": NEXT_STAGE["pending_review"],
        "live_apply": False,
        "apply_status": APPLY_STATUS,
    }


def load_decision_state(inputs: Dict[str, Any]) -> Dict[str, Any]:
    state, _ = read_json(STATE_JSON)
    decisions = (state or {}).get("decisions") or {}
    normalized = {gate_id: default_decision(gate_id) for gate_id in GATES}
    for gate_id, item in decisions.items():
        if gate_id in normalized and isinstance(item, dict) and item.get("decision") in DECISIONS:
            normalized[gate_id].update({
                "decision": item.get("decision"),
                "note": redact_text(item.get("note"), default=""),
                "updated_at": item.get("updated_at"),
                "next_allowed_stage": NEXT_STAGE[item.get("decision")],
                "live_apply": False,
                "apply_status": APPLY_STATUS,
            })
    summary = summarize_decisions(normalized)
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "decisions": normalized,
        "summary": summary,
        "input_status": inputs["status"],
        "live_apply": False,
        "emergency_stop_unchanged": True,
        "apply_status": APPLY_STATUS,
        "breach": False,
    }


def summarize_decisions(decisions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    counts = Counter(item.get("decision", "pending_review") for item in decisions.values())
    decided_count = len([item for item in decisions.values() if item.get("decision") != "pending_review"])
    if counts.get("blocked", 0):
        next_stage = "blocked"
    elif counts.get("needs_more_review", 0):
        next_stage = "manual_review_required"
    elif counts.get("pending_review", 0):
        next_stage = "owner_review"
    elif counts.get("approved_for_dry_run_only", 0):
        next_stage = "dry_run_simulation_only"
    else:
        next_stage = "no_action"
    return {
        "gates_count": len(decisions),
        "decided_count": decided_count,
        "approved_for_dry_run_only_count": counts.get("approved_for_dry_run_only", 0),
        "needs_more_review_count": counts.get("needs_more_review", 0),
        "rejected_count": counts.get("rejected", 0),
        "blocked_count": counts.get("blocked", 0),
        "pending_count": counts.get("pending_review", 0),
        "next_safe_stage": next_stage,
    }


def status_from_inputs(inputs: Dict[str, Any], breach: bool) -> str:
    if breach:
        return STATUS_BLOCKED
    upstream = inputs["data"].get("medium_gates_report", {}) or {}
    if upstream.get("breach") or upstream.get("live_apply"):
        return STATUS_BLOCKED
    if any(status not in {"ok", "missing"} for status in inputs["status"].values()):
        return STATUS_WARNINGS
    if any(status == "missing" for status in inputs["status"].values()):
        return STATUS_WARNINGS
    return STATUS_OK


def build_report(action: str, selected_gate: Optional[str] = None, show_gate: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    inputs = load_inputs()
    catalog = gate_catalog(inputs)
    state = load_decision_state(inputs)
    breach = bool(state.get("breach"))
    report = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp_tag(),
        "timestamp_utc": utc_now(),
        "action": action,
        "status": status_from_inputs(inputs, breach),
        "breach": breach,
        "breach_reasons": [],
        "live_apply": False,
        "emergency_stop_unchanged": True,
        "apply_status": APPLY_STATUS,
        "selected_gate": selected_gate,
        "gates_count": len(GATES),
        "decisions": state["decisions"],
        "summary": state["summary"],
        "input_status": inputs["status"],
        "missing_inputs": [name for name, st in inputs["status"].items() if st == "missing"],
        "gates": [
            {
                "gate_id": gate_id,
                "risk_level": catalog[gate_id].get("risk_level"),
                "confidence_score": catalog[gate_id].get("confidence_score"),
                "status": catalog[gate_id].get("status"),
                "current_decision": state["decisions"][gate_id]["decision"],
                "next_allowed_stage": state["decisions"][gate_id]["next_allowed_stage"],
            }
            for gate_id in GATES
        ],
        "show_gate": show_gate,
    }
    return report


def render_report_md(report: Dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    lines = [
        "# MEDIUM Owner Decision Console",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Breach: `{report.get('breach')}`",
        f"- live_apply: `{report.get('live_apply')}`",
        f"- Emergency stop unchanged: `{report.get('emergency_stop_unchanged')}`",
        f"- Gates: `{report.get('gates_count')}`",
        f"- Decided: `{summary.get('decided_count')}`",
        f"- Approved for dry-run only: `{summary.get('approved_for_dry_run_only_count')}`",
        f"- Needs more review: `{summary.get('needs_more_review_count')}`",
        f"- Pending: `{summary.get('pending_count')}`",
        f"- Next safe stage: `{summary.get('next_safe_stage')}`",
        "",
        "## Gates",
        "",
    ]
    for gate in report.get("gates", []):
        lines.append(
            f"- `{gate.get('gate_id')}` risk=`{gate.get('risk_level')}` "
            f"confidence=`{gate.get('confidence_score')}` decision=`{gate.get('current_decision')}` "
            f"next=`{gate.get('next_allowed_stage')}`"
        )
    return "\n".join(lines) + "\n"


def render_summary_md(report: Dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    lines = [
        "# MEDIUM Owner Decision Summary",
        "",
        f"- approved_for_dry_run_only: `{summary.get('approved_for_dry_run_only_count')}`",
        f"- needs_more_review: `{summary.get('needs_more_review_count')}`",
        f"- rejected: `{summary.get('rejected_count')}`",
        f"- blocked: `{summary.get('blocked_count')}`",
        f"- pending: `{summary.get('pending_count')}`",
        f"- next_safe_stage: `{summary.get('next_safe_stage')}`",
        "",
        "`approved_for_dry_run_only` authorizes only a future simulation/dry-run stage, not production change.",
        "",
    ]
    return "\n".join(lines)


def build_playbook() -> Dict[str, Any]:
    return {
        "name": "medium-owner-decision-console",
        "purpose": "Store Owner decisions for MEDIUM optimization gates without applying changes.",
        "allowed_decisions": list(DECISIONS),
        "next_allowed_stage": NEXT_STAGE,
        "allowed_actions": ["list gates", "show gate details", "store local decision", "write reports", "write audit", "update bot learning"],
        "blocked_actions": [
            "live apply",
            "production change",
            "remote write",
            "database write",
            "cache purge",
            "CDN/security change",
            "webserver config change",
            "content/code edit",
            "service activation",
            "cron install",
        ],
        "safety_rule": "approved_for_dry_run_only permits only future dry-run/simulation, never apply.",
        "outputs": [str(REPORT_JSON), str(STATE_JSON), str(HISTORY_JSONL)],
        "live_apply": False,
        "apply_status": APPLY_STATUS,
    }


def append_markdown_section(path: Path, title: str, body: str) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    marker = f"<!-- sentinel:{title.lower().replace(' ', '-')} -->"
    block = f"\n{marker}\n## {title}\n\n{body.rstrip()}\n"
    if marker in text:
        text = text.split(marker, 1)[0].rstrip() + block
    else:
        text = text.rstrip() + "\n" + block
    write_text_atomic(path, text)


def update_learning(report: Dict[str, Any]) -> None:
    learning = {
        "timestamp_utc": report.get("timestamp_utc"),
        "status": report.get("status"),
        "summary": report.get("summary"),
        "learning": {
            "owner_decisions_are_separate_gate_state": True,
            "approved_for_dry_run_only_is_not_apply": True,
            "needs_more_review_blocks_simulation": True,
            "rejected_and_blocked_exclude_gate": True,
            "decisions_are_auditable": True,
            "bot_may_read_decisions_for_next_safe_stage": True,
        },
    }
    knowledge, _ = read_json(KNOWLEDGE_BASE_JSON)
    knowledge = knowledge or {}
    knowledge["medium_owner_decision_console"] = learning
    write_json_atomic(KNOWLEDGE_BASE_JSON, knowledge)
    append_jsonl(OBSERVATIONS_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "observation_id": "medium-owner-decision-console",
        "area": "Owner Decisions",
        "risk_level": "LOW_RISK_LOCAL_STATE",
        "summary": report.get("summary"),
        "hypothesis": "Owner decisions can advance safe gates only to dry-run/simulation, not apply.",
    }])
    rules, _ = read_json(ACTION_RULES_JSON)
    rules = rules or {}
    rules["medium_owner_decision_console"] = {
        "pending_review": "owner_review",
        "approved_for_dry_run_only": "dry_run_simulation_only",
        "needs_more_review": "manual_review_required",
        "rejected": "no_action",
        "blocked": "blocked",
        "never_allowed_from_console": ["production change", "apply", "cache purge", "remote write", "database write"],
    }
    write_json_atomic(ACTION_RULES_JSON, rules)
    latest, _ = read_json(ADAPTIVE_LATEST_JSON)
    latest = latest or {}
    latest["medium_owner_decision_console"] = {
        "status": report.get("status"),
        "summary": report.get("summary"),
        "breach": report.get("breach"),
        "live_apply": report.get("live_apply"),
    }
    write_json_atomic(ADAPTIVE_LATEST_JSON, latest)
    section = (
        f"- Status: `{report.get('status')}`\n"
        f"- Approved dry-run only: `{(report.get('summary') or {}).get('approved_for_dry_run_only_count')}`\n"
        f"- Needs more review: `{(report.get('summary') or {}).get('needs_more_review_count')}`\n"
        f"- Next safe stage: `{(report.get('summary') or {}).get('next_safe_stage')}`\n"
        "- Learning: Owner decisions are auditable gate state and do not authorize apply.\n"
    )
    append_markdown_section(ADAPTIVE_REPORT_MD, "MEDIUM Owner Decision Console Learning", section)
    append_markdown_section(
        ADAPTIVE_CAPABILITY_MD,
        "MEDIUM Owner Decision Console Capability",
        "- `owner_decision_state`: `True`\n- `dry_run_only_decision`: `True`\n- `medium_apply_from_console`: `False`\n",
    )


def write_outputs(report: Dict[str, Any], write_summary: bool = False) -> None:
    ts = str(report.get("timestamp") or timestamp_tag())
    write_json_atomic(REPORT_JSON, report)
    write_text_atomic(REPORT_MD, render_report_md(report))
    write_json_atomic(SNAPSHOT_DIR / f"medium-owner-decision-console-{ts}.json", report)
    write_json_atomic(PLAYBOOK_JSON, build_playbook())
    if write_summary:
        write_text_atomic(SUMMARY_MD, render_summary_md(report))
    append_jsonl(AUDIT_JSONL, [{
        "timestamp_utc": report.get("timestamp_utc"),
        "action": report.get("action"),
        "selected_gate": report.get("selected_gate"),
        "status": report.get("status"),
        "summary": report.get("summary"),
        "breach": report.get("breach"),
        "live_apply": report.get("live_apply"),
    }])
    update_learning(report)


def persist_state(state: Dict[str, Any]) -> None:
    write_json_atomic(STATE_JSON, state)


def list_action() -> Dict[str, Any]:
    inputs = load_inputs()
    state = load_decision_state(inputs)
    persist_state(state)
    report = build_report("list")
    write_outputs(report)
    return report


def show_action(gate_id: str) -> Dict[str, Any]:
    inputs = load_inputs()
    catalog = gate_catalog(inputs)
    state = load_decision_state(inputs)
    persist_state(state)
    gate = catalog.get(gate_id)
    if not gate:
        raise ValueError(f"unknown gate: {gate_id}")
    show_gate = dict(gate)
    show_gate["current_decision"] = state["decisions"][gate_id]["decision"]
    show_gate["next_allowed_stage"] = state["decisions"][gate_id]["next_allowed_stage"]
    report = build_report("show", selected_gate=gate_id, show_gate=show_gate)
    write_outputs(report)
    return report


def decide_action(gate_id: str, decision: str, note: str) -> Dict[str, Any]:
    if gate_id not in GATES:
        raise ValueError(f"unknown gate: {gate_id}")
    if decision not in DECISIONS:
        raise ValueError(f"unknown decision: {decision}")
    safe_note = reject_secret_note(note)
    inputs = load_inputs()
    state = load_decision_state(inputs)
    state["decisions"][gate_id] = {
        "gate_id": gate_id,
        "decision": decision,
        "note": safe_note,
        "updated_at": utc_now(),
        "next_allowed_stage": NEXT_STAGE[decision],
        "live_apply": False,
        "apply_status": APPLY_STATUS,
    }
    state["summary"] = summarize_decisions(state["decisions"])
    state["timestamp_utc"] = utc_now()
    persist_state(state)
    append_jsonl(HISTORY_JSONL, [{
        "timestamp_utc": state["timestamp_utc"],
        "gate_id": gate_id,
        "decision": decision,
        "note": safe_note,
        "next_allowed_stage": NEXT_STAGE[decision],
        "live_apply": False,
        "apply_status": APPLY_STATUS,
    }])
    report = build_report("decide", selected_gate=gate_id)
    write_outputs(report)
    return report


def decision_summary_action() -> Dict[str, Any]:
    inputs = load_inputs()
    state = load_decision_state(inputs)
    persist_state(state)
    report = build_report("decision-summary")
    write_outputs(report, write_summary=True)
    return report


def print_report_list(report: Dict[str, Any]) -> None:
    print(f"status={report.get('status')}")
    print(f"gates_count={report.get('gates_count')}")
    for gate in report.get("gates", []):
        print(
            f"gate={gate.get('gate_id')} risk={gate.get('risk_level')} confidence={gate.get('confidence_score')} "
            f"decision={gate.get('current_decision')} status={gate.get('status')} next_allowed_stage={gate.get('next_allowed_stage')}"
        )
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")


def print_show(report: Dict[str, Any]) -> None:
    gate = report.get("show_gate") or {}
    print(f"gate={gate.get('gate_id')}")
    print(f"risk={gate.get('risk_level')}")
    print(f"confidence={gate.get('confidence_score')}")
    print(f"current_decision={gate.get('current_decision')}")
    print(f"next_allowed_stage={gate.get('next_allowed_stage')}")
    print(f"expected_benefit={redact_text(gate.get('expected_benefit'))}")
    print(f"manual_review_steps_count={len(gate.get('exact_manual_review_steps') or [])}")
    print(f"pre_healthcheck_count={len(gate.get('pre_healthcheck') or [])}")
    print(f"post_healthcheck_count={len(gate.get('post_healthcheck') or [])}")
    print(f"rollback_plan_count={len(gate.get('rollback_plan') or [])}")
    print(f"blocked_auto_actions_count={len(gate.get('blocked_auto_actions') or [])}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")


def print_summary(report: Dict[str, Any]) -> None:
    summary = report.get("summary") or {}
    print(f"status={report.get('status')}")
    print(f"gates_count={report.get('gates_count')}")
    print(f"decided_count={summary.get('decided_count')}")
    print(f"approved_for_dry_run_only_count={summary.get('approved_for_dry_run_only_count')}")
    print(f"needs_more_review_count={summary.get('needs_more_review_count')}")
    print(f"rejected_count={summary.get('rejected_count')}")
    print(f"blocked_count={summary.get('blocked_count')}")
    print(f"pending_count={summary.get('pending_count')}")
    print(f"next_safe_stage={summary.get('next_safe_stage')}")
    print(f"breach={report.get('breach')}")
    print(f"live_apply={report.get('live_apply')}")
    print(f"emergency_stop_unchanged={report.get('emergency_stop_unchanged')}")


def status_action() -> None:
    data, status = read_json(REPORT_JSON)
    if not data:
        print(f"status=not_available input_status={status}")
        return
    print_summary(data)


def run_self_test() -> int:
    parser = build_parser()
    if "--apply" in parser.format_help():
        raise AssertionError("apply mode exposed")
    if set(GATES) != {"images", "inline-css", "scripts", "cache-expires", "html-size"}:
        raise AssertionError("gate registry mismatch")
    if set(DECISIONS) != {"pending_review", "approved_for_dry_run_only", "needs_more_review", "rejected", "blocked"}:
        raise AssertionError("decision registry mismatch")
    fake_inputs = {"data": {}, "status": {name: "missing" for name in INPUTS}}
    catalog = gate_catalog(fake_inputs)
    if len(catalog) != 5:
        raise AssertionError("catalog did not preserve five gates")
    try:
        if "unknown" not in GATES:
            raise ValueError("unknown gate blocked")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown gate not blocked")
    if NEXT_STAGE["approved_for_dry_run_only"] != "dry_run_simulation_only":
        raise AssertionError("approved decision maps incorrectly")
    if "apply" in NEXT_STAGE["approved_for_dry_run_only"].replace("dry_run_simulation_only", ""):
        raise AssertionError("approved dry-run maps to apply")
    decisions = {gate_id: default_decision(gate_id) for gate_id in GATES}
    decisions["images"]["decision"] = "approved_for_dry_run_only"
    decisions["images"]["next_allowed_stage"] = NEXT_STAGE["approved_for_dry_run_only"]
    summary = summarize_decisions(decisions)
    if summary["approved_for_dry_run_only_count"] != 1 or summary["pending_count"] != 4:
        raise AssertionError("summary counts failed")
    if "abcdef" in reject_secret_note("Owner note ok"):
        raise AssertionError("unexpected note issue")
    try:
        reject_secret_note("password=abcdef12345")
    except ValueError:
        pass
    else:
        raise AssertionError("secret note not rejected")
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
        SUMMARY_MD,
        STATE_JSON,
        HISTORY_JSONL,
        SNAPSHOT_DIR / "x.json",
        AUDIT_JSONL,
        PLAYBOOK_JSON,
    ):
        assert_allowed_write(path)
    json.dumps({"summary": summary, "catalog": catalog})
    print("self-test ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MEDIUM Owner Decision Console.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--list", action="store_true")
    group.add_argument("--show", choices=GATES)
    group.add_argument("--decide", nargs=2, metavar=("GATE", "DECISION"))
    group.add_argument("--decision-summary", action="store_true")
    group.add_argument("--status", action="store_true")
    parser.add_argument("--note", default="", help="Owner note for --decide. Secret-like values are refused.")
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
        if args.list:
            report = list_action()
            print_report_list(report)
        elif args.show:
            report = show_action(args.show)
            print_show(report)
        elif args.decide:
            gate_id, decision = args.decide
            report = decide_action(gate_id, decision, args.note)
            print_summary(report)
        elif args.decision_summary:
            report = decision_summary_action()
            print_summary(report)
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
            "breach_reasons": [redact_text(exc)],
            "live_apply": False,
            "emergency_stop_unchanged": True,
            "apply_status": APPLY_STATUS,
        }
        try:
            write_json_atomic(REPORT_JSON, failed)
            write_text_atomic(REPORT_MD, render_report_md(failed))
            append_jsonl(AUDIT_JSONL, [failed])
        except Exception:
            pass
        print(f"status={STATUS_FAILED}")
        print("breach=True")
        print(f"error={redact_text(exc, max_len=300)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
