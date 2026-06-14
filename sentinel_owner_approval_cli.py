#!/usr/bin/env python3
"""Sentinel Owner Approval CLI (Phase 2.1).

A safe command-line interface for the owner to review the existing Owner
Approval Queue and record status changes *inside the queue only*. It applies
nothing live and never grants an apply.

Hard safety guarantees (enforced structurally):
  * No live changes; no WordPress/.htaccess/Cloudflare/Nginx edits.
  * No external/network access — local files only (no network imports).
  * No secrets/cookies/authorization values are stored or emitted.
  * No apply function; apply_status always stays not_applied.
  * approved_for_manual_apply is NEVER set by this module.
  * HIGH is NEVER approved_for_draft_only.
  * MEDIUM/REVIEW_ONLY is NEVER auto-approved.
  * Writes only ever under:
        /srv/sentinel-defense/drafts/approval
        /srv/sentinel-defense/reports/latest
        /srv/sentinel-defense/audit
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROJECT_DIR = Path("/srv/sentinel-defense")

# --- Inputs / Outputs -------------------------------------------------------
QUEUE_JSON = PROJECT_DIR / "drafts/approval/owner-approval-queue.json"
QUEUE_MD = PROJECT_DIR / "drafts/approval/owner-approval-queue.md"
AUDIT_JSONL = PROJECT_DIR / "audit/owner-approval-actions.jsonl"
CLI_REPORT_JSON = PROJECT_DIR / "reports/latest/owner-approval-cli-report.json"
CLI_REPORT_MD = PROJECT_DIR / "reports/latest/owner-approval-cli-report.md"

# --- Allowed write roots (the only paths this module may ever write) --------
ALLOWED_WRITE_ROOTS = (
    PROJECT_DIR / "drafts/approval",
    PROJECT_DIR / "reports/latest",
    PROJECT_DIR / "audit",
)

SCHEMA_VERSION = "owner-approval-cli-2.1"

SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization|"
    r"cookie|set-cookie|credential|x-api-key|access[_-]?key|session)"
)

# Risk classes.
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_REVIEW_ONLY = "REVIEW_ONLY"

# Queue statuses (mirrors sentinel_owner_approval_queue.py).
QUEUE_PENDING_OWNER_REVIEW = "pending_owner_review"
QUEUE_APPROVED_FOR_DRAFT_ONLY = "approved_for_draft_only"
QUEUE_APPROVED_FOR_MANUAL_APPLY = "approved_for_manual_apply"  # NEVER set here
QUEUE_REJECTED = "rejected"
QUEUE_MONITOR_ONLY = "monitor_only"
QUEUE_BLOCKED_HIGH_RISK = "blocked_high_risk"

ALL_QUEUE_STATUSES = (
    QUEUE_PENDING_OWNER_REVIEW,
    QUEUE_APPROVED_FOR_DRAFT_ONLY,
    QUEUE_APPROVED_FOR_MANUAL_APPLY,
    QUEUE_REJECTED,
    QUEUE_MONITOR_ONLY,
    QUEUE_BLOCKED_HIGH_RISK,
)

ALLOWED_NEXT_ACTION = {
    QUEUE_PENDING_OWNER_REVIEW: "await_owner_decision",
    QUEUE_APPROVED_FOR_DRAFT_ONLY: "draft_only",
    QUEUE_APPROVED_FOR_MANUAL_APPLY: "manual_owner_apply",
    QUEUE_REJECTED: "no_action",
    QUEUE_MONITOR_ONLY: "observe_only",
    QUEUE_BLOCKED_HIGH_RISK: "no_action_blocked",
}

OWNER_APPROVAL_REQUIRED_BY_STATUS = {
    QUEUE_PENDING_OWNER_REVIEW: True,
    QUEUE_APPROVED_FOR_DRAFT_ONLY: False,
    QUEUE_APPROVED_FOR_MANUAL_APPLY: True,
    QUEUE_REJECTED: False,
    QUEUE_MONITOR_ONLY: False,
    QUEUE_BLOCKED_HIGH_RISK: True,
}

MUTATING_COMMANDS = {"approve-draft-only", "reject", "monitor", "comment"}


# ===========================================================================
# Safety helpers
# ===========================================================================
def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(value: Any, default: str = "-", max_len: int = 300) -> str:
    if value is None:
        return default
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    if SECRETISH_RE.search(text):
        return "[redacted]"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text or default


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_allowed_write(path: Path) -> None:
    if not any(is_within(path, root) for root in ALLOWED_WRITE_ROOTS):
        raise ValueError(
            f"Refusing to write outside allowed owner-approval CLI roots: {path}"
        )


def write_text_atomic(path: Path, content: str) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def write_json_atomic(path: Path, data: Any) -> None:
    write_text_atomic(
        path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )


def append_jsonl_atomic(path: Path, record: Dict[str, Any]) -> None:
    assert_allowed_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def read_queue(path: Path = QUEUE_JSON) -> Tuple[Optional[Dict[str, Any]], str]:
    try:
        if not path.exists():
            return None, "not_available"
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None, "read_error"
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None, "invalid_json"
    if not isinstance(data, dict):
        return None, "invalid_root"
    return data, "ok"


def normalize_risk(value: Any) -> str:
    risk = str(value or "").strip().upper()
    if risk in (RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY):
        return risk
    return RISK_HIGH


# ===========================================================================
# Queue lookup + transition logic
# ===========================================================================
def find_item(queue: Dict[str, Any], queue_id: str) -> Optional[Dict[str, Any]]:
    items = queue.get("queue_items")
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, dict) and item.get("queue_id") == queue_id:
            return item
    return None


def evaluate_command(command: str, item: Dict[str, Any]) -> Tuple[bool, Optional[str], str]:
    """Decide whether a command is allowed for an item.

    Returns (allowed, new_status_or_None, reason). new_status is None for
    'comment' (no status change) and for denied commands.
    apply_status is never changed by any command.
    """
    risk = normalize_risk(item.get("risk_classification"))
    old_status = str(item.get("queue_status", ""))

    if command == "comment":
        return True, None, "Owner note recorded; no risk/status change."

    if command == "reject":
        return True, QUEUE_REJECTED, "Owner rejected; no apply, apply_status stays not_applied."

    if command == "monitor":
        return True, QUEUE_MONITOR_ONLY, "Owner set monitor-only; observe only, no apply."

    if command == "approve-draft-only":
        if risk == RISK_HIGH:
            return False, None, "DENIED: HIGH can never be approved_for_draft_only."
        if risk in (RISK_MEDIUM, RISK_REVIEW_ONLY):
            return False, None, f"DENIED: {risk} cannot be auto-approved via CLI; requires explicit owner review."
        if risk == RISK_LOW:
            return True, QUEUE_APPROVED_FOR_DRAFT_ONLY, "Owner approved draft-only for LOW item; apply_status stays not_applied."
        return False, None, "DENIED: only LOW / draft-only-capable items may be approved draft-only."

    return False, None, f"DENIED: unknown command '{redact_text(command, max_len=40)}'."


def apply_transition(item: Dict[str, Any], command: str, new_status: Optional[str], note: Optional[str], timestamp: str) -> None:
    """Mutate the item in place. apply_status is forced to not_applied."""
    if new_status is not None:
        item["queue_status"] = new_status
        item["allowed_next_action"] = ALLOWED_NEXT_ACTION.get(new_status, "no_action")
        item["owner_approval_required"] = OWNER_APPROVAL_REQUIRED_BY_STATUS.get(new_status, True)
    # Safety invariants: apply_status never changes; manual-apply never set here.
    item["apply_status"] = "not_applied"
    if note is not None:
        redacted = redact_text(note, default="-", max_len=240)
        item["owner_note"] = redacted
        history = item.get("owner_note_history")
        if not isinstance(history, list):
            history = []
        history.append({"timestamp_utc": timestamp, "command": command, "note": redacted})
        item["owner_note_history"] = history
    item["last_owner_action"] = command
    item["last_owner_action_utc"] = timestamp


def compute_policy_breach(items: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Policy breach: a HIGH item approved, manual-apply set, or any
    apply_status != not_applied. Owner reject/monitor of HIGH is NOT a breach."""
    problems: List[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        risk = normalize_risk(item.get("risk_classification"))
        status = str(item.get("queue_status", ""))
        if item.get("apply_status") != "not_applied":
            problems.append(f"apply_status != not_applied: {item.get('queue_id')}")
        if status == QUEUE_APPROVED_FOR_MANUAL_APPLY:
            problems.append(f"approved_for_manual_apply set: {item.get('queue_id')}")
        if risk == RISK_HIGH and status in (QUEUE_APPROVED_FOR_DRAFT_ONLY, QUEUE_APPROVED_FOR_MANUAL_APPLY):
            problems.append(f"HIGH approved: {item.get('queue_id')}")
    return (len(problems) > 0), problems


def recompute_aggregates(queue: Dict[str, Any]) -> None:
    items = [i for i in queue.get("queue_items", []) if isinstance(i, dict)]
    counts = {s: 0 for s in ALL_QUEUE_STATUSES}
    for item in items:
        st = item.get("queue_status")
        if st in counts:
            counts[st] += 1
    breach, problems = compute_policy_breach(items)
    queue["status_counts"] = counts
    queue["queue_breach"] = breach
    queue["queue_breach_problems"] = problems
    pending = [i for i in items if i.get("queue_status") == QUEUE_PENDING_OWNER_REVIEW]
    queue["top_pending_items"] = [
        {
            "queue_id": i.get("queue_id"),
            "title": redact_text(i.get("title"), max_len=160),
            "impact_area": redact_text(i.get("impact_area"), max_len=40),
            "risk_classification": normalize_risk(i.get("risk_classification")),
        }
        for i in pending[:5]
    ]
    queue["summary"] = {
        "queue_item_count": len(items),
        "pending_owner_review_count": counts[QUEUE_PENDING_OWNER_REVIEW],
        "approved_for_draft_only_count": counts[QUEUE_APPROVED_FOR_DRAFT_ONLY],
        "approved_for_manual_apply_count": counts[QUEUE_APPROVED_FOR_MANUAL_APPLY],
        "rejected_count": counts[QUEUE_REJECTED],
        "monitor_only_count": counts[QUEUE_MONITOR_ONLY],
        "blocked_high_risk_count": counts[QUEUE_BLOCKED_HIGH_RISK],
        "all_not_applied": all(i.get("apply_status") == "not_applied" for i in items),
    }


# ===========================================================================
# Rendering
# ===========================================================================
def render_queue_md(queue: Dict[str, Any]) -> str:
    summary = queue.get("summary", {})
    lines = ["# Owner Approval Queue (owner-updated, review only)", ""]
    lines.append(f"- Updated (UTC): `{utc_now()}`")
    lines.append(
        f"- Items: {summary.get('queue_item_count')} "
        f"(pending={summary.get('pending_owner_review_count')}, "
        f"draft_only={summary.get('approved_for_draft_only_count')}, "
        f"rejected={summary.get('rejected_count')}, "
        f"monitor_only={summary.get('monitor_only_count')}, "
        f"blocked_high_risk={summary.get('blocked_high_risk_count')})"
    )
    lines.append(f"- all_not_applied: {summary.get('all_not_applied')} · queue_breach: {queue.get('queue_breach')}")
    lines.append("- Mode: review-only; nothing applied. apply_status=not_applied. No apply function.")
    lines.append("")
    lines.append("| queue_id | risk | queue_status | next_action | apply_status | owner_note |")
    lines.append("|---|---|---|---|---|---|")
    for i in queue.get("queue_items", []):
        if not isinstance(i, dict):
            continue
        note = redact_text(i.get("owner_note"), default="-", max_len=60).replace("|", "\\|")
        lines.append(
            f"| `{i.get('queue_id')}` | {i.get('risk_classification')} | "
            f"`{i.get('queue_status')}` | {i.get('allowed_next_action')} | "
            f"{i.get('apply_status')} | {note} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_cli_report_md(report: Dict[str, Any]) -> str:
    lines = ["# Owner Approval CLI Report (Phase 2.1)", ""]
    lines.append(f"- Generated (UTC): `{report.get('generated_at_utc')}`")
    lines.append(f"- Last command: `{report.get('last_owner_action')}`")
    lines.append(f"- Allowed: {report.get('last_owner_action_allowed')}")
    lines.append(f"- Queue id: `{report.get('last_owner_action_queue_id')}`")
    lines.append(f"- Status change: `{report.get('last_owner_action_status_change')}`")
    lines.append(f"- apply_status: `{report.get('apply_status')}`")
    lines.append(f"- Queue policy breach: {report.get('queue_policy_breach')}")
    lines.append(f"- Reason: {report.get('reason')}")
    lines.append("")
    lines.append("## Safety")
    lines.append("")
    lines.append("- Owner CLI changes status inside the queue only; nothing applied.")
    lines.append("- apply_status stays not_applied; approved_for_manual_apply is never set here.")
    lines.append("- HIGH is never approved_for_draft_only; MEDIUM/REVIEW_ONLY is never auto-approved.")
    lines.append("- No WordPress/.htaccess/Cloudflare/Nginx/external change; no network access.")
    lines.append("- No secrets/cookies/authorization values are stored or emitted.")
    lines.append("")
    return "\n".join(lines)


# ===========================================================================
# Command handlers
# ===========================================================================
def cmd_list(queue: Dict[str, Any]) -> int:
    items = [i for i in queue.get("queue_items", []) if isinstance(i, dict)]
    if not items:
        print("Queue is empty or not available.")
        return 0
    by_status: Dict[str, List[Dict[str, Any]]] = {}
    for item in items:
        by_status.setdefault(str(item.get("queue_status", "unknown")), []).append(item)
    for status in ALL_QUEUE_STATUSES:
        group = by_status.get(status, [])
        print(f"\n[{status}] ({len(group)})")
        for item in group:
            print(
                f"  {item.get('queue_id')}  risk={item.get('risk_classification')}  "
                f"next={item.get('allowed_next_action')}  apply={item.get('apply_status')}"
            )
    return 0


def cmd_show(queue: Dict[str, Any], queue_id: str) -> int:
    item = find_item(queue, queue_id)
    if item is None:
        print(f"ERROR: queue_id not found: {redact_text(queue_id, max_len=80)}")
        return 2
    fields = (
        "queue_id", "roadmap_id", "source", "title", "impact_area",
        "risk_classification", "autonomy_policy_class", "queue_status",
        "allowed_next_action", "apply_status", "owner_approval_required",
        "owner_note", "reason",
    )
    print(f"Queue item: {item.get('queue_id')}")
    for f in fields:
        if f in item:
            print(f"  {f}: {redact_text(item.get(f), default='-', max_len=200)}")
    return 0


def cmd_mutate(queue: Dict[str, Any], command: str, queue_id: str, note: Optional[str]) -> int:
    item = find_item(queue, queue_id)
    timestamp = utc_now()
    if item is None:
        # Nothing is written for an invalid queue_id.
        print(f"ERROR: queue_id not found: {redact_text(queue_id, max_len=80)}")
        _write_cli_report(command, queue_id, False, None, "DENIED: queue_id not found.", timestamp, queue_policy_breach=False, persisted=False)
        return 2

    old_status = str(item.get("queue_status", ""))
    allowed, new_status, reason = evaluate_command(command, item)

    if not allowed:
        # Denied commands must not change the queue.
        print(f"DENIED ({command} on {queue_id}): {reason}")
        _audit(command, queue_id, old_status, old_status, False, reason, note, timestamp)
        _write_cli_report(command, queue_id, False, f"{old_status} -> {old_status}", reason, timestamp, queue_policy_breach=bool(queue.get("queue_breach")), persisted=False)
        return 1

    apply_transition(item, command, new_status, note, timestamp)
    recompute_aggregates(queue)
    breach = bool(queue.get("queue_breach"))
    effective_new = item.get("queue_status")
    status_change = f"{old_status} -> {effective_new}"

    # Persist queue + audit + cli report.
    queue["last_updated_by"] = "owner_approval_cli"
    queue["last_updated_utc"] = timestamp
    write_json_atomic(QUEUE_JSON, queue)
    write_text_atomic(QUEUE_MD, render_queue_md(queue))
    _audit(command, queue_id, old_status, effective_new, True, reason, note, timestamp)
    _write_cli_report(command, queue_id, True, status_change, reason, timestamp, queue_policy_breach=breach, persisted=True)
    print(f"OK ({command} on {queue_id}): {status_change} (apply_status=not_applied)")
    return 0


def _audit(command: str, queue_id: str, old_status: str, new_status: str, allowed: bool, reason: str, note: Optional[str], timestamp: str) -> None:
    record = {
        "timestamp_utc": timestamp,
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "queue_id": queue_id,
        "old_status": old_status,
        "new_status": new_status,
        "allowed": allowed,
        "reason": reason,
        "owner_note_redacted": redact_text(note, default="-", max_len=240) if note is not None else "-",
        "apply_status": "not_applied",
    }
    append_jsonl_atomic(AUDIT_JSONL, record)


def _write_cli_report(command: str, queue_id: str, allowed: bool, status_change: Optional[str], reason: str, timestamp: str, queue_policy_breach: bool, persisted: bool) -> None:
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": timestamp,
        "read_only_outside_queue": True,
        "productive_change": False,
        "apply_function": False,
        "last_owner_action": command,
        "last_owner_action_allowed": bool(allowed),
        "last_owner_action_queue_id": redact_text(queue_id, default="-", max_len=80),
        "last_owner_action_status_change": status_change,
        "apply_status": "not_applied",
        "queue_policy_breach": bool(queue_policy_breach),
        "persisted": bool(persisted),
        "reason": reason,
    }
    write_json_atomic(CLI_REPORT_JSON, report)
    write_text_atomic(CLI_REPORT_MD, render_cli_report_md(report))


# ===========================================================================
# Self-tests
# ===========================================================================
def run_self_tests() -> int:
    # Write-path guard.
    for ok in (QUEUE_JSON, QUEUE_MD, AUDIT_JSONL, CLI_REPORT_JSON, CLI_REPORT_MD):
        assert_allowed_write(ok)
    for forbidden in (
        Path("/etc/nginx/c.conf"),
        Path("/var/www/.htaccess"),
        Path("/srv/sentinel-defense/sentinel_master.py"),
        Path("/srv/sentinel-defense/drafts/roadmap/x.json"),
    ):
        try:
            assert_allowed_write(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError(f"forbidden write path not rejected: {forbidden}")

    def item(qid, risk, status="pending_owner_review"):
        return {
            "queue_id": qid, "risk_classification": risk, "queue_status": status,
            "allowed_next_action": "await_owner_decision", "apply_status": "not_applied",
            "owner_approval_required": True, "title": "t", "impact_area": "SEO",
        }

    # approve-draft-only: LOW allowed, HIGH denied, MEDIUM/REVIEW_ONLY denied.
    low = item("q:low", RISK_LOW)
    allowed, new, reason = evaluate_command("approve-draft-only", low)
    assert allowed is True and new == QUEUE_APPROVED_FOR_DRAFT_ONLY
    high = item("q:high", RISK_HIGH, "blocked_high_risk")
    allowed, new, reason = evaluate_command("approve-draft-only", high)
    assert allowed is False and new is None and "HIGH" in reason
    med = item("q:med", RISK_MEDIUM)
    allowed, new, reason = evaluate_command("approve-draft-only", med)
    assert allowed is False and new is None
    rev = item("q:rev", RISK_REVIEW_ONLY)
    allowed, new, reason = evaluate_command("approve-draft-only", rev)
    assert allowed is False and new is None

    # reject / monitor allowed for any risk.
    for risk in (RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_REVIEW_ONLY):
        a, n, _ = evaluate_command("reject", item("q", risk))
        assert a is True and n == QUEUE_REJECTED
        a, n, _ = evaluate_command("monitor", item("q", risk))
        assert a is True and n == QUEUE_MONITOR_ONLY

    # comment: allowed, no status change.
    a, n, _ = evaluate_command("comment", item("q", RISK_LOW))
    assert a is True and n is None

    # approved_for_manual_apply is never produced.
    for cmd in ("approve-draft-only", "reject", "monitor", "comment"):
        _, n, _ = evaluate_command(cmd, item("q", RISK_LOW))
        assert n != QUEUE_APPROVED_FOR_MANUAL_APPLY

    # apply_transition keeps apply_status not_applied and redacts notes.
    it = item("q:low", RISK_LOW)
    apply_transition(it, "approve-draft-only", QUEUE_APPROVED_FOR_DRAFT_ONLY, "ok note", "T")
    assert it["queue_status"] == QUEUE_APPROVED_FOR_DRAFT_ONLY
    assert it["apply_status"] == "not_applied"
    assert it["allowed_next_action"] == "draft_only"
    it2 = item("q:s", RISK_LOW)
    apply_transition(it2, "comment", None, "Bearer secrettoken", "T")
    assert it2["owner_note"] == "[redacted]"
    assert it2["queue_status"] == "pending_owner_review"  # comment does not change status

    # Policy breach detection.
    clean = [item("a", RISK_LOW, QUEUE_APPROVED_FOR_DRAFT_ONLY), item("b", RISK_HIGH, QUEUE_BLOCKED_HIGH_RISK),
             item("c", RISK_HIGH, QUEUE_MONITOR_ONLY)]  # HIGH monitor is NOT a breach
    breach, problems = compute_policy_breach(clean)
    assert breach is False, problems
    dirty = [item("d", RISK_HIGH, QUEUE_APPROVED_FOR_DRAFT_ONLY)]  # HIGH approved -> breach
    breach2, problems2 = compute_policy_breach(dirty)
    assert breach2 is True and problems2
    applied = item("e", RISK_LOW, QUEUE_APPROVED_FOR_DRAFT_ONLY)
    applied["apply_status"] = "applied"
    breach3, _ = compute_policy_breach([applied])
    assert breach3 is True

    # recompute_aggregates produces consistent counts.
    q = {"queue_items": [item("a", RISK_LOW, QUEUE_APPROVED_FOR_DRAFT_ONLY),
                          item("b", RISK_MEDIUM, QUEUE_PENDING_OWNER_REVIEW),
                          item("c", RISK_HIGH, QUEUE_BLOCKED_HIGH_RISK)]}
    recompute_aggregates(q)
    assert q["summary"]["approved_for_draft_only_count"] == 1
    assert q["summary"]["pending_owner_review_count"] == 1
    assert q["summary"]["blocked_high_risk_count"] == 1
    assert q["summary"]["all_not_applied"] is True
    assert q["queue_breach"] is False

    # find_item.
    assert find_item(q, "a") is not None
    assert find_item(q, "missing") is None

    print("owner-approval-cli self-tests: OK")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Owner Approval CLI (queue-only; no apply)."
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in safety/unit tests.")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List queue items grouped by status.")

    p_show = sub.add_parser("show", help="Show one queue item.")
    p_show.add_argument("--queue-id", required=True)

    for name in ("approve-draft-only", "reject", "monitor", "comment"):
        p = sub.add_parser(name)
        p.add_argument("--queue-id", required=True)
        p.add_argument("--note", default=None)

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()

    if not args.command:
        print("ERROR: no command given. Use: list | show | approve-draft-only | reject | monitor | comment")
        return 2

    try:
        queue, status = read_queue()
        if queue is None:
            print(f"ERROR: approval queue not available ({status}). Run sentinel_owner_approval_queue.py first.")
            return 2

        if args.command == "list":
            return cmd_list(queue)
        if args.command == "show":
            return cmd_show(queue, args.queue_id)
        if args.command in MUTATING_COMMANDS:
            return cmd_mutate(queue, args.command, args.queue_id, getattr(args, "note", None))

        print(f"ERROR: unknown command '{redact_text(args.command, max_len=40)}'.")
        return 2
    except Exception as exc:  # never crash; report clearly
        print(f"ERROR: {exc.__class__.__name__}: {redact_text(str(exc), max_len=160)}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
