# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Sentinel Defense is a **defensive, report-driven** protection and improvement chain for the
`electri-c-ity-studios-24-7.com` website (behind Cloudflare), a Hetzner server, and a private
local Ubuntu PC. It is a collection of standalone Python 3.12 scripts and bash helpers wired
together by systemd timers — there is no package, build step, or test suite. Most documentation
(README, runbooks, `docs/`) is written in German; keep that convention when editing docs.

The single most important property of this codebase is its **safety model** (see below). Almost
every script is structurally read-only and refuses to mutate production. Preserve those guarantees
when changing anything.

## Safety model — do not break these invariants

These are enforced structurally throughout the code and stated in nearly every script's docstring:

- **Read-only by default.** Most scripts perform no network access, no WordPress/CMS login, no
  API calls, and no production writes. They only read local snapshots/reports and write
  drafts/reports/audit files under this project tree.
- **The only script that touches Cloudflare** is `sentinel_defense_bot.py`, and only in
  `--mode apply-safe` / `consolidate-apply-safe` **with `--confirm-apply`**. Apply is gated by
  simulation, a ruleset backup, a rollback note, an allowlist of defensive actions, and
  `--max-actions <= 2`. Never add an auto-apply path or remove these gates.
- **Cloudflare actions are limited to `managed_challenge`.** No IP/ASN/country rules, no global
  blocks, no counter-attacks, no foreign scans, no credential collection. Foreign (non-Sentinel)
  Cloudflare rules must never be modified.
- **No secrets in logs or reports.** Never `source` `.env` files in a shell; the env file lives at
  `/etc/sentinel-defense.env` and is read via systemd `EnvironmentFile=` or a safe parser, not
  shell sourcing.
- The autonomy/approval pipeline (Phase 1.5–3.1 scripts) records *decisions and drafts only*. It
  never performs real approvals or applies. "Apply" in these script names means producing an
  owner-facing manual checklist, not executing a change.

## Common commands

All commands run from `/srv/sentinel-defense`.

```bash
# Generate the Cloudflare daily monitor report (feeds the bot)
/bin/bash cloudflare_daily_monitor.sh

# Website evaluation — observe (read-only scoring/recommendations only)
python3 sentinel_defense_bot.py --mode observe \
  --report cloudflare-monitor/latest/cloudflare-daily-monitor.md

# Website simulation (plans actions, no Cloudflare mutation)
python3 sentinel_defense_bot.py --mode simulate \
  --report cloudflare-monitor/latest/cloudflare-daily-monitor.md \
  --out-md reports/latest/sentinel-defense-simulate-report.md \
  --out-json reports/latest/sentinel-defense-simulate-report.json

# Hetzner local agent (read-only)
python3 sentinel_hetzner_local_agent.py --mode observe

# Aggregate everything into the master report
python3 sentinel_master.py

# Email the master report
python3 sentinel_daily_mailer.py --dry-run   # prints non-secret SMTP/report metadata
python3 sentinel_daily_mailer.py --send      # actually sends via SMTP (only outbound network use)

# Validate a produced report is well-formed JSON
python3 -m json.tool reports/latest/sentinel-master-report.json >/dev/null

# Timer health
systemctl is-active   cloudflare-daily-monitor.timer sentinel-defense.timer sentinel-master.timer sentinel-daily-mail.timer
systemctl list-timers cloudflare-daily-monitor.timer sentinel-defense.timer sentinel-master.timer sentinel-daily-mail.timer
```

Apply commands are deliberately kept out of this file and live only in a dedicated manual section
of the runbooks (`SENTINEL_*_RUNBOOK.md`).

## Architecture

### Daily defense chain (the original pipeline)

```text
cloudflare_daily_monitor.sh        # bash: produces cloudflare-monitor/latest/cloudflare-daily-monitor.md
  -> sentinel_defense_bot.py       # website evaluation: watchpoints, Correlation Layer v2, Trend Layer
  -> sentinel_hetzner_local_agent.py  # passive local server metrics -> reports/latest + inbox/local
  -> sentinel_master.py            # aggregates website + local (+ many optional) reports
  -> sentinel_daily_mailer.py      # SMTP send with --send
```

`sentinel_master.py` reads the website report from `reports/latest/sentinel-defense-report.json`
and the Hetzner-local report from `inbox/local/local-defense-report.json` as **required** sources;
if either is missing it must not aggregate to `OK`. It also optionally folds in ~20 other report
JSONs (sourcemap, AI-radio timeout, autonomy policy, SEO optimizer, perf audit, roadmap, approval
queue, etc.) via `--*-json` flags, each with a default path under `reports/latest/`.

### Operating cycle and status vocabulary

```text
observe -> correlate -> simulate -> apply-safe -> validate -> report
```

Status values that appear across reports (defined in README / `docs/sentinel-current-state.md`):
- Overall: `OK`, `WARNING`, `CRITICAL` (`CRITICAL` never triggers an automatic apply)
- Website correlation: `NORMAL`, `WATCH`, `ACTION_CANDIDATE`
- Action: `OK`, `WARNING_REVIEW`, `APPLY_CANDIDATE`, `WATCH_ONLY`, `LOCAL_ATTENTION`, `UNKNOWN`

Cloudflare reports use a **rolling 24h window**, so old events can still show as `CRITICAL` for a
while after a protective rule is in place — this is expected, not a regression.

### Autonomy / owner-approval pipeline (Phase 1.5 → 3.1)

A second, newer layer turns read-only SEO/performance findings into owner-reviewable drafts. Each
script is a phase that consumes the previous phase's JSON and writes its own draft/report/audit
output. None of them apply anything; the chain ends at a human-executed manual checklist.

```text
sentinel_seo_safe_optimizer.py / sentinel_performance_safe_audit.py  (read-only audits)
  -> sentinel_safe_improvement_roadmap.py        (1.9  merge into prioritized roadmap)
  -> sentinel_autonomy_policy.py                 (1.5  policy: whether an action could ever be allowed)
  -> sentinel_owner_approval_queue.py            (2.0  build approval queue, draft-only for safe LOW)
  -> sentinel_owner_approval_cli.py              (2.1  owner records status changes in-queue only)
  -> sentinel_draft_execution_planner.py         (2.3  LOW approved-for-draft -> manual draft plans)
  -> sentinel_owner_review_pack.py               (2.4  owner-facing copy-paste pack)
  -> sentinel_manual_apply_checklist.py          (2.5  manual checklist; applies nothing)
  -> sentinel_post_manual_validation.py          (2.6  read-only validation after manual changes)
  -> sentinel_manual_completion_tracker.py       (2.7  track owner-reported progress)
  -> sentinel_owner_daily_action_summary.py      (2.8  short owner daily summary + readiness)
  -> sentinel_safe_apply_candidate_registry.py   (3.0  registry of LOW candidates for future autonomy)
  -> sentinel_safe_apply_guard_checker.py        (3.1  check registry guard readiness)
  -> sentinel_safe_apply_scope_manager.py        (3.2  strict scope/allowlist of permitted future scope types)
  -> sentinel_safe_apply_dry_run_planner.py      (3.3  dry-run plans: prechecks/postchecks/rollback, applies nothing)
  -> sentinel_safe_apply_preflight_validator.py  (3.4  validate global + per-candidate preflight preconditions, applies nothing)
  -- sentinel_autonomy_runtime_lock.py           (3.5  owner-controlled runtime lock + disable switch; subcommands, state in config/, applies nothing)
  -> sentinel_safe_draft_autonomy_runner.py      (3.6  gated by 3.5 lock; refreshes draft/report/validation files only, no live apply)
  -> sentinel_safe_draft_autonomy_verifier.py    (3.7  read-only verification of 3.6 outputs: existence/allowed-path/JSON/secret/non-productive checks, applies nothing)
  -> sentinel_safe_draft_autonomy_scheduler_plan.py (3.8  review-only scheduler plan: planned frequency/sequence/preconditions/stop-conditions for a FUTURE timer; installs no timer, writes no systemd/cron, applies nothing)
  -> sentinel_safe_draft_autonomy_timer_draft.py  (3.9  review-only systemd service/timer DRAFTS + install/rollback review under drafts/apply; never writes /etc/systemd or crontab, runs no systemctl, applies nothing)
  -> sentinel_safe_draft_autonomy_timer_install_reviewer.py (4.0  install-readiness review of the 3.9 drafts: scans draft content for banner/active-ExecStart/systemctl/network/secret, emits owner checklist; installs nothing, emergency-stop blocks but is not a breach)
  -- (Phases 4.1 -> 5.4 add further read-only owner packet/evidence/decision-gate, master-critical-cause, rolling-window-decay, low-growth-readiness and manual-website-recheck modules; each consumes the prior phase JSON, writes report/snapshot/draft/audit only, and applies nothing.)
  -> sentinel_low_risk_autonomy_readiness_gate.py (5.5  read-only readiness gate: from the 5.4 manual-website-recheck-gate + low-growth/rolling-window/critical-cause/final-owner/final-safety reports + runtime lock, decides whether LOW-RISK SEO/perf autonomy may even be PREPARED as a policy draft; emergency-stop blocks but is not a breach; never enables apply/install/timer, writes reports/latest+drafts/owner+snapshots+audit only)
  -> sentinel_low_risk_policy_boundary_draft.py (5.6  read-only policy boundary draft: from the 5.5 readiness gate + recheck/low-growth/rolling-window/critical-cause/final-owner + safe-apply candidate/guard/scope/preflight reports + runtime lock, classifies possible future SEO/perf actions into LOW_RISK_DRAFT_ONLY / LOW_RISK_REVIEW_ONLY / LOW_RISK_POTENTIAL_FUTURE_APPLY / MEDIUM_RISK_OWNER_APPROVAL_REQUIRED / HIGH_RISK_NEVER_AUTO_APPLY / FORBIDDEN; every future LOW-RISK action presupposes backup/healthcheck/rollback/audit/owner-policy-review; activates nothing, policy_activation_allowed=false, emergency-stop locks but is not a breach; writes reports/latest+drafts/owner+snapshots+audit only)
  -> sentinel_low_risk_policy_owner_review_tracker.py (5.7  review-only owner tracker for the 5.6 policy boundary items; starts unchecked, records only reviewed/needs_work/reset state in state/+reports/latest+drafts/owner+snapshots+audit, rejects secret-like notes, and never activates anything)
  -> sentinel_low_risk_policy_review_completion_gate.py (5.8  read-only completion gate: checks whether all 5.7 policy review items are reviewed; complete still means locked by Emergency Stop, not activation)
  -> sentinel_low_risk_autonomy_final_safety_seal.py (5.9  read-only final safety seal for the LOW-RISK preparation chain: policy boundary, owner review, completion gate, runtime lock and final safety signals; no live apply, no install)
  -> sentinel_safe_end_summary.py (5.10  final owner summary of the safe locked end state across evidence review, website/rolling-window diagnostics and LOW-RISK policy chain; reports SAFE_END_COMPLETE_LOCKED or SAFE_END_INCOMPLETE_LOCKED, applies nothing)
  -> sentinel_safe_end_archive_snapshot.py (5.11  archive/readiness snapshot for the locked Safe-End state: SHA256 checksums, manifest, copied JSON/MD/TXT references and owner restore-readiness checklist under archives/safe-end; no restore script, no install, no activation)
  -> sentinel_safe_end_archive_integrity_verifier.py (5.12  read-only verifier for the latest Safe-End archive: checks manifest, copied archive files, SHA256 checksums and forbidden artifacts; no restore, no install, no activation)
  -> sentinel_concrete_seo_performance_optimizer.py (6.0  read-only concrete SEO/perf owner draft packs incl. the WordPress JSON-LD schema pack; produces copy/paste owner drafts only, no live apply)
  -> sentinel_safe_sftp_seo_apply_lane.py (6.1  FIRST controlled LOW-RISK auto-apply lane: builds a tightly-scoped WordPress MU-plugin that ONLY injects static JSON-LD into wp_head and can publish it via SFTP to exactly one allowed path (wp-content/mu-plugins/sentinel-seo-jsonld-injector.php). Modes: dry-run/prepare-upload NEVER upload; apply-with-owner-approval uploads only with state/owner-approved-seo-jsonld-apply.json present, guarded by backup + atomic rename + HTTP healthcheck + SFTP rollback; rollback touches only the one allowed file. SFTP creds env-only, never written to outputs. Any change outside the single target, forbidden plugin token, infra/DB write, secret output, or healthcheck+rollback failure is apply_breach. Writes reports/latest+drafts/owner+snapshots+audit+exports/sftp-seo-apply only)
```

Phase 5.10 is a safe locked end state, not autonomy activation.
Phase 5.11 archives the locked safe end state. It is not activation, not install, not restore.
Phase 5.12 verifies the locked archive. It is not restore, not activation, not install.
Phase 6.1 is the first controlled live-apply lane and is the ONLY non-Cloudflare script that may write to production — and only the single allowed MU-plugin path, only via `apply-with-owner-approval` with an explicit owner-approval file. Dry-run/prepare are the safe defaults; there is no uncontrolled live apply.

`sentinel_owner_approval_cli.py` and `sentinel_manual_completion_tracker.py` use argparse
subcommands (`list`, `show`, plus per-item status commands). The phase number in each docstring is
the canonical ordering.

### Standalone diagnostic tools

`sentinel_sourcemap_prevention.py` (`--mode observe|simulate|sourcemap-apply-safe`; the only other
script with an apply mode, scoped strictly to WPO-Minify cache edits, never Cloudflare/WordPress
source) and the `sentinel_ai_radio_*` scripts (Cloudflare origin discovery, microcache preflight,
API timeout diagnosis) are independent investigations that emit JSON+MD into `reports/latest/`.

## Conventions

- **Output pattern:** scripts take `--out-md` / `--out-json` / `--history-path` and write a Markdown
  report for humans plus a JSON twin for the next stage, appending to a JSONL history. Audit trails
  go to `audit/<tool>.jsonl`. Keep this MD+JSON+JSONL triple when adding a stage.
- **Default paths** are module-level `DEFAULT_*` constants near the bottom argparse block; prefer
  adding a flag with a sensible default over hardcoding a path inline.
- Directory roles: `reports/latest/` (current outputs) and `reports/history/` (JSONL),
  `inbox/local/` (compat location for the local agent's report), `drafts/` (per-phase draft output),
  `config/` (owner-controlled runtime state, e.g. `autonomy-runtime-lock.json`),
  `audit/` (JSONL audit logs), `cloudflare-monitor/` (raw monitor snapshots), `seo-inputs/`,
  `ionos-htaccess-backups/` and `sourcemap-backups/` (rollback material), `systemd/` (unit files).
- There is **no automated test suite.** `reports/latest/test-report.*` are sample data, not tests.
  Validate changes by running the relevant script in `observe`/`simulate`/`--dry-run` mode and
  checking the JSON parses.

## Reference

Runbooks (German) hold the authoritative manual/apply procedures and troubleshooting:
`SENTINEL_DEFENSE_RUNBOOK.md`, `SENTINEL_MASTER_RUNBOOK.md`, `SENTINEL_HETZNER_LOCAL_RUNBOOK.md`,
`SENTINEL_LOCAL_RUNBOOK.md`, and the read-only helper docs. `docs/sentinel-current-state.md`
records the documented operational state, including the active consolidated Cloudflare rule
`sentinel_combined_wordpress_scanner_challenge`.
