# Proof-Carrying Autonomous Remediation

## Objective

Sentinel must not receive broader authority merely because it can classify a problem. A productive candidate is eligible only when it carries a machine-verifiable safety proof and a separate adapter-free verifier accepts that proof.

The layer does not activate runtime flags, access credentials, call remote APIs, or add authority. In the final production boundary, all autonomous external and WAF mutation contracts are runtime-disabled. The proof path remains as a fail-closed invariant for any future owner-reviewed action class.

## Architecture

The enforcement path is:

1. Existing telemetry and diagnostics select a registered candidate.
2. The proof builder binds current evidence hashes, freshness, trigger facts, action scope, policy hashes, runtime flags, TTL, health profile, and change budget into a short-lived PREPARE envelope.
3. The independent verifier re-reads fixed local evidence and rejects stale, changed, incomplete, or expanded proofs.
4. Only after `PROOF_PREPARE_VERIFIED` may the existing adapter perform its read-only prepare operation.
5. The proof builder binds the remote before-hash and the local rollback artifact into a COMMIT envelope.
6. The independent verifier validates artifact identity and requires `after_hash=null`, proving no productive write has occurred yet.
7. Only after `PROOF_COMMIT_VERIFIED` could a separately owner-enabled guarded canary path continue. No such external path is enabled in the final production policy.

Any missing or failed check produces `NO_ACTION` or `PROOF_GATE_BLOCKED`.

## Independent Verifier Boundary

The verifier intentionally has no:

- adapter import
- credential file access
- network library
- subprocess execution
- arbitrary path input
- productive write capability

It reads only fixed project-local policy, reports, state, and rollback artifacts. This implements least privilege consistent with [NIST SP 800-207](https://doi.org/10.6028/NIST.SP.800-207).

## Canary and Change Budget

Google SRE describes canarying as a way to learn about a change while limiting the affected population and error-budget cost. Sentinel therefore permits at most one active action, one new action per hour, a ten-minute maximum TTL, and zero tolerated failed rollbacks. See [Canarying Releases](https://sre.google/workbook/canarying-releases/).

The proof gate does not treat an exhausted technical reliability reference as proof of user harm. It retains `verified_user_impact=unknown` unless direct user evidence exists.

## Bot Protection Scope

OWASP recommends classifying automated abuse before applying controls and preserving legitimate bots and users. Sentinel therefore requires every observed trigger path to belong to its static high-confidence scanner allowlist. Mixed path groups are ineligible because aggregate volume cannot be attributed safely. See the [OWASP Bot Management and Anti-Automation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html).

The static scanner contract remains review-only. Autonomous WAF execution is disabled, so scanner evidence produces monitoring, diagnosis, and owner escalation rather than a rule write.

## Crash Safety and Local Self-Healing

All Sentinel-owned derived-state writes use atomic replacement and filesystem synchronization. A durable transaction journal records every pre-apply and apply boundary. An interrupted pre-apply transaction is closed without a productive write; an uncertain apply requires read-only reconciliation and exact rollback, otherwise Sentinel enters emergency stop.

Sentinel may repair only its two mirrored guarded-runtime state documents. Repair requires one exact valid mirror and one invalid or missing peer. Existing bytes are backed up, the replacement hash is verified, and a failed verification restores the backup. Two conflicting valid documents produce no change.

## Independent Production Runtime

The systemd timer calls a fixed Python entry point every two minutes. Runtime modules have no dependency on Codex, Claude, ChatGPT, or another LLM. A committed source manifest seals the executable runtime, policy, unit, and safety playbook hashes; source drift blocks any productive action while monitoring remains fail-closed.

## Origin Evidence

Owner-provided origin logs may be placed manually in the fixed local evidence spool. The collector accepts bounded JSON, JSONL, and log files, rejects symlinks and oversized files, skips secret-bearing rows, and stores only normalized categories, timestamps, status codes, path classes, and fingerprints. Raw lines and filenames are not retained.

The spool ignores all evidence files in Git by default. Only its `.gitignore` guard is repository-safe.

Direct origin evidence can identify PHP fatal errors, WordPress application failures, upstream timeouts, hosting resource limits, database failures, and origin TLS failures. It never authorizes WordPress, PHP, database, hosting, DNS, SSL, or Nginx changes automatically.

## Immutable Safety Boundary

- no new live action class
- no autonomous external or WAF mutation
- no runtime activation effect
- no automatic policy expansion
- no WordPress, PHP, database, DNS, SSL, certificate, or Nginx mutation
- no country, ASN, browser, or root-path rule
- no LOW_LIVE action without both proof phases
- no LOW_LIVE action without a proven cause and exact scope
- no source-code self-modification
- MEDIUM and HIGH remain unavailable
- rollback remains possible even when new actions are blocked
- audit records are hash-chained
- reports, state, audit, and origin evidence remain outside Git recommendations

The governance model follows the continuous monitoring, documented oversight, recovery, and deactivation outcomes in the [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/).
