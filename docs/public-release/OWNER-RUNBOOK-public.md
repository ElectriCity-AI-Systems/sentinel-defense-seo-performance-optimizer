# Public Owner Runbook

## Start

1. Run `python3 sentinel_autonomy.py status`.
2. Run `python3 sentinel_autonomy.py preflight`.
3. Review the public safety boundaries.

## Daily Manual Flow

1. Check status.
2. Check operation-governor status.
3. Run a bounded safe batch only when local reports should be refreshed.
4. Review the owner briefing and readiness seal.

## Safe Diagnosis Flow

1. Run preflight.
2. Run operation-governor status.
3. Run soak status.
4. Run release-candidate status.
5. Review generated local evidence before deciding any next phase.

## Owner Review Flow

Any production action starts as a separate owner-reviewed phase. Sentinel public release commands do not approve production changes.

## Git Checkpoint Flow

Commit only code, playbooks and public release docs listed in `COMMIT-RECOMMENDATION.md`. Keep local runtime artifacts out of public commits.

## Emergency Note

Emergency Stop remains active for live/external actions. It does not block safe local documentation or validation.
