# Owner Commands

These commands create local reports, local state, local audit events and local documentation. They must not perform live changes.

- `python3 sentinel_autonomy.py status`: Show the local safe operations status.
- `python3 sentinel_autonomy.py preflight`: Check local prerequisites and safety flags.
- `python3 sentinel_autonomy.py operation-governor-status`: Show operation scoring and diversity state.
- `python3 sentinel_autonomy.py run-safe-once`: Run one bounded local safe operation.
- `python3 sentinel_autonomy.py run-safe-batch 3`: Run a bounded local batch of safe operations.
- `python3 sentinel_autonomy.py soak-status`: Show the latest local soak-test result.
- `python3 sentinel_autonomy.py soak-run 3`: Run a bounded local soak test.
- `python3 sentinel_autonomy.py readiness-seal`: Build or show the local readiness seal.
- `python3 sentinel_autonomy.py rc-status`: Show release-candidate status.
- `python3 sentinel_autonomy.py rc-briefing`: Build the owner command console.
- `python3 sentinel_autonomy.py rc-evidence`: Build the local evidence pack.
- `python3 sentinel_autonomy.py rc-runbook`: Build the owner runbook.
- `python3 sentinel_autonomy.py public-release-status`: Show public release pack status.
- `python3 sentinel_autonomy.py public-summary`: Build public README and manifest.
- `python3 sentinel_autonomy.py sales-copy`: Build Payhip, Gumroad and FAQ copy.
- `python3 sentinel_autonomy.py github-release-notes`: Build GitHub release notes.

The commands above are bounded local flows. They do not install timers, send email, call production APIs, write remote systems or disable emergency stop.
