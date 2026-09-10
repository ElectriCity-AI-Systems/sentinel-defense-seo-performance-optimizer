# Sentinel Bot Defense V1 - Design Review

Classification: PRIVATE_OWNER_DESIGN | SIMULATION_ONLY | NO_PRODUCTION_APPLY

## Decision

`SENTINEL_BOT_DEFENSE_V1` targets behavior, not named user agents. The IONOS
search-engine category declined from 510 to 421 requests. SiteLockSpider
declined from 102 to 67 requests, while the previously observed `/wp-login.php`
volume was 7,466 requests. Search crawlers therefore do not explain the large
login/scanner volume, and SiteLockSpider is not the primary current problem.

The model keeps these classes separate:

- `VERIFIED_SEARCH_BOT`
- `KNOWN_COMMERCIAL_CRAWLER`
- `SECURITY_SCANNER`
- `UNKNOWN_AUTOMATION`
- `BEHAVIORAL_PHP_SCANNER`
- `NORMAL_BROWSER`

Googlebot, Bingbot, and Mediapartners-Google receive a hard false-positive
protection only when search identity is independently verified. A claimed user
agent is neither proof of identity nor sufficient evidence for an action.

`meta-webindexer`, `CMS-Security-Auditor`, `DataForSeoBot`, and SiteLockSpider
remain monitor-only when the evidence is only a named analytics aggregate.

## Behavioral Model

The score combines unusual PHP or WordPress paths, request velocity, suspicious
path diversity, 404/403/429/503 failure correlation, repeated source or actor
groups, HTTP method, success/failure ratio, and an automated user-agent signal.
The user-agent signal contributes at most 5 of 100 points and is excluded from
the minimum four independent behavioral signal families.

Observed random PHP paths such as `/000.php`, `/abcd.php`, `/bless.php`,
`/dex.php`, and `/file.php` can be classified as `BEHAVIORAL_PHP_SCANNER`.
Classification alone does not authorize a live action.

## Action Boundary

The only simulated defensive action is `TEMPORARY_MANAGED_CHALLENGE` through
the already registered `temporary_scanner_managed_challenge_v1` contract. Its
scope remains the existing static high-confidence scanner allowlist. This
design does not generate Cloudflare expressions and does not extend that
allowlist.

Consequences:

- random PHP or WordPress paths outside the existing allowlist are monitor-only;
- `/wp-login.php` POST bursts are monitor-only because the login action remains disabled;
- ordinary `/wp-login.php` GET requests are not challenged;
- `/xmlrpc.php` protection remains disabled;
- no country, ASN, broad IP, browser, or user-agent rule is permitted;
- no permanent block is permitted.

## Required Gates

A simulated candidate requires all of the following:

- current evidence no older than five minutes;
- at least 100 requests in at most five minutes;
- at least three suspicious paths;
- at least four independent behavioral signal families;
- low false-positive risk;
- legitimate path use explicitly disproven;
- no shared/NAT-source ambiguity;
- exact match to the existing registered scanner scope;
- website status `OK`;
- circuit breaker `CIRCUIT_BREAKER_ARMED`;
- `breach=false`;
- owner policy permits the existing action.

Missing or unknown evidence blocks the candidate.

## Preserved Limits

```text
MAX_ACTIONS_PER_HOUR=1
MAX_ACTIONS_PER_DAY=4
MAX_ACTIVE_RULES=1
RULE_TTL_MINUTES=10
COOLDOWN_MINUTES=30
```

The existing before-hash, canary, validation, Sentinel-owned rollback, expiry,
audit, cooldown, budget, and circuit-breaker requirements remain authoritative.

## Simulation

Run locally:

```bash
python3 sentinel_adaptive_bot_defense.py --self-test
python3 sentinel_adaptive_bot_defense.py --validate-playbook
python3 sentinel_adaptive_bot_defense.py --simulate
python3 sentinel_adaptive_bot_defense.py --build-report
```

The regression suite covers normal browsers, verified Google, Bing, and
Mediapartners-Google bots, SiteLock without proven harm, normal login GET,
suspicious login POST bursts, random PHP scanners, Go-http-client as a
supporting signal, shared/NAT false positives, IPv4, IPv6, malformed evidence,
and the separately monitored named crawlers. It also reconciles all supplied
analytics actor counts to the reported total of 421.

The module does not invoke a network client, Cloudflare adapter, subprocess, or
runtime-state writer. It creates only fixed local design reports when
`--build-report` is explicitly selected.

## Owner Gate

This package is ready for simulation only. It is not wired into the production
decision engine, does not activate LOW_LIVE, and does not authorize deployment.
A later owner review would be required before any runtime integration or scope
change.
