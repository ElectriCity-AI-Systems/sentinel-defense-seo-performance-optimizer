# Safety Boundaries

Sentinel is built around local autonomy with strict owner control.

## Blocked Automatically

- no unchecked live changes
- no automatic WordPress changes
- no automatic Cloudflare changes
- no database writes
- no SFTP/FTP uploads
- no Nginx changes
- no `.htaccess` changes
- no cache purge
- no URL rewrites
- no Payhip API access
- no email sending
- no timer, cron or system-service installation
- no credential handling
- no remote writes
- no LOW_LIVE, MEDIUM or HIGH execution

## Allowed Locally

- safe status checks
- local preflight checks
- local report generation
- local owner briefings
- local release evidence
- local public documentation generation
- local safe operation batches
- local soak tests

## Owner Review

Any action that could affect a real customer system, website, account, server, deployment, payment platform or DNS/CDN configuration requires a separate owner-reviewed phase.
