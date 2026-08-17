# Repository Hygiene

## Allowed Git Files

- Sentinel scripts
- public documentation
- distribution documentation
- playbooks intended for public release

## Do Not Commit

- runtime reports
- adaptive state ledgers
- audit logs
- generated exports
- backups
- credential files
- downloaded assets
- local environment files

## Checks

- run secret scan
- validate JSON manifests
- review public docs for private paths, IP addresses and customer data
- verify Git recommendation excludes runtime artifacts
- decide license terms before public release
