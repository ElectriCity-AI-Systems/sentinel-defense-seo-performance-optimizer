# Manual Publication Checklist

This checklist is for owner review only. It does not publish, push, upload, tag, email or change any live system.

## Preconditions

- selected license: `polyform-noncommercial`
- license decision status: `LICENSE_CHOICE_SET`
- release candidate: `RC_GREEN`
- public pack: `PUBLIC_PACK_GREEN`
- distribution pack: `DISTRIBUTION_PACK_YELLOW`

## Manual Steps

1. Review `docs/release-final/LICENSE-DRAFT.md`.
2. Review `docs/release-final/ROOT-README-ACTIVATION-DRAFT.md`.
3. Manually decide whether and when to copy approved README text into `README.md`.
4. Manually decide whether and when to create a final `LICENSE`.
5. Run repository hygiene and secret scan before any commit.
6. Manually decide whether and when to create a Git tag.
7. Manually decide whether and when to publish a GitHub release.
8. Manually decide whether and when to launch on Payhip or Gumroad.

## Hard Blocks

- no remote push
- no marketplace API upload
- no email sending
- no live website, server, database, CDN or remote-file change
- no timer or background installation
