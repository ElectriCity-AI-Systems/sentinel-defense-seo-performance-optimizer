# GitHub Release Checklist

- Confirm Public Pack status is green.
- Confirm Distribution Pack validation status.
- Review `ROOT-README-DRAFT.md` before copying any content into a root README.
- Review `CHANGELOG.md`.
- Review `VERSION-MANIFEST.md`.
- Confirm no runtime reports, adaptive state, audit logs, exports, backups or credential files are staged.
- Run a local secret scan before commit.
- Run JSON validation for public manifests and playbooks.
- Confirm release notes do not include private paths, IP addresses, customer data or unsupported claims.
- Do not push automatically from this checklist.
