# Security policy

This project is pre-1.0. Security fixes are supported on the current development line; older snapshots may not receive patches.

## Reporting a vulnerability

Use GitHub Security Advisories when that feature is enabled for this repository. If no private channel is visible, open a minimal non-sensitive issue asking maintainers to provide a private contact route. Do not include exploit details, secrets, personal data, or sensitive repository content in a public issue.

## Security posture

- Configuration files are trusted local input and may select local schema resources.
- Repository content is untrusted data. The tool parses it but does not execute it.
- Remote and external-file schema references are unsupported and rejected.
- Scanning does not follow symlinked files or directories.
- Report destinations are checked for scan isolation, lexical containment, and existing symlink ancestors before a file write.
- The tool does not auto-fix or mutate inspected repository content.

These controls reduce exposure but are not a general filesystem sandbox. Run untrusted configurations under ordinary operating-system isolation appropriate to your environment.
