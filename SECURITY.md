# Security Policy

This project is a fork of [sigoden/dufs](https://github.com/sigoden/dufs). Where to report a
vulnerability depends on which code it is in.

## Supported Versions

Only the latest release of this fork is supported. Fixes for security issues found will be included
in the next release.

## Reporting a Vulnerability

### Issues in the fork's additions

Report vulnerabilities in what this fork adds to a **confidential issue** on
[GitLab](https://gitlab.com/endekasoft/dufs-oidc/-/issues/new) (tick "This issue is confidential").
This covers:

- OIDC login: the `/oidc/*` routes, ID token validation, session and transaction cookies
- `api_keys` authentication (Basic and Bearer)
- claim-to-permission rules and download tokens for OIDC sessions
- the Dockerfile, `docker-compose.yml` and the `dev/` tooling

Please do **not** report these to the upstream project: its maintainers do not ship or maintain this code.

### Issues in the original dufs code

Report vulnerabilities that exist in upstream dufs itself, meaning they also reproduce on an
unmodified [sigoden/dufs](https://github.com/sigoden/dufs) build (for example static file serving,
uploads, WebDAV, archive download, the `--auth` rules and Digest/Basic handling, TLS), using
[*dufs*'s security advisory reporting tool provided by
GitHub](https://github.com/sigoden/dufs/security/advisories/new).

If you are unsure which category an issue is in, report it to this fork first. We will check and
forward it upstream if it belongs there.

## What to include

We strive to fix security issues as quickly as possible. We encourage you to minimize the delay
between when you find an issue and when you contact us. You do not need to convince us to take your
report seriously. You don't need to create a PoC or a patch if that would slow down your reporting.
You don't need an elaborate write-up. A short, informal note about the issue is good. We can always
communicate later to fill in any details we need after that first note is shared with us.
