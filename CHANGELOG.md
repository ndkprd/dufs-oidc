# Changelog

All notable changes to this fork are documented in this file.

This fork is based on [sigoden/dufs](https://github.com/sigoden/dufs) 0.46.0. Changes up to and including that release are listed in the [upstream changelog](https://github.com/sigoden/dufs/blob/main/CHANGELOG.md).

## [Unreleased]

### Features

- OpenID Connect browser login: authorization code flow with PKCE, ID token validation against the IdP's JWKS (lazy discovery), signed `HttpOnly` cookie sessions. New top-level `oidc` config block.
- Claim-to-permission rules (`oidc.rules`, `oidc.default_paths`) mapped onto the existing `path:perm` syntax.
- Named `api_keys` with per-key path permissions, usable as `Authorization: Basic name:token` or `Bearer token`. Tokens may be plain, `sha256:<hex>` or `$6$` (Basic only).
- Routes `/oidc/login`, `/oidc/callback` and `/oidc/logout`; `oidc` is a reserved top-level name while OIDC is enabled.
- `?tokengen` / `?token=` download tokens for OIDC sessions.
- The web UI logs in and out through the `/oidc` routes when OIDC is enabled.
- Login events are logged with the claim values the rules look at, and a warning when no rule matches.
- Root `Dockerfile` that builds this fork from source, and a `docker-compose.yml` to run it.
- `config.example.yaml` and [docs/oidc-api-keys.md](docs/oidc-api-keys.md); a dev Keycloak in `dev/keycloak` with ignored end-to-end tests (`tests/oidc_keycloak.rs`).
- New `oidc` cargo feature, enabled by default.

### Security

- Session and transaction cookies are HMAC-signed, `SameSite=Lax`, and `Secure` when `redirect_url` is https; redirect targets are limited to same-origin paths; secrets are compared in constant time and never logged.
- Hardened session, token and cross-site write handling.

### Compatibility

- Auth stays opt-in. Without `oidc` or `api_keys`, behavior is identical to upstream; `--auth`, Digest, `$6$` hashes and `?token=` keep working.
- Write access still needs the server flags (`allow-all`, `allow-upload`, ...) in addition to a `:rw` path.
