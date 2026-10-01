# Roadmap: dufs-oidc

No GitLab remote yet, so tracked here. Migrate to issues once one exists.

## Auth revamp
- [x] OIDC login (authorization code + PKCE, signed cookie session), `api_keys` (Basic/Bearer), claim-to-path rules
- [x] Keycloak integration harness (`dev/keycloak`), docs, example config, Dockerfile
- [x] Security review pass
- [ ] Restructure: flatten fork to repo root
