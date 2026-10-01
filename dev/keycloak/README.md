# Keycloak dev harness

Throwaway Keycloak for testing dufs OIDC login. Dev mode, in-memory H2, no TLS. Never use it in production.

## Start

```bash
docker compose -f dev/keycloak/docker-compose.yml up -d
# ready when this returns JSON (about 30-60 s):
curl -s http://localhost:8080/realms/dufs/.well-known/openid-configuration | jq .issuer
```

Stop and discard state: `docker compose -f dev/keycloak/docker-compose.yml down`.

## Realm `dufs`

| Item | Value |
|---|---|
| Client | `dufs`, confidential, secret `dufs-dev-secret`, standard flow only, PKCE `S256` required |
| Redirect URIs | `http://localhost:5000/oidc/callback`, `http://localhost:5055/oidc/callback` |
| Claim | `groups` in the ID token, full path (`/devops`) |
| User `alice` / `alice` | member of `/devops` |
| User `bob` / `bob` | no group |
| Admin console | <http://localhost:8080>, `admin` / `admin` (override with `KC_BOOTSTRAP_ADMIN_USERNAME`, `KC_BOOTSTRAP_ADMIN_PASSWORD`) |

## Try it with dufs

```yaml
# config.yaml
oidc:
  enabled: true
  issuer: http://localhost:8080/realms/dufs
  client_id: dufs
  client_secret: dufs-dev-secret
  redirect_url: http://localhost:5000/oidc/callback
  session_secret: "dev-only-session-secret-32-bytes-minimum!!"
  rules:
    - claim: groups
      contains: /devops
      paths: ["/:rw"]
```

Run `dufs --config config.yaml .`, open <http://localhost:5000>, sign in as `alice` (read/write) or `bob` (403).

## Integration test

The ignored Rust test in `dufs/tests/oidc.rs` runs only when this is set:

```bash
DUFS_TEST_OIDC_ISSUER=http://localhost:8080/realms/dufs \
  cargo test --test oidc_keycloak -- --ignored
```

The image tag is pinned in `docker-compose.yml`.
