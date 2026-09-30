use crate::args::OidcConfig;
use crate::auth::OidcIdentity;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex as StdMutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::OnceCell;

const SESSION_COOKIE: &str = "dufs_session";
const TX_COOKIE: &str = "dufs_oidc_tx";
const TX_TTL: u64 = 600;
const MAX_COOKIE_VALUE: usize = 3500;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

type HmacSha256 = Hmac<Sha256>;

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
pub enum OidcError {
    BadRequest(String),
    Unavailable(String),
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcError::BadRequest(v) | OidcError::Unavailable(v) => f.write_str(v),
        }
    }
}

impl std::error::Error for OidcError {}

pub struct LoginRedirect {
    pub location: String,
    pub set_cookie: String,
}

pub struct CallbackOutcome {
    pub return_path: String,
    pub set_cookies: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Session {
    sub: String,
    name: String,
    claims: BTreeMap<String, Vec<String>>,
    exp: u64,
}

#[derive(Serialize, Deserialize)]
struct Transaction {
    state: String,
    nonce: String,
    verifier: String,
    ret: String,
    exp: u64,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

pub struct OidcClient {
    http: reqwest::Client,
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    scope: String,
    secret: Vec<u8>,
    session_ttl: u64,
    user_claim: String,
    wanted: Vec<(String, String)>,
    cookie_path: String,
    secure: bool,
    discovery: OnceCell<Discovery>,
    jwks: RwLock<Option<JwkSet>>,
    /// `state` values already redeemed at the callback, with their expiry.
    used_states: StdMutex<HashMap<String, u64>>,
}

impl OidcClient {
    pub fn new(cfg: &OidcConfig, wanted: Vec<(String, String)>, cookie_path: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .expect("failed to build the OIDC http client");
        Self {
            http,
            issuer: cfg.issuer.trim_end_matches('/').to_string(),
            client_id: cfg.client_id.clone(),
            client_secret: cfg.client_secret.clone(),
            redirect_url: cfg.redirect_url.clone(),
            scope: cfg.scopes.join(" "),
            secret: cfg.session_secret.as_bytes().to_vec(),
            session_ttl: cfg.session_ttl,
            user_claim: cfg.user_claim.clone(),
            wanted,
            cookie_path: cookie_path.to_string(),
            secure: cfg.redirect_url.starts_with("https://"),
            discovery: OnceCell::new(),
            jwks: RwLock::new(None),
            used_states: StdMutex::new(HashMap::new()),
        }
    }

    pub async fn login(&self, return_path: &str) -> Result<LoginRedirect, OidcError> {
        let discovery = self.discovery().await?;
        let tx = Transaction {
            state: random_token(),
            nonce: random_token(),
            verifier: random_token(),
            ret: self.safe_return_path(return_path),
            exp: now() + TX_TTL,
        };
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(tx.verifier.as_bytes()));
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("scope", &self.scope)
            .append_pair("state", &tx.state)
            .append_pair("nonce", &tx.nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .finish();
        let endpoint = &discovery.authorization_endpoint;
        let sep = if endpoint.contains('?') { '&' } else { '?' };
        Ok(LoginRedirect {
            location: format!("{endpoint}{sep}{query}"),
            set_cookie: self.cookie(TX_COOKIE, &seal(&self.secret, TX_COOKIE, &tx), TX_TTL),
        })
    }

    pub async fn callback(
        &self,
        query: &HashMap<String, String>,
        cookie_header: Option<&str>,
    ) -> Result<CallbackOutcome, OidcError> {
        let tx: Transaction = cookie_value(cookie_header, TX_COOKIE)
            .and_then(|v| open(&self.secret, TX_COOKIE, v))
            .filter(|tx: &Transaction| tx.exp > now())
            .ok_or_else(|| bad("login transaction is missing or expired"))?;
        if query.contains_key("error") {
            return Err(bad("the identity provider returned an error"));
        }
        if query.get("state") != Some(&tx.state) {
            return Err(bad("state mismatch"));
        }
        let code = query.get("code").ok_or_else(|| bad("missing code"))?;
        self.redeem_once(&tx.state, tx.exp)?;

        let id_token = self.exchange_code(code, &tx.verifier).await?;
        let claims = self.validate_id_token(&id_token, &tx.nonce).await?;
        let value = self.sealed_session(&self.build_session(&claims)?)?;
        Ok(CallbackOutcome {
            return_path: tx.ret,
            set_cookies: vec![
                self.cookie(SESSION_COOKIE, &value, self.session_ttl),
                self.cookie(TX_COOKIE, "", 0),
            ],
        })
    }

    /// A login transaction may reach the token endpoint only once.
    fn redeem_once(&self, state: &str, exp: u64) -> Result<(), OidcError> {
        let mut used = self.used_states.lock().unwrap_or_else(|e| e.into_inner());
        used.retain(|_, expires| *expires > now());
        if used.insert(state.to_string(), exp).is_some() {
            return Err(bad("login already used, start again"));
        }
        Ok(())
    }

    pub fn identity(&self, cookie_header: Option<&str>) -> Option<OidcIdentity> {
        let session: Session = open(
            &self.secret,
            SESSION_COOKIE,
            cookie_value(cookie_header, SESSION_COOKIE)?,
        )?;
        (session.exp > now()).then_some(OidcIdentity {
            name: session.name,
            claims: session.claims,
        })
    }

    pub fn logout_cookies(&self) -> Vec<String> {
        vec![
            self.cookie(SESSION_COOKIE, "", 0),
            self.cookie(TX_COOKIE, "", 0),
        ]
    }

    fn cookie(&self, name: &str, value: &str, max_age: u64) -> String {
        let secure = if self.secure { "; Secure" } else { "" };
        format!(
            "{name}={value}; HttpOnly; SameSite=Lax; Path={}; Max-Age={max_age}{secure}",
            self.cookie_path
        )
    }

    fn safe_return_path(&self, path: &str) -> String {
        let ok = path.starts_with('/')
            && !path.starts_with("//")
            && !path.starts_with("/\\")
            && !path.chars().any(|c| c.is_control());
        if ok {
            path.to_string()
        } else {
            self.cookie_path.clone()
        }
    }

    async fn discovery(&self) -> Result<&Discovery, OidcError> {
        self.discovery
            .get_or_try_init(|| async {
                let url = format!("{}/.well-known/openid-configuration", self.issuer);
                let discovery: Discovery = self.get_json(&url).await?;
                if discovery.issuer.trim_end_matches('/') != self.issuer {
                    return Err(unavailable("issuer in discovery document does not match"));
                }
                Ok(discovery)
            })
            .await
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, OidcError> {
        let res = self.http.get(url).send().await.map_err(unavailable_err)?;
        res.error_for_status()
            .map_err(unavailable_err)?
            .json()
            .await
            .map_err(unavailable_err)
    }

    async fn refresh_jwks(&self) -> Result<(), OidcError> {
        let uri = &self.discovery().await?.jwks_uri;
        let set: JwkSet = self.get_json(uri).await?;
        *self.jwks.write().unwrap() = Some(set);
        Ok(())
    }

    async fn exchange_code(&self, code: &str, verifier: &str) -> Result<String, OidcError> {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", &self.client_secret)
            .append_pair("code_verifier", verifier)
            .finish();
        let res = self
            .http
            .post(&self.discovery().await?.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(unavailable_err)?;
        let status = res.status();
        if status.is_server_error() {
            return Err(unavailable("token endpoint failed"));
        }
        if !status.is_success() {
            return Err(bad("token endpoint rejected the authorization code"));
        }
        let mut value: Value = res.json().await.map_err(unavailable_err)?;
        match value["id_token"].take() {
            Value::String(token) => Ok(token),
            _ => Err(bad("token response has no id_token")),
        }
    }

    async fn validate_id_token(&self, token: &str, nonce: &str) -> Result<Value, OidcError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| bad("invalid id_token"))?;
        if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
            return Err(bad("unsupported id_token algorithm"));
        }
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.client_id.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_nbf = true;
        validation.leeway = 5;

        let key = match self.find_key(header.kid.as_deref()) {
            Some(key) => key,
            None => {
                self.refresh_jwks().await?;
                self.find_key(header.kid.as_deref())
                    .ok_or_else(|| bad("id_token signed by an unknown key"))?
            }
        };
        let data = jsonwebtoken::decode::<Value>(token, &key, &validation).map_err(|e| {
            log::warn!("OIDC id_token rejected: {:?}", e.kind());
            bad("id_token validation failed")
        })?;
        if data.claims["nonce"].as_str() != Some(nonce) {
            return Err(bad("nonce mismatch"));
        }
        Ok(data.claims)
    }

    fn find_key(&self, kid: Option<&str>) -> Option<DecodingKey> {
        let guard = self.jwks.read().unwrap();
        let set = guard.as_ref()?;
        let jwk = match kid {
            Some(kid) => set.find(kid)?,
            None => set.keys.first()?,
        };
        DecodingKey::from_jwk(jwk).ok()
    }

    fn sealed_session(&self, session: &Session) -> Result<String, OidcError> {
        let value = seal(&self.secret, SESSION_COOKIE, session);
        if value.len() > MAX_COOKIE_VALUE {
            return Err(bad("session cookie would be too large"));
        }
        Ok(value)
    }

    fn build_session(&self, claims: &Value) -> Result<Session, OidcError> {
        let first = |path: &str| claim_values(claims, path).into_iter().next();
        let sub = first("sub").ok_or_else(|| bad("id_token has no sub"))?;
        let name = first(&self.user_claim)
            .or_else(|| first("email"))
            .unwrap_or_else(|| sub.clone());
        let mut granted: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (path, wanted) in &self.wanted {
            if claim_values(claims, path).contains(wanted) {
                let values = granted.entry(path.clone()).or_default();
                if !values.contains(wanted) {
                    values.push(wanted.clone());
                }
            }
        }
        Ok(Session {
            sub,
            name,
            claims: granted,
            exp: now() + self.session_ttl,
        })
    }
}

fn bad(msg: &str) -> OidcError {
    OidcError::BadRequest(msg.to_string())
}

fn unavailable(msg: &str) -> OidcError {
    OidcError::Unavailable(msg.to_string())
}

fn unavailable_err(err: reqwest::Error) -> OidcError {
    OidcError::Unavailable(format!(
        "identity provider request failed: {}",
        err.without_url()
    ))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn mac(secret: &[u8]) -> HmacSha256 {
    HmacSha256::new_from_slice(secret).expect("hmac accepts any key length")
}

fn seal<T: Serialize>(secret: &[u8], purpose: &str, value: &T) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap_or_default());
    let mut mac = mac(secret);
    mac.update(purpose.as_bytes());
    mac.update(b"\0");
    mac.update(payload.as_bytes());
    format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn open<T: DeserializeOwned>(secret: &[u8], purpose: &str, value: &str) -> Option<T> {
    let (payload, signature) = value.split_once('.')?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = mac(secret);
    mac.update(purpose.as_bytes());
    mac.update(b"\0");
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature).ok()?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

fn cookie_value<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    header?.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then_some(value.trim())
    })
}

/// Resolves a claim by exact name, else as a dotted path (`realm_access.roles`).
fn claim_values(claims: &Value, path: &str) -> Vec<String> {
    let found = claims.get(path).or_else(|| {
        path.split('.')
            .try_fold(claims, |value, segment| value.get(segment))
    });
    match found {
        Some(Value::Array(items)) => items.iter().filter_map(scalar).collect(),
        Some(value) => scalar(value).into_iter().collect(),
        None => vec![],
    }
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(v) => Some(v.clone()),
        Value::Bool(_) | Value::Number(_) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    // Throwaway key generated only for these tests.
    const TEST_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2jm0pUUalks/IEszeBKe1JGql+O0LeaXN5d+v86IFDJxC+Ba
BAPbf/76bWOjSfdCKTWpM2OtnZv8JyX9U1DPjq7NNT8Nwje9PXtsQcx9u9Uszvu2
nCVrnVotpi1pvCSLAg3cTtd8gr8tSXuDSM0VgwoMcpjWaN9bNjhW8xOsjVfNwdfD
Hr7HkZhAkGVld9d4+i89gawD51RVxiPckx/scqorBimf7BM1u3yZ6UAvUIba+9E/
lKx2MCjOj/nyace7QmqsD/Qysb2dniimirnHOI7wQqQJLFDbFJPZTNvnof0pOLaJ
rx3ttQ+kLRMNUdalj0fRsRsWsnyJLRiO+k8hwwIDAQABAoIBAArO/OGKsKxtAa1p
zBzQX0mMBXUMdCop16eLO13ortjBPtQlwo+cWUzXpjOw0a+iLYa4/65p63l49l5C
BXAQ+pbIlaVjgBz0gcz/xfbkV/3rqxJ9aSgGunPKuaQXb7s/3Bq38Qd+qM4ZBfcz
xObgMYaSAtfSNhxvo6bl13imqs89SKtqLuxXdTxMC81hv/nMZ7RClJSyuwHSOlkB
St7Con/nT7hbFCpXVT4DVci8FVrFtaXGg89XEdBW4q+k+ABsKK1FsAtQGep3eqXo
9CO1G+u5UJNxuiWxV+OCZ2cQGeqLdgbFlUImStJNUuiQ752q+WgEGAXG188CYc74
g19DrnECgYEA7stoyTOsJvV6zYYp9Aru55iUI2cNQCue1wMm3Xr+mAgA/pZGC8w3
4y1K8d1oEM42jnlonq7LekRFpMPT91Bq4FnAIVnTZctv5PYVSOSrA9Q4KTOqaKTm
hcsdcIOgoYL3aE/CwNbtjELYC87CsCZTl1+RKxSbEN4B6qYROgl5Nf8CgYEA6fLl
aCHGojTbWgFvOuK0ZctsCAWJzzRG6Uqqq33oIZWUOY4cUjzrSU0BP58tSakILpSx
YD0xfpIVFWh9E8DcsIYN96AxG5A6tJqKw/cIpBhfRYALpAt6TBI7qS7Zt8uhjF3c
6TNk1DqGrnWrrUAg3GwqG6i8Js7JGweOKoc6vD0CgYEAy2V69ZYL1otVdGYIqhP9
9kqiM519TeFZxG6s1g4DeV+n6TH6q+Xg3KIhqe4ay+W51pVXJYJhUt2ALJ2YmJlo
z3vjCQVH6PblcjKhYptTh0lmJMIbLlL2/5NImiOj2K6DKdh2XGc1ozj0aOpOLlgW
72K5deZxRmazXzjgh3y2P+UCgYEAz6EXINf5JjSrCLKFOUnCuSVU97mSmSbYWGxA
FHtl7YiHSJ1rXUFbwG5rUT/APcOa01x8H+Gvb5nOxHU7rLBaLQCMnNy7OK9Eqs0N
ouY38QsAYvpFWo4lOCZmdLxz1b8P3Tfgu8c1EXXv2h3tA5IKmBYXOP0EH50etrJ5
5hymcDECgYAkryg9KkWMPgEyPOadhZgj66Qb8q1k+CPTl2UVrBHFii/PYglPtx02
c1Qujifhgy5NY7wRcSUZfTcDuOAr7WFC/aWRGrqDTHpjPGYTQeP2qmC1hRve4pLQ
A0OSFnZLaqMaEuysprKm3Qq5IhIvfnRIKUVfgSK2v33+1O5ZhYJ3JA==
-----END RSA PRIVATE KEY-----
";
    const TEST_KEY_N: &str = "2jm0pUUalks_IEszeBKe1JGql-O0LeaXN5d-v86IFDJxC-BaBAPbf_76bWOjSfdCKTWpM2OtnZv8JyX9U1DPjq7NNT8Nwje9PXtsQcx9u9Uszvu2nCVrnVotpi1pvCSLAg3cTtd8gr8tSXuDSM0VgwoMcpjWaN9bNjhW8xOsjVfNwdfDHr7HkZhAkGVld9d4-i89gawD51RVxiPckx_scqorBimf7BM1u3yZ6UAvUIba-9E_lKx2MCjOj_nyace7QmqsD_Qysb2dniimirnHOI7wQqQJLFDbFJPZTNvnof0pOLaJrx3ttQ-kLRMNUdalj0fRsRsWsnyJLRiO-k8hww";
    const KID: &str = "test-key";
    const CLIENT_ID: &str = "dufs";

    fn config(issuer: &str, redirect_url: &str) -> OidcConfig {
        OidcConfig {
            enabled: true,
            issuer: issuer.to_string(),
            client_id: CLIENT_ID.to_string(),
            client_secret: "client-secret".to_string(),
            redirect_url: redirect_url.to_string(),
            session_secret: "0123456789abcdef0123456789abcdef".to_string(),
            ..Default::default()
        }
    }

    fn client(redirect_url: &str) -> OidcClient {
        install_crypto_provider();
        let wanted = vec![("realm_access.roles".to_string(), "release".to_string())];
        OidcClient::new(&config("http://127.0.0.1:1", redirect_url), wanted, "/")
    }

    fn set_cookie_value(set_cookie: &str) -> &str {
        set_cookie.split(';').next().unwrap()
    }

    #[test]
    fn session_round_trip() {
        let c = client("http://localhost/oidc/callback");
        let session = Session {
            sub: "u1".into(),
            name: "alice".into(),
            claims: BTreeMap::from([("groups".to_string(), vec!["dev".to_string()])]),
            exp: now() + 60,
        };
        let header = format!(
            "a=b; {SESSION_COOKIE}={}; c=d",
            seal(&c.secret, SESSION_COOKIE, &session)
        );
        let id = c.identity(Some(&header)).unwrap();
        assert_eq!(id.name, "alice");
        assert_eq!(id.claims["groups"], vec!["dev"]);
    }

    #[test]
    fn tampered_or_expired_session_rejected() {
        let c = client("http://localhost/oidc/callback");
        let mk = |exp| Session {
            sub: "u1".into(),
            name: "alice".into(),
            claims: BTreeMap::new(),
            exp,
        };
        let value = seal(&c.secret, SESSION_COOKIE, &mk(now() + 60));
        let (payload, sig) = value.split_once('.').unwrap();
        let forged = seal(
            &c.secret,
            SESSION_COOKIE,
            &Session {
                name: "root".into(),
                ..mk(now() + 60)
            },
        );
        let forged_payload = forged.split_once('.').unwrap().0;
        for bad_value in [
            format!("{forged_payload}.{sig}"),
            format!("{payload}.{}A", sig),
            format!("{payload}."),
            payload.to_string(),
            seal(
                b"another-secret-another-secret-xxxx",
                SESSION_COOKIE,
                &mk(now() + 60),
            ),
            seal(&c.secret, SESSION_COOKIE, &mk(now() - 1)),
            // same key, other purpose: a login-transaction MAC is not a session
            seal(&c.secret, TX_COOKIE, &mk(now() + 60)),
        ] {
            let header = format!("{SESSION_COOKIE}={bad_value}");
            assert!(c.identity(Some(&header)).is_none(), "{bad_value}");
        }
        assert!(c.identity(None).is_none());
    }

    #[test]
    fn cookie_attributes() {
        let http = client("http://localhost/oidc/callback");
        let cookie = http.cookie(SESSION_COOKIE, "v", 28800);
        assert_eq!(
            cookie,
            "dufs_session=v; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800"
        );
        let https = client("https://files.example.com/oidc/callback");
        assert!(https
            .cookie(TX_COOKIE, "v", 600)
            .ends_with("Max-Age=600; Secure"));
        assert!(https
            .logout_cookies()
            .iter()
            .all(|c| c.contains("Max-Age=0")));
    }

    #[test]
    fn return_path_sanitiser() {
        let c = client("http://localhost/oidc/callback");
        for (input, expected) in [
            ("//evil.com", "/"),
            ("/\\evil", "/"),
            ("https://x", "/"),
            ("", "/"),
            ("/a\r\nSet-Cookie: x=y", "/"),
            ("/ok/path?x=1", "/ok/path?x=1"),
        ] {
            assert_eq!(c.safe_return_path(input), expected, "{input}");
        }
    }

    #[test]
    fn claim_extraction() {
        let claims = json!({
            "sub": "u1",
            "realm_access": {"roles": ["release", "dev"]},
            "dept": "it",
            "a.b": "exact",
            "admin": true,
            "obj": {"x": 1},
        });
        assert_eq!(
            claim_values(&claims, "realm_access.roles"),
            vec!["release", "dev"]
        );
        assert_eq!(claim_values(&claims, "dept"), vec!["it"]);
        assert_eq!(claim_values(&claims, "a.b"), vec!["exact"]);
        assert_eq!(claim_values(&claims, "admin"), vec!["true"]);
        assert!(claim_values(&claims, "obj").is_empty());
        assert!(claim_values(&claims, "realm_access.missing.deep").is_empty());
    }

    #[test]
    fn wanted_claims_are_filtered() {
        let mut c = client("http://localhost/oidc/callback");
        c.wanted = vec![
            ("realm_access.roles".into(), "release".into()),
            ("realm_access.roles".into(), "admin".into()),
            ("dept".into(), "hr".into()),
        ];
        let claims = json!({
            "sub": "u1", "email": "a@b.c",
            "realm_access": {"roles": ["release", "other"]}, "dept": "it",
        });
        let session = c.build_session(&claims).unwrap();
        assert_eq!(session.name, "a@b.c");
        assert_eq!(
            session.claims,
            BTreeMap::from([(
                "realm_access.roles".to_string(),
                vec!["release".to_string()]
            )])
        );
        assert!(c.build_session(&json!({"email": "x"})).is_err());
    }

    #[test]
    fn oversize_session_rejected() {
        let c = client("http://localhost/oidc/callback");
        let session = Session {
            sub: "u1".into(),
            name: "n".repeat(MAX_COOKIE_VALUE),
            claims: BTreeMap::new(),
            exp: now() + 60,
        };
        assert!(matches!(
            c.sealed_session(&session),
            Err(OidcError::BadRequest(_))
        ));
    }

    struct Stub {
        base: String,
        token: Arc<Mutex<String>>,
    }

    async fn spawn_stub() -> Stub {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let token = Arc::new(Mutex::new(String::new()));
        let (b, t) = (base.clone(), token.clone());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (b, t) = (b.clone(), t.clone());
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let body = match req.uri().path() {
                            "/.well-known/openid-configuration" => json!({
                                "issuer": b,
                                "authorization_endpoint": format!("{b}/authorize"),
                                "token_endpoint": format!("{b}/token"),
                                "jwks_uri": format!("{b}/jwks"),
                            }),
                            "/jwks" => json!({"keys": [{
                                "kty": "RSA", "alg": "RS256", "use": "sig",
                                "kid": KID, "n": TEST_KEY_N, "e": "AQAB",
                            }]}),
                            _ => json!({"id_token": t.lock().unwrap().clone()}),
                        };
                        async move {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from(body.to_string()),
                            )))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        Stub { base, token }
    }

    fn sign(claims: &Value) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        let body: String = TEST_KEY_PEM
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();
        let key = jsonwebtoken::EncodingKey::from_rsa_der(&der);
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    fn unsigned(claims: &Value) -> String {
        let part = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
        format!(
            "{}.{}.",
            part(&json!({"alg": "none", "typ": "JWT"})),
            part(claims)
        )
    }

    fn query_of(url: &str) -> HashMap<String, String> {
        url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    /// Runs a full login + callback against the stub; `mutate` edits the ID token claims.
    async fn round_trip(
        make_token: impl Fn(&Value) -> String,
        mutate: impl Fn(&mut Value),
    ) -> Result<(OidcClient, CallbackOutcome), OidcError> {
        install_crypto_provider();
        let stub = spawn_stub().await;
        let wanted = vec![("realm_access.roles".to_string(), "release".to_string())];
        let client = OidcClient::new(
            &config(&stub.base, "http://localhost/oidc/callback"),
            wanted,
            "/",
        );
        let login = client.login("/releases/").await.unwrap();
        let auth = query_of(&login.location);
        assert_eq!(auth["code_challenge_method"], "S256");
        assert_eq!(auth["client_id"], CLIENT_ID);
        let mut claims = json!({
            "iss": stub.base, "aud": CLIENT_ID, "sub": "u1",
            "preferred_username": "alice", "nonce": auth["nonce"],
            "exp": now() + 300,
            "realm_access": {"roles": ["release", "noise"]},
        });
        mutate(&mut claims);
        *stub.token.lock().unwrap() = make_token(&claims);
        let cb_query = HashMap::from([
            ("code".to_string(), "abc".to_string()),
            ("state".to_string(), auth["state"].clone()),
        ]);
        let cookie = set_cookie_value(&login.set_cookie).to_string();
        let outcome = client.callback(&cb_query, Some(&cookie)).await?;
        Ok((client, outcome))
    }

    #[tokio::test]
    async fn valid_token_is_accepted() {
        let (client, outcome) = round_trip(sign, |_| {}).await.unwrap();
        assert_eq!(outcome.return_path, "/releases/");
        assert_eq!(outcome.set_cookies.len(), 2);
        let header = set_cookie_value(&outcome.set_cookies[0]).to_string();
        let id = client.identity(Some(&header)).unwrap();
        assert_eq!(id.name, "alice");
        assert_eq!(id.claims["realm_access.roles"], vec!["release"]);
    }

    #[tokio::test]
    async fn invalid_tokens_are_rejected() {
        for field in ["iss", "aud", "exp", "nonce"] {
            let err = round_trip(sign, |c| {
                c[field] = match field {
                    "exp" => json!(now() - 3600),
                    _ => json!("wrong"),
                }
            })
            .await
            .err();
            assert!(matches!(err, Some(OidcError::BadRequest(_))), "{field}");
        }
        let err = round_trip(unsigned, |_| {}).await.err();
        assert!(matches!(err, Some(OidcError::BadRequest(_))), "alg none");
    }

    #[tokio::test]
    async fn state_mismatch_and_idp_error_rejected() {
        install_crypto_provider();
        let stub = spawn_stub().await;
        let client = OidcClient::new(&config(&stub.base, "http://localhost/cb"), vec![], "/");
        let login = client.login("/").await.unwrap();
        let cookie = set_cookie_value(&login.set_cookie).to_string();
        let wrong = HashMap::from([("code".into(), "c".into()), ("state".into(), "nope".into())]);
        assert!(matches!(
            client.callback(&wrong, Some(&cookie)).await,
            Err(OidcError::BadRequest(_))
        ));
        let errored = HashMap::from([("error".into(), "access_denied".into())]);
        assert!(matches!(
            client.callback(&errored, Some(&cookie)).await,
            Err(OidcError::BadRequest(_))
        ));
        assert!(matches!(
            client.callback(&wrong, None).await,
            Err(OidcError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn unreachable_idp_is_unavailable() {
        let c = client("http://localhost/cb");
        assert!(matches!(c.login("/").await, Err(OidcError::Unavailable(_))));
    }
}
