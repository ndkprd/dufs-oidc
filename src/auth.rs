use crate::{
    args::{ApiKeyConfig, Args, OidcConfig},
    server::Response,
    utils::unix_now,
};

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{ed25519::signature::SignerMut, Signature, SigningKey};
use headers::HeaderValue;
use hyper::{header::WWW_AUTHENTICATE, Method};
use indexmap::IndexMap;
use lazy_static::lazy_static;
use md5::Context;
use sha2::{Digest, Sha256};
use sha_crypt::PasswordVerifier;
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const REALM: &str = "DUFS";
const DIGEST_AUTH_TIMEOUT: u32 = 60 * 60 * 24 * 7; // 7 days
const TOKEN_EXPIRATION: u64 = 1000 * 60 * 60 * 24 * 3; // 3 days

lazy_static! {
    static ref NONCESTARTHASH: Context = {
        let mut h = Context::new();
        h.consume(Uuid::new_v4().as_bytes());
        h.consume(std::process::id().to_be_bytes());
        h
    };
}

#[derive(Debug, Clone, PartialEq)]
pub struct AccessControl {
    empty: bool,
    use_hashed_password: bool,
    users: IndexMap<String, (String, AccessPaths)>,
    api_keys: IndexMap<String, ApiKey>,
    oidc: Option<OidcRules>,
    anonymous: Option<AccessPaths>,
}

/// A machine credential from the `api_keys` config. `token` is plain, `sha256:<hex>` or `$6$...`.
#[derive(Debug, Clone, PartialEq)]
struct ApiKey {
    token: String,
    paths: AccessPaths,
}

/// Claim-to-permission mapping for OIDC users.
#[derive(Debug, Clone, PartialEq)]
struct OidcRules {
    session_secret: String,
    rules: Vec<(String, String, AccessPaths)>,
    default_paths: Option<AccessPaths>,
}

/// An authenticated OIDC user. `claims` only holds the values some rule looks at.
#[derive(Debug, Clone, PartialEq)]
pub struct OidcIdentity {
    pub name: String,
    pub claims: BTreeMap<String, Vec<String>>,
}

/// Prefix byte marking download tokens minted for OIDC users.
const OIDC_TOKEN_MARK: u8 = 1;

impl Default for AccessControl {
    fn default() -> Self {
        AccessControl {
            empty: true,
            use_hashed_password: false,
            users: IndexMap::new(),
            api_keys: IndexMap::new(),
            oidc: None,
            anonymous: Some(AccessPaths::new(AccessPerm::ReadWrite)),
        }
    }
}

impl AccessControl {
    pub fn new(raw_rules: &[&str]) -> Result<Self> {
        if raw_rules.is_empty() {
            return Ok(Self::default());
        }
        let new_raw_rules = split_rules(raw_rules);
        let mut use_hashed_password = false;
        let mut annoy_paths = None;
        let mut account_paths_pairs = vec![];
        for rule in &new_raw_rules {
            let (account, paths) =
                split_account_paths(rule).ok_or_else(|| anyhow!("Invalid auth `{rule}`"))?;
            if account.is_empty() {
                if annoy_paths.is_some() {
                    bail!("Invalid auth, no duplicate anonymous rules");
                }
                annoy_paths = Some(paths)
            } else if let Some((user, pass)) = account.split_once(':') {
                if user.is_empty() || pass.is_empty() {
                    bail!("Invalid auth `{rule}`");
                }
                account_paths_pairs.push((user, pass, paths));
            }
        }
        let mut anonymous = None;
        if let Some(paths) = annoy_paths {
            let mut access_paths = AccessPaths::default();
            access_paths
                .merge(paths)
                .ok_or_else(|| anyhow!("Invalid auth value `@{paths}"))?;
            anonymous = Some(access_paths);
        }
        let mut users = IndexMap::new();
        for (user, pass, paths) in account_paths_pairs.into_iter() {
            let mut access_paths = AccessPaths::default();
            access_paths
                .merge(paths)
                .ok_or_else(|| anyhow!("Invalid auth value `{user}:{pass}@{paths}"))?;
            if let Some(anon_ap) = &anonymous {
                let orig_user = access_paths.clone();
                access_paths.absorb_anon(
                    anon_ap,
                    &orig_user,
                    AccessPerm::IndexOnly,
                    AccessPerm::IndexOnly,
                );
            }
            if pass.starts_with("$6$") {
                use_hashed_password = true;
            }
            users.insert(user.to_string(), (pass.to_string(), access_paths));
        }

        Ok(Self {
            empty: false,
            use_hashed_password,
            users,
            api_keys: IndexMap::new(),
            oidc: None,
            anonymous,
        })
    }

    /// True when a login is meaningful: `--auth` users, api keys or OIDC.
    pub fn has_users(&self) -> bool {
        !self.users.is_empty() || !self.api_keys.is_empty() || self.oidc.is_some()
    }

    pub fn oidc_enabled(&self) -> bool {
        self.oidc.is_some()
    }

    /// `(claim, value)` pairs the OIDC rules look at; the session only needs to remember these.
    pub fn oidc_wanted_claims(&self) -> Vec<(String, String)> {
        let rules = self.oidc.iter().flat_map(|o| o.rules.iter());
        rules.map(|(c, v, _)| (c.clone(), v.clone())).collect()
    }

    /// Register `api_keys`; an unconfigured server stays open, any key closes it to anonymous.
    pub fn add_api_keys(&mut self, keys: &[ApiKeyConfig]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        for key in keys {
            if key.name.is_empty() || key.token.is_empty() {
                bail!("api_keys entries need `name` and `token`");
            }
            if key.name.contains(':') {
                bail!("api_keys name `{}` must not contain ':'", key.name);
            }
            if key.paths.is_empty() {
                bail!("api_keys `{}` needs `paths`", key.name);
            }
            if self.users.contains_key(&key.name) || self.api_keys.contains_key(&key.name) {
                bail!("Duplicate api_keys name `{}`", key.name);
            }
            if !key.token.starts_with("sha256:") && !key.token.starts_with("$6$") {
                log::warn!("api_keys `{}` uses a plain token, prefer `sha256:<hex>`", key.name);
            }
            let paths = self.parse_paths(&key.paths)?;
            let token = key.token.clone();
            self.api_keys.insert(key.name.clone(), ApiKey { token, paths });
        }
        self.close_to_anonymous();
        Ok(())
    }

    pub fn enable_oidc(&mut self, config: &OidcConfig) -> Result<()> {
        let mut rules = vec![];
        for rule in &config.rules {
            let value = rule.equals.as_ref().or(rule.contains.as_ref());
            let value = value.ok_or_else(|| anyhow!("oidc rule `{}` has no value", rule.claim))?;
            rules.push((rule.claim.clone(), value.clone(), self.parse_paths(&rule.paths)?));
        }
        let default_paths = match config.default_paths.is_empty() {
            true => None,
            false => Some(self.parse_paths(&config.default_paths)?),
        };
        self.oidc = Some(OidcRules {
            session_secret: config.session_secret.clone(),
            rules,
            default_paths,
        });
        self.close_to_anonymous();
        Ok(())
    }

    fn close_to_anonymous(&mut self) {
        if self.empty {
            self.empty = false;
            self.anonymous = None;
        }
    }

    /// Parse `/path:perm` items, letting anonymous index-only paths show through.
    fn parse_paths(&self, items: &[String]) -> Result<AccessPaths> {
        let mut paths = AccessPaths::default();
        paths
            .merge(&items.join(","))
            .ok_or_else(|| anyhow!("Invalid paths `{}`", items.join(",")))?;
        Ok(self.with_anonymous(paths))
    }

    fn with_anonymous(&self, mut paths: AccessPaths) -> AccessPaths {
        if let Some(anon) = self.anonymous.as_ref().filter(|_| !self.empty) {
            let orig = paths.clone();
            paths.absorb_anon(anon, &orig, AccessPerm::IndexOnly, AccessPerm::IndexOnly);
        }
        paths
    }

    /// Permissions of an OIDC user: union of matching rules, else `default_paths`, else none.
    pub fn oidc_access(&self, claims: &BTreeMap<String, Vec<String>>) -> Option<AccessPaths> {
        let oidc = self.oidc.as_ref()?;
        let mut matched: Option<AccessPaths> = None;
        for (claim, value, paths) in &oidc.rules {
            if claims.get(claim).is_some_and(|vs| vs.contains(value)) {
                let acc = matched.get_or_insert_with(AccessPaths::default);
                let orig = acc.clone();
                acc.absorb_anon(paths, &orig, AccessPerm::IndexOnly, AccessPerm::IndexOnly);
            }
        }
        matched.or_else(|| oidc.default_paths.clone())
    }

    fn credential(&self, user: &str) -> Option<(&str, &AccessPaths)> {
        if let Some((pass, ap)) = self.users.get(user) {
            return Some((pass, ap));
        }
        self.api_keys.get(user).map(|k| (k.token.as_str(), &k.paths))
    }

    fn find_api_key_by_token(&self, presented: &str) -> Option<(&String, &ApiKey)> {
        let usable = self.api_keys.iter().filter(|(_, k)| !k.token.starts_with("$6$"));
        usable.into_iter().find(|(_, k)| token_matches(&k.token, presented))
    }

    pub fn guard(
        &self,
        path: &str,
        method: &Method,
        authorization: Option<&HeaderValue>,
        token: Option<&String>,
        guard_options: bool,
        identity: Option<&OidcIdentity>,
    ) -> (Option<String>, Option<AccessPaths>) {
        if self.empty {
            return (None, Some(AccessPaths::new(AccessPerm::ReadWrite)));
        }

        if let Some(identity) = identity {
            let paths = self.oidc_access(&identity.claims);
            return (
                Some(identity.name.clone()),
                paths.and_then(|ap| ap.guard(path, method)),
            );
        }

        if method == Method::GET {
            if let Some(token) = token {
                if let Ok((user, ap)) = self.verify_token(token, path) {
                    return (Some(user), ap.guard(path, method));
                }
            }
        }

        if let Some(authorization) = authorization {
            if let Some(presented) = bearer_token(authorization) {
                return match self.find_api_key_by_token(presented) {
                    Some((name, key)) => (Some(name.clone()), key.paths.guard(path, method)),
                    None => (None, None),
                };
            }
            if let Some(user) = get_auth_user(authorization) {
                if let Some(key) = self.api_keys.get(&user) {
                    if method == Method::OPTIONS {
                        return (Some(user), Some(AccessPaths::new(AccessPerm::ReadOnly)));
                    }
                    if basic_token_matches(authorization, &user, &key.token) {
                        return (Some(user), key.paths.guard(path, method));
                    }
                } else if let Some((pass, ap)) = self.users.get(&user) {
                    if method == Method::OPTIONS {
                        return (Some(user), Some(AccessPaths::new(AccessPerm::ReadOnly)));
                    }
                    if check_auth(authorization, method.as_str(), &user, pass).is_some() {
                        return (Some(user), ap.guard(path, method));
                    }
                }
            }

            return (None, None);
        }

        if !guard_options && method == Method::OPTIONS {
            return (None, Some(AccessPaths::new(AccessPerm::ReadOnly)));
        }

        if let Some(ap) = self.anonymous.as_ref() {
            return (None, ap.guard(path, method));
        }

        (None, None)
    }

    /// Mint a download token for `user` (an `--auth` user or api key) or an OIDC identity.
    pub fn generate_token(
        &self,
        path: &str,
        user: &str,
        identity: Option<&OidcIdentity>,
    ) -> Result<String> {
        let exp = unix_now().as_millis() as u64 + TOKEN_EXPIRATION;
        let (mut signing_key, who, payload) = match (identity, &self.oidc) {
            (Some(id), Some(oidc)) => {
                let grants = self.oidc_access(&id.claims).map(|ap| ap.rules()).unwrap_or_default();
                let payload = format!("{}\0{}", id.name, grants.join(","));
                let who = [&[OIDC_TOKEN_MARK], payload.as_bytes()].concat();
                (derive_secret_key("oidc", &oidc.session_secret), who, payload)
            }
            _ => {
                let (pass, _) = self
                    .credential(user)
                    .ok_or_else(|| anyhow!("Not found user '{user}'"))?;
                (derive_secret_key(user, pass), user.as_bytes().to_vec(), String::new())
            }
        };
        let message = match payload.is_empty() {
            true => format!("{path}:{exp}"),
            false => format!("{path}:{exp}:{payload}"),
        };
        let sig = signing_key.sign(message.as_bytes()).to_bytes();

        let mut raw = Vec::with_capacity(64 + 8 + who.len());
        raw.extend_from_slice(&sig);
        raw.extend_from_slice(&exp.to_be_bytes());
        raw.extend_from_slice(&who);

        Ok(hex::encode(raw))
    }

    fn verify_token(&self, token: &str, path: &str) -> Result<(String, AccessPaths)> {
        let raw = hex::decode(token)?;

        if raw.len() < 72 {
            bail!("Invalid token");
        }

        let sig_bytes = &raw[..64];
        let exp_bytes = &raw[64..72];
        let user_bytes = &raw[72..];

        let exp = u64::from_be_bytes(exp_bytes.try_into()?);
        if unix_now().as_millis() as u64 > exp {
            bail!("Token expired");
        }
        let sig = Signature::from_bytes(&<[u8; 64]>::try_from(sig_bytes)?);

        if user_bytes.first() == Some(&OIDC_TOKEN_MARK) {
            let oidc = self.oidc.as_ref().ok_or_else(|| anyhow!("OIDC is disabled"))?;
            let payload = std::str::from_utf8(&user_bytes[1..])?;
            let message = format!("{path}:{exp}:{payload}");
            derive_secret_key("oidc", &oidc.session_secret).verify(message.as_bytes(), &sig)?;
            let (name, grants) = payload.split_once('\0').ok_or_else(|| anyhow!("Invalid token"))?;
            let mut paths = AccessPaths::default();
            paths.merge(grants).ok_or_else(|| anyhow!("Invalid token"))?;
            return Ok((name.to_string(), paths));
        }

        let user = std::str::from_utf8(user_bytes)?;
        let (pass, ap) = self
            .credential(user)
            .ok_or_else(|| anyhow!("Not found user '{user}'"))?;

        let message = format!("{path}:{exp}");
        derive_secret_key(user, pass).verify(message.as_bytes(), &sig)?;
        Ok((user.to_string(), ap.clone()))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AccessPaths {
    perm: AccessPerm,
    children: IndexMap<String, AccessPaths>,
}

impl AccessPaths {
    pub fn new(perm: AccessPerm) -> Self {
        Self {
            perm,
            ..Default::default()
        }
    }

    pub fn perm(&self) -> AccessPerm {
        self.perm
    }

    pub fn set_perm(&mut self, perm: AccessPerm) {
        if !perm.indexonly() {
            self.perm = perm;
        }
    }

    pub fn merge(&mut self, paths: &str) -> Option<()> {
        for item in paths.trim_matches(',').split(',') {
            let (path, perm) = match item.split_once(':') {
                None => (item, AccessPerm::ReadOnly),
                Some((path, "ro")) => (path, AccessPerm::ReadOnly),
                Some((path, "rw")) => (path, AccessPerm::ReadWrite),
                _ => return None,
            };
            self.add(path, perm);
        }
        Some(())
    }

    pub fn guard(&self, path: &str, method: &Method) -> Option<Self> {
        let target = self.find(path)?;
        if !is_readonly_method(method) && !target.perm().readwrite() {
            return None;
        }
        Some(target)
    }

    fn add(&mut self, path: &str, perm: AccessPerm) {
        let path = path.trim_matches('/');
        if path.is_empty() {
            self.set_perm(perm);
        } else {
            let parts: Vec<&str> = path.split('/').collect();
            self.add_impl(&parts, perm);
        }
    }

    fn add_impl(&mut self, parts: &[&str], perm: AccessPerm) {
        if parts.is_empty() {
            self.perm = perm;
            return;
        }
        let child = self.children.entry(parts[0].to_string()).or_default();
        child.add_impl(&parts[1..], perm)
    }

    /// Merge anonymous `AccessPaths` into `self` (a user's paths) with "higher perm wins" semantics.
    /// `orig_user` is a snapshot of `self` before any anonymous merging begins, used so that
    /// the user's own effective perm is measured against the pre-merge state.
    fn absorb_anon(
        &mut self,
        anon: &AccessPaths,
        orig_user: &AccessPaths,
        user_inherited: AccessPerm,
        anon_inherited: AccessPerm,
    ) {
        let anon_eff = if !anon.perm.indexonly() {
            anon.perm
        } else {
            anon_inherited
        };
        let orig_user_eff = if !orig_user.perm.indexonly() {
            orig_user.perm
        } else {
            user_inherited
        };

        let combined = std::cmp::max(anon_eff, orig_user_eff);
        if !combined.indexonly() && combined > self.perm {
            self.perm = combined;
        }

        let default_ap = AccessPaths::default();
        for (name, anon_child) in &anon.children {
            let orig_user_child = orig_user.children.get(name).unwrap_or(&default_ap);
            let user_child = self.children.entry(name.clone()).or_default();
            user_child.absorb_anon(anon_child, orig_user_child, orig_user_eff, anon_eff);
        }
    }

    pub fn find(&self, path: &str) -> Option<AccessPaths> {
        let parts: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|v| !v.is_empty())
            .collect();
        self.find_impl(&parts, self.perm)
    }

    fn find_impl(&self, parts: &[&str], perm: AccessPerm) -> Option<AccessPaths> {
        let perm = if !self.perm.indexonly() {
            self.perm
        } else {
            perm
        };
        if parts.is_empty() {
            if perm.indexonly() {
                return Some(self.clone());
            } else {
                return Some(AccessPaths::new(perm));
            }
        }
        let child = match self.children.get(parts[0]) {
            Some(v) => v,
            None => {
                if perm.indexonly() {
                    return None;
                } else {
                    return Some(AccessPaths::new(perm));
                }
            }
        };
        child.find_impl(&parts[1..], perm)
    }

    /// Flatten to `/path:perm` items (inverse of `merge`), for embedding in tokens.
    pub fn rules(&self) -> Vec<String> {
        let mut out = vec![];
        self.rules_impl("", &mut out);
        out
    }

    fn rules_impl(&self, prefix: &str, out: &mut Vec<String>) {
        if !self.perm.indexonly() {
            let perm = if self.perm.readwrite() { "rw" } else { "ro" };
            out.push(format!("{}:{perm}", if prefix.is_empty() { "/" } else { prefix }));
        }
        for (name, child) in &self.children {
            child.rules_impl(&format!("{prefix}/{name}"), out);
        }
    }

    pub fn child_names(&self) -> Vec<&String> {
        self.children.keys().collect()
    }

    pub fn entry_paths(&self, base: &Path) -> Vec<PathBuf> {
        if !self.perm().indexonly() {
            return vec![base.to_path_buf()];
        }
        let mut output = vec![];
        self.entry_paths_impl(&mut output, base);
        output
    }

    fn entry_paths_impl(&self, output: &mut Vec<PathBuf>, base: &Path) {
        for (name, child) in self.children.iter() {
            let base = base.join(name);
            if child.perm().indexonly() {
                child.entry_paths_impl(output, &base);
            } else {
                output.push(base)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum AccessPerm {
    #[default]
    IndexOnly,
    ReadOnly,
    ReadWrite,
}

impl AccessPerm {
    pub fn indexonly(&self) -> bool {
        self == &AccessPerm::IndexOnly
    }

    pub fn readwrite(&self) -> bool {
        self == &AccessPerm::ReadWrite
    }
}

pub fn www_authenticate(res: &mut Response, args: &Args) -> Result<()> {
    if args.auth.use_hashed_password || args.auth.users.is_empty() {
        let basic = HeaderValue::from_str(&format!("Basic realm=\"{REALM}\""))?;
        res.headers_mut().insert(WWW_AUTHENTICATE, basic);
    } else {
        let nonce = create_nonce()?;
        let digest = HeaderValue::from_str(&format!(
            "Digest realm=\"{REALM}\", nonce=\"{nonce}\", qop=\"auth\""
        ))?;
        let basic = HeaderValue::from_str(&format!("Basic realm=\"{REALM}\""))?;
        res.headers_mut().append(WWW_AUTHENTICATE, digest);
        res.headers_mut().append(WWW_AUTHENTICATE, basic);
    }
    if !args.auth.api_keys.is_empty() {
        let bearer = HeaderValue::from_str(&format!("Bearer realm=\"{REALM}\""))?;
        res.headers_mut().append(WWW_AUTHENTICATE, bearer);
    }
    Ok(())
}

/// The token of an `Authorization: Bearer <token>` header.
fn bearer_token(authorization: &HeaderValue) -> Option<&str> {
    let value = strip_prefix(authorization.as_bytes(), b"Bearer ")?;
    std::str::from_utf8(value).ok().map(str::trim)
}

fn basic_token_matches(authorization: &HeaderValue, user: &str, stored: &str) -> bool {
    let Some(value) = strip_prefix(authorization.as_bytes(), b"Basic ") else {
        return false;
    };
    let decoded = STANDARD.decode(value).ok();
    let credentials = decoded.as_deref().and_then(|v| std::str::from_utf8(v).ok());
    match credentials.and_then(|v| v.split_once(':')) {
        Some((name, presented)) => name == user && token_matches(stored, presented),
        None => false,
    }
}

/// Compare a presented token with a stored plain, `sha256:<hex>` or `$6$` token.
fn token_matches(stored: &str, presented: &str) -> bool {
    if stored.starts_with("$6$") {
        return sha_crypt::ShaCrypt::SHA512
            .verify_password(presented.as_bytes(), stored)
            .is_ok();
    }
    if let Some(hex_digest) = stored.strip_prefix("sha256:") {
        let digest = hex::encode(Sha256::digest(presented.as_bytes()));
        return ct_eq(hex_digest.to_ascii_lowercase().as_bytes(), digest.as_bytes());
    }
    ct_eq(stored.as_bytes(), presented.as_bytes())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn get_auth_user(authorization: &HeaderValue) -> Option<String> {
    if let Some(value) = strip_prefix(authorization.as_bytes(), b"Basic ") {
        let value: Vec<u8> = STANDARD.decode(value).ok()?;
        let parts: Vec<&str> = std::str::from_utf8(&value).ok()?.split(':').collect();
        Some(parts[0].to_string())
    } else if let Some(value) = strip_prefix(authorization.as_bytes(), b"Digest ") {
        let digest_map = to_headermap(value).ok()?;
        let username = digest_map.get(b"username".as_ref())?;
        std::str::from_utf8(username).map(|v| v.to_string()).ok()
    } else {
        None
    }
}

pub fn check_auth(
    authorization: &HeaderValue,
    method: &str,
    auth_user: &str,
    auth_pass: &str,
) -> Option<()> {
    if let Some(value) = strip_prefix(authorization.as_bytes(), b"Basic ") {
        let value: Vec<u8> = STANDARD.decode(value).ok()?;
        let (user, pass) = std::str::from_utf8(&value).ok()?.split_once(':')?;

        if user != auth_user {
            return None;
        }

        if auth_pass.starts_with("$6$") {
            if sha_crypt::ShaCrypt::SHA512
                .verify_password(pass.as_bytes(), auth_pass)
                .is_ok()
            {
                return Some(());
            }
        } else if pass == auth_pass {
            return Some(());
        }

        None
    } else if let Some(value) = strip_prefix(authorization.as_bytes(), b"Digest ") {
        let digest_map = to_headermap(value).ok()?;
        if let (Some(username), Some(nonce), Some(user_response)) = (
            digest_map
                .get(b"username".as_ref())
                .and_then(|b| std::str::from_utf8(b).ok()),
            digest_map.get(b"nonce".as_ref()),
            digest_map.get(b"response".as_ref()),
        ) {
            match validate_nonce(nonce) {
                Ok(true) => {}
                _ => return None,
            }
            if auth_user != username {
                return None;
            }

            let mut h = Context::new();
            h.consume(format!("{auth_user}:{REALM}:{auth_pass}").as_bytes());
            let auth_pass = format!("{:x}", h.finalize());

            let mut ha = Context::new();
            ha.consume(method);
            ha.consume(b":");
            if let Some(uri) = digest_map.get(b"uri".as_ref()) {
                ha.consume(uri);
            }
            let ha = format!("{:x}", ha.finalize());
            let mut correct_response = None;
            if let Some(qop) = digest_map.get(b"qop".as_ref()) {
                if qop == &b"auth".as_ref() || qop == &b"auth-int".as_ref() {
                    correct_response = Some({
                        let mut c = Context::new();
                        c.consume(&auth_pass);
                        c.consume(b":");
                        c.consume(nonce);
                        c.consume(b":");
                        if let Some(nc) = digest_map.get(b"nc".as_ref()) {
                            c.consume(nc);
                        }
                        c.consume(b":");
                        if let Some(cnonce) = digest_map.get(b"cnonce".as_ref()) {
                            c.consume(cnonce);
                        }
                        c.consume(b":");
                        c.consume(qop);
                        c.consume(b":");
                        c.consume(&*ha);
                        format!("{:x}", c.finalize())
                    });
                }
            }
            let correct_response = match correct_response {
                Some(r) => r,
                None => {
                    let mut c = Context::new();
                    c.consume(&auth_pass);
                    c.consume(b":");
                    c.consume(nonce);
                    c.consume(b":");
                    c.consume(&*ha);
                    format!("{:x}", c.finalize())
                }
            };
            if correct_response.as_bytes() == *user_response {
                return Some(());
            }
        }
        None
    } else {
        None
    }
}

fn derive_secret_key(user: &str, pass: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(format!("{user}:{pass}").as_bytes());
    let hash = hasher.finalize();
    SigningKey::from_bytes(&hash.into())
}

/// Check if a nonce is still valid.
/// Return an error if it was never valid
fn validate_nonce(nonce: &[u8]) -> Result<bool> {
    if nonce.len() != 34 {
        bail!("invalid nonce");
    }
    //parse hex
    if let Ok(n) = std::str::from_utf8(nonce) {
        //get time
        if let Ok(secs_nonce) = u32::from_str_radix(&n[..8], 16) {
            //check time
            let now = unix_now();
            let secs_now = now.as_secs() as u32;

            if let Some(dur) = secs_now.checked_sub(secs_nonce) {
                //check hash
                let mut h = NONCESTARTHASH.clone();
                h.consume(secs_nonce.to_be_bytes());
                let h = format!("{:x}", h.finalize());
                if h[..26] == n[8..34] {
                    return Ok(dur < DIGEST_AUTH_TIMEOUT);
                }
            }
        }
    }
    bail!("invalid nonce");
}

fn is_readonly_method(method: &Method) -> bool {
    method == Method::GET
        || method == Method::OPTIONS
        || method == Method::HEAD
        || method.as_str() == "PROPFIND"
        || method.as_str() == "CHECKAUTH"
        || method.as_str() == "LOGOUT"
}

fn strip_prefix<'a>(search: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let l = prefix.len();
    if search.len() < l {
        return None;
    }
    if &search[..l] == prefix {
        Some(&search[l..])
    } else {
        None
    }
}

fn to_headermap(header: &[u8]) -> Result<HashMap<&[u8], &[u8]>, ()> {
    let mut sep = Vec::new();
    let mut assign = Vec::new();
    let mut i: usize = 0;
    let mut esc = false;
    for c in header {
        match (c, esc) {
            (b'=', false) => assign.push(i),
            (b',', false) => sep.push(i),
            (b'"', false) => esc = true,
            (b'"', true) => esc = false,
            _ => {}
        }
        i += 1;
    }
    sep.push(i);

    i = 0;
    let mut ret = HashMap::new();
    for (&k, &a) in sep.iter().zip(assign.iter()) {
        while header[i] == b' ' {
            i += 1;
        }
        if a <= i || k <= 1 + a {
            //keys and values must contain one char
            return Err(());
        }
        let key = &header[i..a];
        let val = if header[1 + a] == b'"' && header[k - 1] == b'"' {
            //escaped
            &header[2 + a..k - 1]
        } else {
            //not escaped
            &header[1 + a..k]
        };
        i = 1 + k;
        ret.insert(key, val);
    }
    Ok(ret)
}

fn create_nonce() -> Result<String> {
    let now = unix_now();
    let secs = now.as_secs() as u32;
    let mut h = NONCESTARTHASH.clone();
    h.consume(secs.to_be_bytes());

    let n = format!("{:08x}{:032x}", secs, h.finalize());
    Ok(n[..34].to_string())
}

fn split_account_paths(s: &str) -> Option<(&str, &str)> {
    let i = s.find("@/")?;
    Some((&s[0..i], &s[i + 1..]))
}

fn split_rules(rules: &[&str]) -> Vec<String> {
    let mut output = vec![];
    for rule in rules {
        let parts: Vec<&str> = rule.split('|').collect();
        let mut rules_list = vec![];
        let mut concated_part = String::new();
        for (i, part) in parts.iter().enumerate() {
            if part.contains("@/") {
                concated_part.push_str(part);
                let mut concated_part_tmp = String::new();
                std::mem::swap(&mut concated_part_tmp, &mut concated_part);
                rules_list.push(concated_part_tmp);
                continue;
            }
            concated_part.push_str(part);
            if i < parts.len() - 1 {
                concated_part.push('|');
            }
        }
        if !concated_part.is_empty() {
            rules_list.push(concated_part)
        }
        output.extend(rules_list);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_account_paths() {
        assert_eq!(
            split_account_paths("user:pass@/:rw"),
            Some(("user:pass", "/:rw"))
        );
        assert_eq!(
            split_account_paths("user:pass@@/:rw"),
            Some(("user:pass@", "/:rw"))
        );
        assert_eq!(
            split_account_paths("user:pass@1@/:rw"),
            Some(("user:pass@1", "/:rw"))
        );
    }

    #[test]
    fn test_compact_split_rules() {
        assert_eq!(
            split_rules(&["user1:pass1@/:rw|user2:pass2@/:rw"]),
            ["user1:pass1@/:rw", "user2:pass2@/:rw"]
        );
        assert_eq!(
            split_rules(&["user1:pa|ss1@/:rw|user2:pa|ss2@/:rw"]),
            ["user1:pa|ss1@/:rw", "user2:pa|ss2@/:rw"]
        );
        assert_eq!(
            split_rules(&["user1:pa|ss1@/:rw|@/"]),
            ["user1:pa|ss1@/:rw", "@/"]
        );
    }

    #[test]
    fn test_access_paths() {
        let mut paths = AccessPaths::default();
        paths.add("/dir1", AccessPerm::ReadWrite);
        paths.add("/dir2/dir21", AccessPerm::ReadWrite);
        paths.add("/dir2/dir21/dir211", AccessPerm::ReadOnly);
        paths.add("/dir2/dir22", AccessPerm::ReadOnly);
        paths.add("/dir2/dir22/dir221", AccessPerm::ReadWrite);
        paths.add("/dir2/dir23/dir231", AccessPerm::ReadWrite);
        assert_eq!(
            paths.entry_paths(Path::new("/tmp")),
            [
                "/tmp/dir1",
                "/tmp/dir2/dir21",
                "/tmp/dir2/dir22",
                "/tmp/dir2/dir23/dir231",
            ]
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>()
        );
        assert_eq!(
            paths
                .find("dir2")
                .map(|v| v.entry_paths(Path::new("/tmp/dir2"))),
            Some(
                [
                    "/tmp/dir2/dir21",
                    "/tmp/dir2/dir22",
                    "/tmp/dir2/dir23/dir231"
                ]
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>()
            )
        );
        assert_eq!(
            paths.find("dir1/file"),
            Some(AccessPaths::new(AccessPerm::ReadWrite))
        );
        assert_eq!(
            paths.find("dir2/dir21/file"),
            Some(AccessPaths::new(AccessPerm::ReadWrite))
        );
        assert_eq!(
            paths.find("dir2/dir21/dir211/file"),
            Some(AccessPaths::new(AccessPerm::ReadOnly))
        );
        assert_eq!(
            paths.find("dir2/dir22/file"),
            Some(AccessPaths::new(AccessPerm::ReadOnly))
        );
        assert_eq!(
            paths.find("dir2/dir22/dir221/file"),
            Some(AccessPaths::new(AccessPerm::ReadWrite))
        );
        assert_eq!(paths.find("dir2/dir23/file"), None);
        assert_eq!(
            paths.find("dir2/dir23//dir231/file"),
            Some(AccessPaths::new(AccessPerm::ReadWrite))
        );
    }

    fn key(name: &str, token: &str, paths: &[&str]) -> ApiKeyConfig {
        ApiKeyConfig {
            name: name.into(),
            token: token.into(),
            paths: paths.iter().map(|v| v.to_string()).collect(),
        }
    }

    fn basic(user: &str, pass: &str) -> HeaderValue {
        let encoded = STANDARD.encode(format!("{user}:{pass}"));
        HeaderValue::from_str(&format!("Basic {encoded}")).unwrap()
    }

    fn bearer(token: &str) -> HeaderValue {
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap()
    }

    fn sha256_token(token: &str) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(token.as_bytes())))
    }

    fn keyed_acl() -> AccessControl {
        let mut acl = AccessControl::new(&["legacy:pw@/"]).unwrap();
        let hashed = "$6$gQxZwKyWn/ZmWEA2$4uV7KKMnSUnET2BtWTj/9T5.Jq3h/MdkOlnIl5hdlTxDZ4MZKmJ.kl6C.NL9xnNPqC4lVHC1vuI0E5cLpTJX81";
        acl.add_api_keys(&[
            key("ci", "plain-token", &["/releases:rw"]),
            key("viewer", &sha256_token("view-token"), &["/:ro"]),
            key("hashed", hashed, &["/docs:ro"]),
        ])
        .unwrap();
        acl
    }

    fn guard_with(acl: &AccessControl, method: Method, auth: &HeaderValue, path: &str) -> (Option<String>, bool) {
        let (user, ap) = acl.guard(path, &method, Some(auth), None, false, None);
        (user, ap.is_some())
    }

    #[test]
    fn test_api_key_basic() {
        let acl = keyed_acl();
        assert_eq!(guard_with(&acl, Method::GET, &basic("ci", "plain-token"), "/releases"), (Some("ci".into()), true));
        assert_eq!(guard_with(&acl, Method::GET, &basic("ci", "nope"), "/releases"), (None, false));
        assert_eq!(guard_with(&acl, Method::GET, &basic("viewer", "view-token"), "/x"), (Some("viewer".into()), true));
        assert_eq!(guard_with(&acl, Method::GET, &basic("legacy", "pw"), "/x"), (Some("legacy".into()), true));
    }

    #[test]
    fn test_api_key_bearer() {
        let acl = keyed_acl();
        assert_eq!(guard_with(&acl, Method::GET, &bearer("plain-token"), "/releases"), (Some("ci".into()), true));
        assert_eq!(guard_with(&acl, Method::GET, &bearer("view-token"), "/any"), (Some("viewer".into()), true));
        assert_eq!(guard_with(&acl, Method::GET, &bearer("unknown"), "/releases"), (None, false));
        // the sha256 digest itself is not a credential
        let digest = sha256_token("view-token").replace("sha256:", "");
        assert_eq!(guard_with(&acl, Method::GET, &bearer(&digest), "/any"), (None, false));
    }

    #[test]
    fn test_api_key_permissions() {
        let acl = keyed_acl();
        let ci = basic("ci", "plain-token");
        assert!(guard_with(&acl, Method::PUT, &ci, "/releases/a").1);
        assert!(!guard_with(&acl, Method::GET, &ci, "/docs").1);
        let viewer = bearer("view-token");
        assert!(guard_with(&acl, Method::GET, &viewer, "/docs").1);
        assert_eq!(guard_with(&acl, Method::PUT, &viewer, "/docs"), (Some("viewer".into()), false));
    }

    #[test]
    fn test_api_key_hashed_is_basic_only() {
        let mut acl = AccessControl::default();
        // hash of "pass" (same fixture as tests/auth.rs)
        let hash = "$6$gQxZwKyWn/ZmWEA2$4uV7KKMnSUnET2BtWTj/9T5.Jq3h/MdkOlnIl5hdlTxDZ4MZKmJ.kl6C.NL9xnNPqC4lVHC1vuI0E5cLpTJX81";
        acl.add_api_keys(&[key("h", hash, &["/:rw"])]).unwrap();
        assert!(guard_with(&acl, Method::GET, &basic("h", "pass"), "/").1);
        assert!(!guard_with(&acl, Method::GET, &basic("h", "wrong"), "/").1);
        assert!(!guard_with(&acl, Method::GET, &bearer("pass"), "/").1);
    }

    #[test]
    fn test_api_keys_close_open_server() {
        let mut acl = AccessControl::default();
        acl.add_api_keys(&[key("k", "t", &["/:ro"])]).unwrap();
        let (user, ap) = acl.guard("/", &Method::GET, None, None, false, None);
        assert_eq!((user, ap), (None, None));
    }

    #[test]
    fn test_api_key_download_token() {
        let acl = keyed_acl();
        let token = acl.generate_token("/releases/a", "ci", None).unwrap();
        let (user, ap) = acl.verify_token(&token, "/releases/a").unwrap();
        assert_eq!(user, "ci");
        assert!(ap.guard("/releases/a", &Method::PUT).is_some());
        assert!(acl.verify_token(&token, "/releases/b").is_err());
    }

    fn oidc_acl() -> AccessControl {
        let mut acl = AccessControl::default();
        let config = OidcConfig {
            enabled: true,
            session_secret: "0123456789abcdef0123456789abcdef".into(),
            rules: vec![
                crate::args::OidcRule {
                    claim: "groups".into(),
                    contains: Some("/devops".into()),
                    paths: vec!["/releases:rw".into()],
                    ..Default::default()
                },
                crate::args::OidcRule {
                    claim: "realm_access.roles".into(),
                    equals: Some("reader".into()),
                    paths: vec!["/:ro".into()],
                    ..Default::default()
                },
            ],
            default_paths: vec!["/public:ro".into()],
            ..Default::default()
        };
        acl.enable_oidc(&config).unwrap();
        acl
    }

    fn claims(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<String>> {
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in pairs {
            out.entry(k.to_string()).or_default().push(v.to_string());
        }
        out
    }

    #[test]
    fn test_oidc_rules() {
        let acl = oidc_acl();
        let devops = acl.oidc_access(&claims(&[("groups", "/devops")])).unwrap();
        assert!(devops.guard("/releases/a", &Method::PUT).is_some());
        assert!(devops.guard("/docs", &Method::GET).is_none());

        let both = acl
            .oidc_access(&claims(&[("groups", "/devops"), ("realm_access.roles", "reader")]))
            .unwrap();
        assert!(both.guard("/releases/a", &Method::PUT).is_some());
        assert!(both.guard("/docs", &Method::GET).is_some());
        assert!(both.guard("/docs", &Method::PUT).is_none());

        let nobody = acl.oidc_access(&claims(&[])).unwrap();
        assert!(nobody.guard("/public/x", &Method::GET).is_some());
        assert!(nobody.guard("/releases", &Method::GET).is_none());
        assert_eq!(acl.oidc_wanted_claims().len(), 2);
    }

    #[test]
    fn test_oidc_no_default_means_no_access() {
        let mut acl = AccessControl::default();
        acl.enable_oidc(&OidcConfig { enabled: true, ..Default::default() }).unwrap();
        assert!(acl.oidc_access(&claims(&[])).is_none());
    }

    #[test]
    fn test_oidc_identity_guard_and_token() {
        let acl = oidc_acl();
        let identity = OidcIdentity {
            name: "alice".into(),
            claims: claims(&[("groups", "/devops")]),
        };
        let (user, ap) = acl.guard("/releases", &Method::PUT, None, None, false, Some(&identity));
        assert_eq!((user.as_deref(), ap.is_some()), (Some("alice"), true));
        let (_, ap) = acl.guard("/docs", &Method::GET, None, None, false, Some(&identity));
        assert!(ap.is_none());

        let token = acl.generate_token("/releases/a.bin", "alice", Some(&identity)).unwrap();
        let (user, ap) = acl.verify_token(&token, "/releases/a.bin").unwrap();
        assert_eq!(user, "alice");
        assert!(ap.guard("/releases/a.bin", &Method::GET).is_some());
        assert!(ap.guard("/docs", &Method::GET).is_none());
        assert!(acl.verify_token(&token, "/releases/other").is_err());
        // a token minted with another secret is rejected
        let mut other = oidc_acl();
        other.oidc.as_mut().unwrap().session_secret = "x".repeat(32);
        assert!(other.verify_token(&token, "/releases/a.bin").is_err());
    }

    #[test]
    fn test_access_paths_rules_roundtrip() {
        let mut ap = AccessPaths::default();
        ap.merge("/a:rw,/b/c:ro").unwrap();
        let mut back = AccessPaths::default();
        back.merge(&ap.rules().join(",")).unwrap();
        assert_eq!(ap, back);
    }

    #[test]
    fn test_api_key_name_collides_with_legacy_user() {
        let mut acl = AccessControl::new(&["ci:pw@/"]).unwrap();
        let err = acl.add_api_keys(&[key("ci", "t", &["/:ro"])]).unwrap_err();
        assert!(err.to_string().contains("Duplicate"));
    }
}
