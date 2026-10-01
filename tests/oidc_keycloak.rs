//! Full OIDC login against the Keycloak in `dev/keycloak` (see its README).
//!
//!     KC_PORT=28080 docker compose -f dev/keycloak/docker-compose.yml up -d
//!     DUFS_TEST_OIDC_ISSUER=http://localhost:28080/realms/dufs \
//!         cargo test --test oidc_keycloak -- --ignored
//!
//! dufs must listen on a redirect URI registered in the realm, hence the fixed port.

mod fixtures;

use assert_fs::{prelude::*, TempDir};
use fixtures::{tmpdir, wait_for_port, Error};
use regex::Regex;
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use rstest::rstest;
use std::process::{Child, Command, Stdio};

const DUFS_PORT: u16 = 5055;

struct Dufs(Child);

impl Drop for Dufs {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn start(tmpdir: &TempDir, issuer: &str) -> Dufs {
    let config = format!(
        r#"
allow-all: true
oidc:
  enabled: true
  issuer: {issuer}
  client_id: dufs
  client_secret: dufs-dev-secret
  redirect_url: http://localhost:{DUFS_PORT}/oidc/callback
  session_secret: dev-only-session-secret-32-bytes-minimum!!
  rules:
    - claim: groups
      contains: /devops
      paths: ['/:rw']
"#
    );
    let config_file = tmpdir.child("dufs.yaml");
    config_file.write_str(&config).unwrap();
    let child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .args(["-p", &DUFS_PORT.to_string()])
        .args(["--config", &config_file.path().display().to_string()])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_port(DUFS_PORT);
    Dufs(child)
}

fn location(resp: &Response) -> String {
    resp.headers()["location"].to_str().unwrap().to_string()
}

/// Walk dufs -> Keycloak login form -> dufs callback and return a client holding the session.
fn log_in(user: &str, password: &str) -> Result<Client, Error> {
    let client = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()?;
    let base = format!("http://localhost:{DUFS_PORT}");

    let resp = client
        .get(format!("{base}/oidc/login?return=/dir1/"))
        .send()?;
    assert_eq!(resp.status(), 302);
    let form_page = client.get(location(&resp)).send()?.text()?;

    let action = Regex::new(r#"action="([^"]+)""#)?
        .captures(&form_page)
        .expect("Keycloak login form")[1]
        .replace("&amp;", "&");
    let resp = client
        .post(action)
        .form(&[("username", user), ("password", password)])
        .send()?;
    assert_eq!(resp.status(), 302, "Keycloak rejected the login");

    let resp = client.get(location(&resp)).send()?;
    assert_eq!(resp.status(), 302, "{}", resp.text()?);
    assert_eq!(location(&resp), "/dir1/");
    let cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().collect();
    assert!(cookies
        .iter()
        .any(|c| c.to_str().unwrap().starts_with("dufs_session=")));
    Ok(client)
}

#[rstest]
#[ignore = "needs Keycloak, set DUFS_TEST_OIDC_ISSUER"]
fn member_of_group_can_read_and_write(tmpdir: TempDir) -> Result<(), Error> {
    let issuer = std::env::var("DUFS_TEST_OIDC_ISSUER")?;
    let _dufs = start(&tmpdir, &issuer);
    let client = log_in("alice", "alice")?;
    let base = format!("http://localhost:{DUFS_PORT}");

    let listing = client.get(format!("{base}/dir1/?json")).send()?;
    assert_eq!(listing.status(), 200);
    let data: serde_json::Value = serde_json::from_str(&listing.text()?)?;
    assert_eq!(data["user"], "alice");

    let put = client
        .put(format!("{base}/dir1/from-alice.txt"))
        .body("hi")
        .send()?;
    assert_eq!(put.status(), 201);

    // a cross-site page cannot write with the session cookie
    let forged = client
        .put(format!("{base}/dir1/csrf.txt"))
        .header("Origin", "http://evil.example")
        .body("x")
        .send()?;
    assert_eq!(forged.status(), 403);

    // download tokens work for OIDC sessions, without the cookie
    let token = client
        .get(format!("{base}/dir1/test.txt?tokengen"))
        .send()?
        .text()?;
    let plain = Client::new();
    let resp = plain
        .get(format!("{base}/dir1/test.txt?token={token}"))
        .send()?;
    assert_eq!(resp.text()?, "This is dir1/test.txt");

    let out = client.get(format!("{base}/oidc/logout")).send()?;
    assert_eq!(out.status(), 302);
    let after = Client::new().get(format!("{base}/dir1/?json")).send()?;
    assert_eq!(after.status(), 401);
    Ok(())
}

#[rstest]
#[ignore = "needs Keycloak, set DUFS_TEST_OIDC_ISSUER"]
fn user_without_group_is_forbidden(tmpdir: TempDir) -> Result<(), Error> {
    let issuer = std::env::var("DUFS_TEST_OIDC_ISSUER")?;
    let _dufs = start(&tmpdir, &issuer);
    let client = log_in("bob", "bob")?;
    let base = format!("http://localhost:{DUFS_PORT}");

    assert_eq!(
        client.get(format!("{base}/dir1/?json")).send()?.status(),
        403
    );
    assert_eq!(
        client
            .put(format!("{base}/dir1/x.txt"))
            .body("x")
            .send()?
            .status(),
        403
    );
    Ok(())
}
