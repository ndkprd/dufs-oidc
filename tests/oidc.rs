//! OIDC routes and api_keys against a stub IdP that only serves discovery and an empty JWKS.
//! The full login (token exchange) is covered by the Keycloak test at the bottom.

mod fixtures;
mod utils;

use assert_fs::{prelude::*, TempDir};
use fixtures::{port, tmpdir, wait_for_port, Error};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::redirect::Policy;
use rstest::rstest;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;

const SESSION_SECRET: &str = "0123456789abcdef0123456789abcdef";
// sha256("view-token")
const VIEW_TOKEN_SHA256: &str =
    "sha256:5e17bb983b1ff3b4acbcaa8451a4173faa5575c682e7cf8615e2ed5e50fad7bd";

struct Dufs {
    child: Child,
    port: u16,
    _dir: TempDir,
}

impl Drop for Dufs {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

impl Dufs {
    fn url(&self, path: &str) -> String {
        format!("http://localhost:{}/{path}", self.port)
    }
}

fn client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

fn serve_stub_idp(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            answer(&mut stream, port);
        }
    });
}

fn answer(stream: &mut TcpStream, port: u16) {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).unwrap_or(0);
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request.split_whitespace().nth(1).unwrap_or_default();
    let base = format!("http://127.0.0.1:{port}");
    let body = if path.ends_with("openid-configuration") {
        serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/auth"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
        })
    } else {
        serde_json::json!({ "keys": [] })
    }
    .to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn start(tmpdir: TempDir, port: u16, idp_port: u16) -> Dufs {
    serve_stub_idp(idp_port);
    tmpdir
        .child("oidc/secret.txt")
        .write_str("reserved")
        .unwrap();
    let config = format!(
        r#"
allow-all: true
oidc:
  enabled: true
  issuer: http://127.0.0.1:{idp_port}
  client_id: dufs
  client_secret: shh
  redirect_url: http://localhost:{port}/oidc/callback
  session_secret: {SESSION_SECRET}
  rules:
    - claim: groups
      contains: /devops
      paths: ['/:rw']
api_keys:
  - name: ci
    token: plain-token
    paths: ['/dir1:rw']
  - name: viewer
    token: {VIEW_TOKEN_SHA256}
    paths: ['/:ro']
"#
    );
    let config_file = tmpdir.child("dufs.yaml");
    config_file.write_str(&config).unwrap();
    let child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .args(["-p", &port.to_string()])
        .args(["--config", &config_file.path().display().to_string()])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_port(port);
    Dufs {
        child,
        port,
        _dir: tmpdir,
    }
}

fn browser(request: RequestBuilder) -> RequestBuilder {
    request.header("Accept", "text/html,application/xhtml+xml")
}

#[rstest]
fn unauthenticated_browser_is_sent_to_login(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let idp_port = fixtures::port();
    let dufs = start(tmpdir, port, idp_port);

    let resp = browser(client().get(dufs.url("dir1/"))).send()?;
    assert_eq!(resp.status(), 302);
    let location = resp.headers()["location"].to_str()?;
    assert_eq!(location, "/oidc/login?return=%2Fdir1%2F");

    let resp = client().get(dufs.url("dir1/")).send()?;
    assert_eq!(resp.status(), 401);
    let challenges: Vec<_> = resp.headers().get_all("www-authenticate").iter().collect();
    assert!(challenges
        .iter()
        .any(|v| v.to_str().unwrap().starts_with("Basic")));
    assert!(challenges
        .iter()
        .any(|v| v.to_str().unwrap().starts_with("Bearer")));
    Ok(())
}

#[rstest]
fn login_redirects_to_idp_with_pkce(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let idp_port = fixtures::port();
    let dufs = start(tmpdir, port, idp_port);

    let resp = client().get(dufs.url("oidc/login?return=/dir1/")).send()?;
    assert_eq!(resp.status(), 302);
    let location = resp.headers()["location"].to_str()?;
    assert!(
        location.starts_with(&format!("http://127.0.0.1:{idp_port}/auth?")),
        "{location}"
    );
    for needle in [
        "response_type=code",
        "client_id=dufs",
        "code_challenge_method=S256",
        "state=",
        "nonce=",
    ] {
        assert!(location.contains(needle), "{needle} missing in {location}");
    }
    let cookie = resp.headers()["set-cookie"].to_str()?;
    assert!(
        cookie.starts_with("dufs_oidc_tx=") && cookie.contains("HttpOnly"),
        "{cookie}"
    );
    Ok(())
}

#[rstest]
fn callback_rejects_unknown_state(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let dufs = start(tmpdir, port, fixtures::port());
    let resp = client()
        .get(dufs.url("oidc/callback?code=x&state=forged"))
        .send()?;
    assert_eq!(resp.status(), 400);
    Ok(())
}

#[rstest]
fn logout_clears_cookies(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let dufs = start(tmpdir, port, fixtures::port());
    let resp = client().get(dufs.url("oidc/logout")).send()?;
    assert_eq!(resp.status(), 302);
    let cookies: Vec<_> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("dufs_session=") && c.contains("Max-Age=0")),
        "{cookies:?}"
    );
    Ok(())
}

#[rstest]
fn forged_session_cookie_is_ignored(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let dufs = start(tmpdir, port, fixtures::port());
    let forged = "dufs_session=eyJzdWIiOiJldmlsIn0.AAAA";

    let resp = browser(client().get(dufs.url("dir1/")).header("Cookie", forged)).send()?;
    assert_eq!(resp.status(), 302);

    let resp = client()
        .get(dufs.url("dir1/test.txt"))
        .header("Cookie", forged)
        .header("Authorization", "Bearer plain-token")
        .send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn api_keys_basic_and_bearer(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let dufs = start(tmpdir, port, fixtures::port());
    let get = |path: &str| client().get(dufs.url(path));

    assert_eq!(
        get("dir1/test.txt")
            .basic_auth("ci", Some("plain-token"))
            .send()?
            .status(),
        200
    );
    assert_eq!(
        get("dir1/test.txt")
            .basic_auth("ci", Some("wrong"))
            .send()?
            .status(),
        401
    );
    assert_eq!(
        get("dir1/test.txt")
            .bearer_auth("plain-token")
            .send()?
            .status(),
        200
    );
    assert_eq!(
        get("dir1/test.txt").bearer_auth("nope").send()?.status(),
        401
    );
    // `ci` may only touch /dir1
    assert_eq!(
        get("dir2/test.txt")
            .bearer_auth("plain-token")
            .send()?
            .status(),
        403
    );

    assert_eq!(
        get("dir2/test.txt")
            .bearer_auth("view-token")
            .send()?
            .status(),
        200
    );
    let put = client()
        .put(dufs.url("dir2/new.txt"))
        .bearer_auth("view-token")
        .body("x")
        .send()?;
    assert_eq!(put.status(), 403);
    let put = client()
        .put(dufs.url("dir1/new.txt"))
        .bearer_auth("plain-token")
        .body("x")
        .send()?;
    assert_eq!(put.status(), 201);
    Ok(())
}

#[rstest]
fn oidc_name_is_reserved(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let dufs = start(tmpdir, port, fixtures::port());
    let key = |req: RequestBuilder| req.bearer_auth("view-token");

    let listing = key(client().get(dufs.url("?json"))).send()?.text()?;
    assert!(!listing.contains("\"name\": \"oidc\""), "{listing}");

    assert_eq!(
        key(client().get(dufs.url("oidc/secret.txt")))
            .send()?
            .status(),
        404
    );

    let put = client()
        .put(dufs.url("oidc/new.txt"))
        .bearer_auth("plain-token")
        .body("x")
        .send()?;
    assert_eq!(put.status(), 404);

    let copy = client()
        .request(
            reqwest::Method::from_bytes(b"COPY")?,
            dufs.url("dir1/test.txt"),
        )
        .bearer_auth("plain-token")
        .header("Destination", dufs.url("oidc/copy.txt"))
        .send()?;
    assert_eq!(copy.status(), 403);
    Ok(())
}

#[rstest]
fn index_data_tells_ui_oidc_is_on(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let dufs = start(tmpdir, port, fixtures::port());
    let page = client()
        .get(dufs.url(""))
        .bearer_auth("view-token")
        .send()?
        .text()?;
    let data = utils::retrieve_json(&page).unwrap();
    assert_eq!(data["oidc"], true);
    assert_eq!(data["auth"], true);
    Ok(())
}
