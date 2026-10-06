//! The inbox handles one request at a time, so a client that never finishes sending its
//! request must not be able to hold the line. Documented bound (see `cmd/inbox.rs`): a request
//! has to arrive in full within 10 seconds and no single wait for bytes lasts longer than 5,
//! so a dangling or trickling connection is cut off within 15 seconds, and while it dangles,
//! the CLI's `/verify` probe and a human's paste still go through.
//!
//! Every test here runs a real `tokenstash inbox` on a free loopback port under a scratch
//! `TOKENSTASH_HOME` with the insecure file stash; the browser session and proof key it
//! mints there are throwaways. The child is killed when the test's guard drops, including
//! on a panic.

mod common;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

/// The whole-request deadline plus the per-wait timeout the inbox documents.
const DOCUMENTED_BOUND: Duration = Duration::from_secs(15);
/// Generous room for a slow CI box on top of the bound.
const SLACK: Duration = Duration::from_secs(10);
/// How long a request that must not be held up may take.
const PROMPT: Duration = Duration::from_secs(3);

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokenstash-inbox-deadline-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A port nobody is listening on right now. Handed to the inbox by config and `--port`, so
/// `tokenstash need` probing the configured port finds this test's inbox and spawns nothing.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A running inbox on a scratch home. Killed on drop, so a failing assertion never leaves a
/// server behind.
struct Inbox {
    child: Child,
    home: PathBuf,
    port: u16,
}

impl Inbox {
    fn start(name: &str) -> Inbox {
        let home = tmp(&format!("home-{name}"));
        let port = free_port();
        std::fs::write(home.join("config.toml"), format!("notifications = false\ninbox_port = {port}\nstash_backend = \"insecure-file\"\nverify_every = \"never\"\n")).unwrap();
        let child = common::tokenstash()
            .args(["inbox", "--port", &port.to_string()])
            .env("TOKENSTASH_HOME", &home)
            .env("TOKENSTASH_STASH", "insecure-file")
            .env_remove("CLAUDECODE")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().unwrap();
        let mut inbox = Inbox { child, home, port };
        let started = Instant::now();
        loop {
            // The session is minted only after the bind, so its presence means the inbox is up.
            if TcpStream::connect_timeout(&inbox.addr(), Duration::from_millis(200)).is_ok() && inbox.home.join("inbox.session").exists() {
                break;
            }
            if let Some(status) = inbox.child.try_wait().unwrap() {
                panic!("the inbox exited before it started listening: {status}");
            }
            assert!(started.elapsed() < Duration::from_secs(20), "the inbox did not come up on {}", inbox.port);
            std::thread::sleep(Duration::from_millis(50));
        }
        inbox
    }

    fn addr(&self) -> SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }

    /// The browser session the inbox minted in the scratch home: the full credential.
    fn token(&self) -> String {
        std::fs::read_to_string(self.home.join("inbox.session")).unwrap().trim().to_string()
    }

    /// The persistent ownership-proof key `/verify` answers with. Never sent; the test holds
    /// it only to check the answer.
    fn proof(&self) -> String {
        std::fs::read_to_string(self.home.join("inbox.proof.key")).unwrap().trim().to_string()
    }

    /// A connection with client-side timeouts well past the bound, so a stalled server shows
    /// up as a timing failure here rather than a hung test.
    fn connect(&self) -> TcpStream {
        let s = TcpStream::connect_timeout(&self.addr(), Duration::from_secs(5)).unwrap();
        s.set_read_timeout(Some(DOCUMENTED_BOUND + SLACK)).unwrap();
        s.set_write_timeout(Some(DOCUMENTED_BOUND + SLACK)).unwrap();
        s.set_nodelay(true).unwrap();
        s
    }

    /// One complete request; the status code and the response body.
    fn request(&self, raw: &str) -> (u16, String) {
        let mut s = self.connect();
        s.write_all(raw.as_bytes()).unwrap();
        s.flush().unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).expect("a complete response before the client-side timeout");
        let text = String::from_utf8_lossy(&buf).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or_else(|| panic!("no header terminator in {text:?}"));
        let status: u16 = head.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or_else(|| panic!("no status in {head:?}"));
        (status, body.to_string())
    }

    /// The CLI's ownership probe, timed. Fails loudly if it takes longer than `PROMPT`.
    fn verify_promptly(&self, what: &str) {
        let nonce = format!("{:x}{:x}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let started = Instant::now();
        let (status, body) = self.request(&format!("GET /verify?c={nonce} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", self.port));
        let took = started.elapsed();
        assert_eq!(status, 200, "{what}: /verify answered {status}");
        // HMAC-SHA256(proof key, domain tag || nonce), as `inbox_auth::verify_response` defines it.
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.proof().as_bytes()).unwrap();
        mac.update(format!("tokenstash-inbox-verify-v1:{nonce}").as_bytes());
        let expected: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(body.trim(), expected, "{what}: /verify did not prove the key");
        assert!(took < PROMPT, "{what}: /verify took {took:?}");
    }

    fn cli(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        common::tokenstash().args(args).current_dir(cwd)
            .env("TOKENSTASH_HOME", &self.home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap()
    }

    /// File a missing-key card from `proj` and return its id.
    fn file_card(&self, proj: &Path, name: &str) -> String {
        let out = self.cli(proj, &["need", name, "--agent", "seed"]);
        assert_eq!(out.status.code(), Some(10), "need should file a card: {}", String::from_utf8_lossy(&out.stderr));
        let tasks = self.cli(proj, &["tasks", "--json"]);
        let v: serde_json::Value = serde_json::from_slice(&tasks.stdout).unwrap();
        v.as_array().unwrap().iter().find(|t| t["name"] == name).unwrap()["id"].as_str().unwrap().to_string()
    }

    fn status_of(&self, proj: &Path, id: &str) -> String {
        let tasks = self.cli(proj, &["tasks", "--json", "--history"]);
        let v: serde_json::Value = serde_json::from_slice(&tasks.stdout).unwrap();
        v.as_array().unwrap().iter().find(|t| t["id"] == id).unwrap()["status"].as_str().unwrap().to_string()
    }

    /// A POST to a card with the session cookie and the CSRF field, `Content-Length` as given
    /// (which need not match `body`), and only the first `send` bytes of the body written.
    fn post_head(&self, id: &str, cookie: bool, content_length: usize) -> String {
        let cookie = if cookie { format!("Cookie: tokenstash_inbox={}\r\n", self.token()) } else { String::new() };
        format!("POST /t/{id} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{cookie}Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {content_length}\r\n\r\n", self.port)
    }
}

impl Drop for Inbox {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// True once the server has closed `s`: a read that returns EOF or an error (a `408` may arrive
/// first). A read timeout means it is still open.
fn wait_closed(s: &mut TcpStream, within: Duration) -> bool {
    let started = Instant::now();
    s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let mut buf = [0u8; 1024];
    while started.elapsed() < within {
        match s.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(_) => return true,
        }
    }
    false
}

/// The original bug: a POST whose body never arrives parked the single-threaded handler in
/// `read_to_end`, and every later request, including the CLI's `/verify` probe, waited
/// behind it forever. Three danglers at once (one silent, one mid-headers, one mid-body) must
/// leave the probe and a real paste unaffected, and each must be cut off within the bound.
#[test]
fn dangling_requests_do_not_hold_up_verify_or_a_paste_and_are_cut_off() {
    let inbox = Inbox::start("dangling");
    let proj = tmp("proj-dangling");
    let id = inbox.file_card(&proj, "GROQ_API_KEY");
    inbox.verify_promptly("before anything dangles");

    let opened = Instant::now();
    // Connected, never speaks (a browser's speculative preconnect looks like this too).
    let mut silent = inbox.connect();
    // Stops in the middle of the headers.
    let mut mid_head = inbox.connect();
    mid_head.write_all(format!("POST /t/{id} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Len", inbox.port).as_bytes()).unwrap();
    // Full headers with the session cookie, then only the start of the declared body.
    let mut mid_body = inbox.connect();
    mid_body.write_all(inbox.post_head(&id, true, 4096).as_bytes()).unwrap();
    mid_body.write_all(b"t=").unwrap();
    for s in [&mut silent, &mut mid_head, &mut mid_body] { s.flush().unwrap(); }
    std::thread::sleep(Duration::from_millis(300));

    inbox.verify_promptly("while three requests dangle");

    // A human's paste, with the danglers still open.
    let value = "gsk_aaaaaaaaaaaaaaaaaaaa";
    let body = format!("t={}&value={value}&skip_check=1", inbox.token());
    let started = Instant::now();
    let (status, _) = inbox.request(&format!("{}{body}", inbox.post_head(&id, true, body.len())));
    assert_eq!(status, 303, "a complete, authenticated paste is stored");
    assert!(started.elapsed() < PROMPT, "the paste took {:?}", started.elapsed());
    assert_eq!(inbox.status_of(&proj, &id), "answered");
    let env = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(env.contains(&format!("GROQ_API_KEY={value}")) || env.contains(&format!("GROQ_API_KEY=\"{value}\"")), "the key was written to the project: {env:?}");

    // ...and each dangler is closed by the server within the documented bound.
    for (what, s) in [("silent", &mut silent), ("mid-headers", &mut mid_head), ("mid-body", &mut mid_body)] {
        assert!(wait_closed(s, DOCUMENTED_BOUND + SLACK), "{what} connection was not cut off within {:?}", DOCUMENTED_BOUND + SLACK);
        assert!(opened.elapsed() < DOCUMENTED_BOUND + SLACK, "{what}: closed only after {:?}", opened.elapsed());
    }
}

/// A body that keeps trickling in under the per-wait timeout must still hit the absolute
/// deadline: one byte a second never lets any single wait expire, so only a whole-request
/// deadline ends it.
#[test]
fn a_trickled_body_is_cut_off_by_the_whole_request_deadline() {
    let inbox = Inbox::start("trickle");
    let proj = tmp("proj-trickle");
    let id = inbox.file_card(&proj, "GROQ_API_KEY");

    let mut trickle = inbox.connect();
    trickle.write_all(inbox.post_head(&id, true, 4096).as_bytes()).unwrap();
    trickle.flush().unwrap();
    let opened = Instant::now();
    let mut checked = false;
    let closed_after = loop {
        std::thread::sleep(Duration::from_secs(1));
        if trickle.write_all(b"t").and_then(|_| trickle.flush()).is_err() {
            break opened.elapsed();
        }
        if wait_closed(&mut trickle, Duration::from_millis(600)) {
            break opened.elapsed();
        }
        if !checked && opened.elapsed() > Duration::from_secs(3) {
            inbox.verify_promptly("while a body trickles in");
            checked = true;
        }
        assert!(opened.elapsed() < DOCUMENTED_BOUND + SLACK, "still open after {:?}", opened.elapsed());
    };
    assert!(checked, "the probe should have run while the trickle was in progress");
    assert!(closed_after >= Duration::from_secs(8), "cut off after only {closed_after:?}: that is a per-wait timeout, not the whole-request deadline");
    assert_eq!(inbox.status_of(&proj, &id), "pending", "a body that never completed answered nothing");
    assert!(!proj.join(".env.local").exists(), "nothing was written");
}

/// A declared body over the cap is refused before a byte of it is read, so it can neither
/// stall the reader nor be stored in part, with a 413 for a session holder and the usual
/// bare 404 for anyone else.
#[test]
fn an_oversized_declared_body_is_refused_unread_and_stores_nothing() {
    let inbox = Inbox::start("oversized");
    let proj = tmp("proj-oversized");
    let id = inbox.file_card(&proj, "GROQ_API_KEY");
    let too_big = 64 * 1024 + 1;

    // Declared but never sent: the answer comes back at once instead of waiting for the body.
    let started = Instant::now();
    let (status, body) = inbox.request(&inbox.post_head(&id, true, too_big));
    assert_eq!(status, 413, "{body}");
    assert!(body.contains("nothing was stored"), "{body}");
    assert!(started.elapsed() < PROMPT, "the server waited for a body it should never read: {:?}", started.elapsed());

    // Fully sent, well-formed, authenticated: still refused whole; the value never lands.
    let mut form = format!("t={}&value=gsk_", inbox.token());
    while form.len() < too_big { form.push('a'); }
    let (status, _) = inbox.request(&format!("{}{form}", inbox.post_head(&id, true, form.len())));
    assert_eq!(status, 413);

    // No session: the same nothing everything else gets, and just as promptly.
    let started = Instant::now();
    let (status, body) = inbox.request(&inbox.post_head(&id, false, too_big));
    assert_eq!(status, 404);
    assert!(body.is_empty(), "{body}");
    assert!(started.elapsed() < PROMPT);

    assert_eq!(inbox.status_of(&proj, &id), "pending");
    assert!(!proj.join(".env.local").exists(), "nothing was written");
    let _ = std::fs::remove_dir_all(&proj);
}
