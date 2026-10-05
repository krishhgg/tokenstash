//! `remote = "tailscale"` end to end, with a fake `tailscale` and loopback aliases standing in
//! for the tailnet: 127.0.0.2 is this machine's Tailscale address, 127.0.0.3 another device
//! signed in as the owner, 127.0.0.4 a device of someone else. Linux only: other systems do
//! not answer on every 127.x address. Requests go out through `curl --interface`, which picks
//! the address a request comes from.
#![cfg(target_os = "linux")]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const OWNER: &str = "owner@example.com";

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokenstash-remote-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// What `tailscale status --json` and `tailscale whois --json IP` answer on this fake tailnet.
fn fake_tailscale(dir: &Path) -> PathBuf {
    let p = dir.join("tailscale");
    std::fs::write(&p, format!(r#"#!/bin/sh
case "$1" in
status) echo '{{"BackendState":"Running","Self":{{"TailscaleIPs":["127.0.0.2","fd7a::2"],"DNSName":"","UserID":1,"Tags":[]}},"User":{{"1":{{"LoginName":"{OWNER}"}}}}}}' ;;
whois)
  case "$3" in
  127.0.0.3) echo '{{"Node":{{"Tags":[]}},"UserProfile":{{"LoginName":"{OWNER}"}}}}' ;;
  127.0.0.4) echo '{{"Node":{{"Tags":[]}},"UserProfile":{{"LoginName":"someone@else.example"}}}}' ;;
  *) echo "no such peer" >&2; exit 1 ;;
  esac ;;
*) exit 2 ;;
esac
"#)).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

struct World { home: PathBuf, proj: PathBuf, port: u16, tailscale: PathBuf }

impl World {
    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_tokenstash"));
        c.env("TOKENSTASH_HOME", &self.home).env("TOKENSTASH_STASH", "insecure-file").env("TOKENSTASH_TAILSCALE", &self.tailscale)
            .env("HOME", self.home.join("user-home")).env("XDG_CONFIG_HOME", self.home.join("user-home/.config"))
            .env_remove("CLAUDECODE").env_remove("TOKENSTASH_AGENT");
        c
    }
    fn run(&self, args: &[&str]) -> std::process::Output {
        self.cmd().args(args).current_dir(&self.proj).stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap()
    }
    fn tasks(&self) -> serde_json::Value {
        serde_json::from_slice(&self.run(&["tasks", "--json", "--history"]).stdout).unwrap()
    }
    fn status_of(&self, id: &str) -> String {
        self.tasks().as_array().unwrap().iter().find(|t| t["id"] == id).map(|t| t["status"].as_str().unwrap().to_string()).unwrap_or_default()
    }
}

struct Inbox(Child);
impl Drop for Inbox {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One request from `from`, to the inbox's Tailscale address. Returns (status, headers, body).
fn curl(w: &World, from: &str, method: &str, path: &str, host: Option<&str>, cookie: Option<&str>, body: Option<&str>) -> (u16, String, String) {
    let url = format!("http://127.0.0.2:{}{path}", w.port);
    let mut c = Command::new("curl");
    c.args(["-s", "-i", "--noproxy", "*", "--max-time", "10", "--interface", from, "-X", method, &url]);
    if let Some(h) = host { c.args(["-H", &format!("Host: {h}")]); }
    if let Some(k) = cookie { c.args(["-H", &format!("Cookie: {k}")]); }
    if let Some(b) = body { c.args(["--data", b]); }
    let out = c.output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
    let (head, rest) = text.split_once("\n\n").unwrap_or((&text, ""));
    let status = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, head.to_string(), rest.to_string())
}

/// GET `path` on `to` (another tailnet address of this machine) from `from`.
fn curl_to(w: &World, to: &str, from: &str, path: &str) -> (u16, String) {
    let out = Command::new("curl").args(["-s", "-i", "--noproxy", "*", "--max-time", "10", "--interface", from, &format!("http://{to}:{}{path}", w.port)]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
    let status = text.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, text)
}

fn session_cookie(head: &str) -> Option<String> {
    head.lines().find_map(|l| l.strip_prefix("Set-Cookie: tokenstash_inbox=").or_else(|| l.strip_prefix("set-cookie: tokenstash_inbox="))).map(|v| v.split(';').next().unwrap().to_string())
}

#[test]
fn the_owners_other_devices_are_the_person_and_nobody_else_is() {
    if Command::new("curl").arg("--version").stdout(Stdio::null()).status().map(|s| !s.success()).unwrap_or(true) {
        eprintln!("skipped: no curl");
        return;
    }
    let root = tmp("world");
    let port = free_port();
    let home = root.join("home");
    let proj = root.join("proj");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(home.join("config.toml"), format!("notifications = false\ninbox_port = {port}\nstash_backend = \"insecure-file\"\nverify_every = \"never\"\n")).unwrap();
    let w = World { tailscale: fake_tailscale(&root), home, proj, port };
    let inbox = Inbox(w.cmd().args(["inbox", "--port", &port.to_string(), "--keep"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let start = Instant::now();
    while Command::new("curl").args(["-s", "--noproxy", "*", "-o", "/dev/null", &format!("http://127.0.0.1:{port}/verify?c=ready")]).status().map(|s| !s.success()).unwrap_or(true) {
        assert!(start.elapsed() < Duration::from_secs(20), "the inbox did not come up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Off: nothing answers on the Tailscale address yet, and links point at loopback.
    let need = w.run(&["need", "OPENAI_API_KEY"]);
    assert!(String::from_utf8_lossy(&need.stdout).contains(&format!("http://127.0.0.1:{port}/p/")));

    // An agent may not name another login as the person on a machine that has an owner.
    let other = w.run(&["remote", "tailscale", "--login", "someone@else.example"]);
    assert!(!other.status.success() && String::from_utf8_lossy(&other.stderr).contains("for a person at a terminal"), "{}", String::from_utf8_lossy(&other.stderr));
    // On, from an agent's shell: the person it is for cannot reach the inbox until it is.
    let on = w.run(&["remote", "tailscale"]);
    assert!(on.status.success(), "{}", String::from_utf8_lossy(&on.stderr));
    assert!(String::from_utf8_lossy(&on.stdout).contains(&format!("http://127.0.0.2:{port}/")));
    let cfg = std::fs::read_to_string(w.home.join("config.toml")).unwrap();
    assert!(cfg.contains("remote = \"tailscale\"") && cfg.contains(&format!("remote_login = \"{OWNER}\"")), "{cfg}");
    // The running inbox starts listening on the Tailscale address within a second or so
    // (anything but a refused connection: this machine without a credential gets a 404).
    let start = Instant::now();
    while curl(&w, "127.0.0.2", "GET", "/", None, None, None).0 == 0 {
        assert!(start.elapsed() < Duration::from_secs(10), "the inbox did not start listening on the Tailscale address");
        std::thread::sleep(Duration::from_millis(100));
    }
    let need = w.run(&["need", "OPENAI_API_KEY"]);
    let text = String::from_utf8_lossy(&need.stdout).into_owned();
    let link = text.split_whitespace().find(|t| t.starts_with(&format!("http://127.0.0.2:{port}/p/"))).unwrap_or_else(|| panic!("no tailnet link: {text}")).to_string();
    let card_path = link.strip_prefix(&format!("http://127.0.0.2:{port}")).unwrap().to_string();
    let id = card_path.trim_start_matches("/p/").split('?').next().unwrap().to_string();

    // The ownership check is loopback's alone: no tailnet peer gets a signed reply.
    assert_eq!(curl(&w, "127.0.0.4", "GET", "/verify?c=nonce", None, None, None).0, 404);
    assert_eq!(curl(&w, "127.0.0.3", "GET", "/verify?c=nonce", None, None, None).0, 404);
    // Someone else's device: nothing, link or no link.
    assert_eq!(curl(&w, "127.0.0.4", "GET", &card_path, None, None, None).0, 404);
    assert_eq!(curl(&w, "127.0.0.4", "GET", "/", None, None, None).0, 404);
    // The owner's other device: the agent's link lands on the card's full route, with the
    // session set, and the card opens with full authority without any cookie having come back.
    let (st, head, _) = curl(&w, "127.0.0.3", "GET", &card_path, None, None, None);
    assert_eq!(st, 303, "{head}");
    assert!(head.contains(&format!("Location: /t/{id}")) || head.contains(&format!("location: /t/{id}")), "{head}");
    let session = session_cookie(&head).expect("the session cookie is set");
    assert_eq!(session, std::fs::read_to_string(w.home.join("inbox.session")).unwrap());
    let (st, _, page) = curl(&w, "127.0.0.3", "GET", &format!("/t/{id}"), None, None, None);
    assert!(st == 200 && page.contains("Store &amp; inject"), "{page}");
    let (st, _, index) = curl(&w, "127.0.0.3", "GET", "/", None, None, None);
    assert!(st == 200 && index.contains(&id), "{index}");
    // A post still needs the cookie and the matching field: a page open in the same browser
    // cannot answer on its own.
    let (st, _, _) = curl(&w, "127.0.0.3", "POST", &format!("/t/{id}"), None, None, Some(&format!("value=sk-proj-fromthelaptop0123456789ab&skip_check=1&t={session}")));
    assert_eq!(st, 404);
    assert_eq!(w.status_of(&id), "pending");
    let (st, _, _) = curl(&w, "127.0.0.3", "POST", &format!("/t/{id}"), None, Some(&format!("tokenstash_inbox={session}")), Some("value=sk-proj-fromthelaptop0123456789ab&skip_check=1&t=wrong"));
    assert_eq!(st, 404);
    let (st, _, _) = curl(&w, "127.0.0.3", "POST", &format!("/t/{id}"), None, Some(&format!("tokenstash_inbox={session}")), Some(&format!("value=sk-proj-fromthelaptop0123456789ab&skip_check=1&t={session}")));
    assert_eq!(st, 303);
    assert_eq!(w.status_of(&id), "answered");
    // A setting that cannot be read is not "on": the owner's device gets nothing meanwhile.
    let good = std::fs::read_to_string(w.home.join("config.toml")).unwrap();
    std::fs::write(w.home.join("config.toml"), format!("{good}this is not toml\n")).unwrap();
    assert_eq!(curl(&w, "127.0.0.3", "GET", "/", None, None, None).0, 404);
    std::fs::write(w.home.join("config.toml"), &good).unwrap();
    assert_eq!(curl(&w, "127.0.0.3", "GET", "/", None, None, None).0, 200);
    // Another name in the Host header is not this machine: the DNS-rebinding defence holds
    // on this listener too.
    assert_eq!(curl(&w, "127.0.0.3", "GET", "/", Some("evil.example"), None, None).0, 404);
    // This machine itself, over its own Tailscale address, is not "another device": it gets
    // what loopback gets, which without a credential is nothing.
    assert_eq!(curl(&w, "127.0.0.2", "GET", "/", None, None, None).0, 404);

    // The address changes (Tailscale handed out a new one; here written into the setting):
    // the inbox listens on the new one and closes the old one, freeing its port.
    let moved = std::fs::read_to_string(w.home.join("config.toml")).unwrap().replace("127.0.0.2", "127.0.0.5");
    std::fs::write(w.home.join("config.toml"), moved).unwrap();
    let start = Instant::now();
    while curl_to(&w, "127.0.0.5", "127.0.0.3", "/").0 != 200 || curl(&w, "127.0.0.3", "GET", "/", None, None, None).0 != 0 {
        assert!(start.elapsed() < Duration::from_secs(10), "the inbox did not move to the new address");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(TcpListener::bind(("127.0.0.2", port)).is_ok(), "the old listener let go of its port");
    let back = std::fs::read_to_string(w.home.join("config.toml")).unwrap().replace("127.0.0.5", "127.0.0.2");
    std::fs::write(w.home.join("config.toml"), back).unwrap();
    let start = Instant::now();
    while curl(&w, "127.0.0.3", "GET", "/", None, None, None).0 != 200 {
        assert!(start.elapsed() < Duration::from_secs(10), "the inbox did not move back to the old address");
        std::thread::sleep(Duration::from_millis(100));
    }

    // Off again: the Tailscale address stops answering, at once, and then closes.
    assert!(w.run(&["remote", "off"]).status.success());
    assert_ne!(curl(&w, "127.0.0.3", "GET", "/", None, None, None).0, 200);
    let need = w.run(&["need", "RESEND_API_KEY"]);
    assert!(String::from_utf8_lossy(&need.stdout).contains(&format!("http://127.0.0.1:{port}/p/")), "links point at loopback again");
    drop(inbox);
}
