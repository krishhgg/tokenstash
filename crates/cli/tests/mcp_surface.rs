//! What the MCP surface may say. The server talks to a model, so every byte it returns is
//! context: a value must never appear there, and one project's cards must never be visible
//! from another. Malformed framing is answered, never fatal.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

fn tmp(name: &str) -> PathBuf {
    let p = Path::new("/tmp").join(format!("tokenstash-mcps-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p.canonicalize().unwrap()
}

/// A port nothing holds right now. Tests in one binary run in parallel, and two scratch homes
/// on one port each see the other's inbox as foreign; the name-derived ports collided.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn home(name: &str) -> PathBuf {
    let h = tmp(name);
    let port = free_port();
    std::fs::write(h.join("config.toml"), format!("notifications = false\ninbox_port = {port}\nstash_backend = \"insecure-file\"\nverify_every = \"never\"\n")).unwrap();
    h
}

struct Client { child: Child, stdin: ChildStdin, lines: Receiver<String> }

impl Client {
    fn start(home: &Path, cwd: &Path) -> Client {
        let mut child = common::tokenstash()
            .arg("mcp").current_dir(cwd)
            .env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file")
            .env_remove("CLAUDECODE")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines() {
                let Ok(l) = l else { break };
                if tx.send(l).is_err() { break; }
            }
        });
        let mut c = Client { child, stdin, lines: rx };
        c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "clientInfo": { "name": "test" }, "capabilities": {} } }));
        c.expect_id(1);
        c.send(serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        c
    }
    fn send(&mut self, v: serde_json::Value) { writeln!(self.stdin, "{v}").unwrap(); }
    fn send_raw(&mut self, bytes: &[u8]) { self.stdin.write_all(bytes).unwrap(); self.stdin.flush().unwrap(); }
    fn next_line(&self, within: Duration) -> Option<String> { self.lines.recv_timeout(within).ok() }
    fn expect_id(&self, id: u64) -> serde_json::Value {
        loop {
            let l = self.next_line(Duration::from_secs(20)).expect("a response before the timeout");
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) else { continue };
            if v.get("id") == Some(&serde_json::json!(id)) { return v; }
        }
    }
    fn call(&mut self, id: u64, tool: &str, args: serde_json::Value) -> serde_json::Value {
        self.send(serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": args } }));
        self.expect_id(id)
    }
}

impl Drop for Client {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}

/// Seed a stashed value the way a human would: file a card, answer it from the CLI.
fn seed(home: &Path, proj: &Path, name: &str, value: &str) {
    let out = common::tokenstash().arg("need").arg(name)
        .current_dir(proj).env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file")
        .output().unwrap();
    assert!(out.status.code() == Some(10), "a first request is pending: {out:?}");
    let tasks = common::tokenstash().arg("tasks").arg("--json")
        .current_dir(proj).env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file").output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&tasks.stdout).unwrap();
    let id = v.as_array().unwrap().iter().find(|t| t["name"] == serde_json::json!(name)).expect("a card for the key")["id"].as_str().unwrap().to_string();
    let mut child = common::tokenstash().arg("answer").arg(&id).arg("--stdin").arg("--skip-check")
        .current_dir(proj).env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file")
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(format!("{value}\n").as_bytes()).unwrap();
    assert!(child.wait().unwrap().success(), "the seed answer stored the value");
}

/// The headline promise, asserted at the surface that faces the model rather than at the
/// type that happens not to carry a value today.
#[test]
fn no_tool_result_ever_contains_a_value() {
    let home = home("secrecy");
    let proj = tmp("secrecy-proj");
    let canary = "sk-mcpcanary-9f2b1c7d4e6a8b0c";
    seed(&home, &proj, "OPENAI_API_KEY", canary);
    // A report is confirmed with the provider before it changes anything, so reporting a key
    // that has a probe sends it to the real provider. EXA_API_KEY has none: this test must
    // never depend on, or talk to, the internet.
    let reported = "exa-mcpcanary-3c5e7a9b1d2f4e6a";
    seed(&home, &proj, "EXA_API_KEY", reported);

    let mut c = Client::start(&home, &proj);
    let mut seen = String::new();
    seen.push_str(&c.call(2, "secrets_request", serde_json::json!({ "secrets": [{ "name": "OPENAI_API_KEY", "why": "test" }] })).to_string());
    seen.push_str(&c.call(3, "secrets_list", serde_json::json!({})).to_string());
    seen.push_str(&c.call(4, "task_list", serde_json::json!({})).to_string());
    seen.push_str(&c.call(5, "secrets_report_invalid", serde_json::json!({ "name": "EXA_API_KEY", "message": canary })).to_string());
    seen.push_str(&c.call(6, "human_request", serde_json::json!({ "title": "check something", "expects": "confirm" })).to_string());

    assert!(!seen.contains(canary) && !seen.contains(reported), "a value reached the agent: {seen}");
    // ...and the delivery really happened: the value is in the env file and nowhere else.
    let env = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(env.contains(canary), "the key was delivered to the project");
}

/// Task ids are scoped to the bound project, including the ambiguous-prefix path, which
/// used to answer by naming other projects' cards.
#[test]
fn task_check_never_answers_for_another_project() {
    let home = home("scope");
    let mine = tmp("scope-mine");
    let theirs = tmp("scope-theirs");
    seed(&home, &theirs, "RESEND_API_KEY", "re_theirs_00000000000000");

    let out = common::tokenstash().arg("need").arg("OPENAI_API_KEY")
        .current_dir(&theirs).env("TOKENSTASH_HOME", &home).env("TOKENSTASH_STASH", "insecure-file").output().unwrap();
    assert_eq!(out.status.code(), Some(10));
    let tasks = common::tokenstash().arg("tasks").arg("--json")
        .current_dir(&theirs).env("TOKENSTASH_HOME", &home).env("TOKENSTASH_STASH", "insecure-file").output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&tasks.stdout).unwrap();
    let their_id = v.as_array().unwrap()[0]["id"].as_str().unwrap().to_string();

    let mut c = Client::start(&home, &mine);
    let exact = c.call(2, "task_check", serde_json::json!({ "task_id": their_id })).to_string();
    assert!(!exact.contains(&their_id) || exact.contains("no task"), "{exact}");
    for prefix in ["t", "t_", "a"] {
        let r = c.call(3, "task_check", serde_json::json!({ "task_id": prefix })).to_string();
        assert!(!r.contains(&their_id), "prefix {prefix:?} named another project's card: {r}");
    }
}

/// Framing failures are answered and the session continues. A single non-UTF-8 byte used to
/// end the read loop, and an unterminated line grew without bound.
#[test]
fn malformed_frames_never_end_the_session() {
    let home = home("framing");
    let proj = tmp("framing-proj");
    let mut c = Client::start(&home, &proj);

    c.send_raw(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\",\"x\":\"\xff\xfe\"}\n");
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 3, "method": "ping" }));
    assert!(c.expect_id(3).get("result").is_some(), "the server survived invalid UTF-8");

    c.send_raw(b"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\"");
    c.send_raw(&vec![b'x'; 5 * 1024 * 1024]);
    c.send_raw(b"\n");
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 5, "method": "ping" }));
    assert!(c.expect_id(5).get("result").is_some(), "the server survived an oversized frame");

    c.send_raw(b"not json at all\n");
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 6, "method": "ping" }));
    assert!(c.expect_id(6).get("result").is_some(), "the server survived a parse error");
}

/// `expects` is stored on the card and drives the inbox form; only the two documented values.
#[test]
fn human_request_refuses_an_unknown_expects() {
    let home = home("expects");
    let proj = tmp("proj-expects");
    let mut c = Client::start(&home, &proj);
    let r = c.call(2, "human_request", serde_json::json!({ "title": "pick one", "expects": "choice" })).to_string();
    assert!(r.contains("expects must be"), "{r}");
    assert!(!r.contains("task_id"), "no card was filed: {r}");
}
