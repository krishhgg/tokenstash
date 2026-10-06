//! The MCP server serves one directory, decided once: the client's `roots` when offered
//! and answered, else its cwd, never a tool argument, and refuses to serve from
//! directories that are not projects.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

fn tmp(name: &str) -> PathBuf {
    let p = Path::new("/tmp").join(format!("tokenstash-mcp-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A scratch home: no notifications, an inbox port nobody else uses.
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

/// A scripted MCP client talking to a real server process.
struct Client {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<serde_json::Value>,
    log: PathBuf,
}

impl Client {
    fn start(home: &Path, cwd: &Path, roots_capability: bool) -> Client {
        let log = home.join(format!("mcp-{}.log", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let mut child = common::tokenstash()
            .arg("mcp")
            .current_dir(cwd)
            .env("TOKENSTASH_HOME", home)
            .env("TOKENSTASH_STASH", "insecure-file")
            .env("TOKENSTASH_MCP_LOG", &log)
            .env_remove("CLAUDECODE")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines() {
                let Ok(l) = l else { break };
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) {
                    if tx.send(v).is_err() { break; }
                }
            }
        });
        let mut c = Client { child, stdin, lines: rx, log };
        let caps = if roots_capability { serde_json::json!({ "roots": { "listChanged": true } }) } else { serde_json::json!({}) };
        c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "clientInfo": { "name": "test" }, "capabilities": caps } }));
        c.expect_id(1);
        c.send(serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        c
    }
    fn send(&mut self, v: serde_json::Value) { writeln!(self.stdin, "{v}").unwrap(); }
    fn next(&self, within: Duration) -> Option<serde_json::Value> { self.lines.recv_timeout(within).ok() }
    /// The response with this id (skipping anything else).
    fn expect_id(&self, id: u64) -> serde_json::Value {
        loop {
            let v = self.next(Duration::from_secs(20)).expect("a response before the timeout");
            if v.get("id") == Some(&serde_json::json!(id)) { return v; }
        }
    }
    /// The server's `roots/list` request, if it sends one soon.
    fn roots_request(&self) -> Option<serde_json::Value> {
        let v = self.next(Duration::from_secs(5))?;
        if v.get("method").and_then(|m| m.as_str()) == Some("roots/list") { Some(v) } else { None }
    }
    fn answer_roots(&mut self, req: &serde_json::Value, uris: &[&str]) {
        let list: Vec<_> = uris.iter().map(|u| serde_json::json!({ "uri": u, "name": "r" })).collect();
        self.send(serde_json::json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "result": { "roots": list } }));
    }
    fn call(&mut self, id: u64, tool: &str, args: serde_json::Value) -> serde_json::Value {
        self.send(serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": args } }));
        self.expect_id(id)
    }
    /// Where the server bound itself: make any tool call (secrets_list touches nothing),
    /// then read the measurement line the server wrote. Ok(path) or Err(refusal text).
    fn bound_project(&mut self, id: u64) -> Result<String, String> {
        let r = self.call(id, "secrets_list", serde_json::json!({}));
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        let last = log.lines().last().expect("the server logged its binding");
        let bound = last.split(" bound=").nth(1).expect("bound= in the log");
        if r.pointer("/result/isError") == Some(&serde_json::json!(true)) {
            assert!(bound.starts_with("err:"), "{last}");
            Err(text_of(&r))
        } else {
            Ok(bound.strip_prefix("ok:").expect("ok:").to_string())
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}

fn text_of(v: &serde_json::Value) -> String {
    v.pointer("/result/content/0/text").and_then(|t| t.as_str()).unwrap_or("").to_string()
}

fn file_uri(p: &Path) -> String { format!("file://{}", p.display()) }
fn canon(p: &Path) -> String { p.canonicalize().unwrap().to_string_lossy().to_string() }

#[test]
fn refused_directories_never_serve() {
    let home = home("home-refused");
    for cwd in [PathBuf::from("/"), dirs::home_dir().unwrap(), PathBuf::from("/tmp")] {
        let mut c = Client::start(&home, &cwd, false);
        let err = c.bound_project(2).unwrap_err();
        assert!(err.contains("no project bound"), "{cwd:?}: {err}");
        assert!(err.contains("Restart your agent in the project directory"));
    }
}

#[test]
fn schemas_name_no_project_and_the_server_refuses_another_directory() {
    let home = home("home-schemas");
    let a = tmp("proj-a");
    let b = tmp("proj-b");
    let mut c = Client::start(&home, &a, false);
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }));
    let tools = c.expect_id(5).to_string();
    assert!(!tools.contains("\"project\""), "no schema may take a project: {tools}");
    assert_eq!(c.bound_project(10).unwrap(), canon(&a));
    // a legacy `project` argument: refused unless it names the bound directory (absolute)
    let r = c.call(20, "human_request", serde_json::json!({ "title": "Other", "project": b.to_string_lossy() }));
    assert!(text_of(&r).contains("does not act for"), "{}", text_of(&r));
    let r = c.call(21, "human_request", serde_json::json!({ "title": "Rel", "project": "." }));
    assert!(text_of(&r).contains("absolute path"), "{}", text_of(&r));
    let r = c.call(22, "task_list", serde_json::json!({ "project": a.to_string_lossy() }));
    assert_ne!(r.pointer("/result/isError"), Some(&serde_json::json!(true)), "naming the bound directory is fine: {r}");
    // protocol hygiene: a batch, a request without a method, a null id
    c.send(serde_json::json!([{ "jsonrpc": "2.0", "id": 30, "method": "ping" }]));
    let v = c.next(Duration::from_secs(5)).unwrap();
    assert_eq!(v.pointer("/error/code"), Some(&serde_json::json!(-32600)), "{v}");
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 31 }));
    let v = c.expect_id(31);
    assert_eq!(v.pointer("/error/code"), Some(&serde_json::json!(-32600)), "{v}");
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": null, "method": "ping" }));
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 32, "method": "ping" }));
    let v = c.expect_id(32);
    assert!(v.get("result").is_some(), "the null-id message was treated as a notification and the next request answered: {v}");
}

#[test]
fn without_the_roots_capability_no_request_is_sent_and_a_planted_answer_is_ignored() {
    let home = home("home-noroots");
    let proj = tmp("proj-noroots");
    let other = tmp("other-noroots");
    let mut c = Client::start(&home, &proj, false);
    assert!(c.roots_request().is_none(), "the server must not ask a client that did not offer roots");
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": "tokenstash-roots-1", "result": { "roots": [{ "uri": file_uri(&other), "name": "x" }] } }));
    assert_eq!(c.bound_project(10).unwrap(), canon(&proj));
}

#[test]
fn a_single_root_binds_the_server_even_when_started_elsewhere() {
    let home = home("home-oneroot");
    let proj = tmp("proj-oneroot");
    let elsewhere = tmp("elsewhere-oneroot");
    let mut c = Client::start(&home, &elsewhere, true);
    let req = c.roots_request().expect("the server asks for roots");
    c.answer_roots(&req, &[&file_uri(&proj)]);
    assert_eq!(c.bound_project(10).unwrap(), canon(&proj), "bound to the root, not the cwd");
    // a message with our id but no result/error is not an answer: the server waits, then cwd
    let mut c = Client::start(&home, &elsewhere, true);
    let _req = c.roots_request().unwrap();
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": "tokenstash-roots-1" }));
    let started = std::time::Instant::now();
    assert_eq!(c.bound_project(10).unwrap(), canon(&elsewhere));
    assert!(started.elapsed() >= Duration::from_millis(1500), "it waited for a real answer");
    // a second `initialized` does not re-ask
    let mut c = Client::start(&home, &elsewhere, true);
    let _req = c.roots_request().unwrap();
    c.send(serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    assert!(c.next(Duration::from_millis(800)).is_none(), "no duplicate roots/list");
}

#[test]
fn a_refused_root_fails_closed_even_though_cwd_is_fine() {
    let home = home("home-refroot");
    let proj = tmp("proj-refroot");
    let mut c = Client::start(&home, &proj, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&dirs::home_dir().unwrap())]);
    let err = c.bound_project(10).unwrap_err();
    assert!(err.contains("your home directory"), "the root, not cwd, was the candidate: {err}");
}

#[test]
fn roots_uris_are_decoded_and_unusable_ones_ignored() {
    let home = home("home-decode");
    let elsewhere = tmp("elsewhere-decode");
    let spaced = tmp("proj with space");
    // percent-encoded, trailing slash, `localhost` authority; non-file schemes and a file
    // (not a directory) alongside; a `%` followed by non-ASCII must not crash the server
    let enc = format!("file://localhost{}/", canon(&spaced).replace(' ', "%20"));
    let afile = spaced.join("Cargo.toml"); std::fs::write(&afile, "x").unwrap();
    let mut c = Client::start(&home, &elsewhere, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&enc, "https://example.com/not-a-root", "vscode-vfs://x", &file_uri(&afile), "file:///tmp/%é%aé"]);
    assert_eq!(c.bound_project(10).unwrap(), canon(&spaced), "one usable root after decoding");
    // a symlinked root binds the directory it points at
    let real = tmp("proj-real");
    let link = Path::new("/tmp").join(format!("tokenstash-mcp-link-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut c = Client::start(&home, &elsewhere, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&link)]);
    assert_eq!(c.bound_project(10).unwrap(), canon(&real));
    let _ = std::fs::remove_file(&link);
}

#[test]
fn several_roots_follow_the_rules() {
    let home = home("home-many");
    let parent = tmp("many-parent");
    let child = parent.join("child"); std::fs::create_dir_all(&child).unwrap();
    let grandchild = child.join("gc"); std::fs::create_dir_all(&grandchild).unwrap();
    let other = tmp("many-other");
    // the most specific root containing cwd wins (not the first listed)
    let mut c = Client::start(&home, &grandchild, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&parent), &file_uri(&child)]);
    assert_eq!(c.bound_project(10).unwrap(), canon(&child));
    // cwd is the parent of exactly one root → that root
    let mut c = Client::start(&home, &parent, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&child), &file_uri(&other)]);
    assert_eq!(c.bound_project(10).unwrap(), canon(&child));
    // several roots, none related to cwd → fail closed
    let mut c = Client::start(&home, &other, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&child), &file_uri(&grandchild)]);
    let err = c.bound_project(10).unwrap_err();
    assert!(err.contains("none is this directory"), "{err}");
    // two roots inside one git repo collapse to the repo, wherever in it we were started
    let repo = tmp("many-repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::create_dir_all(repo.join("a/deep")).unwrap();
    std::fs::create_dir_all(repo.join("b")).unwrap();
    let mut c = Client::start(&home, &repo.join("a/deep"), true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&repo.join("a")), &file_uri(&repo.join("b"))]);
    assert_eq!(c.bound_project(10).unwrap(), canon(&repo), "the owned git root, as a project resolves");
}

#[test]
fn a_late_or_failed_roots_answer_means_cwd() {
    let home = home("home-late");
    let proj = tmp("proj-late");
    let other = tmp("other-late");
    // error answer → cwd
    let mut c = Client::start(&home, &proj, true);
    let req = c.roots_request().unwrap();
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "error": { "code": -1, "message": "no" } }));
    assert_eq!(c.bound_project(10).unwrap(), canon(&proj));
    // no answer at all → the first call waits briefly, then cwd; a later answer changes nothing
    let mut c = Client::start(&home, &proj, true);
    let req = c.roots_request().unwrap();
    let started = std::time::Instant::now();
    assert_eq!(c.bound_project(10).unwrap(), canon(&proj));
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(1500) && waited < Duration::from_secs(8), "waited {waited:?}");
    c.answer_roots(&req, &[&file_uri(&other)]);
    assert_eq!(c.bound_project(20).unwrap(), canon(&proj), "bound once");
}

#[test]
fn secrets_list_shows_only_what_this_directory_holds() {
    let home = home("home-list");
    let proj = tmp("proj-list");
    // a key in the stash that this directory never received
    let seed = common::tokenstash().args(["need", "GROQ_API_KEY", "--agent", "seed"]).current_dir(&proj)
        .env("TOKENSTASH_HOME", &home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE").output().unwrap();
    let _ = seed;
    // Seeded from the project directory: `tasks --all` and answering another directory's
    // card are a person's, and the seed is an agent-shaped process.
    let tasks = common::tokenstash().args(["tasks", "--json"]).current_dir(&proj).env("TOKENSTASH_HOME", &home).env("TOKENSTASH_STASH", "insecure-file").output().unwrap();
    let tid = serde_json::from_slice::<serde_json::Value>(&tasks.stdout).unwrap().as_array().unwrap().iter().find(|t| t["name"] == "GROQ_API_KEY").unwrap()["id"].as_str().unwrap().to_string();
    let mut ans = common::tokenstash().args(["answer", &tid, "--stdin", "--skip-check"]).current_dir(&proj).env("TOKENSTASH_HOME", &home).env("TOKENSTASH_STASH", "insecure-file").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    ans.stdin.take().unwrap().write_all(b"gsk_aaaaaaaaaaaaaaaaaaaa\n").unwrap();
    assert!(ans.wait().unwrap().success());
    // the directory that pasted it lists it; another directory lists nothing
    let mut c = Client::start(&home, &proj, false);
    let r = c.call(2, "secrets_list", serde_json::json!({}));
    let names: Vec<String> = r.pointer("/result/structuredContent/secrets").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|s| s["name"].as_str().map(String::from)).collect()).unwrap_or_default();
    assert_eq!(names, vec!["GROQ_API_KEY".to_string()], "{r}");
    let other = tmp("proj-list-other");
    let mut c = Client::start(&home, &other, false);
    let r = c.call(2, "secrets_list", serde_json::json!({}));
    let names = r.pointer("/result/structuredContent/secrets").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(99);
    assert_eq!(names, 0, "no inventory oracle: {r}");
}
