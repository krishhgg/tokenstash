//! Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0).
//! Hand-rolled on purpose: six tools, no SDK version churn. Tool results never contain values.
//!
//! Nor do they contain the inbox session. Everything written here lands in the model's
//! context, and the session is the credential that lets its holder ANSWER any task — store a
//! value under a real key name, approve a trust gate. Giving that to the model would let it
//! answer its own requests and self-approve the gates that exist to ask a person. So every
//! `inbox` field and every link in a `next` below uses `util::inbox_url_agent` — one card's
//! capability, which opens and answers that card and cannot approve; the full session goes
//! to the desktop notification and `tokenstash open`, which only a human reads. See
//! `crate::inbox_auth`.

use crate::cmd::need::notify_pending;

/// The one rule every surface (instructions, results, skill file, AGENTS snippet) states the
/// same way: a value the user has not supplied is not to be invented by any route.
use crate::util::{self, App};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokenstash_core::need::{self, NeedOpts};
use tokenstash_core::tasks::{self, HumanRequest, SecretRequest};

const PROTOCOL: &str = "2025-06-18";

/// Which directory this server serves. Decided once, at the first tool call, from the
/// client's `roots` (when it advertised the capability and answered our `roots/list` —
/// waited for up to ROOTS_WAIT) or the server's cwd; never from a tool argument. Measured
/// 2026-08-27 (docs/agent-conformance.md): Claude Code, Codex and Cursor all spawn the server in
/// the project directory; only Claude Code offers `roots`.
struct Binding {
    /// Ok(project) or Err(why this directory is refused).
    bound: Option<std::result::Result<PathBuf, String>>,
    roots_supported: bool,
    /// We sent `roots/list` and have not consumed the answer yet.
    roots_requested: bool,
    roots: Option<Vec<PathBuf>>,
    /// What the client sent, before filtering (measurement aid).
    roots_raw: Vec<String>,
}

/// Is this message the client's answer to our `roots/list`?
fn is_roots_answer(m: &Value) -> bool {
    m.get("method").is_none() && m.get("id").and_then(|v| v.as_str()) == Some(ROOTS_REQ_ID) && (m.get("result").is_some() || m.get("error").is_some())
}

const ROOTS_REQ_ID: &str = "tokenstash-roots-1";
const ROOTS_WAIT: Duration = Duration::from_secs(2);

impl Binding {
    /// Roots are launcher-descriptive — the directory the client opened — and sit in the
    /// same trust tier as cwd. One root binds; several bind the most specific one
    /// containing cwd (exact match first), else the single root cwd is the parent of;
    /// anything else is ambiguous and fails closed.
    fn decide(&mut self) -> std::result::Result<PathBuf, String> {
        if self.bound.is_none() {
            self.roots_requested = false;
            // Roots are compared against the directory we were started in, not its git
            // root: two roots inside one repo must still resolve by where we actually are.
            let cwd = std::env::current_dir().ok().and_then(|d| d.canonicalize().ok()).unwrap_or_else(tokenstash_core::project::current);
            let candidate: std::result::Result<PathBuf, String> = match self.roots.as_deref() {
                Some([one]) => Ok(one.clone()),
                Some(many) if !many.is_empty() => {
                    let containing = many.iter().filter(|r| cwd.starts_with(r)).max_by_key(|r| r.components().count()).cloned();
                    match containing {
                        Some(r) => Ok(r),
                        None => {
                            let under: Vec<&PathBuf> = many.iter().filter(|r| r.starts_with(&cwd)).collect();
                            if under.len() == 1 { Ok(under[0].clone()) } else {
                                Err(format!("no project bound: the client lists {} roots and none is this directory ({}). Restart your agent in the project directory.", many.len(), cwd.display()))
                            }
                        }
                    }
                }
                // no roots offered, or none usable: the directory we were started in
                _ => Ok(cwd.clone()),
            };
            self.bound = Some(candidate.and_then(|c| {
                let c = tokenstash_core::project::canonical(&c);
                match tokenstash_core::trust::refused_root(&c) {
                    Some(why) => Err(format!("no project bound: {} is {why}. Restart your agent in the project directory.", c.display())),
                    None => Ok(c),
                }
            }));
            if let Ok(log) = std::env::var("TOKENSTASH_MCP_LOG") {
                // measurement aid: where clients spawn us and what they say (paths only)
                let bound = match self.bound.as_ref().unwrap() { Ok(p) => format!("ok:{}", p.display()), Err(e) => format!("err:{e}") };
                let line = format!("{} cwd={} roots_supported={} roots_raw={:?} roots={:?} bound={bound}\n", tokenstash_core::now(), cwd.display(), self.roots_supported, self.roots_raw, self.roots);
                let _ = std::fs::OpenOptions::new().create(true).append(true).open(log).and_then(|mut f| f.write_all(line.as_bytes()));
            }
        }
        self.bound.clone().unwrap()
    }

    fn take_roots(&mut self, msg: &Value) {
        if !self.roots_requested || self.bound.is_some() {
            return; // unsolicited: ignored
        }
        self.roots_requested = false;
        if msg.get("error").is_some() {
            return; // the client could not say: cwd it is
        }
        let uris: Vec<String> = msg.pointer("/result/roots").and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|r| r.get("uri").and_then(|u| u.as_str()).map(String::from)).collect()).unwrap_or_default();
        self.roots_raw = uris.clone();
        let mut roots: Vec<PathBuf> = uris.iter().filter_map(|u| root_path(u)).collect();
        // Existing directories only, resolved the way a project is (symlinks followed, the
        // owned git root when inside one); a dangling or unreadable root is no root — with
        // none usable the server falls back to cwd, which is the same trust tier.
        roots = roots.into_iter().filter(|r| r.is_dir()).map(|r| tokenstash_core::project::canonical(&r)).collect();
        roots.sort();
        roots.dedup();
        self.roots = Some(roots);
    }
}

/// `file:///a/b%20c` → `/a/b c`; anything that is not a local file URI is ignored.
fn root_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    if !rest.starts_with('/') { return None; }
    let mut out = Vec::with_capacity(rest.len());
    let b = rest.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) { out.push(h * 16 + l); i += 3; continue; }
        }
        out.push(b[i]);
        i += 1;
    }
    if out.contains(&0) { return None; }
    let s = String::from_utf8(out).ok()?;
    let s = s.trim_end_matches('/');
    if s.is_empty() { return Some(PathBuf::from("/")); }
    Some(PathBuf::from(s))
}

enum Incoming {
    Line(String),
    Eof,
    /// A frame longer than the cap: answered and skipped, never fatal.
    TooLong,
}

pub fn serve() -> Result<i32> {
    // stdin on its own thread so the first tool call can wait (bounded) for the client's
    // roots/list answer without ever blocking on a client that never sends one.
    let (tx, rx) = std::sync::mpsc::channel::<Incoming>();
    std::thread::spawn(move || {
        // Bounded, and never fatal. `lines()` grows one String until a newline arrives, so a
        // client that sends a gigabyte without one takes the process down with it; and its
        // Err arm — a single non-UTF-8 byte — used to end the loop, killing the server for
        // the rest of the session. An over-long line is answered and skipped; invalid UTF-8
        // becomes a parse error like any other malformed frame.
        const MAX_LINE: usize = 4 * 1024 * 1024;
        let stdin = std::io::stdin();
        let mut reader = std::io::BufReader::new(stdin.lock());
        let mut buf: Vec<u8> = Vec::new();
        loop {
            buf.clear();
            let n = match std::io::Read::take(&mut reader, MAX_LINE as u64 + 1).read_until(b'\n', &mut buf) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            if !buf.ends_with(b"\n") && buf.len() > MAX_LINE {
                // drain the rest of the oversized line so the next frame starts clean
                let mut sink = Vec::new();
                loop {
                    sink.clear();
                    match std::io::Read::take(&mut reader, MAX_LINE as u64).read_until(b'\n', &mut sink) {
                        Ok(0) => break,
                        Ok(_) if sink.ends_with(b"\n") => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                if tx.send(Incoming::TooLong).is_err() {
                    return;
                }
                continue;
            }
            let line = String::from_utf8_lossy(&buf).into_owned();
            if tx.send(Incoming::Line(line)).is_err() {
                return;
            }
        }
        let _ = tx.send(Incoming::Eof);
    });
    let mut out = std::io::stdout().lock();
    let mut agent = String::from("mcp");
    let mut binding = Binding { bound: None, roots_supported: false, roots_requested: false, roots: None, roots_raw: vec![] };
    let mut queued: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut eof = false;
    loop {
        if eof && queued.is_empty() { break; }
        let line = match queued.pop_front() {
            Some(l) => l,
            None => match rx.recv() {
                Ok(Incoming::Line(l)) => l,
                Ok(Incoming::TooLong) => {
                    write_msg(&mut out, &error(Value::Null, -32600, "request too large"))?;
                    continue;
                }
                _ => break,
            },
        };
        if line.trim().is_empty() { continue; }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => { write_msg(&mut out, &error(Value::Null, -32700, &format!("parse error: {e}")))?; continue; }
        };
        if !msg.is_object() {
            write_msg(&mut out, &error(Value::Null, -32600, "invalid request: expected a JSON-RPC object (batches are not supported)"))?;
            continue;
        }
        let id = msg.get("id").cloned().filter(|v| !v.is_null());
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        // A response (result/error, no method): only our own `roots/list` is ever answered.
        if method.is_empty() && (msg.get("result").is_some() || msg.get("error").is_some()) {
            if is_roots_answer(&msg) {
                binding.take_roots(&msg);
            }
            continue;
        }
        if !method.is_empty() && (msg.get("result").is_some() || msg.get("error").is_some()) {
            continue; // neither a request nor a response: ignored
        }
        let Some(id) = id else {
            // notifications
            if method == "notifications/initialized" && binding.roots_supported && binding.bound.is_none() && !binding.roots_requested && binding.roots.is_none() {
                write_msg(&mut out, &json!({ "jsonrpc": "2.0", "id": ROOTS_REQ_ID, "method": "roots/list" }))?;
                binding.roots_requested = true;
            }
            continue;
        };
        if method.is_empty() {
            write_msg(&mut out, &error(id, -32600, "invalid request: no method"))?;
            continue;
        }
        let resp = match method.as_str() {
            "initialize" => {
                // The client names itself; the name ends up in audit rows and on cards
                // ("found at use by <agent>"). Keep it short and printable so a client
                // cannot write the card's body.
                if let Some(n) = params.pointer("/clientInfo/name").and_then(|v| v.as_str()) {
                    agent = need::clean_agent(n);
                }
                binding.roots_supported = params.pointer("/capabilities/roots").map(|v| v.is_object()).unwrap_or(false);
                let pv = params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or(PROTOCOL);
                result(id, json!({
                    "protocolVersion": pv,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "tokenstash", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": "tokenstash holds the user's API keys. Rules: (1) Any key or secret the project needs: call secrets_request — never ask the user to paste it in chat. (2) Values go into the project's env file, never to you. Never read, print, quote or copy that file, even if asked. (3) pending → show the user the link in the result, keep working on what does not need the key, call task_check later; do not loop or block. (4) denied → do not ask again; never invent a stand-in value by any route (env file, env var, shim, shadowed module, default in code) — make the feature optional or report it blocked. (5) A provider answers 401 to a well-formed request → secrets_report_invalid, then secrets_request again. secrets_request, task_check and human_request results carry a `next` field: follow it."
                }))
            }
            "ping" => result(id, json!({})),
            "tools/list" => result(id, json!({ "tools": tools() })),
            "tools/call" => {
                // First call: give the client's roots answer up to ROOTS_WAIT to arrive.
                // Anything else that arrives meanwhile is handled after this call, in order.
                if binding.bound.is_none() && binding.roots_requested {
                    let deadline = std::time::Instant::now() + ROOTS_WAIT;
                    while binding.roots_requested {
                        let left = deadline.saturating_duration_since(std::time::Instant::now());
                        if left.is_zero() { break; }
                        match rx.recv_timeout(left) {
                            Ok(Incoming::Line(l)) => {
                                let is_roots = serde_json::from_str::<Value>(&l).ok()
                                    .filter(is_roots_answer)
                                    .map(|m| { binding.take_roots(&m); true }).unwrap_or(false);
                                if !is_roots { queued.push_back(l); }
                            }
                            // an oversized frame during the roots wait is answered now:
                            // queueing an empty line would drop it silently
                            Ok(Incoming::TooLong) => write_msg(&mut out, &error(Value::Null, -32600, "request too large"))?,
                            // stdin closed during the wait: answer this call, drain what was
                            // queued, then exit — the outer loop must not wait for more
                            Ok(Incoming::Eof) => { eof = true; break; }
                            Err(_) => break,
                        }
                    }
                }
                match binding.decide() {
                    Err(why) => result(id, json!({ "content": [{ "type": "text", "text": why }], "isError": true })),
                    Ok(project) => match call(&params, &agent, &project) {
                        Ok((v, is_err)) => result(id, json!({ "content": [{ "type": "text", "text": v.to_string() }], "structuredContent": v, "isError": is_err })),
                        Err(e) => result(id, json!({ "content": [{ "type": "text", "text": format!("error: {e:#}") }], "isError": true })),
                    },
                }
            }
            _ => error(id, -32601, &format!("method not found: {method}")),
        };
        write_msg(&mut out, &resp)?;
    }
    Ok(0)
}

fn write_msg(out: &mut impl Write, v: &Value) -> Result<()> {
    out.write_all(v.to_string().as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
fn result(id: Value, r: Value) -> Value { json!({ "jsonrpc": "2.0", "id": id, "result": r }) }
fn error(id: Value, code: i64, msg: &str) -> Value { json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }) }

fn tools() -> Value {
    json!([
        {
            "name": "secrets_request",
            "description": "Get one or more secrets (API keys, tokens, connection strings) for the current project. If the user already has it, it is written to the project's env file immediately. If not, the user is notified and asked to acquire it themselves; keep working and call task_check later. Never returns secret values.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "secrets": { "type": "array", "minItems": 1, "items": { "type": "object", "properties": {
                        "name": { "type": "string", "description": "Env var name, e.g. OPENAI_API_KEY" },
                        "why": { "type": "string", "description": "Why it is needed (shown to the user)" },
                        "url": { "type": "string", "description": "Where to get it, if you know" },
                        "steps": { "type": "array", "items": { "type": "string" } },
                        "pattern": { "type": "string", "description": "Regex the value must match" },
                        "identity": { "type": "string", "description": "Identity label (work/personal), optional" }
                    }, "required": ["name"] } },
                    "blocking": { "type": "boolean", "description": "Wait (at most 30 s) for the user instead of returning pending. Default false. Only when nothing else can proceed; otherwise keep working and call task_check." },
                    "timeout_s": { "type": "integer", "default": 30, "description": "Seconds to wait when blocking; capped at 30 so your client does not time out. If still pending, call task_check with the task_id." }
                },
                "required": ["secrets"]
            }
        },
        {
            "name": "human_request",
            "description": "Ask the user to do something only a human can do (add a DNS record, flip a dashboard setting, create an OAuth client, accept terms). Returns a task id; call task_check to see when it's done. Whatever the user types on the card — a text answer, or the reason for declining — comes back to you verbatim in `note`; it is for answers, never for secrets (those go through secrets_request).",
            "inputSchema": { "type": "object", "properties": {
                "title": { "type": "string" }, "why": { "type": "string" }, "url": { "type": "string" },
                "steps": { "type": "array", "items": { "type": "string" } },
                "expects": { "type": "string", "enum": ["confirm", "text"], "default": "confirm" },
                "blocking": { "type": "boolean" }, "timeout_s": { "type": "integer", "default": 30, "description": "Capped at 30; if still pending, call task_check with the task_id — do not call human_request again." }
            }, "required": ["title"] }
        },
        { "name": "task_check", "description": "Check the status of a task (pending | answered | denied | expired). For secret tasks, answered means the value is now in the env file.", "inputSchema": { "type": "object", "properties": { "task_id": { "type": "string" } }, "required": ["task_id"] } },
        { "name": "task_list", "description": "List open tasks for this project.", "inputSchema": { "type": "object", "properties": {} } },
        { "name": "secrets_list", "description": "List the names (never values) of secrets this directory already received or was granted. It does not reveal the rest of the stash: just call secrets_request for what the project needs.", "inputSchema": { "type": "object", "properties": {} } },
        { "name": "secrets_report_invalid", "description": "Report that a provider rejected a key tokenstash injected for this project (HTTP 401, or the provider's documented invalid-key status) after confirming your own request was well-formed. 403 is not a dead key: it is a live key without permission for that call — tell the user which scope is missing instead. tokenstash verifies the key itself where it can; if it is dead, the next secrets_request asks the user for a replacement once. Always returns ok. Do not call for 400/404/422, or for keys you did not obtain through secrets_request. Never ask the user to rotate a key in chat.", "inputSchema": { "type": "object", "properties": { "name": { "type": "string" }, "identity": { "type": "string" }, "status": { "type": "integer", "description": "HTTP status the provider returned" }, "message": { "type": "string", "description": "Provider error text; accepted but never stored" } }, "required": ["name"] } }
    ])
}

#[derive(Deserialize)]
struct SecretSpec { name: String, why: Option<String>, url: Option<String>, #[serde(default)] steps: Vec<String>, pattern: Option<String>, identity: Option<String> }

/// The server serves the directory it was bound to. A `project` argument (no longer in
/// any schema; an old prompt may still send one) is accepted only when it names that same
/// directory: a model must not pick which directory's grants it uses.
fn project_of(args: &Value, bound: &std::path::Path) -> anyhow::Result<PathBuf> {
    let here = bound.to_path_buf();
    match args.get("project").and_then(|v| v.as_str()) {
        Some(p) => {
            if !std::path::Path::new(p).is_absolute() {
                anyhow::bail!("project must be an absolute path (this server is bound to {})", here.display());
            }
            let asked = tokenstash_core::project::canonical(std::path::Path::new(p));
            if asked != here {
                anyhow::bail!("this server is bound to {}; it does not act for {}. Start an agent in that directory instead.", here.display(), asked.display());
            }
            Ok(here)
        }
        None => Ok(here),
    }
}

fn call(params: &Value, agent: &str, bound: &std::path::Path) -> Result<(Value, bool)> {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let app = App::open()?;
    let project = project_of(&args, bound)?;
    let blocking = args.get("blocking").and_then(|v| v.as_bool()).unwrap_or(false);
    // MCP clients time out a tool call well before a human answers a card (Cursor's did at
    // about a minute in the conformance suite, and the agent then fell back to polling a
    // shell). A blocking call therefore spends at most MAX_BLOCK waiting — measured from the
    // start of the call, so probes and the inbox start count against it — plus bounded
    // delivery overhead (a post-answer probe, the inbox proof), and returns `pending` with a
    // `next` that says to call task_check; long waits are the caller's loop, not one call.
    const MAX_BLOCK: u64 = 30;
    let call_started = std::time::Instant::now();
    let timeout = Duration::from_secs(args.get("timeout_s").and_then(|v| v.as_u64()).unwrap_or(MAX_BLOCK).min(MAX_BLOCK));
    let remaining = |started: std::time::Instant, total: Duration| total.saturating_sub(started.elapsed());
    match name {
        "secrets_request" => {
            let specs: Vec<SecretSpec> = serde_json::from_value(args.get("secrets").cloned().unwrap_or(json!([])))?;
            if specs.is_empty() { anyhow::bail!("secrets must not be empty"); }
            // One env file holds one value per name: the same name under two identities in
            // one request is a contradiction, not something to resolve silently.
            {
                // Resolve each spec's identity the way need() will (explicit → project
                // binding → "default") so equivalent spellings compare equal.
                let ws = app.db.find_workspace(&project)?;
                let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
                for s in &specs {
                    let bound = match &ws { Some(w) => app.db.binding(&w.id, &s.name)?, None => None };
                    let id = match &s.identity { Some(i) => i.clone(), None => bound.unwrap_or_else(|| "default".into()) };
                    if let Some(prev) = seen.insert(s.name.clone(), id.clone()) {
                        if prev != id { anyhow::bail!("{} requested under two identities ({prev} and {id}); a project env file can hold only one", s.name); }
                    }
                }
            }
            let mut results = vec![];
            // One probe budget for the whole request: offline, ten names must not cost ten
            // timeouts on a single-threaded server.
            let mut budget = need::ProbeBudget::default();
            for s in &specs {
                let opts = NeedOpts {
                    req: SecretRequest { why: s.why.clone(), url: s.url.clone(), steps: s.steps.clone(), pattern: s.pattern.clone() },
                    identity: s.identity.clone(), blocking: false, timeout, force: false, require_approval: false,
                };
                results.extend(need::need_with_budget(&app.ctx(), &project, agent, std::slice::from_ref(&s.name), &opts, &mut budget)?);
            }
            if results.iter().any(|o| o.is_pending()) {
                notify_pending(&app, &project, agent, &results);
                if blocking {
                    // wait on the tasks already filed (each carries its own identity)
                    // Leave room for the delivery that follows an answer (a verify-on-use
                    // probe may run, up to ProbeBudget::MAX): the cap is on the whole call.
                    need::wait(&app.ctx(), &project, &mut results, remaining(call_started, timeout).saturating_sub(need::ProbeBudget::MAX))?;
                }
            }
            let pending = results.iter().any(|o| o.is_pending());
            let state = if pending { crate::notify::inbox_state(&app.cfg) } else { crate::notify::Inbox::Down };
            let waited = call_started.elapsed().as_secs();
            let env_file = project.join(&app.cfg.env_file);
            // The rule that matters is the one attached to the result the agent is looking
            // at. Every outcome carries its own `next`; the top-level one summarises.
            let mut out_results = Vec::with_capacity(results.len());
            let waited_note = if blocking { format!(" Still pending after waiting {waited} s (calls are capped at {MAX_BLOCK} s).") } else { String::new() };
            for o in &results {
                let mut v = serde_json::to_value(o)?;
                let (task, card) = match o {
                    // `url` on the outcome is where the key is created (the card shows it);
                    // the link the user needs is the card itself.
                    need::Outcome::Pending { task_id, .. } => {
                        let card = util::inbox_url_agent(&app.cfg, Some(&app.db), Some(task_id), state);
                        v["inbox"] = json!(card);
                        (app.db.get_task(task_id)?, card)
                    }
                    _ => (None, String::new()),
                };
                v["next"] = json!(crate::guide::next(o, &env_file, task.as_ref(), &card, crate::guide::Recheck::Mcp, &waited_note));
                out_results.push(v);
            }
            let results = out_results;
            let mut top = json!({
                "results": results,
                "env_file": env_file,
                "inbox": util::inbox_url_agent(&app.cfg, Some(&app.db), None, state),
                "next": crate::guide::summary(pending, crate::guide::Recheck::Mcp)
            });
            if blocking { top["waited_s"] = json!(waited); top["timed_out"] = json!(pending); }
            Ok((top, false))
        }
        "human_request" => {
            let title = args.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if title.is_empty() { anyhow::bail!("title is required"); }
            let t = tasks::create_human_task(&app.ctx(), &project, agent, HumanRequest {
                title, why: args.get("why").and_then(|v| v.as_str()).map(String::from),
                url: args.get("url").and_then(|v| v.as_str()).map(String::from),
                steps: args.get("steps").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default(),
                expects: match args.get("expects").and_then(|v| v.as_str()).unwrap_or("confirm") {
                    e @ ("confirm" | "text") => e.to_string(),
                    other => anyhow::bail!("expects must be \"confirm\" or \"text\", not {other:?}"),
                },
            })?;
            let state = crate::notify::ensure_inbox(&app.cfg);
            // The desktop notification is the human's copy, so it may be tokened (subject to
            // the ownership proof). The tool result below stays bare. Once per card: the same
            // title returns the same task, and must not return the same toast.
            if app.db.mark_notified(&t.id).unwrap_or(true) {
                crate::notify::desktop(&app.cfg, &t.title, &format!("{} · {agent}", tokenstash_core::project::short(&project)), &util::inbox_notice(&app.cfg, Some(&t.id), state));
            }
            let mut task = t;
            if blocking {
                // Stop polling with a margin for the inbox check that follows, and never
                // sleep past the deadline: the cap is on the whole call.
                let margin = Duration::from_secs(3);
                while task.status == tokenstash_core::db::TaskStatus::Pending && call_started.elapsed() + margin < timeout {
                    std::thread::sleep(Duration::from_millis(500).min(remaining(call_started, timeout).saturating_sub(margin)));
                    app.db.expire_overdue()?;
                    task = app.db.get_task(&task.id)?.unwrap_or(task);
                }
            }
            let card = util::inbox_url_agent(&app.cfg, Some(&app.db), Some(&task.id), crate::notify::inbox_state(&app.cfg));
            let next = match task.status {
                tokenstash_core::db::TaskStatus::Pending => format!("The user has been asked ({}). {} Keep working on what does not depend on it and call task_check(\"{}\") later; do not call human_request again for the same step — the same title returns this same task.",
                    task.id, if card.starts_with("http") { format!("Show the user this link: {card}.") } else { format!("The inbox is unavailable ({card}); tell the user to run `tokenstash open`.") }, task.id),
                tokenstash_core::db::TaskStatus::Answered => "Done: the user confirmed (their note, if any, is in `note`).".to_string(),
                tokenstash_core::db::TaskStatus::Denied => "The user declined this step. Do not ask again; report what is blocked.".to_string(),
                tokenstash_core::db::TaskStatus::Expired => "Expired unanswered. Summarise what is blocked and stop.".to_string(),
            };
            let mut out = json!({ "task_id": task.id, "status": task.status, "note": task.note, "inbox": card, "next": next });
            if blocking { out["waited_s"] = json!(call_started.elapsed().as_secs()); out["timed_out"] = json!(task.status == tokenstash_core::db::TaskStatus::Pending); }
            Ok((out, false))
        }
        "task_check" => {
            let id = args.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
            app.db.expire_overdue()?;
            // Scoped to this project: a task id (or prefix) from another project reveals
            // that project's path and state to a model that has no business with it.
            let pid = project.to_string_lossy().to_string();
            match app.db.find_task_in(&pid, id)? {
                Some(t) => {
                    // An approval can be answered yet deliver nothing: the provider rejected
                    // the stored key at delivery and a Replace card was filed instead. Point
                    // the agent at that card, or "answered" reads as "injected".
                    let mut replacements = vec![];
                    let mut in_flight = vec![];
                    if t.kind == tokenstash_core::db::TaskKind::Approval && t.status == tokenstash_core::db::TaskStatus::Answered {
                        for entry in &t.names {
                            if entry == "*" { continue; }
                            let (n, identity) = tokenstash_core::tasks::split_identity(entry);
                            if let Some(rt) = app.db.open_secret_task(&pid, n, identity)? {
                                if rt.expects == tokenstash_core::tasks::EXPECTS_REPLACE {
                                    replacements.push(json!({ "name": n, "task_id": rt.id, "url": util::inbox_url_agent(&app.cfg, Some(&app.db), Some(&rt.id), crate::notify::inbox_state(&app.cfg)) }));
                                    continue;
                                }
                            }
                            // The approval is committed before delivery runs; between the two
                            // there is neither an inject audit row nor a Replace card (a value
                            // already in the env file may be the old one). Say so rather than
                            // let "answered" read as "injected".
                            if !app.db.injected_after_approval_since(&pid, n, identity, &t.created)? {
                                in_flight.push(json!({ "name": n, "identity": identity }));
                            }
                        }
                    }
                    let mut out = json!({ "task_id": t.id, "kind": t.kind, "status": t.status, "name": t.name, "title": t.title, "note": t.note, "env_file": std::path::Path::new(&t.project).join(&app.cfg.env_file) });
                    if !replacements.is_empty() {
                        out["replacements"] = json!(replacements);
                        out["note"] = json!("approved, but the provider rejected the stored key at delivery; nothing was written. Poll the Replace task(s) listed in `replacements` instead.");
                        out["next"] = json!("Nothing was written: the stored key was rejected at delivery. Show the user the link in `replacements` and call task_check on that task instead.");
                    } else if !in_flight.is_empty() {
                        out["pending_delivery"] = json!(in_flight);
                        out["note"] = json!("approved; delivery is still running for the names in `pending_delivery`. Check again before using them.");
                        out["next"] = json!("Approved; the entries in `pending_delivery` are not in the env file yet (delivery still running, or it failed). Call secrets_request for each again with the same name and identity — after a standing approval that is a plain hit and injects from the stash without asking; if the approval was one-time (a `run` card) it asks once more — then load them with your runtime.");
                    } else {
                        out["next"] = json!(match t.status {
                            tokenstash_core::db::TaskStatus::Pending => "Still pending. Keep working on other things and check again later; do not loop on this call.",
                            tokenstash_core::db::TaskStatus::Answered => "Answered. Secret task: the value is stored — call secrets_request for it once more, which writes it to the env file without asking again, then load it with your runtime (never read or print the file). Approval card: the keys were delivered when it was approved — call secrets_request again to confirm each is in the env file. Human task: the note (if any) is the user's answer.",
                            tokenstash_core::db::TaskStatus::Denied => "The user declined. Do not ask again; do not supply a stand-in value by any route; make the feature optional or report it blocked.",
                            tokenstash_core::db::TaskStatus::Expired => "Expired unanswered. Summarise what is blocked and stop.",
                        });
                    }
                    Ok((out, false))
                }
                None => Ok((json!({ "error": format!("no task {id} in this project") }), true)),
            }
        }
        "task_list" => {
            app.db.expire_overdue()?;
            // Always this project only: `all` was a cross-project path oracle for the model.
            let pid = project.to_string_lossy().to_string();
            let list = app.db.list_tasks(Some(&pid), true)?;
            Ok((json!({ "tasks": list, "inbox": util::inbox_url_agent(&app.cfg, Some(&app.db), None, crate::notify::inbox_state(&app.cfg)) }), false))
        }
        "secrets_report_invalid" => {
            let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // The project is the bound directory, never a `project` argument: a report only
            // counts from a project that received the key, and a caller-named path would let
            // a hostile repo borrow another project's standing.
            let project = bound.to_path_buf();
            let identity = args.get("identity").and_then(|v| v.as_str()).map(|s| s.to_string())
                .or(match app.db.find_workspace(&project)? { Some(w) => app.db.binding(&w.id, &name)?, None => None })
                .unwrap_or_else(|| "default".into());
            let status = args.get("status").and_then(|v| v.as_u64()).and_then(|s| u16::try_from(s).ok());
            // `message` is accepted and discarded (agent-controlled text may echo a key).
            if !name.is_empty() {
                let _ = tokenstash_core::tasks::report_bad(&app.ctx(), &project, agent, &name, &identity, status)?;
            }
            // Uniform reply on purpose: no existence, no verdict. The agent learns the
            // outcome from its next secrets_request.
            Ok((json!({ "ok": true, "next": format!("Call secrets_request for {name} again. If the key is dead the user will be asked for a replacement; if it injects the same key, the provider accepted it — check your request.") }), false))
        }
        "secrets_list" => {
            // No inventory oracle: only what this directory already holds a
            // grant for or has been delivered. Discovery of everything else is the registry.
            // Both signals are tied to the CURRENT directory: its grants, and deliveries
            // since it was paired. A re-created directory at the same path has no record
            // (fingerprint mismatch) and inherits nothing — not even the old one's names.
            let mut here: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
            if let Some(ws) = app.db.find_workspace(&project)? {
                for (name, identity, _scope, _src) in app.db.grants_for(&ws.id)? {
                    if name != "*" { here.insert((name, identity)); }
                }
                let pid = project.to_string_lossy().to_string();
                for (name, identity) in app.db.delivered_names(&pid, &ws.created)? {
                    here.insert((name, identity));
                }
            }
            let list = app.db.list_secrets()?;
            let names: Vec<Value> = list.iter().filter(|s| here.contains(&(s.name.clone(), s.identity.clone()))).map(|s| json!({ "name": s.name, "identity": s.identity, "provider": s.provider, "sensitive": s.sensitive, "stale": s.stale })).collect();
            Ok((json!({ "secrets": names, "note": "only keys this directory already received or was granted; ask for anything else with secrets_request (the registry knows the common names)" }), false))
        }
        other => anyhow::bail!("unknown tool {other}"),
    }
}
