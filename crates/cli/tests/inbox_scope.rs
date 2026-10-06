//! The inbox's two route families, driven over real HTTP against a real `tokenstash inbox`
//! process in a scratch home: a card link opens its card and nothing else, the session opens
//! everything, neither context leaks into the other, and a restart retires the session.
//!
//! Every process started here is a child of the test and is killed when the test ends; the
//! inbox is started by the test first so that `need` finds it and spawns nothing detached.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn tmp(name: &str) -> PathBuf {
    let p = Path::new("/tmp").join(format!("tokenstash-scope-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A port nothing holds right now. Tests in one binary run in parallel, and two scratch homes
/// on one port each see the other's inbox as foreign; the name-derived ports collided.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn home(name: &str, port: u16) -> PathBuf {
    let h = tmp(name);
    std::fs::write(h.join("config.toml"), format!("notifications = false\ninbox_port = {port}\nstash_backend = \"insecure-file\"\nverify_every = \"never\"\n")).unwrap();
    h
}

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_tokenstash"));
    c.env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE").env_remove("TOKENSTASH_AGENT");
    c
}

/// $HOME and the config root are scratch too: a confirmed action card makes the inbox write
/// agent configs under $HOME and an undo record under the config root.
fn homed(c: &mut Command, home: &Path) {
    c.env("TOKENSTASH_HOME", home).env("HOME", home.join("user-home")).env("XDG_CONFIG_HOME", home.join("user-home/.config"));
}

fn run(home: &Path, cwd: &Path, args: &[&str]) -> std::process::Output {
    let mut c = bin();
    homed(&mut c, home);
    c.args(args).current_dir(cwd).stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap()
}

/// An inbox process that dies with the test.
struct Inbox(Child);
impl Inbox {
    fn start(home: &Path, port: u16) -> Inbox {
        let mut c = bin();
        homed(&mut c, home);
        let child = c.args(["inbox", "--port", &port.to_string(), "--keep"])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let start = Instant::now();
        while http(port, "GET", "/verify?c=ready", &[], None).0 != 200 {
            assert!(start.elapsed() < Duration::from_secs(20), "the inbox did not come up on {port}");
            std::thread::sleep(Duration::from_millis(50));
        }
        Inbox(child)
    }
    fn stop(mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Drop for Inbox {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One request, one connection. Returns (status, Set-Cookie values, Location, body).
fn http(port: u16, method: &str, target: &str, cookies: &[(&str, &str)], body: Option<&str>) -> (u16, Vec<String>, Option<String>, String) {
    let mut s = match TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(500)) {
        Ok(s) => s,
        Err(_) => return (0, vec![], None, String::new()),
    };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    if !cookies.is_empty() {
        req.push_str(&format!("Cookie: {}\r\n", cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{b}", b.len()));
    } else {
        req.push_str("\r\n");
    }
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status: u16 = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).unwrap_or(0);
    let set_cookies = head.lines().filter_map(|l| l.strip_prefix("Set-Cookie: ").or_else(|| l.strip_prefix("set-cookie: "))).map(String::from).collect();
    let location = head.lines().find_map(|l| l.strip_prefix("Location: ").or_else(|| l.strip_prefix("location: "))).map(String::from);
    (status, set_cookies, location, body.to_string())
}

/// The `name=value` of a Set-Cookie line.
fn cookie_value(set: &[String], name: &str) -> Option<String> {
    set.iter().find_map(|c| c.strip_prefix(&format!("{name}=")).map(|rest| rest.split(';').next().unwrap().to_string()))
}

fn task_id(home: &Path, cwd: &Path, name: &str) -> String {
    let out = run(home, cwd, &["tasks", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    v.as_array().unwrap().iter().find(|t| t["name"] == name && t["status"] == "pending").unwrap_or_else(|| panic!("no pending card for {name}: {v}"))["id"].as_str().unwrap().to_string()
}

fn status_of(home: &Path, cwd: &Path, id: &str) -> String {
    let out = run(home, cwd, &["tasks", "--json", "--history"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    v.as_array().unwrap().iter().find(|t| t["id"] == id).map(|t| t["status"].as_str().unwrap().to_string()).unwrap_or_else(|| "gone".into())
}

/// The card link `need` printed for the agent: `/p/<id>?t=<id>.<mac>`.
fn card_link(out: &std::process::Output, port: u16) -> (String, String) {
    let text = String::from_utf8_lossy(&out.stdout);
    let url = text.split_whitespace().find(|w| w.starts_with(&format!("http://127.0.0.1:{port}/p/"))).unwrap_or_else(|| panic!("no card link in: {text}")).to_string();
    let (path, cred) = url.strip_prefix(&format!("http://127.0.0.1:{port}")).unwrap().split_once("?t=").unwrap();
    (path.to_string(), cred.to_string())
}

fn env_has(project: &Path, line: &str) -> bool {
    std::fs::read_to_string(project.join(".env.local")).map(|s| s.lines().any(|l| l == line)).unwrap_or(false)
}

#[test]
fn a_card_link_opens_its_card_and_nothing_else() {
    let port = free_port();
    let home = home("scope-home", port);
    let proj_a = tmp("scope-a");
    let proj_b = tmp("scope-b");
    // Files an older version would have read as credentials. Nothing reads them now.
    std::fs::write(home.join("inbox.token"), "1".repeat(64)).unwrap();
    std::fs::write(home.join("inbox.paste.token"), "2".repeat(64)).unwrap();
    let inbox = Inbox::start(&home, port);

    // Two cards in two directories, each with its own link.
    let need_a = run(&home, &proj_a, &["need", "OPENAI_API_KEY", "--agent", "ci"]);
    assert_eq!(need_a.status.code(), Some(10), "{}", String::from_utf8_lossy(&need_a.stderr));
    let need_b = run(&home, &proj_b, &["need", "RESEND_API_KEY", "--agent", "ci"]);
    assert_eq!(need_b.status.code(), Some(10));
    let a = task_id(&home, &proj_a, "OPENAI_API_KEY");
    let b = task_id(&home, &proj_b, "RESEND_API_KEY");
    let (path_a, cred_a) = card_link(&need_a, port);
    let (path_b, cred_b) = card_link(&need_b, port);
    assert_eq!(path_a, format!("/p/{a}"));
    assert!(cred_a.starts_with(&format!("{a}.")), "{cred_a}");
    let session = std::fs::read_to_string(home.join("inbox.session")).unwrap();
    let proof = std::fs::read_to_string(home.join("inbox.proof.key")).unwrap();
    let cap_key = std::fs::read_to_string(home.join("inbox.cap.key")).unwrap();
    for out in [&need_a, &need_b] {
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        for secret in [&session, &proof, &cap_key] {
            assert!(!text.contains(secret.as_str()), "agent output carries a key or the session: {text}");
        }
    }

    // The link opens its card: the credential becomes a cookie for that card's path only.
    let (st, set, loc, _) = http(port, "GET", &format!("{path_a}?t={cred_a}"), &[], None);
    assert_eq!(st, 303);
    assert_eq!(loc.as_deref(), Some(path_a.as_str()));
    let card_cookie = set.iter().find(|c| c.starts_with("tokenstash_card=")).expect("a card cookie");
    assert!(card_cookie.contains(&format!("Path=/p/{a}")), "{card_cookie}");
    assert!(!set.iter().any(|c| c.starts_with("tokenstash_inbox=")), "a card link never sets the session cookie");
    let jar_a = [("tokenstash_card", cred_a.as_str())];
    let (st, _, _, page) = http(port, "GET", &path_a, &jar_a, None);
    assert_eq!(st, 200);
    assert!(page.contains("OPENAI_API_KEY"), "{page}");
    assert!(page.contains(&format!("name=t value=\"{cred_a}\"")), "the CSRF field is the card credential: {page}");
    assert!(!page.contains(&session), "a scoped page never carries the session");
    assert!(!page.contains(&b), "a scoped page names no other card: {page}");

    // Nothing else opens with it: the sibling's route, the full routes, a prefix, a
    // re-addressed credential.
    let mac_a = cred_a.split_once('.').unwrap().1;
    for (target, why) in [
        (path_b.clone(), "the sibling's card"),
        (format!("/t/{a}"), "the full route for its own card"),
        ("/".to_string(), "the index"),
        (format!("/p/{}", &a[..a.len() - 1]), "a prefix of its own id"),
    ] {
        let (st, _, _, body) = http(port, "GET", &target, &jar_a, None);
        assert_eq!((st, body.as_str()), (404, ""), "{why} opened for a card cookie");
    }
    for (target, cred, why) in [
        (path_b.clone(), format!("{b}.{mac_a}"), "A's MAC re-addressed to B"),
        (path_b.clone(), cred_a.clone(), "A's credential on B's route"),
        (path_a.clone(), format!("{}.{mac_a}", &a[..a.len() - 1]), "a prefix id"),
        (path_a.clone(), format!("{a}.{}", "0".repeat(64)), "a forged MAC"),
        (path_a.clone(), cap_key.clone(), "the capability key itself"),
        (path_a.clone(), proof.clone(), "the proof key"),
        (path_a.clone(), "1".repeat(64), "the legacy full token"),
        (path_a.clone(), "2".repeat(64), "the legacy paste token"),
        (format!("/t/{a}"), cred_a.clone(), "a card credential on a full route"),
        ("/".to_string(), "2".repeat(64), "the legacy paste token on the index"),
    ] {
        let (st, set, _, body) = http(port, "GET", &format!("{target}?t={cred}"), &[], None);
        assert_eq!(st, 404, "{why} authenticated");
        assert!(set.is_empty(), "{why} set a cookie: {set:?}");
        assert!(body.contains("no longer valid"), "{why}: an explicit credential that fails gets the recovery page, not a bare 404: {body}");
        assert!(!body.contains(&a) && !body.contains(&b), "the recovery page names no card: {body}");
    }
    // ...and the same with a full session in the browser: an explicit bad credential still
    // fails, and the card's scoped route is still not served to the session.
    let jar_full = [("tokenstash_inbox", session.as_str())];
    let (st, _, _, body) = http(port, "GET", &format!("{path_b}?t={b}.{mac_a}"), &jar_full, None);
    assert_eq!(st, 404);
    assert!(body.contains("no longer valid"), "{body}");
    let (st, _, _, body) = http(port, "GET", &path_a, &jar_full, None);
    assert_eq!((st, body.as_str()), (404, ""), "a full session is not consulted on a scoped route");

    // POSTs: a card cookie answers its own card only, with its own CSRF field.
    let post = |target: &str, cookies: &[(&str, &str)], body: &str| http(port, "POST", target, cookies, Some(body));
    let (st, _, _, _) = post(&path_b, &jar_a, &format!("action=deny&t={cred_a}"));
    assert_eq!(st, 404, "deny on the sibling");
    assert_eq!(status_of(&home, &proj_b, &b), "pending");
    let (st, _, _, _) = post(&path_b, &jar_a, &format!("value=re_evilevilevil1234&skip_check=1&t={cred_a}"));
    assert_eq!(st, 404, "paste into the sibling");
    assert!(!env_has(&proj_b, "RESEND_API_KEY=re_evilevilevil1234"));
    let (st, _, _, _) = post(&format!("/t/{a}"), &jar_a, &format!("value=sk-viafullroute1234567&skip_check=1&t={cred_a}"));
    assert_eq!(st, 404, "a card cookie on the full route");
    let (st, _, _, _) = post(&path_a, &jar_a, "value=sk-nocsrf12345678901234&skip_check=1");
    assert_eq!(st, 404, "no CSRF field");
    let (st, _, _, _) = post(&path_a, &jar_a, &format!("value=sk-wrongcsrf1234567890&skip_check=1&t={session}"));
    assert_eq!(st, 404, "the session as CSRF field for a card cookie");
    assert_eq!(status_of(&home, &proj_a, &a), "pending");
    // The legitimate answer, from the card link.
    let (st, _, loc, _) = post(&path_a, &jar_a, &format!("value=sk-fromthecardlink1234567&skip_check=1&t={cred_a}"));
    assert_eq!(st, 303);
    assert!(loc.as_deref().unwrap_or("").starts_with(&format!("{path_a}?m=")), "stays on its own route: {loc:?}");
    assert!(env_has(&proj_a, "OPENAI_API_KEY=sk-fromthecardlink1234567"));
    assert_eq!(status_of(&home, &proj_a, &a), "answered");
    let (st, _, _, page) = http(port, "GET", loc.as_deref().unwrap(), &jar_a, None);
    assert_eq!(st, 200);
    assert!(page.contains("Stored OPENAI_API_KEY") && page.contains("This task is answered"), "{page}");

    // A card that reaches another directory: B's card for a key A now holds a grant for.
    let need_b2 = run(&home, &proj_b, &["need", "OPENAI_API_KEY", "--agent", "ci"]);
    // A stash hit in an unpaired directory is an approval card, not a paste card; its link
    // shows the card and can neither approve nor close it.
    let approval = task_id_kind(&home, &proj_b, "approval");
    let (path_ap, cred_ap) = card_link(&need_b2, port);
    assert_eq!(path_ap, format!("/p/{approval}"));
    let jar_ap = [("tokenstash_card", cred_ap.as_str())];
    let (st, _, _, page) = http(port, "GET", &path_ap, &jar_ap, None);
    assert_eq!(st, 200);
    assert!(page.contains("your own inbox link") && page.contains("value=notify") && !page.contains("value=allow"), "{page}");
    for action in ["allow", "allow_broad", "deny"] {
        let (st, _, _, page) = post(&path_ap, &jar_ap, &format!("action={action}&t={cred_ap}"));
        assert_eq!(st, 200, "{action}");
        assert!(page.contains("your own inbox link"), "{action}: {page}");
        assert_eq!(status_of(&home, &proj_b, &approval), "pending", "{action} changed the card");
    }
    assert!(!proj_b.join(".env.local").exists() || !env_has(&proj_b, "OPENAI_API_KEY=sk-fromthecardlink1234567"));

    // A human card in B: a note posted from A's card session is refused, nothing recorded.
    let ask = run(&home, &proj_b, &["ask", "Flip the dashboard switch", "--expects", "text", "--agent", "ci"]);
    assert_eq!(ask.status.code(), Some(10), "{}", String::from_utf8_lossy(&ask.stderr));
    let human = task_id_kind(&home, &proj_b, "human");
    let (st, _, _, _) = post(&format!("/p/{human}"), &jar_a, &format!("action=done&note=forged+answer&t={cred_a}"));
    assert_eq!(st, 404, "a note on a foreign human card");
    let (st, _, _, _) = post(&format!("/p/{human}"), &jar_a, &format!("action=deny&note=forged+reason&t={cred_a}"));
    assert_eq!(st, 404, "a decline on a foreign human card");
    assert_eq!(status_of(&home, &proj_b, &human), "pending");

    // `need --json`: every pending result carries its own scoped link; the top-level field
    // is the bare index; nothing privileged and no key in the output.
    let json = run(&home, &proj_b, &["need", "GROQ_API_KEY", "--agent", "ci", "--json"]);
    let text = String::from_utf8_lossy(&json.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["inbox"].as_str().unwrap(), format!("http://127.0.0.1:{port}/"), "taskless field is bare");
    let r = v["results"].as_array().unwrap().iter().find(|r| r["status"] == "pending").expect("a pending result");
    let jlink = r["inbox"].as_str().unwrap().to_string();
    let jid = r["task_id"].as_str().unwrap();
    assert!(jlink.starts_with(&format!("http://127.0.0.1:{port}/p/{jid}?t={jid}.")), "{jlink}");
    assert!(r["url"].as_str().unwrap_or("").starts_with("https://"), "the provider URL is retained: {r}");
    for secret in [&session, &proof, &cap_key] {
        assert!(!text.contains(secret.as_str()), "need --json carries a key or the session: {text}");
    }
    let (jpath, jcred) = jlink.strip_prefix(&format!("http://127.0.0.1:{port}")).unwrap().split_once("?t=").unwrap();
    let (st, set, _, _) = http(port, "GET", &format!("{jpath}?t={jcred}"), &[], None);
    assert_eq!(st, 303);
    assert!(cookie_value(&set, "tokenstash_card").is_some() && cookie_value(&set, "tokenstash_inbox").is_none());
    let (st, _, _, page) = http(port, "GET", jpath, &[("tokenstash_card", jcred)], None);
    assert_eq!(st, 200);
    assert!(page.contains("GROQ_API_KEY"), "{page}");

    // The full session: sets its cookie at `/`, opens the index and the full route, and is
    // not replaced by a card link followed afterwards.
    let (st, set, _, _) = http(port, "GET", &format!("/?t={session}"), &[], None);
    assert_eq!(st, 303);
    assert_eq!(cookie_value(&set, "tokenstash_inbox").as_deref(), Some(session.as_str()));
    let (st, _, _, index) = http(port, "GET", "/", &jar_full, None);
    assert_eq!(st, 200);
    assert!(index.contains(&approval) && index.contains(&b), "the index lists every card for the session: {index}");
    let (st, set, _, _) = http(port, "GET", &format!("{path_b}?t={cred_b}"), &jar_full, None);
    assert_eq!(st, 303);
    assert!(!set.iter().any(|c| c.starts_with("tokenstash_inbox=")), "a card link leaves the session cookie alone: {set:?}");
    assert_eq!(cookie_value(&set, "tokenstash_card").as_deref(), Some(cred_b.as_str()));
    // Both cookies, card still pending: the scoped route is not elevated by the session,
    // never renders the session as its CSRF field, refuses approve/deny, and stays scoped
    // across a reload, while the full route for the same card offers Allow.
    let jar_both = [("tokenstash_card", cred_ap.as_str()), ("tokenstash_inbox", session.as_str())];
    for _ in 0..2 {
        let (st, _, _, page) = http(port, "GET", &path_ap, &jar_both, None);
        assert_eq!(st, 200);
        assert!(!page.contains("value=allow"), "elevated by the session: {page}");
        assert!(!page.contains(&session), "the session rendered on a scoped page: {page}");
        // A pending approval card offers a scoped session one form, the button that sends the
        // person their own link; whatever CSRF field a scoped page carries is the card credential.
        assert!(!page.contains("name=t value=\"") || page.contains(&format!("name=t value=\"{cred_ap}\"")), "{page}");
        assert!(page.contains("your own inbox link") && page.contains("value=notify"), "sends the person their own link: {page}");
    }
    for action in ["allow", "allow_broad", "deny"] {
        let (st, _, _, page) = post(&path_ap, &jar_both, &format!("action={action}&t={cred_ap}"));
        assert_eq!(st, 200, "{action}");
        assert!(page.contains("your own inbox link"), "{action}: {page}");
        let (st, _, _, _) = post(&path_ap, &jar_both, &format!("action={action}&t={session}"));
        assert_eq!(st, 404, "{action} with the session as CSRF on the scoped route");
        assert_eq!(status_of(&home, &proj_b, &approval), "pending", "{action} changed the card");
    }
    let (st, _, _, page) = http(port, "GET", &format!("/t/{approval}"), &jar_full, None);
    assert_eq!(st, 200);
    assert!(page.contains("value=allow"), "the session may approve: {page}");
    assert!(page.contains(&format!("name=t value=\"{session}\"")));
    let (st, _, _, _) = post(&format!("/t/{approval}"), &jar_full, &format!("action=allow&t={session}"));
    assert_eq!(st, 303);
    assert_eq!(status_of(&home, &proj_b, &approval), "answered");
    assert!(env_has(&proj_b, "OPENAI_API_KEY=sk-fromthecardlink1234567"), "approved and delivered");
    let (st, _, _, page) = http(port, "GET", &path_ap, &jar_both, None);
    assert_eq!(st, 200);
    assert!(page.contains("This task is answered") && !page.contains(&session), "still scoped after approval: {page}");

    // /verify is answered from the proof key; neither the session nor a card credential
    // produces that answer, so a captured link cannot pass as the inbox.
    let (st, _, _, got) = http(port, "GET", "/verify?c=nonce-1", &[], None);
    assert_eq!(st, 200);
    assert_eq!(got.trim(), hmac_hex(&proof, "tokenstash-inbox-verify-v1:nonce-1"));
    assert_ne!(got.trim(), hmac_hex(&session, "tokenstash-inbox-verify-v1:nonce-1"));
    assert_ne!(got.trim(), hmac_hex(&proof, "nonce-1"), "the domain tag is part of the message");
    assert_ne!(got.trim(), hmac_hex(&"1".repeat(64), "tokenstash-inbox-verify-v1:nonce-1"), "the legacy token proves nothing");

    // Restart: the session is retired, the proof key and card links survive.
    inbox.stop();
    let inbox = Inbox::start(&home, port);
    let session2 = std::fs::read_to_string(home.join("inbox.session")).unwrap();
    assert_ne!(session2, session);
    assert_eq!(std::fs::read_to_string(home.join("inbox.proof.key")).unwrap(), proof);
    let (st, _, _, body) = http(port, "GET", &format!("/?t={session}"), &[], None);
    assert_eq!(st, 404);
    assert!(body.contains("no longer valid") && body.contains("Send the link to my desktop") && !body.contains("tokenstash open"), "the old link says how to recover, without a terminal: {body}");
    let (st, _, _, body) = http(port, "GET", "/", &jar_full, None);
    assert_eq!((st, body.as_str()), (404, ""), "the old cookie is dead");
    let (st, _, _, _) = post(&format!("/t/{b}"), &jar_full, &format!("action=deny&t={session}"));
    assert_eq!(st, 404);
    assert_eq!(status_of(&home, &proj_b, &b), "pending");
    let (st, _, _, got) = http(port, "GET", "/verify?c=nonce-2", &[], None);
    assert_eq!(st, 200);
    assert_eq!(got.trim(), hmac_hex(&proof, "tokenstash-inbox-verify-v1:nonce-2"), "same proof key after the restart");
    let jar_b = [("tokenstash_card", cred_b.as_str())];
    let (st, _, _, page) = http(port, "GET", &path_b, &jar_b, None);
    assert_eq!(st, 200, "a card link printed before the restart still opens its card");
    assert!(page.contains("RESEND_API_KEY"));
    let jar_full2 = [("tokenstash_inbox", session2.as_str())];
    let (st, _, _, _) = http(port, "GET", "/", &jar_full2, None);
    assert_eq!(st, 200, "the new session works");
    // A losing bind (the port is held) does not rotate the live session.
    let loser = run(&home, &proj_a, &["inbox", "--port", &port.to_string()]);
    assert!(String::from_utf8_lossy(&loser.stderr).contains("already running"), "{}", String::from_utf8_lossy(&loser.stderr));
    assert_eq!(std::fs::read_to_string(home.join("inbox.session")).unwrap(), session2, "a failed bind must not retire the running inbox's session");
    let (st, _, _, _) = http(port, "GET", "/", &jar_full2, None);
    assert_eq!(st, 200);
    inbox.stop();
}

fn task_id_kind(home: &Path, cwd: &Path, kind: &str) -> String {
    let out = run(home, cwd, &["tasks", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    v.as_array().unwrap().iter().find(|t| t["kind"] == kind && t["status"] == "pending").unwrap_or_else(|| panic!("no pending {kind} card: {v}"))["id"].as_str().unwrap().to_string()
}

fn hmac_hex(key: &str, msg: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key.as_bytes()).unwrap();
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// An action card an agent filed (here: forget a key) runs only on the person's confirm, from
/// their own session. The agent's link can show it, decline it and ask for the person's link
/// to be sent to the desktop; it cannot confirm it.
#[test]
fn an_action_card_runs_only_on_the_persons_confirm() {
    let port = free_port();
    let home = home("action-home", port);
    let proj = tmp("action-proj");
    let inbox = Inbox::start(&home, port);
    let need = run(&home, &proj, &["need", "OPENAI_API_KEY", "--agent", "ci"]);
    let (path, cred) = card_link(&need, port);
    let jar = [("tokenstash_card", cred.as_str())];
    assert_eq!(http(port, "POST", &path, &jar, Some(&format!("value=sk-proj-actioncard0123456789abcd&skip_check=1&t={cred}"))).0, 303);
    assert_eq!(run(&home, &proj, &["need", "OPENAI_API_KEY"]).status.code(), Some(0));

    let out = run(&home, &proj, &["forget", "OPENAI_API_KEY", "--why", "the user asked"]);
    assert_eq!(out.status.code(), Some(10), "{}", String::from_utf8_lossy(&out.stderr));
    let tasks: serde_json::Value = serde_json::from_slice(&run(&home, &proj, &["tasks", "--json"]).stdout).unwrap();
    let id = tasks.as_array().unwrap().iter().find(|t| t["expects"] == "action:forget").unwrap()["id"].as_str().unwrap().to_string();
    let (apath, acred) = card_link(&out, port);
    assert_eq!(apath, format!("/p/{id}"));
    let ajar = [("tokenstash_card", acred.as_str())];
    let (st, _, _, page) = http(port, "GET", &apath, &ajar, None);
    assert!(st == 200 && page.contains("is deleted from your stash") && page.contains("value=notify") && !page.contains("value=done"), "{page}");
    let (st, _, _, page) = http(port, "POST", &apath, &ajar, Some(&format!("action=done&t={acred}")));
    assert!(st == 200 && page.contains("your own inbox link"), "{page}");
    let (st, _, _, page) = http(port, "POST", &apath, &ajar, Some(&format!("action=notify&t={acred}")));
    assert!(st == 200 && page.contains("turned off"), "notifications are off in this home: {page}");
    assert_eq!(status_of(&home, &proj, &id), "pending");
    assert_eq!(run(&home, &proj, &["need", "OPENAI_API_KEY"]).status.code(), Some(0), "nothing was forgotten from the agent's link");

    let session = std::fs::read_to_string(home.join("inbox.session")).unwrap();
    let full = [("tokenstash_inbox", session.as_str())];
    let (st, _, loc, _) = http(port, "POST", &format!("/t/{id}"), &full, Some(&format!("action=done&t={session}")));
    assert_eq!(st, 303);
    assert!(loc.unwrap_or_default().contains("Forgot"));
    assert_eq!(status_of(&home, &proj, &id), "answered");
    assert_eq!(run(&home, &proj, &["need", "OPENAI_API_KEY"]).status.code(), Some(10), "forgotten: the next request asks for it again");
    // Greptile on #68: confirming the same card again runs nothing. Store the key again,
    // then confirm the old forget card a second time: the new key stays.
    let again = task_id(&home, &proj, "OPENAI_API_KEY");
    let (st, _, _, page) = http(port, "POST", &format!("/t/{again}"), &full, Some(&format!("value=sk-proj-storedagain0123456789abc&skip_check=1&t={session}")));
    assert_eq!(st, 303, "{page}");
    let (st, _, _, page) = http(port, "POST", &format!("/t/{id}"), &full, Some(&format!("action=done&t={session}")));
    assert!(st == 200 && page.contains("already answered"), "{page}");
    assert_eq!(run(&home, &proj, &["need", "OPENAI_API_KEY"]).status.code(), Some(0), "the key stored after the first confirm is still there");

    // Greptile on #68: an MCP card filed while agents are in explicit mode says, and does,
    // what it takes: back to automatic mode, with the server.
    std::fs::write(home.join("config.toml"), format!("{}agent_mode = \"explicit\"\n", std::fs::read_to_string(home.join("config.toml")).unwrap())).unwrap();
    std::fs::create_dir_all(home.join("user-home/.codex")).unwrap();
    assert_eq!(run(&home, &proj, &["init", "--mcp"]).status.code(), Some(10));
    let tasks: serde_json::Value = serde_json::from_slice(&run(&home, &proj, &["tasks", "--json"]).stdout).unwrap();
    let mcp = tasks.as_array().unwrap().iter().find(|t| t["expects"] == "action:mcp").unwrap()["id"].as_str().unwrap().to_string();
    let (st, _, _, page) = http(port, "GET", &format!("/t/{mcp}"), &full, None);
    assert!(st == 200 && page.contains("switches back to loading it on their own"), "{page}");
    let (st, _, _, page) = http(port, "POST", &format!("/t/{mcp}"), &full, Some(&format!("action=done&t={session}")));
    assert_eq!(st, 303, "{page}");
    let cfg = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(cfg.contains("mcp = true") && !cfg.contains("agent_mode = \"explicit\""), "{cfg}");
    assert!(std::fs::read_to_string(home.join("user-home/.codex/config.toml")).unwrap().contains("[mcp_servers.tokenstash]"));
    inbox.stop();
}

/// Greptile on #65: Deny on an approval card goes through the same locked comparison with
/// what the page showed as Allow does. A card that grew after the page loaded is refused and
/// stays open, so a key the agent added since is not declined unseen.
#[test]
fn denying_an_approval_card_that_grew_since_the_page_loaded_is_refused() {
    let port = free_port();
    let home = home("deny-grown-home", port);
    let proj_a = tmp("deny-grown-a");
    let proj_b = tmp("deny-grown-b");
    let inbox = Inbox::start(&home, port);
    for (name, value) in [("OPENAI_API_KEY", "sk-proj-denygrown0123456789abcdef"), ("GROQ_API_KEY", "gsk_denygrown0123456789abcdefghij")] {
        let need = run(&home, &proj_a, &["need", name, "--agent", "ci"]);
        let (path, cred) = card_link(&need, port);
        assert_eq!(http(port, "POST", &path, &[("tokenstash_card", cred.as_str())], Some(&format!("value={value}&skip_check=1&t={cred}"))).0, 303, "{name}");
    }
    // B asks for one of them: a pairing card, which the person opens.
    assert_eq!(run(&home, &proj_b, &["need", "OPENAI_API_KEY", "--agent", "ci"]).status.code(), Some(10));
    let approval = task_id_kind(&home, &proj_b, "approval");
    let session = std::fs::read_to_string(home.join("inbox.session")).unwrap();
    let full = [("tokenstash_inbox", session.as_str())];
    let (st, _, _, page) = http(port, "GET", &format!("/t/{approval}"), &full, None);
    let seen = "OPENAI_API_KEY@default";
    assert!(st == 200 && page.contains(&format!("name=seen value='{seen}'")), "{page}");
    // The agent asks for the other key before the person answers: the same card grows.
    assert_eq!(run(&home, &proj_b, &["need", "GROQ_API_KEY", "--agent", "ci"]).status.code(), Some(10));
    assert_eq!(task_id_kind(&home, &proj_b, "approval"), approval, "the card grew");
    let (st, _, _, page) = http(port, "POST", &format!("/t/{approval}"), &full, Some(&format!("action=deny&seen={seen}&t={session}")));
    assert!(st == 200 && page.contains("changed since you read it"), "{page}");
    assert_eq!(status_of(&home, &proj_b, &approval), "pending", "a Deny on what the page showed does not close the grown card");
    // Decided on the card as it is now, the Deny lands.
    let (st, _, _, page) = http(port, "POST", &format!("/t/{approval}"), &full, Some(&format!("action=deny&seen={seen},GROQ_API_KEY@default&t={session}")));
    assert_eq!(st, 303, "{page}");
    assert_eq!(status_of(&home, &proj_b, &approval), "denied");
    inbox.stop();
}
