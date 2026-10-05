//! Credentials for the localhost inbox: the ownership-proof key, the browser session, the
//! per-card capability, and constant-time comparison.
//!
//! # Why the inbox needs a credential at all
//!
//! Binding 127.0.0.1 is not a security boundary. Every process on the machine can reach
//! the port, and so can any web page the user happens to visit: a cross-origin `<form>`
//! POST to `http://127.0.0.1:<port>/` is not blocked by CORS (the request is sent; only
//! the *response* is hidden, and the attacker does not need the response). Without a
//! credential, anything that can make an HTTP request can answer a task — which means it
//! can store a value of its choosing under a real key name and approve its own trust
//! gates. The credentials below close that.
//!
//! # Three keys, three jobs
//!
//! - **The proof key** (`inbox.proof.key`, persistent) answers `/verify`. Before the CLI
//!   reuses "something is listening on the inbox port", it has to know the listener is
//!   *our* inbox for *this* `TOKENSTASH_HOME`. It must not find that out by sending a
//!   credential — a hostile squatter on the port would simply collect it. Instead the CLI
//!   sends a fresh nonce and the server answers `HMAC-SHA256(proof, nonce)`: only a process
//!   that already holds the proof key can produce it. The proof key is never put in a URL,
//!   a cookie or a form field, so a link captured from a chat log, a notification tray or a
//!   browser history never lets its holder pass as the inbox.
//! - **The browser session** (`inbox.session`, rotated every time an inbox process binds
//!   the port) is the full credential: it can paste, approve, and close any card. It
//!   reaches a person through the desktop notification, `tokenstash open` and a terminal.
//!   Rotating it on startup means a URL that was valid before the inbox last restarted is
//!   dead: whoever captured it cannot use it against the inbox that is running now.
//! - **The capability key** (`inbox.cap.key`, persistent) signs one link per card. The
//!   agent is the one who tells the human "you need to paste OPENAI_API_KEY", so the most
//!   useful thing it can hand over is a link that works. That link carries
//!   `<task id>.<HMAC-SHA256(cap, task)>`: it opens *that* card and nothing else. It cannot
//!   list other cards, cannot answer or decline a sibling, cannot approve, and holding it
//!   says nothing about any other card's link. The key itself never crosses HTTP.
//!
//! A full-scope cookie is never downgraded by a later card link, so one `tokenstash open`
//! per browser makes every agent link fully capable from then on. `inbox_links = "full"` in
//! config opts into handing the session to agent surfaces on machines where that
//! trade-off is wanted.
//!
//! The pre-0.2.1 files (`inbox.token`, `inbox.paste.token`) are not read for anything:
//! a link minted from them fails closed, and the person gets a fresh one from the next
//! notification or `tokenstash open`.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use tokenstash_core::db::Task;
use tokenstash_core::fsutil;

/// Name of the session cookie set on the first credentialed visit.
pub const COOKIE: &str = "tokenstash_inbox";
/// Name of the per-card capability cookie, set at `Path=/p/<id>` for that card alone.
pub const CAP_COOKIE: &str = "tokenstash_card";

/// 32 bytes, hex-encoded to 64 characters.
const TOKEN_BYTES: usize = 32;
const TOKEN_CHARS: usize = TOKEN_BYTES * 2;

/// Longest `?c=` challenge `/verify` will answer. Bounds the work an unauthenticated
/// caller can ask for.
pub const MAX_CHALLENGE: usize = 128;

/// Domain separators: each key signs one kind of thing, and a MAC for one purpose is never
/// a valid MAC for another even if the keys were ever confused.
const CAP_DOMAIN: &str = "tokenstash-inbox-task-capability-v1";
/// `/verify` answers `HMAC(proof, "tokenstash-inbox-verify-v1:" || challenge)`. A plain
/// prefix, so a shell script can reproduce it with one `hmac` call.
pub const VERIFY_DOMAIN: &str = "tokenstash-inbox-verify-v1:";

pub fn proof_key_path() -> PathBuf {
    tokenstash_core::config::config_dir().join("inbox.proof.key")
}

pub fn cap_key_path() -> PathBuf {
    tokenstash_core::config::config_dir().join("inbox.cap.key")
}

pub fn session_path() -> PathBuf {
    tokenstash_core::config::config_dir().join("inbox.session")
}

/// What a presented credential is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Everything: paste, approve, close any card.
    Full,
    /// One card, by exact id: open it, answer it, decline it. Nothing else.
    Task(String),
}

/// What the server holds while it runs.
#[derive(Debug, Clone)]
pub struct Tokens {
    session: String,
    cap_key: String,
    proof: String,
}

impl Tokens {
    /// For a server that has just bound the port: a fresh session, and the two persistent
    /// keys (created on first use). Only a process that owns the port may call this —
    /// rotating the session from anywhere else would cut off the inbox that is serving.
    pub fn start() -> Result<Self> {
        let proof = ensure_proof_key()?;
        let cap_key = ensure_cap_key()?;
        let session = rotate_session()?;
        Ok(Self { session, cap_key, proof })
    }

    /// The session itself. The inbox hands it, as a cookie, to the person on another of their
    /// devices (remote access); nothing else outside this module reads it.
    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn proof(&self) -> &str {
        &self.proof
    }

    /// Classify a presented credential (cookie value, `?t=`, or CSRF field). The session is
    /// compared in constant time; a card credential is checked against the card it names,
    /// which the caller looks up by exact id — nothing here is a prefix.
    pub fn scope_of(&self, presented: &str, lookup: impl FnOnce(&str) -> Option<Task>) -> Option<Scope> {
        if ct_eq(presented, &self.session) {
            return Some(Scope::Full);
        }
        let (id, mac) = split_task_credential(presented)?;
        let task = lookup(id)?;
        if task.id != id {
            return None;
        }
        ct_eq(mac, &task_capability(&self.cap_key, &task)).then_some(Scope::Task(task.id))
    }

    /// The credential a card's own link carries.
    #[cfg(test)]
    pub fn task_credential(&self, task: &Task) -> String {
        task_credential(&self.cap_key, task)
    }
}

/// `<task id>.<64 hex>`, or nothing. The id part is validated like every task id, so a
/// malformed credential is refused before any lookup.
fn split_task_credential(s: &str) -> Option<(&str, &str)> {
    let (id, mac) = s.split_once('.')?;
    let id_ok = !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    (id_ok && is_token(mac)).then_some((id, mac))
}

/// The capability for one card: HMAC over the card's immutable identity (id, directory,
/// creation time), so a capability minted for one card never opens another, even one that
/// later reuses the id.
pub fn task_capability(cap_key: &str, task: &Task) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cap_key.as_bytes()).expect("hmac accepts any key length");
    for part in [CAP_DOMAIN, &task.id, &task.project, &task.created] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    hex(&mac.finalize().into_bytes())
}

pub fn task_credential(cap_key: &str, task: &Task) -> String {
    format!("{}.{}", task.id, task_capability(cap_key, task))
}

/// The ownership-proof key for this `TOKENSTASH_HOME`, creating it on first use. Persisted
/// on purpose: the inbox exits after 30 idle minutes and respawns on demand, and the CLI has
/// to recognise the respawned one. Lives at `$TOKENSTASH_HOME/inbox.proof.key`, written
/// 0600 and atomically, like every other file in this project that holds a credential.
pub fn ensure_proof_key() -> Result<String> {
    ensure_key_at(&proof_key_path())
}

/// The capability-signing key, same lifecycle as [`ensure_proof_key`]. Both the inbox and
/// the CLI that prints links read it; neither ever sends it.
pub fn ensure_cap_key() -> Result<String> {
    ensure_key_at(&cap_key_path())
}

/// The browser session as last minted by an inbox process, if any. The CLI reads it to
/// build the links a person clicks; it never mints one.
pub fn read_session() -> Option<String> {
    read_token_at(&session_path())
}

/// A fresh browser session, replacing whatever was there. Called by the inbox process once
/// it holds the port, and by nothing else.
pub fn rotate_session() -> Result<String> {
    let path = session_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let token = fresh_token();
    fsutil::write_atomic_private(&path, &token)?;
    Ok(token)
}

fn ensure_key_at(path: &Path) -> Result<String> {
    let path = path.to_path_buf();
    if let Some(t) = read_token_at(&path) {
        return Ok(t);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Two commands can race to create the key; the loser must adopt the winner's value,
    // not overwrite it, or links already printed stop working.
    fsutil::with_lock(&path, || {
        if let Some(t) = read_token_at(&path) {
            return Ok(t);
        }
        let token = fresh_token();
        fsutil::write_atomic_private(&path, &token)?;
        Ok(token)
    })
}

fn fresh_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex(&bytes)
}

fn is_token(s: &str) -> bool {
    s.len() == TOKEN_CHARS && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A token as already stored, or `None` if there is no well-formed one yet.
fn read_token_at(path: &Path) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim().to_string();
    is_token(&s).then_some(s)
}

/// The answer to a `/verify?c=<challenge>` ownership probe:
/// `HMAC-SHA256(proof, VERIFY_DOMAIN || challenge)`, hex. Keyed with the key's ASCII bytes
/// exactly as they appear in the file, so any client can reproduce it without knowing an
/// encoding convention.
pub fn verify_response(proof: &str, challenge: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(proof.as_bytes()).expect("hmac accepts any key length");
    mac.update(VERIFY_DOMAIN.as_bytes());
    mac.update(challenge.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Compare two credentials without leaking, through timing, how long a prefix matched.
/// Lengths are compared normally: the token length is fixed and public, only the bytes are
/// secret.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// A fresh nonce for a `/verify` probe.
pub fn challenge() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `TOKENSTASH_HOME` is process-global, so every test that sets it shares this lock.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenstash_core::db::{TaskKind, TaskStatus};

    fn tmp_home(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tokenstash-inbox-auth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    pub(crate) fn card(id: &str, project: &str, created: &str) -> Task {
        Task {
            id: id.into(), kind: TaskKind::Secret, project: project.into(), agent: "agent".into(),
            name: Some("OPENAI_API_KEY".into()), identity: "default".into(), title: "OpenAI API key".into(),
            why: None, url: None, steps: vec![], expects: "secret".into(), pattern: None, names: vec![],
            status: TaskStatus::Pending, created: created.into(), deadline: "2099-01-01T00:00:00Z".into(),
            answered_at: None, note: None,
        }
    }

    #[test]
    fn persistent_keys_are_private_stable_and_well_formed() {
        let _g = env_lock();
        let home = tmp_home("perms");
        std::env::set_var("TOKENSTASH_HOME", &home);

        let proof = ensure_proof_key().unwrap();
        let cap = ensure_cap_key().unwrap();
        for t in [&proof, &cap] {
            assert_eq!(t.len(), 64, "32 random bytes, hex");
            assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        assert_ne!(proof, cap, "holding one key must say nothing about the other");
        // A second call adopts the stored key instead of minting a new one: the CLI must
        // keep recognising the inbox, and links already printed must keep working.
        assert_eq!(ensure_proof_key().unwrap(), proof);
        assert_eq!(ensure_cap_key().unwrap(), cap);
        assert_eq!(std::fs::read_to_string(proof_key_path()).unwrap(), proof, "no trailing newline");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [proof_key_path(), cap_key_path()] {
                let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{} must not be readable by other users", p.display());
            }
        }

        // Two homes never share a key: the proof is per-TOKENSTASH_HOME.
        let other = tmp_home("perms-other");
        std::env::set_var("TOKENSTASH_HOME", &other);
        assert_ne!(ensure_proof_key().unwrap(), proof);

        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// The session is minted by the server and changes every time one starts; a stale one
    /// is not a credential for the server that is running now.
    #[test]
    fn the_session_rotates_on_every_start_and_the_old_one_is_refused() {
        let _g = env_lock();
        let home = tmp_home("rotate");
        std::env::set_var("TOKENSTASH_HOME", &home);

        assert_eq!(read_session(), None, "no inbox has run yet: nothing to hand a browser");
        let first = Tokens::start().unwrap();
        assert_eq!(read_session().as_deref(), Some(first.session()), "the CLI reads what the server minted");
        let second = Tokens::start().unwrap();
        assert_ne!(first.session(), second.session(), "a restart mints a new session");
        assert_eq!(second.proof(), first.proof(), "the proof key survives the restart: the CLI still recognises the inbox");
        assert_eq!(second.scope_of(first.session(), |_| None), None, "the old session is dead");
        assert_eq!(second.scope_of(second.session(), |_| None), Some(Scope::Full));
        // Neither persistent key is a browser credential.
        assert_eq!(second.scope_of(second.proof(), |_| None), None, "the proof key must not authenticate a browser");
        assert_eq!(second.scope_of(&ensure_cap_key().unwrap(), |_| None), None, "the capability key must not authenticate a browser");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(session_path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A card link opens exactly the card it was minted for.
    #[test]
    fn a_card_capability_is_bound_to_one_card() {
        let _g = env_lock();
        let home = tmp_home("cap");
        std::env::set_var("TOKENSTASH_HOME", &home);
        let t = Tokens::start().unwrap();
        let a = card("t_aaaaaa", "/p/a", "2026-01-01T00:00:00Z");
        let b = card("t_bbbbbb", "/p/b", "2026-01-01T00:00:00Z");
        let cred_a = t.task_credential(&a);
        assert!(cred_a.starts_with("t_aaaaaa."), "{cred_a}");
        assert_eq!(cred_a.len(), "t_aaaaaa.".len() + 64);
        let lookup = |id: &str| [&a, &b].into_iter().find(|t| t.id == id).cloned();
        assert_eq!(t.scope_of(&cred_a, lookup), Some(Scope::Task("t_aaaaaa".into())));
        // The MAC part of A's link, re-addressed to B, is not B's capability.
        let mac_a = cred_a.split_once('.').unwrap().1;
        assert_eq!(t.scope_of(&format!("t_bbbbbb.{mac_a}"), lookup), None, "cannot mint a sibling from a link");
        // A prefix of the id is not the id.
        assert_eq!(t.scope_of(&format!("t_aaaaa.{mac_a}"), |id| lookup(id).or_else(|| Some(a.clone()))), None, "a lookup that resolves a prefix must still be refused");
        // Same id, different directory or creation time: another card, another capability.
        assert_ne!(task_capability(&ensure_cap_key().unwrap(), &card("t_aaaaaa", "/p/other", "2026-01-01T00:00:00Z")), mac_a);
        assert_ne!(task_capability(&ensure_cap_key().unwrap(), &card("t_aaaaaa", "/p/a", "2026-01-02T00:00:00Z")), mac_a);
        // Malformed credentials are refused before any lookup runs.
        for junk in ["", ".", "t_aaaaaa.", &format!(".{mac_a}"), &format!("t_aa aa.{mac_a}"), &format!("t_aaaaaa.{}", &mac_a[..63]), &format!("t_aaaaaa.{mac_a}0"), "t_aaaaaa"] {
            assert_eq!(t.scope_of(junk, |_| panic!("looked up {junk:?}")), None, "{junk:?}");
        }
        // A different capability key signs differently: the key never leaves the machine,
        // so a link is useless against another home's inbox.
        let other = tmp_home("cap-other");
        std::env::set_var("TOKENSTASH_HOME", &other);
        let t2 = Tokens::start().unwrap();
        assert_eq!(t2.scope_of(&cred_a, lookup), None);
        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn read_token_rejects_a_malformed_file() {
        let _g = env_lock();
        let home = tmp_home("malformed");
        std::env::set_var("TOKENSTASH_HOME", &home);

        for junk in ["", "   ", "not-hex-at-all", &"a".repeat(63), &"z".repeat(64)] {
            std::fs::write(proof_key_path(), junk).unwrap();
            assert!(read_token_at(&proof_key_path()).is_none(), "should reject {junk:?}");
            std::fs::write(session_path(), junk).unwrap();
            assert!(read_session().is_none(), "a malformed session is no session: {junk:?}");
        }
        // ...and a malformed key file is replaced with a real key rather than trusted.
        let t = ensure_proof_key().unwrap();
        assert_eq!(t.len(), 64);

        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn verify_response_is_hmac_and_binds_both_key_and_challenge() {
        // Known-answer vector: HMAC-SHA256(key="key", msg="The quick brown fox jumps over the lazy dog"),
        // reproduced through the domain tag so the tag is exactly what a client prepends.
        let msg = "The quick brown fox jumps over the lazy dog";
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"key").unwrap();
        mac.update(msg.as_bytes());
        assert_eq!(hex(&mac.finalize().into_bytes()), "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
        let mut tagged = <Hmac<Sha256> as Mac>::new_from_slice(b"key").unwrap();
        tagged.update(format!("{VERIFY_DOMAIN}{msg}").as_bytes());
        assert_eq!(verify_response("key", msg), hex(&tagged.finalize().into_bytes()), "the tag is a plain prefix of the message");
        let proof = "a".repeat(64);
        let other = "b".repeat(64);
        assert_eq!(verify_response(&proof, "n1").len(), 64);
        // A different challenge gives a different answer, so a recorded reply proves nothing.
        assert_ne!(verify_response(&proof, "n1"), verify_response(&proof, "n2"));
        // A different key gives a different answer, so another TOKENSTASH_HOME's inbox
        // squatting the port fails the proof — and so does anyone holding only a session
        // token captured from a URL.
        assert_ne!(verify_response(&proof, "n1"), verify_response(&other, "n1"));
        // Deterministic: the prober can recompute it.
        assert_eq!(verify_response(&proof, "n1"), verify_response(&proof, "n1"));
    }

    #[test]
    fn ct_eq_matches_string_equality() {
        let token = "0123456789abcdef".repeat(4);
        assert!(ct_eq(&token, &token.clone()));
        assert!(!ct_eq(&token, &token[..63]), "a prefix is not a match");
        assert!(!ct_eq(&token, &format!("{token}0")), "an extension is not a match");
        assert!(!ct_eq(&token, &token.replacen('0', "1", 1)), "one differing byte is not a match");
        assert!(!ct_eq(&token, ""));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn challenges_do_not_repeat() {
        let a = challenge();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, challenge());
    }
}
