use crate::notify::Inbox;
use anyhow::Result;
use std::path::PathBuf;
use tokenstash_core::stash::Stash;
use tokenstash_core::tasks::Ctx;
use tokenstash_core::{Config, Db};

pub struct App {
    pub cfg: Config,
    pub db: Db,
    pub stash: Box<dyn Stash>,
}

impl App {
    pub fn open() -> Result<Self> {
        let cfg = Config::load()?;
        // Accepted for compatibility, no longer honoured: agent links are scoped to one card
        // whatever this says. Said once per process, on stderr, with no value attached.
        if cfg.inbox_links == "full" {
            eprintln!("tokenstash: inbox_links = \"full\" is deprecated and ignored — links printed to agents are scoped to one card; the full inbox is `tokenstash open` or the desktop notification");
        }
        let db = Db::open_default()?;
        let stash = tokenstash_core::stash::open(&cfg)?;
        Ok(Self { cfg, db, stash })
    }
    pub fn ctx(&self) -> Ctx<'_> {
        Ctx { cfg: &self.cfg, db: &self.db, stash: self.stash.as_ref(), probe: tokenstash_core::tasks::Probe::Network }
    }
}

/// Commands only a person at a terminal may run. Two independent signals: the agent
/// environment markers, and both standard streams being a TTY (an agent's shell has
/// neither, even when it inherits a terminal for one of them). `what` names the command,
/// `why` the reason it is human-only, so the refusal teaches rather than just blocks.
pub fn require_human(what: &str, why: &str) -> Result<()> {
    if !looks_human() {
        anyhow::bail!("`tokenstash {what}` is for a person at a terminal, not an agent: {why}. Run it yourself.");
    }
    Ok(())
}

/// The signal behind [`require_human`]. A heuristic, and documented as one: an agent that
/// scrubs its environment and allocates a pseudo-terminal passes it. Same-user processes
/// are outside what this can tell apart. `TOKENSTASH_AGENT` is never evidence of a person,
/// whatever it says: `TOKENSTASH_AGENT=unknown` used to hide every other marker.
pub fn looks_human() -> bool {
    use std::io::IsTerminal;
    !tokenstash_core::project::agent_environment() && std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// The keys this directory holds a grant for or was delivered since it was paired: all an
/// agent here may learn exists. The rest of the stash is the person's inventory. Both signals
/// belong to the current directory, so a re-created directory at the same path (fingerprint
/// mismatch) inherits nothing, not even the old one's names.
pub fn keys_here(db: &tokenstash_core::Db, project: &std::path::Path) -> Result<std::collections::BTreeSet<(String, String)>> {
    let mut here = std::collections::BTreeSet::new();
    if let Some(ws) = db.find_workspace(project)? {
        for (name, identity, _scope, _src) in db.grants_for(&ws.id)? {
            if name != "*" {
                here.insert((name, identity));
            }
        }
        let pid = project.to_string_lossy().to_string();
        for (name, identity) in db.delivered_names(&pid, &ws.created)? {
            here.insert((name, identity));
        }
    }
    Ok(here)
}

pub fn project_from(arg: &Option<PathBuf>) -> PathBuf {
    match arg {
        Some(p) => tokenstash_core::project::canonical(p),
        None => tokenstash_core::project::current(),
    }
}

pub fn agent_from(arg: &Option<String>) -> String {
    tokenstash_core::need::clean_agent(&arg.clone().unwrap_or_else(tokenstash_core::project::detect_agent))
}

/// The bare inbox URL, no credential: the index, or a card on the full route `/t/<id>`.
/// Only ever shown when nothing better is available; every link a person is expected to
/// click carries a credential (see `inbox_url_agent`, `inbox_url_human`).
pub fn inbox_url(cfg: &Config, task_id: Option<&str>) -> String {
    let base = crate::remote::link_base(cfg);
    match task_id {
        Some(id) => format!("{base}/t/{id}"),
        None => format!("{base}/"),
    }
}

/// One card on the scoped route `/p/<id>`, which is served only to that card's capability.
fn inbox_url_scoped(cfg: &Config, task_id: &str) -> String {
    format!("{}/p/{task_id}", crate::remote::link_base(cfg))
}

/// Which stream a URL is about to be written to. A TTY check is only meaningful for the
/// stream that is actually being written: `run` prints its inbox line to stderr while `tasks`
/// and `doctor` print to stdout, and a pipeline routinely redirects one and not the other.
/// Testing stdout and then printing to stderr would put the token into a captured stderr
/// whenever stdout merely happened to be a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

fn is_terminal(stream: Stream) -> bool {
    use std::io::IsTerminal;
    match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    }
}

/// The inbox URL carrying `?t=<browser session>`, which authenticates the first click and is
/// then swapped for a cookie. For surfaces a person reads directly: the desktop notification
/// and `tokenstash open`. The session is whatever the running inbox minted when it started;
/// this process only reads it, and a link built from it dies with that inbox.
///
/// `state` is a required argument on purpose. The session is appended only when ownership
/// of the port has been *proved* ([`Inbox::Ours`]). Handing `?t=` to a listener that failed
/// the `/verify` challenge would give a squatter exactly the credential it needs to
/// impersonate the inbox and collect whatever the human pastes next — the URL is the one
/// place the session leaves this process, so the check belongs here, where no new call site
/// can forget it.
/// Falls back to the bare URL otherwise; callers talking to a human should use
/// [`inbox_notice`], which explains itself instead of handing over a dead or hostile link.
pub fn inbox_url_human(cfg: &Config, task_id: Option<&str>, state: Inbox) -> String {
    let url = inbox_url(cfg, task_id);
    match (state, crate::inbox_auth::read_session()) {
        (Inbox::Ours, Some(t)) => format!("{url}?t={t}"),
        _ => url,
    }
}

/// The session only when we are demonstrably talking to a person at *this stream's* terminal
/// and the inbox has proved it is ours. `tasks`, `doctor` and `run` print for a human but are
/// also run by agents that capture the output; when the stream is not a TTY (a pipe, a file,
/// an agent's capture buffer) they get the agent link. An agent that allocates a PTY can
/// still see the session here — that is the known limit of a TTY heuristic, and the reason
/// no unconditional surface ever prints it.
///
/// Only a *proved* inbox gets a link at all, bare or tokened, on any stream: a loopback URL
/// in front of a person is an invitation to paste a key into whatever answers there, and an
/// agent relays the line verbatim. `Down` gets no link either — a squatter can bind the port
/// between our probe and the click.
pub fn inbox_url_tty(cfg: &Config, db: Option<&Db>, task_id: Option<&str>, state: Inbox, stream: Stream) -> String {
    if !matches!(state, Inbox::Ours) {
        return inbox_notice(cfg, task_id, state);
    }
    if is_terminal(stream) {
        inbox_url_human(cfg, task_id, state)
    } else {
        inbox_url_agent(cfg, db, task_id, state)
    }
}

/// Agent-facing: a link that WORKS when the person clicks it from the chat. It carries the
/// card's own capability (open, answer or decline that one card; nothing else) and never
/// the session — not for any config value: `inbox_links = "full"` is accepted and ignored,
/// because a session in the agent's context is a credential that approves. See
/// `crate::inbox_auth` for why the scopes are split. Without a card there is nothing to
/// scope a credential to, so the agent gets the bare URL: it opens for a browser that
/// already holds a session and is a 404 for anything else.
/// Not a link at all unless the inbox is proved ours: the agent relays this line to a
/// person, and a link to a squatter is an invitation to paste a key into its form.
///
/// The capability is signed over the card's row, which is why this takes the database; a
/// card that cannot be read gets the bare URL rather than a credential for a guess.
pub fn inbox_url_agent(cfg: &Config, db: Option<&Db>, task_id: Option<&str>, state: Inbox) -> String {
    if !matches!(state, Inbox::Ours) {
        return inbox_notice(cfg, task_id, state);
    }
    let task = match (db, task_id) {
        (Some(db), Some(id)) => db.get_task(id).ok().flatten(),
        _ => None,
    };
    match (task, crate::inbox_auth::ensure_cap_key()) {
        (Some(t), Ok(key)) => format!("{}?t={}", inbox_url_scoped(cfg, &t.id), crate::inbox_auth::task_credential(&key, &t)),
        _ => inbox_url(cfg, task_id),
    }
}

/// Why we are not sending you to the inbox, when we are not. `None` means go ahead.
pub fn inbox_unavailable(cfg: &Config, state: Inbox) -> Option<String> {
    match state {
        Inbox::Ours => None,
        Inbox::Foreign => Some(format!(
            "port {} is held by another process (often a tokenstash inbox started under a different TOKENSTASH_HOME); not sending you there. Stop it, free the port, or change inbox_port in {}.",
            cfg.inbox_port,
            tokenstash_core::config::config_path().display()
        )),
        Inbox::Down => Some("the inbox is not running; start it with `tokenstash open`.".to_string()),
    }
}

/// The one line we put in front of a person telling them where to go: the session URL when
/// ownership is proved, and why we are not sending them anywhere when it is not. Never a link
/// to a listener that failed the proof — even a bare one would walk the human into an
/// impostor's paste form.
pub fn inbox_notice(cfg: &Config, task_id: Option<&str>, state: Inbox) -> String {
    match inbox_unavailable(cfg, state) {
        None => inbox_url_human(cfg, task_id, state),
        Some(why) => format!("tokenstash: {why}"),
    }
}

pub fn short(p: &str) -> String {
    tokenstash_core::project::short(std::path::Path::new(p))
}

/// Human display for approval entries: drop the "*" marker and the "@default" suffix.
pub fn approval_names(names: &[String]) -> Vec<String> {
    names.iter().filter(|n| n.as_str() != "*").map(|n| n.strip_suffix("@default").unwrap_or(n).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard every human-only command shares. An agent is refused on the environment
    /// marker alone, whatever the streams look like.
    #[test]
    fn require_human_refuses_an_agent() {
        let _g = crate::inbox_auth::env_lock();
        std::env::set_var("TOKENSTASH_AGENT", "claude-code");
        let e = require_human("answer --allow", "approving a card is your decision").unwrap_err();
        std::env::remove_var("TOKENSTASH_AGENT");
        let msg = format!("{e:#}");
        assert!(msg.contains("person at a terminal"), "{msg}");
        assert!(msg.contains("approving a card is your decision"), "the refusal says why: {msg}");
        // And in a test process the streams are not a terminal either, so it refuses anyway.
        assert!(require_human("answer --allow", "why").is_err());
    }

    fn with_home<T>(name: &str, f: impl FnOnce(Config, Db) -> T) -> T {
        let _g = crate::inbox_auth::env_lock();
        let home = std::env::temp_dir().join(format!("tokenstash-util-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("TOKENSTASH_HOME", &home);
        let db = Db::open(&home.join("t.db")).unwrap();
        let out = f(Config::default(), db);
        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
        out
    }

    /// A card on file, so a link can be signed over it.
    fn card(db: &Db, id: &str) -> tokenstash_core::db::Task {
        use tokenstash_core::db::{Task, TaskKind, TaskStatus};
        let t = Task {
            id: id.into(), kind: TaskKind::Secret, project: "/tmp/p".into(), agent: "agent".into(),
            name: Some("OPENAI_API_KEY".into()), identity: "default".into(), title: "OpenAI API key".into(),
            why: None, url: None, steps: vec![], expects: "secret".into(), pattern: None, names: vec![],
            status: TaskStatus::Pending, created: "2026-01-01T00:00:00Z".into(), deadline: "2099-01-01T00:00:00Z".into(),
            answered_at: None, note: None,
        };
        db.insert_task(&t).unwrap();
        t
    }

    #[test]
    fn the_session_is_only_attached_to_a_verified_inbox() {
        with_home("verified", |cfg, _db| {
            // Before any inbox has run there is no session, and no link pretends otherwise.
            assert_eq!(inbox_url_human(&cfg, Some("t_abc"), Inbox::Ours), inbox_url(&cfg, Some("t_abc")));
            let token = crate::inbox_auth::rotate_session().unwrap();
            // Proved ours: the human's link carries the session the inbox minted.
            let ours = inbox_url_human(&cfg, Some("t_abc"), Inbox::Ours);
            assert!(ours.contains(&format!("?t={token}")), "{ours}");
            assert!(ours.contains("/t/t_abc"));

            // Anything we could not prove is ours gets no session — a squatter on the port
            // must not be handed the credential that lets it impersonate the inbox.
            for state in [Inbox::Foreign, Inbox::Down] {
                let url = inbox_url_human(&cfg, None, state);
                assert!(!url.contains("t="), "{state:?} produced a tokened URL: {url}");
                assert!(!url.contains(&token), "{state:?} leaked the token: {url}");
            }
            // ...and the bare form never carries it, whatever the state.
            assert!(!inbox_url(&cfg, None).contains("t="));
            // The persistent keys are never what a link carries.
            let proof = crate::inbox_auth::ensure_proof_key().unwrap();
            let cap = crate::inbox_auth::ensure_cap_key().unwrap();
            assert!(!ours.contains(&proof) && !ours.contains(&cap), "{ours}");
        });
    }

    #[test]
    fn an_unverified_inbox_yields_an_explanation_not_a_link() {
        with_home("notice", |cfg, _db| {
            let token = crate::inbox_auth::rotate_session().unwrap();
            assert_eq!(inbox_unavailable(&cfg, Inbox::Ours), None);

            let foreign = inbox_notice(&cfg, Some("t_abc"), Inbox::Foreign);
            assert!(foreign.contains("held by another process"), "{foreign}");
            assert!(!foreign.contains("http"), "a link to an unverified listener: {foreign}");
            assert!(!foreign.contains(&token));

            let down = inbox_notice(&cfg, None, Inbox::Down);
            assert!(down.contains("tokenstash open"), "{down}");
            assert!(!down.contains(&token));

            // Verified: the notice IS the tokened link.
            assert_eq!(inbox_notice(&cfg, None, Inbox::Ours), inbox_url_human(&cfg, None, Inbox::Ours));
        });
    }

    #[test]
    fn agent_links_carry_one_cards_capability_and_never_the_session() {
        with_home("links-scope", |cfg, db| {
            let session = crate::inbox_auth::rotate_session().unwrap();
            let cap = crate::inbox_auth::ensure_cap_key().unwrap();
            let proof = crate::inbox_auth::ensure_proof_key().unwrap();
            let t = card(&db, "t_abc123");
            let url = inbox_url_agent(&cfg, Some(&db), Some("t_abc123"), Inbox::Ours);
            assert!(url.ends_with(&format!("/p/t_abc123?t={}", crate::inbox_auth::task_credential(&cap, &t))), "the scoped route, not the full one: {url}");
            for secret in [&session, &cap, &proof] {
                assert!(!url.contains(secret.as_str()), "an agent link carries no key or session: {url}");
            }
            // No card, no credential: a bare URL, never a session minted for the occasion.
            let bare = inbox_url_agent(&cfg, Some(&db), None, Inbox::Ours);
            assert_eq!(bare, inbox_url(&cfg, None));
            // A card that is not on file gets no credential either — nothing is signed over a
            // guess.
            assert_eq!(inbox_url_agent(&cfg, Some(&db), Some("t_nothere"), Inbox::Ours), inbox_url(&cfg, Some("t_nothere")));
            assert_eq!(inbox_url_agent(&cfg, None, Some("t_abc123"), Inbox::Ours), inbox_url(&cfg, Some("t_abc123")));
            // The retired opt-out changes nothing: same scoped link, no session, taskless
            // still bare.
            let mut full = cfg.clone();
            full.inbox_links = "full".into();
            assert_eq!(inbox_url_agent(&full, Some(&db), Some("t_abc123"), Inbox::Ours), url, "inbox_links = full is ignored");
            assert_eq!(inbox_url_agent(&full, Some(&db), None, Inbox::Ours), inbox_url(&cfg, None));
            assert!(!inbox_url_agent(&full, Some(&db), Some("t_abc123"), Inbox::Ours).contains(&session));
        });
    }

    #[test]
    fn an_unproved_inbox_gets_no_link_on_any_surface() {
        with_home("unproved", |cfg, db| {
            card(&db, "t_abc");
            for state in [Inbox::Foreign, Inbox::Down] {
                for stream in [Stream::Stdout, Stream::Stderr] {
                    let out = inbox_url_tty(&cfg, Some(&db), Some("t_abc"), state, stream);
                    assert!(!out.contains("http"), "{state:?}/{stream:?} linked to an unproved inbox: {out}");
                }
                let out = inbox_url_agent(&cfg, Some(&db), Some("t_abc"), state);
                assert!(!out.contains("http"), "agent surface linked to an unproved inbox: {out}");
            }
            assert!(inbox_url_agent(&cfg, Some(&db), None, Inbox::Ours).starts_with("http://127.0.0.1:"));
        });
    }

    #[test]
    fn a_non_terminal_stream_never_gets_the_session() {
        with_home("stream", |cfg, db| {
            let token = crate::inbox_auth::rotate_session().unwrap();
            let t = card(&db, "t_abc123");
            // Under `cargo test` both streams are captured, so neither is a terminal: the
            // point is that each variant consults its own stream rather than a fixed one.
            for stream in [Stream::Stdout, Stream::Stderr] {
                if !is_terminal(stream) {
                    let url = inbox_url_tty(&cfg, Some(&db), Some("t_abc123"), Inbox::Ours, stream);
                    assert_eq!(url, inbox_url_agent(&cfg, Some(&db), Some("t_abc123"), Inbox::Ours), "{stream:?} must hand a captured stream the agent link");
                    assert!(!url.contains(&token), "the session must never reach a captured stream");
                    let cap = crate::inbox_auth::ensure_cap_key().unwrap();
                    assert!(url.contains(&crate::inbox_auth::task_credential(&cap, &t)), "the agent link carries the card's capability");
                }
            }
        });
    }
}
