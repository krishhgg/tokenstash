//! Task lifecycle: create (secret / approval / human), answer, deny.
//! Answering a secret task is the only place a value enters the system: validate → store → inject.

use crate::db::{Task, TaskKind, TaskStatus};
use crate::stash::{stash_key, Stash};
use crate::validate::{self, Liveness};
use crate::{registry, Config, Db};
use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};

/// Minimum accepted length for a pasted secret.
pub const MIN_SECRET_CHARS: usize = 6;

pub struct Ctx<'a> {
    pub cfg: &'a Config,
    pub db: &'a Db,
    pub stash: &'a dyn Stash,
    /// How a liveness probe reaches the provider. `Network` in the binary; tests must use
    /// `Off` or `Stub` — a unit test that sends a canary to api.openai.com is a bug.
    pub probe: Probe<'a>,
}

/// The one seam between tokenstash and the provider's HTTP endpoint.
#[derive(Clone, Copy)]
pub enum Probe<'a> {
    Network,
    /// No probe ever runs (tests, or callers that must stay offline).
    Off,
    /// A canned verdict (tests). Receives the check so a test can assert which one ran.
    Stub(&'a dyn Fn(&crate::registry::Check) -> Liveness),
}

impl Probe<'_> {
    /// `None` when probing is off. Never logs the value.
    pub fn run(&self, check: &crate::registry::Check, value: &SecretString, timeout: std::time::Duration) -> Option<Liveness> {
        let _ = (value, timeout);
        match self {
            #[cfg(test)]
            Probe::Network => panic!("unit tests must not probe the network: use Probe::Off or Probe::Stub"),
            #[cfg(not(test))]
            Probe::Network => Some(validate::liveness(check, value, timeout)),
            Probe::Off => None,
            Probe::Stub(f) => Some(f(check)),
        }
    }
}

/// What the human-side store knows about the value it is storing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// The provider accepted it just now.
    Ok,
    /// No probe exists, or it could not be reached: unknown, verify-on-use stays on.
    Unknown,
    /// The human chose to skip the check: verify-on-use is off for this key until a probe
    /// says Ok, so a probe that would keep rejecting cannot keep filing cards.
    Skipped,
}

pub fn new_id(prefix: &str) -> String {
    let n: u32 = rand::thread_rng().gen_range(0..0xFFFFFF);
    format!("{prefix}_{n:06x}")
}

pub fn deadline(cfg: &Config) -> String {
    (chrono::Utc::now() + chrono::Duration::hours(cfg.task_ttl_hours as i64))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Everything on a card that an agent chose. The `agent` name is already narrowed to a
/// label by [`crate::need::clean_agent`]; these are the fields that carry the card's meaning
/// (title, why, steps) and must not be able to forge UI. Bidi overrides and zero-width
/// characters can reorder or hide what the human reads, control characters can break the
/// line the terminal renders, and unbounded text can push the real question off screen.
/// HTML escaping happens at the inbox; this is the layer above it, and it also protects
/// `tokenstash answer`, which has no escaping at all.
pub fn clean_text(raw: &str, max: usize) -> String {
    let out: String = raw
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c,
                    '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        })
        .take(max)
        .collect();
    out.trim().to_string()
}

fn clean_text_opt(raw: Option<String>, max: usize) -> Option<String> {
    let c = clean_text(raw.as_deref().unwrap_or_default(), max);
    if c.is_empty() { None } else { Some(c) }
}

/// A link an agent supplied. The inbox renders it as an `href` the human clicks, so the
/// scheme is an allowlist: `javascript:` there would run in the inbox's own origin — the
/// origin holding the session that approves grants. Whitespace and control characters are
/// refused outright rather than stripped: a URL that needed cleaning is not one to trust.
pub fn clean_url(raw: Option<String>) -> Option<String> {
    let u = raw?;
    let u = u.trim();
    if u.len() > MAX_URL_CHARS || u.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let lower = u.to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://")).then(|| u.to_string())
}

/// Caps for what an agent may put on a card.
pub const MAX_TITLE_CHARS: usize = 120;
/// An approval card explains the decision and names the destination file; longer than a why.
pub const MAX_APPROVAL_WHY_CHARS: usize = 700;
pub const MAX_WHY_CHARS: usize = 300;
pub const MAX_STEP_CHARS: usize = 200;
pub const MAX_STEPS: usize = 8;
pub const MAX_URL_CHARS: usize = 300;

fn clean_steps(steps: &[String]) -> Vec<String> {
    steps.iter().map(|s| clean_text(s, MAX_STEP_CHARS)).filter(|s| !s.is_empty()).take(MAX_STEPS).collect()
}

#[derive(Debug, Default, Clone)]
pub struct SecretRequest {
    pub why: Option<String>,
    pub url: Option<String>,
    pub steps: Vec<String>,
    pub pattern: Option<String>,
}

/// Create (or reuse the open) secret task for `name` in `project`. Registry fills in gaps.
pub fn create_secret_task(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, req: &SecretRequest) -> Result<Task> {
    create_secret_task_kind(ctx, project, agent, name, identity, req, "secret")
}

/// A replacement card for a stale key: same shape, marked so its answer propagates.
pub fn create_replacement_task(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, req: &SecretRequest) -> Result<Task> {
    create_secret_task_kind(ctx, project, agent, name, identity, req, EXPECTS_REPLACE)
}

fn create_secret_task_kind(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, req: &SecretRequest, expects: &str) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    if let Some(t) = ctx.db.open_secret_task(&pid, name, identity)? {
        // An ordinary card reused for a replacement must carry the marker, or its answer
        // would not propagate; the reverse never downgrades.
        if expects == EXPECTS_REPLACE && t.expects != EXPECTS_REPLACE {
            ctx.db.set_task_expects(&t.id, EXPECTS_REPLACE)?;
            return Ok(Task { expects: EXPECTS_REPLACE.into(), ..t });
        }
        return Ok(t);
    }
    let p = registry::lookup(name);
    let title = match p {
        Some(p) => format!("{} API key ({})", p.provider, name),
        None => format!("Provide {name}"),
    };
    let t = Task {
        id: new_id("t"),
        kind: TaskKind::Secret,
        project: pid.clone(),
        agent: agent.into(),
        name: Some(name.into()),
        identity: identity.into(),
        title,
        why: clean_text_opt(req.why.clone(), MAX_WHY_CHARS),
        // The registry's link wins over the agent's. Otherwise an agent requesting a key it
        // knows the human has can point "Open openai.com ↗" at its own lookalike page, in
        // the one flow where the human is about to produce a live credential. An agent link
        // survives only for a name no provider claims, where it is the only link there is.
        url: p.map(|p| p.url.clone()).or_else(|| clean_url(req.url.clone())),
        steps: if !req.steps.is_empty() { clean_steps(&req.steps) } else { p.map(|p| p.steps.clone()).unwrap_or_default() },
        expects: expects.into(),
        // The registry's pattern wins, like its link. An agent pattern survives only for a
        // name no provider claims, and only if it compiles: a bad regex would make the card
        // unanswerable, and an unbounded one is compiled on the human's side.
        pattern: p.and_then(|p| p.pattern.clone()).or_else(|| req.pattern.clone().filter(|s| s.len() <= 200 && regex::Regex::new(s).is_ok())),
        names: vec![],
        status: TaskStatus::Pending,
        created: crate::now(),
        deadline: deadline(ctx.cfg),
        answered_at: None,
        note: None,
    };
    ctx.db.insert_task(&t)?;
    ctx.db.audit(Some(&pid), Some(agent), "task.secret", Some(name), Some(identity), None)?;
    Ok(t)
}

/// Split an approval entry `NAME@identity` (identity defaults to "default").
pub fn split_identity(entry: &str) -> (&str, &str) {
    match entry.split_once('@') {
        Some((n, i)) if !i.is_empty() => (n, i),
        _ => (entry, "default"),
    }
}

/// Marker in `expects` for a secret task that REPLACES a stale value (a rotation or a
/// reported-dead key). Only answers to such cards propagate to other projects; an ordinary
/// paste card answered later, even if the key has since gone stale elsewhere, does not.
pub const EXPECTS_REPLACE: &str = "replace";

/// Marker in `expects` for an approval that must not become a standing grant: a program's
/// own output chose the key (`run` shim), so the human authorises THIS injection only.
pub const APPROVAL_ONCE: &str = "once";
pub const APPROVAL_PAIRING: &str = "pairing";
pub const APPROVAL_SENSITIVE: &str = "sensitive";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalKind {
    /// First delivery of stored keys into this workspace: one batched card.
    Pairing,
    /// Sensitive or unregistered keys: their own card, exact grants only.
    Sensitive,
    /// A program's output chose the key (`run`): a fresh yes every time, no grant.
    Once,
}

impl ApprovalKind {
    pub fn expects(self) -> &'static str {
        match self { ApprovalKind::Pairing => APPROVAL_PAIRING, ApprovalKind::Sensitive => APPROVAL_SENSITIVE, ApprovalKind::Once => APPROVAL_ONCE }
    }
}

/// What the human pressed on an approval card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Deny,
    /// Exactly the listed keys.
    Allow,
    /// The listed keys, plus any registry-confirmed non-sensitive key for the same
    /// identity in this workspace. Pairing cards only.
    AllowBroad,
}

/// One card per kind per workspace: a pairing card and a sensitive card merge with the
/// open one of their kind; a one-time card never merges.
pub fn create_approval_task(ctx: &Ctx, project: &Path, agent: &str, names: &[String], kind: ApprovalKind) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    if kind != ApprovalKind::Once {
        // Read-merge-write under the write lock: two processes growing the same card must
        // not overwrite each other's names.
        let own_tx = ctx.db.conn.is_autocommit();
        if own_tx { ctx.db.conn.execute_batch("BEGIN IMMEDIATE")?; }
        let merged_card = (|| -> Result<Option<Task>> {
            let Some(mut t) = ctx.db.open_approval_task_kind(&pid, kind.expects())? else { return Ok(None) };
            let mut merged = t.names.clone();
            for n in names {
                if !merged.contains(n) {
                    merged.push(n.clone());
                }
            }
            if merged == t.names {
                return Ok(Some(t));
            }
            if ctx.db.update_task_names(&t.id, &merged)? {
                t.names = merged;
                return Ok(Some(t));
            }
            Ok(None) // answered between our read and this write: a new card, not a free ride
        })();
        if own_tx {
            match &merged_card { Ok(_) => ctx.db.conn.execute_batch("COMMIT")?, Err(_) => { let _ = ctx.db.conn.execute_batch("ROLLBACK"); } }
        }
        if let Some(t) = merged_card? {
            return Ok(t);
        }
    }
    let shown: Vec<String> = names.iter().map(|n| n.strip_suffix("@default").unwrap_or(n).to_string()).collect();
    let short = crate::project::short(project);
    let (title, why) = match kind {
        ApprovalKind::Pairing => (
            format!("{short} wants {}", if shown.len() == 1 { shown[0].clone() } else { format!("{} keys", shown.len()) }),
            format!("First time this directory asks for stored keys. \"Allow these\" writes exactly these into {}: {}. \"Allow these + any non-sensitive key here\" also lets this directory receive any registry-confirmed non-sensitive key for the same identity, without asking. Nothing applies to any other directory.", project.join(&ctx.cfg.env_file).display(), shown.join(", ")),
        ),
        ApprovalKind::Sensitive => (
            format!("{short} wants sensitive key(s): {}", shown.join(", ")),
            format!("Tagged sensitive (live payments, cloud credentials, unbounded spend) or unknown to the registry: each needs its own yes for this directory. Written to {}.", project.join(&ctx.cfg.env_file).display()),
        ),
        ApprovalKind::Once => (
            format!("A program in {short} asked for {}", shown.join(", ")),
            "The key was chosen by a running program's output, not by you or the agent. Allowing delivers it once; the next run asks again.".to_string(),
        ),
    };
    // The directory name is the agent's to choose (`mkdir`, `cd`): a card title must not
    // carry its control, bidi or zero-width characters into `tasks` output or the inbox.
    let title = clean_text(&title, MAX_TITLE_CHARS);
    let why = clean_text(&why, MAX_APPROVAL_WHY_CHARS);
    let t = Task {
        id: new_id("a"),
        kind: TaskKind::Approval,
        project: pid.clone(),
        agent: agent.into(),
        name: None,
        identity: "default".into(),
        title,
        why: Some(why),
        url: None,
        steps: vec![],
        expects: kind.expects().into(),
        pattern: None,
        names: names.to_vec(),
        status: TaskStatus::Pending,
        created: crate::now(),
        deadline: deadline(ctx.cfg),
        answered_at: None,
        note: None,
    };
    ctx.db.insert_task(&t)?;
    ctx.db.audit(Some(&pid), Some(agent), "task.approval", None, None, Some(&format!("{}: {}", kind.expects(), names.join(","))))?;
    Ok(t)
}

pub struct HumanRequest {
    pub title: String,
    pub why: Option<String>,
    pub url: Option<String>,
    pub steps: Vec<String>,
    /// "confirm" | "text" | "choice"
    pub expects: String,
}

pub fn create_human_task(ctx: &Ctx, project: &Path, agent: &str, req: HumanRequest) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    // Clean before the dedup comparison below, not after: the stored card holds the cleaned
    // text, so comparing raw request text against it would never match and every repeat of
    // the same question would file another card.
    let (title, why, url, steps) =
        (clean_text(&req.title, MAX_TITLE_CHARS), clean_text_opt(req.why, MAX_WHY_CHARS), clean_url(req.url), clean_steps(&req.steps));
    // Same title and answer type, same project, still open, same instructions: that is the
    // same request (an agent whose blocking call timed out and asked again), not a second
    // card. Different instructions under the same title are a different request. Lookup and
    // insert happen under one write lock so two processes asking at once file one card.
    ctx.db.conn.execute_batch("BEGIN IMMEDIATE").context("locking the task table")?;
    let existing = match ctx.db.open_human_tasks(&pid, &title, &req.expects) {
        Ok(e) => e,
        Err(e) => { let _ = ctx.db.conn.execute_batch("ROLLBACK"); return Err(e); }
    };
    if let Some(t) = existing.into_iter().find(|t| t.why == why && t.url == url && t.steps == steps) {
        ctx.db.conn.execute_batch("COMMIT")?;
        return Ok(t);
    }
    let t = Task {
        id: new_id("h"),
        kind: TaskKind::Human,
        project: pid.clone(),
        agent: agent.into(),
        name: None,
        identity: "default".into(),
        title,
        why,
        url,
        steps,
        expects: req.expects,
        pattern: None,
        names: vec![],
        status: TaskStatus::Pending,
        created: crate::now(),
        deadline: deadline(ctx.cfg),
        answered_at: None,
        note: None,
    };
    if let Err(e) = ctx.db.insert_task(&t).and_then(|_| ctx.db.audit(Some(&pid), Some(agent), "task.human", None, None, Some(&t.title))) {
        let _ = ctx.db.conn.execute_batch("ROLLBACK");
        return Err(e);
    }
    ctx.db.conn.execute_batch("COMMIT").context("recording the human task")?;
    Ok(t)
}

#[derive(Debug)]
pub enum AnswerResult {
    Stored { injected_to: Option<PathBuf>, sensitive: bool, liveness: Option<Liveness>, rotation: Option<RotationReport> },
    /// `replaced`: approved, but the provider rejected the stored key at delivery; a Replace
    /// card is waiting for each of these instead of a value in the env file.
    Approved { injected: Vec<String>, replaced: Vec<String> },
    Denied,
    Done,
}

/// Who is answering, as far as the caller can tell. It decides how far an answer may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// A person: the full inbox session, or a terminal that passed the human-only check.
    /// May answer anything, including a paste that other directories receive.
    Human,
    /// The card's own requester: an agent at a shell in the card's directory, or a browser
    /// holding that one card's link. May answer this card for this directory and nothing
    /// that reaches beyond it.
    Requester,
}

/// Would answering this card reach beyond the card's own directory? A replacement card
/// rewrites every project holding the old value, and a standing grant elsewhere delivers the
/// new value there on its next `need`. Either way the paste decides for other directories, so
/// it is not one the agent's own link (or an agent at a shell) may make: without this, a
/// hostile repo's agent runs `report-bad` → `need` → `answer --stdin` and points every project
/// of the user at its own database.
///
/// "A standing grant elsewhere" is an exact grant for the name, or a broad grant that the
/// gate would open for it. The value is not known yet, so whether it would be tagged
/// sensitive at paste time (`sensitive_pattern`) is not either; sensitivity is judged on the
/// name alone, which is the stricter reading — a value the pattern later tags is refused
/// broad delivery by the gate anyway. Grants outlive the value (`forget` keeps them), so a
/// re-paste after `forget` fans out exactly like the first paste did. A directory whose
/// record no longer matches it (re-created) still counts: a record is a record.
///
/// Called under the index write lock by [`answer_secret_by`], so what it reads is what the
/// store that follows will act on: a grant committed in another directory a moment earlier
/// is seen, and one a moment later waits for the store to finish. It says nothing about
/// grants given afterwards — a directory paired broadly next week receives whatever value
/// is stored under a registry name then, whoever pasted it.
pub fn fans_out(ctx: &Ctx, task: &Task) -> Result<bool> {
    if task.expects == EXPECTS_REPLACE {
        return Ok(true);
    }
    let Some(name) = task.name.as_deref() else { return Ok(false) };
    let p = registry::lookup(name);
    let broad = crate::trust::broad_applies(p.map(|p| p.sensitive).unwrap_or(false), p.is_some());
    let granted = ctx.db.workspaces_granted(name, &task.identity, broad)?;
    Ok(granted.iter().any(|w| w.root != task.project))
}

/// Store a secret value for a task, as a person: pattern → liveness → stash → index →
/// inject → audit. Agent-facing callers use [`answer_secret_by`] with the actor they have.
pub fn answer_secret(ctx: &Ctx, task: &Task, value: SecretString, skip_liveness: bool) -> Result<AnswerResult> {
    answer_secret_by(ctx, Actor::Human, task, value, skip_liveness)
}

/// [`answer_secret`] with the answering actor named. A [`Actor::Requester`] may not make a
/// paste that [`fans_out`]; that is checked at the operation, not only where a button is
/// hidden, so every surface that lets a requester answer gets the same refusal with nothing
/// stored. The shape and provider checks run first (a slow probe must not run under the
/// lock); then the card and the grants are re-read under the index write lock, the gate is
/// applied to what is there *now*, and the claim, the stash write and the record follow
/// under the same lock — see [`store_and_inject`].
pub fn answer_secret_by(ctx: &Ctx, actor: Actor, task: &Task, value: SecretString, skip_liveness: bool) -> Result<AnswerResult> {
    if task.kind != TaskKind::Secret {
        bail!("task {} is not a secret task", task.id);
    }
    if task.status != TaskStatus::Pending {
        bail!("task {} is already {}", task.id, task.status.as_str());
    }
    let name = task.name.clone().ok_or_else(|| anyhow!("secret task without name"))?;
    // No real credential is this short. Refusing here keeps trivially short strings out of
    // the stash entirely, so the redactor never has to special-case them.
    if value.expose_secret().chars().count() < MIN_SECRET_CHARS {
        bail!("value is shorter than {MIN_SECRET_CHARS} characters; that is not a credential. Not stored.");
    }
    if let Some(p) = &task.pattern {
        if !validate::matches_pattern(p, &value)? {
            bail!("value does not match the expected pattern for {name} ({p}). Not stored.");
        }
    }
    let provider = registry::lookup(&name);
    let mut liveness = None;
    if !skip_liveness {
        if let Some(check) = provider.and_then(|p| p.check.as_ref()) {
            if let Some(l) = ctx.probe.run(check, &value, validate::TIMEOUT_HUMAN) {
                if let Liveness::Rejected(code) = l {
                    bail!("{} rejected this key (HTTP {code}). Not stored. Re-run with --skip-check to store anyway.", provider.map(|p| p.provider.as_str()).unwrap_or("provider"));
                }
                liveness = Some(l);
            }
        }
    }
    let sensitive = registry::is_sensitive(provider, &value)?;
    // Rotation: when a STALE key is being replaced, remember the value so every other project
    // still holding it can be rewritten below. An ordinary paste that happens to differ from
    // a stored value (two projects with their own pending cards) is not a rotation.
    let is_replacement = task.expects == EXPECTS_REPLACE;
    let injected_to = store_and_inject_gated(
        ctx, &name, &task.identity, &value, provider.map(|p| p.provider.clone()), task.url.clone(), sensitive,
        Path::new(&task.project), &task.agent, Some(&task.id),
        match liveness {
            Some(Liveness::Ok) => Verified::Ok,
            // "Skipped" only means something for a key that could have been checked.
            _ if skip_liveness && provider.and_then(|p| p.check.as_ref()).is_some() => Verified::Skipped,
            _ => Verified::Unknown,
        },
        crate::db::GRANT_PASTE,
        |fresh| {
            // The card as it is under the lock, not as it was read. Promotion to Replace
            // while validation ran changes the meaning of the answer for either actor, so
            // this attempt must stop before claiming the card or touching the stash.
            let fresh = fresh.ok_or_else(|| anyhow!("task {} is gone", task.id))?;
            if fresh.expects != task.expects {
                bail!("this card changed since you read it; reload it and try again");
            }
            if actor == Actor::Requester && fans_out(ctx, fresh)? {
                bail!("other directories hold this key, so the paste would reach them too: open this card from the desktop notification or run `tokenstash open`");
            }
            Ok(())
        },
    )?;
    // A replacement card's answer reaches every project that was ever given this key and
    // does not already hold the new value — whichever old value it holds (the stash may
    // have changed between the stale mark and this answer).
    let rotation = if is_replacement { Some(rewrite_replaced_value(ctx, &name, &task.identity, &value, &task.project)?) } else { None };
    Ok(AnswerResult::Stored { injected_to, sensitive, liveness, rotation })
}

/// Shared by `answer_secret` and auto-generated secrets. See [`store_and_inject_gated`].
#[allow(clippy::too_many_arguments)]
pub fn store_and_inject(
    ctx: &Ctx,
    name: &str,
    identity: &str,
    value: &SecretString,
    provider: Option<String>,
    source_url: Option<String>,
    sensitive: bool,
    project: &Path,
    agent: &str,
    answering_task: Option<&str>,
    verified: Verified,
    grant_source: &str,
) -> Result<Option<PathBuf>> {
    store_and_inject_gated(ctx, name, identity, value, provider, source_url, sensitive, project, agent, answering_task, verified, grant_source, |_| Ok(()))
}

/// Store a value: ONE index write lock (`BEGIN IMMEDIATE`) held across re-reading the card,
/// the caller's `gate`, the claim of the card, the keychain write, and the record of it
/// (index entry, audit row, grant). Nothing another process commits can slip between the
/// gate's reading and the store's effect, and two answers racing for one card (an inbox
/// POST and a `tokenstash answer`, two tabs) serialise on the lock: whoever claims first
/// owns the answer, the other is told so and stores nothing.
///
/// `gate` sees the card as it is under the lock (`None` when no card is being answered)
/// and may refuse; a refusal rolls everything back with nothing written anywhere. A keychain
/// write that fails rolls back too. The stash is an external side effect: when it accepts a
/// value but an index statement or COMMIT later fails, the task, metadata and grants roll
/// back but the value remains in the stash without an index row. The next `need` adopts it
/// rather than asking again.
///
/// Injection into the env file happens last, outside the lock: if it fails the task is
/// already answered and the value already stored, so a re-run of `need` hits and injects
/// rather than asking the human again. It writes what the stash holds when the env file's
/// lock is taken, which is a newer store's value if one committed in the meantime.
#[allow(clippy::too_many_arguments)]
fn store_and_inject_gated(
    ctx: &Ctx,
    name: &str,
    identity: &str,
    value: &SecretString,
    provider: Option<String>,
    source_url: Option<String>,
    sensitive: bool,
    project: &Path,
    agent: &str,
    answering_task: Option<&str>,
    verified: Verified,
    grant_source: &str,
    gate: impl FnOnce(Option<&Task>) -> Result<()>,
) -> Result<Option<PathBuf>> {
    let pid = project.to_string_lossy().to_string();
    // Every caller reaches this in autocommit; a caller that already holds a transaction
    // would be sharing its lock with the gate below, which is not the contract.
    if !ctx.db.conn.is_autocommit() {
        bail!("store_and_inject called inside a transaction");
    }
    ctx.db.conn.execute_batch("BEGIN IMMEDIATE").context("locking the index")?;
    let stored = (|| -> Result<()> {
        let fresh = match answering_task {
            Some(tid) => Some(ctx.db.get_task(tid)?.filter(|t| t.status == TaskStatus::Pending).ok_or_else(|| anyhow!("task {tid} was answered somewhere else while this was in flight; nothing was stored"))?),
            None => None,
        };
        gate(fresh.as_ref())?;
        if let Some(tid) = answering_task {
            if !ctx.db.close_task_if_open(tid, TaskStatus::Answered, None)? {
                bail!("task {tid} was answered somewhere else while this was in flight; nothing was stored");
            }
        }
        ctx.stash.set(&stash_key(name, identity), value).context("storing the value")?;
        record_stored(ctx, name, identity, provider, source_url, sensitive, project, agent, verified, grant_source, &pid)
    })();
    match stored {
        Ok(()) => {
            if let Err(e) = ctx.db.conn.execute_batch("COMMIT") {
                let cause = anyhow!(e).context("recording the stored secret");
                return Err(rollback_store(ctx, cause));
            }
        }
        Err(e) => return Err(rollback_store(ctx, e)),
    }
    // Another store may have committed a newer value since this one did, and written it
    // here already. Reading the stash under the env file's lock, as `need::deliver` does,
    // keeps this write from putting the older value back.
    let injected_to = if project.is_dir() {
        let p = crate::envfile::write_with(project, &ctx.cfg.env_file, name, || ctx.stash.get(&stash_key(name, identity)))?;
        if p.is_some() {
            ctx.db.audit_grant(Some(&pid), Some(agent), "inject", Some(name), Some(identity), None, grant_source)?;
        }
        p
    } else {
        None
    };
    Ok(injected_to)
}

/// Run `apply` under the index write lock, but only if the stash still holds `probed` for
/// this key. Returns `None`, with nothing applied, when it holds something else. A probe
/// takes seconds and runs outside any lock, so a human can store a new value while it is in
/// flight. A 401 for the old value must not mark the new one stale, and an Ok must not
/// clear a flag the new one earned. [`store_and_inject_gated`] and `tokenstash import` write
/// the stash under this same lock, so no store can land between the comparison here and
/// `apply`.
pub fn if_still_stored<T>(ctx: &Ctx, name: &str, identity: &str, probed: Option<&SecretString>, apply: impl FnOnce() -> Result<T>) -> Result<Option<T>> {
    ctx.db.locked(|| {
        let now = ctx.stash.get(&stash_key(name, identity))?;
        if now.as_ref().map(|v| v.expose_secret()) != probed.map(|v| v.expose_secret()) {
            return Ok(None);
        }
        apply().map(Some)
    })
}

/// Restore autocommit after any failure in the raw `BEGIN IMMEDIATE` transaction. SQLite
/// leaves a transaction active after some COMMIT failures (notably deferred constraints),
/// so the COMMIT error path must explicitly roll back just like a statement error does.
fn rollback_store(ctx: &Ctx, cause: anyhow::Error) -> anyhow::Error {
    if ctx.db.conn.is_autocommit() {
        return cause;
    }
    match ctx.db.conn.execute_batch("ROLLBACK") {
        Ok(()) if ctx.db.conn.is_autocommit() => cause,
        Ok(()) => cause.context("rolling back the failed store left the index transaction active"),
        Err(_) if ctx.db.conn.is_autocommit() => cause,
        Err(e) => cause.context(format!("rolling back the failed store also failed: {e}")),
    }
}

/// The index row, the audit line and the grant for a value that is now in the stash. Runs
/// inside the caller's transaction.
#[allow(clippy::too_many_arguments)]
fn record_stored(ctx: &Ctx, name: &str, identity: &str, provider: Option<String>, source_url: Option<String>, sensitive: bool, project: &Path, agent: &str, verified: Verified, grant_source: &str, pid: &str) -> Result<()> {
    ctx.db.upsert_secret(&crate::db::SecretMeta {
        name: name.into(),
        identity: identity.into(),
        provider,
        sensitive,
        source_url,
        created: crate::now(),
        last_used: Some(crate::now()),
        stale: false,
        last_verified: if verified == Verified::Ok { Some(crate::now()) } else { None },
        stale_reason: None,
        stale_source: None,
        next_probe: None,
        verify_off: verified == Verified::Skipped,
    })?;
    ctx.db.audit(Some(pid), Some(agent), "store", Some(name), Some(identity), None)?;
    // The human just handled this key for this project: that is the grant — this key,
    // this identity, this workspace, nothing broader.
    if project.is_dir() {
        // The directory the human is answering for: if its record no longer matches it,
        // the human's paste is the pairing of the new directory.
        let ws = ctx.db.workspace_for(project)?;
        if ws.fingerprint_ok {
            ctx.db.grant(&ws.id, name, identity, crate::db::GRANT_KEY, grant_source)?;
        } else {
            // The record is for a directory that no longer exists here. A bare paste must
            // not silently wipe it; the next request pairs this directory with a card, and
            // answering that is what replaces the record.
            ctx.db.audit(Some(pid), Some(agent), "grant.skipped", Some(name), Some(identity), Some("directory re-created since it was paired; it will pair again on its next request"))?;
        }
    }
    Ok(())
}

/// The grant source an answered approval card records, by its kind.
fn approval_grant_source(kind: &str) -> &'static str {
    match kind {
        APPROVAL_ONCE => crate::db::GRANT_ONCE,
        APPROVAL_SENSITIVE => crate::db::GRANT_SENSITIVE,
        _ => crate::db::GRANT_PAIRING,
    }
}

/// `seen` is the list of names the human was shown; if the card grew since (an agent
/// asked for more while the page was open) the answer is refused and the human re-reads.
pub fn answer_approval(ctx: &Ctx, task: &Task, decision: Decision, seen: Option<&[String]>) -> Result<AnswerResult> {
    if task.kind != TaskKind::Approval {
        bail!("task {} is not an approval task", task.id);
    }
    if task.status != TaskStatus::Pending {
        bail!("task {} is already {}", task.id, task.status.as_str());
    }
    // 1. Decide on the card as it is under the index write lock. The re-read, the comparison
    //    with what the human was shown, the grants and the close all happen on that one
    //    version. An agent growing the card takes the same lock (`create_approval_task`),
    //    so its merge lands before the re-read, and the comparison refuses, or after the
    //    close, and it files a new card. Compared outside the lock, a name added in between
    //    was closed with the card, so a denial recorded a key the human never saw.
    //    Every grant plus the task's answered status commit together. Once this commits the
    //    human's answer is final and nothing can ask them again. A one-time approval
    //    (program-derived, `run`) records the answer but no grant, so the next request for
    //    the same key in this project asks again, by design.
    if !ctx.db.conn.is_autocommit() {
        bail!("answer_approval called inside a transaction");
    }
    ctx.db.conn.execute_batch("BEGIN IMMEDIATE").context("locking the index")?;
    let decided = (|| -> Result<Task> {
        let task = ctx.db.get_task(&task.id)?.unwrap_or_else(|| task.clone());
        if let Some(seen) = seen {
            let mut a: Vec<&String> = task.names.iter().collect(); a.sort();
            let mut b: Vec<&String> = seen.iter().collect(); b.sort();
            if a != b {
                bail!("this card changed since you read it (it now lists {}); reload it and decide again", task.names.iter().map(|n| n.strip_suffix("@default").unwrap_or(n)).collect::<Vec<_>>().join(", "));
            }
        }
        let pid = task.project.clone();
        if decision == Decision::Deny {
            if !ctx.db.close_task_if_open(&task.id, TaskStatus::Denied, None)? {
                bail!("task {} was already answered somewhere else", task.id);
            }
            ctx.db.audit(Some(&pid), Some(&task.agent), "deny", None, None, Some(&task.names.join(",")))?;
            return Ok(task);
        }
        let project = Path::new(&pid);
        let kind = task.expects.as_str();
        if decision == Decision::AllowBroad && kind != APPROVAL_PAIRING {
            bail!("only a pairing card can grant broadly");
        }
        if kind != APPROVAL_ONCE {
            // The human is pairing THIS directory. If the record on file is for a directory
            // that no longer exists at this path, replace it (revoking the old grants).
            let ws = match ctx.db.find_workspace(project)? {
                Some(ws) => ws,
                None if project.is_dir() => ctx.db.repair_workspace(project)?,
                None => bail!("{} no longer exists", crate::project::short(project)),
            };
            for entry in &task.names {
                let (n, identity) = split_identity(entry);
                ctx.db.grant(&ws.id, n, identity, crate::db::GRANT_KEY, approval_grant_source(kind))?;
                if decision == Decision::AllowBroad {
                    ctx.db.grant(&ws.id, "*", identity, crate::db::GRANT_BROAD, crate::db::GRANT_PAIRING)?;
                }
            }
        }
        if !ctx.db.close_task_if_open(&task.id, TaskStatus::Answered, None)? {
            bail!("task {} was already answered somewhere else; nothing was granted", task.id);
        }
        ctx.db.audit(Some(&pid), Some(&task.agent), "approve", None, None, Some(&format!("{}{}: {}", kind, if decision == Decision::AllowBroad { "+broad" } else { "" }, task.names.join(","))))?;
        Ok(task)
    })();
    let task = match decided {
        Ok(t) => match ctx.db.conn.execute_batch("COMMIT") {
            Ok(()) => t,
            Err(e) => return Err(rollback_store(ctx, anyhow!(e).context("recording the answer"))),
        },
        Err(e) => return Err(rollback_store(ctx, e)),
    };
    if decision == Decision::Deny {
        return Ok(AnswerResult::Denied);
    }
    let task = &task;
    let pid = task.project.clone();
    let project = Path::new(&pid);
    let kind = task.expects.as_str();
    let grant_source = approval_grant_source(kind);
    // 2. Inject each requested identity. Failures are collected and surfaced after all
    //    entries are attempted; the approval itself is already recorded.
    let mut injected = vec![];
    let mut replaced = vec![];
    let mut failures = vec![];
    let mut budget = crate::need::ProbeBudget::default();
    for entry in &task.names {
        if entry == "*" {
            continue;
        }
        let (n, identity) = split_identity(entry);
        // A card can gate a key that does not exist yet: a `run`-derived request for a
        // generatable name is approved *before* anything is generated, so the stash is
        // empty here. Approving is the human saying yes to the delivery — generate it now,
        // or the card would be answered and nothing would ever arrive.
        let stashed = ctx.stash.get(&stash_key(n, identity))?;
        let stashed = match stashed {
            Some(v) => Some(v),
            None => match registry::lookup(n).and_then(|p| p.generate.clone()) {
                Some(spec) if project.is_dir() => {
                    // Same rule as `need`: a value the env file already holds is kept, not
                    // overwritten — minting a new JWT_SECRET over a live one logs every user out.
                    let adopted = crate::need::adoptable(project, &ctx.cfg.env_file, n);
                    let source = if adopted.is_some() { crate::db::GRANT_ON_DISK } else { crate::db::GRANT_GENERATED };
                    match adopted.or_else(|| crate::need::generate(&spec)) {
                    Some(v) => {
                        match store_and_inject(ctx, n, identity, &v, registry::lookup(n).map(|p| p.provider.clone()), None, false, project, &task.agent, None, Verified::Unknown, source) {
                            Ok(_) => injected.push(n.to_string()),
                            Err(e) => failures.push(format!("{n}: {e:#}")),
                        }
                        None // delivered here; the loop below is for stashed values
                    }
                    None => { failures.push(format!("{n}: could not generate a value")); None }
                    }
                }
                _ => None,
            },
        };
        if let Some(v) = stashed {
            if project.is_dir() {
                // The approval is the authorization; delivery still verifies on use. A key
                // the provider rejects becomes a Replace card for this project instead of
                // a dead value in its env file.
                match crate::need::deliver(ctx, project, &task.agent, n, identity, &v, Some("after-approval"), grant_source, &mut budget) {
                    Ok(crate::need::Delivery::Injected { .. }) => injected.push(n.to_string()),
                    Ok(crate::need::Delivery::Rejected { reason }) => {
                        let why = format!("Replace {n}: {reason}. The new value is written to {}.", project.join(&ctx.cfg.env_file).display());
                        let req = SecretRequest { why: Some(why), ..Default::default() };
                        create_replacement_task(ctx, project, &task.agent, n, identity, &req)?;
                        replaced.push(n.to_string());
                    }
                    Ok(crate::need::Delivery::NotDelivered) => failures.push(format!("{n}: value changed during delivery; ask again")),
                    Err(e) => failures.push(format!("{n}: {e:#}")),
                }
            }
        }
    }
    if !failures.is_empty() {
        // What the human has to do next depends entirely on what their answer recorded.
        // A pairing or sensitive approval wrote grants, so re-running `need` completes
        // silently. A one-time approval wrote none: the card is the only trace of the yes,
        // so if nothing at all was delivered their decision bought nothing — put the card
        // back rather than make them approve the same request a second time.
        if kind == APPROVAL_ONCE {
            if injected.is_empty() && replaced.is_empty() {
                let _ = ctx.db.reopen_task(&task.id);
                bail!("approval recorded, but nothing could be delivered: {}. The card is still open — fix that and answer it again.", failures.join("; "));
            }
            bail!("approval recorded, but {} failed. A one-time approval covers only this run, so re-running `need` asks again for what did not arrive.", failures.join("; "));
        }
        bail!("approval recorded, but injection failed for {}. Re-run `need`; the approval stands, so it will not ask again.", failures.join("; "));
    }
    Ok(AnswerResult::Approved { injected, replaced })
}

pub fn answer_human(ctx: &Ctx, task: &Task, note: Option<&str>) -> Result<AnswerResult> {
    if task.kind != TaskKind::Human {
        bail!("task {} is not a human task", task.id);
    }
    // Text answers are returned to the agent and shown in task history. A credential must
    // never travel that path; refuse it here rather than trying to redact it later.
    if let Some(n) = note {
        if validate::looks_like_secret(n) {
            bail!("that answer looks like a credential; it would be shown to the agent. Decline this task and have the agent request it with `tokenstash need NAME` instead.");
        }
    }
    if !ctx.db.close_task_if_open(&task.id, TaskStatus::Answered, note)? {
        bail!("task {} was already answered somewhere else", task.id);
    }
    ctx.db.audit(Some(&task.project), Some(&task.agent), "human.done", None, None, Some(&task.title))?;
    Ok(AnswerResult::Done)
}

pub fn deny(ctx: &Ctx, task: &Task, note: Option<&str>) -> Result<AnswerResult> {
    // The note goes back to the agent as the reason. Same rule as a human answer.
    if let Some(n) = note {
        if validate::looks_like_secret(n) {
            bail!("that note looks like a credential; it would be shown to the agent. Deny without it.");
        }
    }
    if !ctx.db.deny_unless_claimed(&task.id, note)? {
        match ctx.db.get_task(&task.id)? {
            Some(t) if t.status == TaskStatus::Pending => bail!("this card is being carried out right now, so it cannot be declined; reload in a minute"),
            Some(t) => bail!("task {} is already {}", task.id, t.status.as_str()),
            None => bail!("task {} is already gone", task.id),
        }
    }
    ctx.db.audit(Some(&task.project), Some(&task.agent), "deny", task.name.as_deref(), None, None)?;
    Ok(AnswerResult::Denied)
}

/// After a key is replaced, every other project that was given this key and whose env
/// file does not already hold the NEW value gets it — otherwise each of them fails next
/// week and files its own card. The comparison happens here, value to value, and is never
/// shown. Projects that no longer exist, or no longer have the variable at all, are left
/// alone.
/// What the post-rotation rewrite did, for the human: the projects updated and the ones
/// that still hold the old value and why (a git-tracked env file, a permission error).
/// Those need a hand before the old key is revoked.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RotationReport {
    pub rewritten: Vec<String>,
    pub skipped: Vec<(String, String)>,
}

pub fn rewrite_replaced_value(ctx: &Ctx, name: &str, identity: &str, new: &SecretString, answering_project: &str) -> Result<RotationReport> {
    let mut report = RotationReport::default();
    // A past delivery is not a standing grant. Only workspaces the human granted this key
    // (exactly, or broadly for its identity) are rewritten: a one-time `run` approval or an
    // on-disk match never authorised future values, and a re-created directory is not the
    // one that was paired (`workspaces_granted` returns records; the fingerprint is
    // re-checked below).
    let meta = ctx.db.get_secret(name, identity)?;
    let sensitive = meta.as_ref().map(|m| m.sensitive).unwrap_or(false) || registry::lookup(name).map(|p| p.sensitive).unwrap_or(false);
    let granted = ctx.db.workspaces_granted(name, identity, crate::trust::broad_applies(sensitive, registry::lookup(name).is_some()))?;
    for project in ctx.db.delivered_projects(name, identity)? {
        if project == answering_project {
            continue;
        }
        let dir = Path::new(&project);
        if !dir.is_dir() {
            continue;
        }
        // A DB error here used to abort the whole fan-out with the value already stored:
        // some projects rewritten, the rest untouched, and no report of either. One project
        // failing is one line in the report.
        let current = match ctx.db.find_workspace(dir) {
            Ok(w) => w,
            Err(e) => {
                report.skipped.push((project.clone(), format!("could not read its workspace record ({e:#})")));
                continue;
            }
        };
        let still_granted = granted.iter().any(|w| w.root == project) && current.map(|w| granted.iter().any(|g| g.id == w.id)).unwrap_or(false);
        if !still_granted {
            let why = "no standing grant for this key here; it will ask on its next `need`".to_string();
            let _ = ctx.db.audit(Some(&project), None, "rotate.skip", Some(name), Some(identity), Some(&why));
            report.skipped.push((project.clone(), why));
            continue;
        }
        // Both of these used to `continue` in silence. A project whose env file cannot be
        // resolved or read still holds the old value, and the human is about to revoke it
        // on the strength of this report — so it has to be named, not dropped.
        let env_path = match crate::envfile::resolve(dir, &ctx.cfg.env_file) {
            Ok(p) => p,
            Err(e) => {
                report.skipped.push((project.clone(), format!("cannot locate its env file ({e:#})")));
                continue;
            }
        };
        if !env_path.exists() {
            continue; // nothing of ours there to replace
        }
        let Some(text) = crate::envfile::read_regular_file(&env_path) else {
            report.skipped.push((project.clone(), format!("cannot read {} (unreadable, or not a regular file)", env_path.display())));
            continue;
        };
        let needs_update = text.lines().filter_map(crate::envfile::parse_line).any(|(k, v)| k == name && v != new.expose_secret());
        if !needs_update {
            // A `NAME=` line we cannot parse is not "no old value here" — it is a value we
            // cannot compare (an unterminated quote written by an older build). Say so
            // rather than counting the project as clean.
            let prefix = format!("{name}=");
            if text.lines().any(|l| { let l = l.trim_start().strip_prefix("export ").unwrap_or(l.trim_start()); l.starts_with(&prefix) && crate::envfile::parse_line(l).is_none() }) {
                report.skipped.push((project.clone(), format!("its {} holds a {name}= line this version cannot read; replace it by hand", env_path.display())));
            }
            continue;
        }
        match crate::envfile::write(dir, &ctx.cfg.env_file, name, new) {
            Ok(_) => {
                let _ = ctx.db.audit_grant(Some(&project), None, "inject", Some(name), Some(identity), Some("after-rotation"), crate::db::GRANT_ROTATION);
                report.rewritten.push(project.clone());
            }
            Err(e) => {
                let why = format!("{e:#}");
                let _ = ctx.db.audit(Some(&project), None, "rotate.skip", Some(name), Some(identity), Some(&why));
                report.skipped.push((project.clone(), why));
            }
        }
    }
    Ok(report)
}

/// The human asked to replace a key: mark it stale and file the replacement card now.
pub fn rotate(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    if ctx.db.get_secret(name, identity)?.is_none() {
        bail!("{name}@{identity} is not in the stash; use `tokenstash need {name}` to add it");
    }
    ctx.db.mark_stale(name, identity, true, Some(crate::db::Db::ROTATE_REASON), Some(crate::db::STALE_ROTATE))?;
    ctx.db.audit(Some(&pid), Some(agent), "rotate", Some(name), Some(identity), None)?;
    let req = SecretRequest { why: Some(format!("Replace {name}: {}. Paste the new key first, then revoke the old one in the dashboard.", crate::db::Db::ROTATE_REASON)), ..Default::default() };
    create_replacement_task(ctx, project, agent, name, identity, &req)
}

/// What a report changed. Never returned to the agent (see `report_bad`); for tests and
/// the CLI's own output.
#[derive(Debug, Clone, PartialEq)]
pub enum ReportOutcome {
    /// Not delivered here, on cooldown, unknown: nothing changed.
    Ignored,
    /// The registry probe accepted the key: the report was wrong.
    FalseReport,
    /// Marked stale (by probe verdict, or by the report when no probe exists).
    MarkedStale,
}

/// An agent says a provider rejected a key. The agent is the only sensor tokenstash has —
/// it is never in the request path — but its word is a claim, not a verdict:
/// - only a project that actually received the key can report it (otherwise: ignored, and
///   the caller cannot tell — no stash-existence oracle);
/// - when the registry has a liveness check, the probe decides: a hostile repo cannot make
///   the provider reject a live key;
/// - one report per (project, key) per task_ttl_hours; a probe that says Ok records a
///   false report and further reports are ignored for the window.
///
/// The replacement card always names the reporting project and agent.
pub fn report_bad(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, status: Option<u16>) -> Result<ReportOutcome> {
    let pid = project.to_string_lossy().to_string();
    if !ctx.db.has_delivered(&pid, name, identity)? {
        return Ok(ReportOutcome::Ignored);
    }
    let Some(meta) = ctx.db.get_secret(name, identity)? else { return Ok(ReportOutcome::Ignored) };
    if meta.stale {
        return Ok(ReportOutcome::Ignored); // already a miss; nothing to add
    }
    // One report per (project, key) per TTL — but a report made BEFORE the current value
    // was stored is about a previous value and must not shadow a report about this one.
    let ttl_since = ctx.cfg.ttl_since();
    let since = if meta.created > ttl_since { meta.created.clone() } else { ttl_since };
    if ctx.db.recent_report(&pid, name, identity, &since)?.is_some() {
        return Ok(ReportOutcome::Ignored);
    }
    // Only the status is recorded. The provider's message is agent-controlled text that may
    // echo a key (this one, or a previous one the redactor no longer knows); nothing from it
    // is persisted or shown.
    let detail = format!("HTTP {}", status.map(|s| s.to_string()).unwrap_or_else(|| "?".into()));
    let provider = registry::lookup(name);
    let value = ctx.stash.get(&stash_key(name, identity))?;
    let has_check = provider.and_then(|p| p.check.as_ref()).is_some();
    let verdict = match (provider.and_then(|p| p.check.as_ref()), value.as_ref()) {
        (Some(check), Some(v)) => ctx.probe.run(check, v, validate::TIMEOUT_HUMAN),
        _ => None,
    };
    let date = crate::now();
    // The verdict is about the value read above. If a human stored another one while the
    // probe ran, it says nothing about that one. No flag changes, and the audit row left
    // behind is not one the cooldown counts against reports about the new value.
    let applied = if_still_stored(ctx, name, identity, value.as_ref(), || match verdict {
        Some(Liveness::Ok) => {
            ctx.db.set_verified(name, identity)?;
            ctx.db.audit(Some(&pid), Some(agent), "false_report", Some(name), Some(identity), Some(&detail))?;
            Ok(ReportOutcome::FalseReport)
        }
        Some(Liveness::Rejected(code)) => {
            let reason = format!("rejected by {} (HTTP {code}) on {date}, reported by {agent} in {}", provider.map(|p| p.provider.as_str()).unwrap_or("the provider"), crate::project::short(project));
            ctx.db.mark_stale(name, identity, true, Some(&reason), Some(crate::db::STALE_REPORT))?;
            ctx.db.audit(Some(&pid), Some(agent), "report", Some(name), Some(identity), Some(&detail))?;
            Ok(ReportOutcome::MarkedStale)
        }
        // The provider has a probe but it could not be reached: no verdict, no change. The
        // agent retries later; the human is not asked on the strength of an offline report.
        Some(Liveness::Unknown(_)) => {
            ctx.db.audit(Some(&pid), Some(agent), "report.unverified", Some(name), Some(identity), Some(&detail))?;
            Ok(ReportOutcome::Ignored)
        }
        // No probe exists for this provider: the report stands, and the card says exactly
        // who made it and that it is unverified.
        None if !has_check => {
            let reason = format!("reported rejected ({detail}) on {date} by {agent} in {} — unverified (no liveness check for this provider)", crate::project::short(project));
            ctx.db.mark_stale(name, identity, true, Some(&reason), Some(crate::db::STALE_REPORT))?;
            ctx.db.audit(Some(&pid), Some(agent), "report", Some(name), Some(identity), Some(&detail))?;
            Ok(ReportOutcome::MarkedStale)
        }
        None => Ok(ReportOutcome::Ignored),
    })?;
    match applied {
        Some(outcome) => Ok(outcome),
        None => {
            ctx.db.audit(Some(&pid), Some(agent), "report.superseded", Some(name), Some(identity), Some(&format!("{detail}; the stored value changed while the report was checked")))?;
            Ok(ReportOutcome::Ignored)
        }
    }
}
