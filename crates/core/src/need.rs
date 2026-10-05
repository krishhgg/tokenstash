//! `need`: the one call an agent makes. Hit → inject silently (unless gated). Miss → file a task.

use crate::db::TaskStatus;
use crate::stash::stash_key;
use crate::tasks::{self, Ctx, SecretRequest};
use crate::trust::{self, Gate, GateReason};
use crate::db::GRANT_PASTE;
use crate::registry;
use crate::validate::Liveness;
use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct NeedOpts {
    pub req: SecretRequest,
    pub identity: Option<String>,
    pub blocking: bool,
    pub timeout: Duration,
    /// Ask again even if the user recently denied this key for this project.
    pub force: bool,
    /// Never inject silently: route every hit through a fresh approval task, even if this
    /// project was approved before. Used when the request was derived from untrusted input
    /// (a program's output in `run`) — each invocation needs its own human yes.
    pub require_approval: bool,
    /// An agent asking again after the person said no (`need --force` from an agent). With
    /// `force`, a denied key gets a fresh card, and never arrives on the strength of a broad
    /// grant or an on-disk match: those decided about the directory before the no.
    pub ask_again: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    /// `unverified`: the key has a registry probe that was due but could not run (provider
    /// unreachable, rate-limited, or the per-call probe budget was spent). Delivered anyway.
    Injected { name: String, identity: String, written_to: String, generated: bool, unverified: bool },
    Pending { name: String, identity: String, task_id: String, title: String, url: Option<String> },
    Denied { name: String, task_id: String },
    Expired { name: String, task_id: String },
}

impl Outcome {
    pub fn name(&self) -> &str {
        match self {
            Outcome::Injected { name, .. } | Outcome::Pending { name, .. } | Outcome::Denied { name, .. } | Outcome::Expired { name, .. } => name,
        }
    }
    pub fn is_pending(&self) -> bool {
        matches!(self, Outcome::Pending { .. })
    }
}

/// Auto-generate local secrets (session secrets etc.) instead of asking a human.
pub(crate) fn generate(spec: &str) -> Option<SecretString> {
    use rand::RngCore;
    let (kind, n) = spec.split_once(':')?;
    let n: usize = n.parse().ok()?;
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    let s = match kind {
        "base64" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        }
        "hex" => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        _ => return None,
    };
    Some(SecretString::from(s))
}

/// The identity a generated secret is stored under: one per project directory.
///
/// A generated value has no provider account behind it — it is this application's signing
/// key. Stored under the plain `default` identity it would be one value shared by every
/// project that asks, so a directory holding a broad grant would silently receive another
/// application's `JWT_SECRET` and could mint sessions for it. The label is the directory
/// name plus a digest of its canonical path: readable in `tokenstash list`, distinct per
/// directory, and stable across a re-pair (unlike the workspace id).
pub fn project_identity(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    let name: String = project
        .file_name()
        .map(|n| n.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '-' }).take(24).collect())
        .unwrap_or_default();
    let name = if name.is_empty() { "project".to_string() } else { name };
    let digest = format!("{:x}", Sha256::digest(project.as_os_str().as_encoded_bytes()));
    format!("{name}-{}", &digest[..6])
}

pub fn need(ctx: &Ctx, project: &Path, agent: &str, names: &[String], opts: &NeedOpts) -> Result<Vec<Outcome>> {
    need_with_budget(ctx, project, agent, names, opts, &mut ProbeBudget::default())
}

/// `need` with a caller-owned probe budget, for callers that issue several `need`s in one
/// request (the MCP server, one per name) and must not pay one timeout per name offline.
pub fn need_with_budget(ctx: &Ctx, project: &Path, agent: &str, names: &[String], opts: &NeedOpts, budget: &mut ProbeBudget) -> Result<Vec<Outcome>> {
    ctx.db.expire_overdue()?;
    // Approvals, bindings, and tasks are keyed by the resolved path, so a symlink that is
    // later retargeted cannot inherit another project's approval.
    let project = &project.canonicalize().with_context(|| format!("project directory {} does not exist", project.display()))?;
    if let Some(why) = trust::refused_root(project) {
        anyhow::bail!("{} is {why}; tokenstash does not deliver keys there. Run the agent (or this command) in the project directory.", project.display());
    }
    let pid = project.to_string_lossy().to_string();
    // First contact creates the workspace record; every later decision hangs off it.
    let ws = ctx.db.workspace_for(project)?;
    let mut outcomes: Vec<Outcome> = Vec::with_capacity(names.len());
    let mut pairing: Vec<String> = vec![];   // name@identity needing the pairing card
    let mut sensitive_gated: Vec<String> = vec![]; // name@identity needing its own card
    let mut once: Vec<String> = vec![];      // run-derived: one-time approval, every time

    for name in names {
        if !valid_name(name) {
            anyhow::bail!("{name:?} is not an environment variable name (letters, digits and underscores, not starting with a digit)");
        }
        let provider = registry::lookup(name);
        if let Some(i) = opts.identity.as_deref() {
            if !valid_identity(i) {
                anyhow::bail!("{i:?} is not an identity (letters, digits, dot, dash and underscore, up to 64 characters)");
            }
        }
        // A generated secret is this directory's own signing key and nothing else's. The
        // caller does not get to choose its identity: `identity: "default"` from project B
        // would hit the value an older tokenstash stored for project A under the shared
        // label, and a broad grant would deliver A's key to B without a card. The binding
        // is ignored for the same reason.
        let identity = if provider.and_then(|p| p.generate.as_deref()).is_some() {
            project_identity(project)
        } else {
            opts.identity.clone().or(ctx.db.binding(&ws.id, name)?).unwrap_or_else(|| "default".into())
        };
        // When this read finds a generated key missing or stale, the store that follows
        // looks for a store recorded after this mark (`tasks::store_generated`).
        let read_mark = ctx.db.audit_mark()?;
        let hit = ctx.stash.get(&stash_key(name, &identity))?;

        if let Some(value) = hit {
            let mut meta = ctx.db.get_secret(name, &identity)?;
            if meta.is_none() {
                // The stash is per-user; this index is per-TOKENSTASH_HOME. A key stored under
                // another home is real and usable, but `list` here would deny it exists —
                // a stash that says "empty" and then injects is the worst kind of surprise.
                // Adopt it into this index, visibly, before anything else happens.
                // Sensitivity as a paste derives it: the registry tag, or the value
                // matching the provider's sensitive pattern (a live-mode Stripe key).
                let by_pattern = registry::is_sensitive(provider, &value).unwrap_or(true);
                let m = crate::db::SecretMeta {
                    name: name.clone(),
                    identity: identity.clone(),
                    provider: provider.map(|p| p.provider.clone()),
                    sensitive: provider.map(|p| p.sensitive).unwrap_or(false) || by_pattern,
                    source_url: provider.map(|p| p.url.clone()),
                    created: crate::now(),
                    last_used: None,
                    stale: false,
                    last_verified: None,
                    stale_reason: None,
                    stale_source: None,
                    next_probe: None,
                    verify_off: false,
                };
                // The row and its audit line commit together, because a generated key's store
                // reads them as one record (`Db::recorded_since`).
                ctx.db.locked(|| {
                    ctx.db.upsert_secret(&m)?;
                    ctx.db.audit(Some(&pid), Some(agent), "adopt", Some(name), Some(&identity), Some("found in the stash but not in this home's index"))
                })?;
                meta = Some(m);
            }
            let sensitive = meta.as_ref().map(|m| m.sensitive).unwrap_or(false) || provider.map(|p| p.sensitive).unwrap_or(false);
            let registered = provider.is_some();
            // A program's own output chose the key (`run`): a fresh yes every invocation,
            // before any grant or on-disk check can open the gate.
            if opts.require_approval {
                once.push(format!("{name}@{identity}"));
                outcomes.push(Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: String::new(), title: String::new(), url: None });
                continue;
            }
            let gate = match trust::gate(ctx.db, &ws, name, &identity, sensitive, registered)? {
                Gate::NeedsApproval { reason: GateReason::Pairing } => {
                    // The env file may already hold this very value (a copy that brought its
                    // .env.local along). One check per (directory, key) per TTL: a planted
                    // guess must not be an oracle for the stash.
                    let since = ctx.cfg.ttl_since();
                    if !ctx.db.recent_on_disk_miss(&pid, name, &identity, &since)? && crate::envfile::has(project, &ctx.cfg.env_file, name) {
                        if trust::on_disk_equivalent(project, &ctx.cfg.env_file, name, &value) {
                            Gate::Open { source: crate::db::GRANT_ON_DISK.into() }
                        } else {
                            ctx.db.audit(Some(&pid), Some(agent), "on_disk.miss", Some(name), Some(&identity), Some("env file not comparable or holds a different value; no comparison for this key until the TTL passes"))?;
                            Gate::NeedsApproval { reason: GateReason::Pairing }
                        }
                    } else {
                        Gate::NeedsApproval { reason: GateReason::Pairing }
                    }
                }
                g => g,
            };
            // A grant for this exact key is the human deciding about this key. A broad grant
            // (or an on-disk match) is not: it was a decision about the directory, made
            // earlier, and it must not quietly overrule "no" to this key here. Without this
            // a denied card followed by a paste elsewhere turns into a silent delivery.
            let denied_now = |ctx: &Ctx| -> Result<bool> {
                let since = ctx.cfg.ttl_since();
                Ok(ctx.db.recent_denial(&pid, name, &identity, &since)?.is_some() || denied_card_for(ctx, &pid, &format!("{name}@{identity}"), &since)?.is_some())
            };
            let gate = match &gate {
                // Asked again after a no: the person answers a card again, whatever grant
                // opened the gate before the no, an exact one included (a grant outlives
                // `forget`, and the key may since have been stored from another directory).
                Gate::Open { .. } if opts.ask_again && denied_now(ctx)? => Gate::NeedsApproval { reason: if sensitive { GateReason::Sensitive } else { GateReason::Pairing } },
                Gate::Open { source } if source == crate::db::GRANT_BROAD || source == crate::db::GRANT_ON_DISK => {
                    let since = ctx.cfg.ttl_since();
                    // Both kinds of "no" count: a refused paste card and a refused pairing or
                    // sensitive card that named this key. Only the pairing path used to look
                    // at the second, so "deny the card, later allow-broad on another key"
                    // delivered the denied key silently.
                    let denied = match ctx.db.recent_denial(&pid, name, &identity, &since)? {
                        Some(d) => Some(d.id),
                        None => denied_card_for(ctx, &pid, &format!("{name}@{identity}"), &since)?,
                    };
                    match denied {
                        Some(tid) if !opts.force => {
                            ctx.db.audit(Some(&pid), Some(agent), "deny.honored", Some(name), Some(&identity), Some("a broad grant does not overrule a denial for this key here"))?;
                            outcomes.push(Outcome::Denied { name: name.clone(), task_id: tid });
                            continue;
                        }
                        _ => gate,
                    }
                }
                _ => gate,
            };
            match gate {
                Gate::Open { source } => match deliver(ctx, project, agent, name, &identity, &value, None, &source, budget)? {
                    Delivery::Injected { path, unverified } => {
                        outcomes.push(Outcome::Injected { name: name.clone(), identity, written_to: path.display().to_string(), generated: false, unverified });
                    }
                    Delivery::Rejected { reason } => outcomes.push(replacement(ctx, project, agent, name, &identity, opts, &reason, read_mark)?),
                    // The value changed under an on-disk delivery: the directory never held the
                    // new one, so it pairs like any other first delivery.
                    Delivery::NotDelivered => {
                        pairing.push(format!("{name}@{identity}"));
                        outcomes.push(Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: String::new(), title: String::new(), url: None });
                    }
                },
                Gate::NeedsApproval { reason } => {
                    // Carry the identity into the approval so the approver injects the key
                    // that was actually requested, not the binding/default.
                    let entry = format!("{name}@{identity}");
                    match reason {
                        GateReason::Pairing => pairing.push(entry),
                        GateReason::Sensitive => sensitive_gated.push(entry),
                    }
                    // placeholder; task id filled below
                    outcomes.push(Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: String::new(), title: String::new(), url: None });
                }
            }
            continue;
        }

        // Miss. Generate locally if the registry says so.
        if let Some(spec) = provider.and_then(|p| p.generate.as_deref()) {
            // Generating is delivering: it writes a value into the env file and leaves a
            // standing grant. A `run`-derived request (a program's own output chose the
            // name) gets the same one-time approval here as it does on a hit.
            if opts.require_approval {
                once.push(format!("{name}@{identity}"));
                outcomes.push(Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: String::new(), title: String::new(), url: None });
                continue;
            }
            // Adopt before generating. This project's env file may already hold a value
            // under this name — one an earlier tokenstash generated under the old shared
            // identity, or one the human wrote by hand. Minting a new one would overwrite
            // it: every session signed with the old JWT_SECRET becomes invalid, and
            // anything encrypted with the old ENCRYPTION_KEY becomes unreadable.
            if let Some(existing) = adoptable(project, &ctx.cfg.env_file, name) {
                tasks::store_and_inject(ctx, name, &identity, &existing, provider.map(|p| p.provider.clone()), None, false, project, agent, None, tasks::Verified::Unknown, crate::db::GRANT_ON_DISK)?;
                ctx.db.audit(Some(&pid), Some(agent), "adopt.generated", Some(name), Some(&identity), Some("kept the value this project's env file already held instead of generating a new one"))?;
                outcomes.push(Outcome::Injected { name: name.clone(), identity, written_to: project.join(&ctx.cfg.env_file).display().to_string(), generated: false, unverified: false });
                continue;
            }
            if let Some(v) = generate(spec) {
                let (p, generated) = tasks::store_generated(ctx, name, &identity, &v, project, agent, read_mark)?;
                outcomes.push(Outcome::Injected { name: name.clone(), identity, written_to: p.map(|p| p.display().to_string()).unwrap_or_default(), generated, unverified: false });
                continue;
            }
        }

        // Honor a recent refusal: "denied — do not ask again" must actually mean that.
        if !opts.force {
            let since = ctx.cfg.ttl_since();
            if let Some(d) = ctx.db.recent_denial(&pid, name, &identity, &since)? {
                outcomes.push(Outcome::Denied { name: name.clone(), task_id: d.id });
                continue;
            }
        }
        let t = tasks::create_secret_task(ctx, project, agent, name, &identity, &opts.req)?;
        outcomes.push(Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: t.id, title: t.title, url: t.url });
    }

    // One card per kind per call. "Deny" on a card is remembered for task_ttl_hours, like
    // a denied paste: every entry the human already refused for this workspace comes back
    // Denied instead of a fresh card. Without this a program failing in a loop files a new
    // card per failure until the human clicks through.
    for (entries, kind) in [(&pairing, tasks::ApprovalKind::Pairing), (&sensitive_gated, tasks::ApprovalKind::Sensitive), (&once, tasks::ApprovalKind::Once)] {
        if entries.is_empty() {
            continue;
        }
        let mut denied_entries: Vec<(String, String)> = vec![]; // (entry, denying task id)
        if !opts.force {
            let since = ctx.cfg.ttl_since();
            for d in ctx.db.recent_denied_approvals(&pid, &since)? {
                // A denied "this run only" card says nothing about pairing; a denied pairing
                // or sensitive card does block a later one-time request for the same key.
                if d.expects == tasks::APPROVAL_ONCE && kind != tasks::ApprovalKind::Once {
                    continue;
                }
                for g in entries {
                    if denied_entries.iter().any(|(e, _)| e == g) {
                        continue;
                    }
                    let name_only = tasks::split_identity(g).0.to_string();
                    if d.names.iter().any(|n| n == g || n == &name_only) {
                        denied_entries.push((g.clone(), d.id.clone()));
                    }
                }
            }
            for o in outcomes.iter_mut() {
                if let Outcome::Pending { name, identity, task_id, .. } = o {
                    if task_id.is_empty() {
                        if let Some((_, tid)) = denied_entries.iter().find(|(e, _)| e == &format!("{name}@{identity}")) {
                            *o = Outcome::Denied { name: name.clone(), task_id: tid.clone() };
                        }
                    }
                }
            }
        }
        let denied: Vec<String> = denied_entries.into_iter().map(|(e, _)| e).collect();
        let still: Vec<String> = entries.iter().filter(|g| !denied.contains(g)).cloned().collect();
        if still.is_empty() {
            continue;
        }
        let t = tasks::create_approval_task(ctx, project, agent, &still, kind)?;
        for o in outcomes.iter_mut() {
            if let Outcome::Pending { name, identity, task_id, title, .. } = o {
                if task_id.is_empty() && still.contains(&format!("{name}@{identity}")) {
                    *task_id = t.id.clone();
                    *title = t.title.clone();
                }
            }
        }
    }

    if opts.blocking && outcomes.iter().any(|o| o.is_pending()) {
        wait(ctx, project, &mut outcomes, opts.timeout)?;
    }
    Ok(outcomes)
}

/// Poll until every pending task resolves or the timeout elapses. Callers that already
/// filed tasks use this instead of calling `need` again, so no duplicate tasks are created.
pub fn wait(ctx: &Ctx, project: &Path, outcomes: &mut [Outcome], timeout: Duration) -> Result<()> {
    let project = &project.canonicalize().unwrap_or_else(|_| project.to_path_buf());
    let start = Instant::now();
    let mut budget = ProbeBudget::default();
    loop {
        let mut any_pending = false;
        for o in outcomes.iter_mut() {
            if let Outcome::Pending { name, identity, task_id, .. } = o {
                let Some(t) = ctx.db.get_task(task_id)? else { continue };
                match t.status {
                    TaskStatus::Pending => any_pending = true,
                    TaskStatus::Answered => {
                        // Answered means stored/approved; do not assume injected, and do not
                        // trust a same-named entry already in the file (it may belong to another
                        // identity). Always inject the identity THIS request asked for; the
                        // write is an idempotent upsert.
                        let written: PathBuf = project.join(&ctx.cfg.env_file);
                        let v = ctx.stash.get(&stash_key(name, identity))?
                            .ok_or_else(|| anyhow::anyhow!("task {} is answered but {name}@{identity} is not in the stash", t.id))?;
                        let source = match t.kind {
                            crate::db::TaskKind::Secret => GRANT_PASTE,
                            _ => match t.expects.as_str() { tasks::APPROVAL_ONCE => crate::db::GRANT_ONCE, tasks::APPROVAL_SENSITIVE => crate::db::GRANT_SENSITIVE, _ => crate::db::GRANT_PAIRING },
                        };
                        // "Answered" is not authorisation by itself: a standing approval must
                        // have left a grant for THIS name (a card that grew after the human read
                        // it did not), and a one-time card must have named it.
                        let entry = format!("{name}@{identity}");
                        let authorised = match t.kind {
                            crate::db::TaskKind::Secret => true,
                            _ if t.expects == tasks::APPROVAL_ONCE => t.names.contains(&entry),
                            _ => ctx.db.find_workspace(project)?.map(|w| ctx.db.grant_source(&w.id, name, identity)).transpose()?.flatten().is_some(),
                        };
                        if !authorised {
                            // ask again, on a card of its own
                            let kind = if t.expects == tasks::APPROVAL_SENSITIVE { tasks::ApprovalKind::Sensitive } else { tasks::ApprovalKind::Pairing };
                            let nt = tasks::create_approval_task(ctx, project, &t.agent, &[entry], kind)?;
                            *o = Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: nt.id, title: nt.title, url: nt.url };
                            any_pending = true;
                            continue;
                        }
                        match deliver(ctx, project, &t.agent, name, identity, &v, Some("after-answer"), source, &mut budget)
                            .map_err(|e| anyhow::anyhow!("{name} is stored but could not be delivered to {}: {e:#}", written.display()))?
                        {
                            Delivery::Injected { unverified, .. } => {
                                *o = Outcome::Injected { name: name.clone(), identity: identity.clone(), written_to: written.display().to_string(), generated: false, unverified };
                            }
                            // Approved, then found dead at delivery: file the replacement so
                            // the human sees it now; the caller keeps waiting on the new card.
                            Delivery::Rejected { reason } => {
                                let why = format!("Replace {name}: {reason}. The new value is written to {}.", written.display());
                                let req = SecretRequest { why: Some(why), ..Default::default() };
                                let nt = tasks::create_replacement_task(ctx, project, &t.agent, name, identity, &req)?;
                                *o = Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: nt.id, title: nt.title, url: nt.url };
                                any_pending = true;
                            }
                            Delivery::NotDelivered => any_pending = true,
                        }
                    }
                    TaskStatus::Denied => *o = Outcome::Denied { name: name.clone(), task_id: task_id.clone() },
                    TaskStatus::Expired => *o = Outcome::Expired { name: name.clone(), task_id: task_id.clone() },
                }
            }
        }
        if !any_pending || start.elapsed() > timeout {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Wall-clock a single `need`/`wait`/approval may spend on verify-on-use probes. Past it,
/// remaining keys are delivered unverified: an offline agent asking for five keys must not
/// wait five timeouts.
#[derive(Default)]
pub struct ProbeBudget {
    spent: Duration,
}
impl ProbeBudget {
    pub const MAX: Duration = Duration::from_secs(6);
    /// A budget with nothing left (tests; callers that must not wait on the network).
    pub fn exhausted() -> Self { Self { spent: Self::MAX } }
}

/// Lease taken before a probe goes on the wire, and the backoff after "no verdict".
const PROBE_LEASE: chrono::Duration = chrono::Duration::minutes(10);
const PROBE_BACKOFF_RATE_LIMITED: chrono::Duration = chrono::Duration::minutes(60);
/// After an Ok, no probe for at least this long whatever `verify_every` says: `always`
/// means "every call, at most once a minute", so a `need` loop cannot become a request
/// loop against the user's real quota.
const PROBE_FLOOR: chrono::Duration = chrono::Duration::seconds(60);

/// The routine window as a chrono duration (`Always` → the floor).
fn window(cfg: &crate::config::Config) -> chrono::Duration {
    use crate::config::VerifyEvery::*;
    match cfg.verify_every {
        Always | Never => PROBE_FLOOR,
        Every(d) => chrono::Duration::from_std(d).unwrap_or_else(|_| chrono::Duration::days(1)).max(PROBE_FLOOR),
    }
}

/// An env var name and nothing else: what the env file grammar and the cards can carry.
/// An identity is a label the human reads on a card and a component of the stash key.
/// `@` would split a different key out of `NAME@identity`, `,` is the separator the inbox
/// uses for the list of names on a card, and an empty one makes `split_identity` hand back
/// a name that is not the one requested. None of that is worth tolerating for a field the
/// caller chooses freely.
pub fn valid_identity(identity: &str) -> bool {
    !identity.is_empty()
        && identity.len() <= 64
        && identity.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The value this project's env file already holds for a generatable name, if it is worth
/// keeping: long enough to be a secret and not a placeholder. `cp .env.example .env.local`
/// leaves `JWT_SECRET=changeme`; adopting that would store a known signing key and report
/// it delivered.
pub(crate) fn adoptable(project: &Path, env_file: &str, name: &str) -> Option<SecretString> {
    use secrecy::ExposeSecret;
    let v = crate::envfile::read_value(project, env_file, name)?;
    let s = v.expose_secret();
    if s.chars().count() < tasks::MIN_SECRET_CHARS || crate::envcrawl::is_placeholder(s) {
        return None;
    }
    Some(v)
}

/// Has the person said no to `name` for this project within the TTL: a declined paste card,
/// or a declined pairing or sensitive card that named it? The identity is resolved the way
/// `need` resolves it (the one given, else the project's binding, else `default`). An agent
/// asking again (`need --force`) counts as a second ask only after a no.
pub fn denied_here(ctx: &Ctx, project: &Path, name: &str, identity: Option<&str>) -> Result<bool> {
    let Ok(project) = project.canonicalize() else { return Ok(false) };
    let pid = project.to_string_lossy().to_string();
    let bound = match ctx.db.find_workspace(&project)? { Some(ws) => ctx.db.binding(&ws.id, name)?, None => None };
    let identity = identity.map(String::from).or(bound).unwrap_or_else(|| "default".into());
    let since = ctx.cfg.ttl_since();
    Ok(ctx.db.recent_denial(&pid, name, &identity, &since)?.is_some() || denied_card_for(ctx, &pid, &format!("{name}@{identity}"), &since)?.is_some())
}

/// A denied pairing or sensitive card within the TTL that named this entry. A denied
/// "this run only" card says nothing about the key in general.
fn denied_card_for(ctx: &Ctx, pid: &str, entry: &str, since: &str) -> Result<Option<String>> {
    let name_only = tasks::split_identity(entry).0.to_string();
    for d in ctx.db.recent_denied_approvals(pid, since)? {
        if d.expects == tasks::APPROVAL_ONCE {
            continue;
        }
        if d.names.iter().any(|n| n == entry || n == &name_only) {
            return Ok(Some(d.id));
        }
    }
    Ok(None)
}

pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    name.len() <= 128 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Agent names come from the caller (`--agent`, `TOKENSTASH_AGENT`, MCP `clientInfo.name`)
/// and end up in audit rows and on cards (`found at use by <agent>`). Short and printable,
/// so a caller cannot write the card's body.
pub fn clean_agent(raw: &str) -> String {
    let clean: String = raw.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-')).take(48).collect();
    let clean = clean.trim().to_string();
    if clean.is_empty() { "agent".into() } else { clean }
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub enum Delivery {
    Injected { path: PathBuf, unverified: bool },
    /// The provider rejected the stored value just now. It is marked stale; the caller files
    /// the replacement card. Nothing was written.
    Rejected { reason: String },
    /// The stash value changed under a delivery whose grant does not cover the new one (an
    /// on-disk match, or a broad grant and a sensitive value). Nothing was written; the
    /// caller treats it as a first delivery.
    NotDelivered,
}

enum AtUse {
    NotDue,
    Verified,
    Unverified,
    Rejected(String),
}

/// Hand a stash value to a project. Every path that writes a stored key into an env file
/// after authorization goes through here — the plain hit, the after-approval inject, the
/// after-answer inject — so neither verify-on-use nor the stale flag can be bypassed by
/// taking a different door.
#[allow(clippy::too_many_arguments)]
pub fn deliver(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, value: &SecretString, note: Option<&str>, grant: &str, budget: &mut ProbeBudget) -> Result<Delivery> {
    let pid = project.to_string_lossy().to_string();
    // Re-read: the flag may have been set after the caller looked (a report from another
    // project while an approval card was pending, a probe in another process).
    if let Some(m) = ctx.db.get_secret(name, identity)? {
        if m.stale {
            return Ok(Delivery::Rejected { reason: m.stale_reason.unwrap_or_else(|| "the stored key was marked stale".into()) });
        }
    }
    let unverified = match verify_at_use(ctx, project, agent, name, identity, value, budget)? {
        AtUse::Rejected(reason) => return Ok(Delivery::Rejected { reason }),
        AtUse::Unverified => true,
        AtUse::NotDue | AtUse::Verified => false,
    };
    // The value written is read from the stash under the env file's lock, not taken from the
    // caller, who read it some time ago. A store writes this file under the same lock after
    // its COMMIT and reads the stash there too, so whichever write comes last writes what the
    // stash holds then. Without this, a delivery that read A could write A over the B a
    // human had just stored and written, and report success.
    let mut refused = None;
    let mut changed = false;
    let written = crate::envfile::write_with(project, &ctx.cfg.env_file, name, || {
        let Some(now) = ctx.stash.get(&stash_key(name, identity))? else {
            anyhow::bail!("{name}@{identity} was removed from the stash while it was being delivered; nothing was written");
        };
        if now.expose_secret() == value.expose_secret() {
            return Ok(Some(now));
        }
        // Stored since the caller read it. The new value may itself be stale by now.
        if let Some(m) = ctx.db.get_secret(name, identity)? {
            if m.stale {
                refused = Some(Delivery::Rejected { reason: m.stale_reason.unwrap_or_else(|| "the stored key was marked stale".into()) });
                return Ok(None);
            }
        }
        // On-disk equivalence proved the directory held the OLD value; it says nothing about
        // the new one. A broad grant covers the name only while the value is not sensitive,
        // and a live-mode key can replace a test-mode one.
        if grant == crate::db::GRANT_ON_DISK || (grant == crate::db::GRANT_BROAD && registry::is_sensitive(registry::lookup(name), &now)?) {
            refused = Some(Delivery::NotDelivered);
            return Ok(None);
        }
        changed = true;
        Ok(Some(now))
    })?;
    let Some(path) = written else { return Ok(refused.unwrap_or(Delivery::NotDelivered)) };
    ctx.db.touch_secret(name, identity)?;
    ctx.db.audit_grant(Some(&pid), Some(agent), "inject", Some(name), Some(identity), note, grant)?;
    // A value that changed under the delivery was not the one probed.
    Ok(Delivery::Injected { path, unverified: unverified || changed })
}

/// Re-check a stored key with its provider before delivering it, when due.
///
/// Due = the registry allows this probe unattended (`check.at_use`), the human has not
/// turned it off for this key, `verify_every` says so, no backoff/lease is in force.
/// The probe transmits the key, so this runs only after the trust gate has opened.
fn verify_at_use(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, value: &SecretString, budget: &mut ProbeBudget) -> Result<AtUse> {
    use crate::config::VerifyEvery;
    if matches!(ctx.probe, tasks::Probe::Off) || ctx.cfg.verify_every == VerifyEvery::Never {
        return Ok(AtUse::NotDue);
    }
    let Some(check) = registry::lookup(name).and_then(|p| p.check.as_ref()).filter(|c| c.at_use) else {
        return Ok(AtUse::NotDue);
    };
    let Some(meta) = ctx.db.get_secret(name, identity)? else { return Ok(AtUse::NotDue) };
    if meta.verify_off || meta.stale {
        return Ok(AtUse::NotDue);
    }
    let now = chrono::Utc::now();
    if let VerifyEvery::Every(d) = ctx.cfg.verify_every {
        // A timestamp we cannot parse, or one from the future (clock moved back), counts as
        // "never verified": probing is the safe answer to bad data.
        let fresh = meta.last_verified.as_deref().and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok()).map(|t| {
            let t = t.with_timezone(&chrono::Utc);
            t <= now && now - t < chrono::Duration::from_std(d).unwrap_or_else(|_| chrono::Duration::days(1))
        }).unwrap_or(false);
        if fresh {
            return Ok(AtUse::NotDue);
        }
    }
    // Out of time for this call: deliver unverified without taking a lease, so the next
    // call (or another process) still gets to probe.
    if budget.spent >= ProbeBudget::MAX {
        return Ok(AtUse::Unverified);
    }
    // Backoff, floor and lease live in one column (never the routine window, which is
    // derived from `last_verified` so a config change applies at once): a future
    // `next_probe` means "not now", whoever set it. `claim_probe` is a conditional UPDATE,
    // so two processes racing to the same due key produce one request, not two. A key
    // inside a backoff is delivered, but the caller is told it was not checked.
    if !ctx.db.claim_probe(name, identity, &rfc3339(now + PROBE_LEASE))? {
        return Ok(AtUse::Unverified);
    }
    // The probe gets what is left of the budget, never more than its own timeout, so a
    // request with several slow providers ends near MAX rather than MAX plus a timeout.
    let timeout = crate::validate::TIMEOUT_AT_USE.min(ProbeBudget::MAX - budget.spent);
    let started = Instant::now();
    let verdict = ctx.probe.run(check, value, timeout);
    budget.spent += started.elapsed();
    let Some(verdict) = verdict else { return Ok(AtUse::NotDue) };
    let pid = project.to_string_lossy().to_string();
    // Another process may have replaced the value while the probe was in flight (the human
    // answered a card): a verdict about the old value says nothing about the new one. The
    // comparison and the update share one index write lock, so a store cannot land between
    // them.
    let applied = tasks::if_still_stored(ctx, name, identity, Some(value), || match &verdict {
        Liveness::Ok => {
            ctx.db.set_verified(name, identity)?;
            ctx.db.set_next_probe(name, identity, &rfc3339(chrono::Utc::now() + PROBE_FLOOR))?;
            Ok(AtUse::Verified)
        }
        Liveness::Rejected(code) => {
            let provider = registry::lookup(name).map(|p| p.provider.as_str()).unwrap_or("the provider");
            let reason = format!("rejected by {provider} (HTTP {code}) on {}, found at use by {agent} in {}", crate::now(), crate::project::short(project));
            ctx.db.mark_stale(name, identity, true, Some(&reason), Some(crate::db::STALE_PROBE))?;
            ctx.db.audit(Some(&pid), Some(agent), "probe.rejected", Some(name), Some(identity), Some(&format!("HTTP {code}")))?;
            Ok(AtUse::Rejected(reason))
        }
        Liveness::Unknown(_) => {
            // 403 is a verdict ("live, not permitted here") that will not change: wait a
            // whole window, not a backoff, or a restricted key is probed every ten minutes.
            let wait = if verdict.is_rate_limited() { PROBE_BACKOFF_RATE_LIMITED } else if verdict.is_forbidden() { window(ctx.cfg) } else { PROBE_LEASE };
            ctx.db.set_next_probe(name, identity, &rfc3339(chrono::Utc::now() + wait))?;
            Ok(AtUse::Unverified)
        }
    })?;
    // A dropped verdict leaves the new value unchecked; `deliver` writes it, read again
    // under the env file's lock.
    Ok(applied.unwrap_or(AtUse::Unverified))
}

/// The stash holds a value the project may have, but it is stale: regenerate a generated
/// secret, honour a recent "do not ask again", else file the replacement card.
/// `read_mark` is [`crate::db::Db::audit_mark`] taken just before the caller read the stale
/// value from the stash.
#[allow(clippy::too_many_arguments)]
fn replacement(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, opts: &NeedOpts, reason: &str, read_mark: i64) -> Result<Outcome> {
    let pid = project.to_string_lossy().to_string();
    let provider = registry::lookup(name);
    // Generated secrets are never pasted: regenerate.
    if let Some(spec) = provider.and_then(|p| p.generate.as_deref()) {
        if let Some(v) = generate(spec) {
            let (p, generated) = tasks::store_generated(ctx, name, identity, &v, project, agent, read_mark)?;
            return Ok(Outcome::Injected { name: name.into(), identity: identity.into(), written_to: p.map(|p| p.display().to_string()).unwrap_or_default(), generated, unverified: false });
        }
    }
    if !opts.force {
        let since = ctx.cfg.ttl_since();
        if let Some(d) = ctx.db.recent_denial(&pid, name, identity, &since)? {
            return Ok(Outcome::Denied { name: name.into(), task_id: d.id });
        }
    }
    // The value stays in the stash (a live re-paste of the same value self-heals a false
    // positive); the card says why, so the human can judge the report.
    let why = format!("Replace {name}: {reason}. The new value is written to {}.", project.join(&ctx.cfg.env_file).display());
    let req = SecretRequest { why: Some(why), ..opts.req.clone() };
    let t = tasks::create_replacement_task(ctx, project, agent, name, identity, &req)?;
    Ok(Outcome::Pending { name: name.into(), identity: identity.into(), task_id: t.id, title: t.title, url: t.url })
}
