use crate::cmd::need::status_icon;
use crate::util::{self, App};
use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use secrecy::ExposeSecret;
use std::path::PathBuf;
use tokenstash_core::stash::stash_key;
use tokenstash_core::tasks::{Ctx, Probe};
use tokenstash_core::validate::Liveness;
use tokenstash_core::Config;

#[derive(Args)]
pub struct TasksArgs {
    /// Every project, not just this one.
    #[arg(long)]
    pub all: bool,
    /// Include answered/denied/expired.
    #[arg(long)]
    pub history: bool,
    #[arg(long)]
    pub json: bool,
}

pub fn tasks(a: TasksArgs) -> Result<i32> {
    // Other directories' cards are a person's to see; an agent gets its own.
    if a.all {
        util::require_human("tasks --all", "it lists every directory's cards")?;
    }
    let app = App::open()?;
    app.db.expire_overdue()?;
    let project = tokenstash_core::project::current();
    let pid = project.to_string_lossy().to_string();
    let list = app.db.list_tasks(if a.all { None } else { Some(&pid) }, !a.history)?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(0);
    }
    if list.is_empty() {
        println!("no {}tasks{}", if a.history { "" } else { "open " }, if a.all { "" } else { " in this project" });
        return Ok(0);
    }
    for t in &list {
        let what = match t.kind {
            tokenstash_core::db::TaskKind::Secret => t.name.clone().unwrap_or_default(),
            tokenstash_core::db::TaskKind::Approval => format!("approve {}", crate::util::approval_names(&t.names).join(", ")),
            tokenstash_core::db::TaskKind::Human => t.title.clone(),
        };
        println!("{} {:<10} {:<40} {:<24} {}", status_icon(&t.status), t.id, what, util::short(&t.project), t.agent);
    }
    // Printed to stdout, so the TTY check must be stdout's.
    let state = crate::notify::inbox_state(&app.cfg);
    println!("\ninbox: {}", util::inbox_url_tty(&app.cfg, Some(&app.db), None, state, util::Stream::Stdout));
    if let Some(why) = util::inbox_unavailable(&app.cfg, state) {
        println!("       {why}");
    }
    Ok(0)
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long)]
    pub json: bool,
}

pub fn list(a: ListArgs) -> Result<i32> {
    let app = App::open()?;
    // Every key the person holds is their inventory, not the agent's. An agent gets what this
    // directory may know exists: the keys it was granted or received, as `secrets_list` does.
    let here = if util::looks_human() { None } else { Some(util::keys_here(&app.db, &tokenstash_core::project::current())?) };
    let secrets: Vec<_> = app.db.list_secrets()?.into_iter().filter(|s| here.as_ref().is_none_or(|h| h.contains(&(s.name.clone(), s.identity.clone())))).collect();
    if here.is_some() && !a.json && secrets.is_empty() {
        println!("this directory has not received any key yet (only the keys a directory received or was granted are listed for an agent)");
        return Ok(0);
    }
    if a.json {
        println!("{}", serde_json::to_string_pretty(&secrets)?);
        return Ok(0);
    }
    if secrets.is_empty() {
        println!("no secrets indexed in {}. Run `tokenstash need SOME_KEY` from a project to start.", tokenstash_core::config::config_dir().display());
        println!("(the {} stash itself is per-user; a key stored under another TOKENSTASH_HOME is adopted here, and listed, the first time a project needs it)", app.stash.backend());
        return Ok(0);
    }
    println!("{:<36} {:<10} {:<18} {:<24} LAST USED", "NAME", "IDENTITY", "PROVIDER", "FLAGS");
    for s in &secrets {
        let mut flags = vec![];
        if s.sensitive { flags.push("sensitive"); }
        if s.stale { flags.push("STALE"); }
        if s.verify_off { flags.push("no-verify"); }
        println!("{:<36} {:<10} {:<18} {:<24} {}", s.name, s.identity, s.provider.clone().unwrap_or_default(), flags.join(","), s.last_used.clone().unwrap_or_default());
    }
    for s in secrets.iter().filter(|s| s.stale) {
        println!("  {}@{}: {}", s.name, s.identity, s.stale_reason.clone().unwrap_or_else(|| "stale".into()));
    }
    if secrets.iter().any(|s| s.verify_off) {
        println!("  no-verify: stored with --skip-check / --no-verify, so it is not re-checked before use; `tokenstash check NAME` turns that back on once the provider accepts it");
    }
    println!("\n{} secrets in the {} stash (values never shown)", secrets.len(), app.stash.backend());
    Ok(0)
}

#[derive(Args)]
pub struct ForgetArgs {
    pub name: String,
    #[arg(long, default_value = "default")]
    pub identity: String,
    /// Why (shown on the card when an agent asks).
    #[arg(long)]
    pub why: Option<String>,
}

pub fn forget(a: ForgetArgs) -> Result<i32> {
    check_name_identity(&a.name, &a.identity)?;
    let app = App::open()?;
    // Grants outlive the value: whoever fills the next card for this name reaches every
    // directory that holds one. Emptying the slot is the person's decision, so from an agent
    // it is a card the person confirms. The card is filed whether or not the key exists: the
    // agent learns nothing about the stash from it.
    if !util::looks_human() {
        let action = tokenstash_core::actions::Action::Forget { name: a.name.clone(), identity: a.identity.clone() };
        return crate::cmd::actions::request(&app, &tokenstash_core::project::current(), &util::agent_from(&None), &action, a.why.clone());
    }
    if crate::cmd::actions::forget_key(&app, &a.name, &a.identity)? {
        println!("✓ forgot {}@{}", a.name, a.identity);
    } else {
        println!("nothing stored for {}@{}", a.name, a.identity);
    }
    Ok(0)
}

#[derive(Args)]
pub struct BindArgs {
    pub name: String,
    #[arg(long)]
    pub identity: String,
    #[arg(long)]
    pub project: Option<PathBuf>,
    /// Why (shown on the card when an agent asks).
    #[arg(long)]
    pub why: Option<String>,
}

/// The same rules `need` applies, checked before anything is filed or changed.
fn check_name_identity(name: &str, identity: &str) -> Result<()> {
    if !tokenstash_core::need::valid_name(name) {
        bail!("{name:?} is not an environment variable name (letters, digits and underscores, not starting with a digit)");
    }
    if !tokenstash_core::need::valid_identity(identity) {
        bail!("{identity:?} is not an identity (letters, digits, dash and underscore, up to 64 characters)");
    }
    Ok(())
}

pub fn bind(a: BindArgs) -> Result<i32> {
    check_name_identity(&a.name, &a.identity)?;
    let app = App::open()?;
    // Which copy of a key a project receives is the person's decision: from an agent, a card.
    if !util::looks_human() {
        if a.project.is_some() {
            bail!("--project is for a person at a terminal; an agent asks for the project it runs in");
        }
        let project = tokenstash_core::project::current();
        if app.db.find_workspace(&project)?.is_none() {
            bail!("{} has not asked for any key yet, so there is nothing to bind; run `tokenstash need {} --identity {}` instead", tokenstash_core::project::short(&project), a.name, a.identity);
        }
        let action = tokenstash_core::actions::Action::Bind { name: a.name.clone(), identity: a.identity.clone() };
        return crate::cmd::actions::request(&app, &project, &util::agent_from(&None), &action, a.why.clone());
    }
    let project = util::project_from(&a.project);
    let Some(ws) = app.db.find_workspace(&project)? else {
        bail!("{} is not a paired directory yet; run `tokenstash need {}` there first (the card pairs it), then bind", tokenstash_core::project::short(&project), a.name);
    };
    app.db.set_binding(&ws.id, &a.name, &a.identity)?;
    println!("✓ {} → {}@{} for {}", a.name, a.name, a.identity, tokenstash_core::project::short(&project));
    Ok(0)
}

#[derive(Args)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub cmd: Option<TrustCmd>,
}

#[derive(Subcommand)]
pub enum TrustCmd {
    /// Retired (0.2): prints how pairing replaced trust roots.
    Add { path: Option<PathBuf> },
    /// Remove a retired trust root from config.toml.
    Rm { path: PathBuf },
    /// Retired (0.2): prints how pairing replaced trust roots.
    List,
}

/// Trust roots are retired (0.2): a folder never said which keys the human meant. Each
/// directory pairs once instead. `rm` still works so old configs can be cleaned up.
pub fn trust(a: TrustArgs) -> Result<i32> {
    let cfg = Config::load()?;
    const NOTICE: &str = "trust roots are retired: the first time a directory asks for stored keys you approve exactly which ones (one card), and they are silent there afterwards. See `tokenstash workspaces`.";
    match a.cmd.unwrap_or(TrustCmd::List) {
        TrustCmd::Add { .. } => {
            println!("nothing to add — {NOTICE}");
        }
        TrustCmd::Rm { path } => {
            let p = path.canonicalize().unwrap_or(path);
            Config::update(|cfg| {
                let before = cfg.trust_roots.len();
                cfg.trust_roots.retain(|r| r != &p);
                if cfg.trust_roots.len() == before {
                    bail!("{} is not in the (retired) trust roots", p.display());
                }
                Ok(())
            })?;
            println!("✓ removed {} from the retired list", tokenstash_core::project::short(&p));
        }
        TrustCmd::List => {
            println!("{NOTICE}");
            if !cfg.trust_roots.is_empty() {
                println!("still listed in config (no effect; `tokenstash trust rm <dir>` to tidy):");
                for r in &cfg.trust_roots {
                    println!("    {}", tokenstash_core::project::short(r));
                }
            }
        }
    }
    Ok(0)
}

#[derive(Args)]
pub struct WorkspacesArgs {
    #[command(subcommand)]
    pub cmd: Option<WorkspacesCmd>,
}

#[derive(Subcommand)]
pub enum WorkspacesCmd {
    /// List paired directories and what each may receive.
    List,
    /// Drop every grant of a directory (values already written stay written).
    Revoke { path: PathBuf },
    /// Forget a directory entirely: its next request pairs again.
    Forget { path: PathBuf },
}

/// Human-only: this is the cross-project inventory the MCP surface deliberately hides.
pub fn workspaces(a: WorkspacesArgs) -> Result<i32> {
    util::require_human("workspaces", "it lists and revokes every directory you have paired")?;
    let app = App::open()?;
    match a.cmd.unwrap_or(WorkspacesCmd::List) {
        WorkspacesCmd::List => {
            let all = app.db.list_workspaces()?;
            if all.is_empty() {
                println!("no paired directories yet — the first stored key a directory asks for pairs it (one card)");
                return Ok(0);
            }
            for w in &all {
                let note = if !w.fingerprint_ok { "  (directory gone or re-created: grants no longer apply until it pairs again)" } else if w.fingerprint_weak { "  (inode-only identity: this filesystem reports no birth time)" } else { "" };
                println!("{}{}", tokenstash_core::project::short(std::path::Path::new(&w.root)), note);
                for (name, identity, scope, source) in app.db.grants_for(&w.id)? {
                    let what = if scope == tokenstash_core::db::GRANT_BROAD { format!("any non-sensitive registry key @{identity}") } else if identity == "default" { name } else { format!("{name}@{identity}") };
                    println!("    {what:<48} via {source}");
                }
            }
        }
        WorkspacesCmd::Revoke { path } => {
            let Some(w) = app.db.find_workspace(&path)? else { bail!("{} is not a paired directory", path.display()) };
            let n = app.db.revoke_workspace(&w.id)?;
            app.db.audit(Some(&w.root), None, "workspace.revoke", None, None, Some(&format!("{n} grants")))?;
            println!("✓ revoked {n} grant(s) for {} — values already in its env file stay there; its next request asks again", tokenstash_core::project::short(std::path::Path::new(&w.root)));
        }
        WorkspacesCmd::Forget { path } => {
            let Some(w) = app.db.find_workspace(&path)? else { bail!("{} is not a paired directory", path.display()) };
            app.db.forget_workspace(&w.id)?;
            app.db.audit(Some(&w.root), None, "workspace.forget", None, None, None)?;
            println!("✓ forgot {}", tokenstash_core::project::short(std::path::Path::new(&w.root)));
        }
    }
    Ok(0)
}

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long, default_value = "30")]
    pub limit: usize,
    /// One JSON object per row (ts, project, agent, action, name, identity, detail).
    #[arg(long)]
    pub json: bool,
}

pub fn audit(a: AuditArgs) -> Result<i32> {
    let app = App::open()?;
    // The whole log names every directory and key; an agent sees its own directory's rows.
    // An agent's view starts when the directory now at this path was paired: a checkout
    // re-created at the same path does not read the old one's history.
    let rows = if util::looks_human() {
        app.db.recent_audit(a.limit)?
    } else {
        let project = tokenstash_core::project::current();
        match app.db.find_workspace(&project)? {
            Some(ws) => app.db.recent_audit_for(&project.to_string_lossy(), &ws.created, a.limit)?,
            None => vec![],
        }
    };
    if a.json {
        let v: Vec<serde_json::Value> = rows.iter().map(|(ts, project, agent, action, name, identity, detail, grant)| serde_json::json!({
            "ts": ts, "project": project, "agent": agent, "action": action, "name": name, "identity": identity, "detail": detail, "grant_source": grant,
        })).collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(0);
    }
    for (ts, project, agent, action, name, identity, detail, grant) in rows {
        println!(
            "{ts}  {:<14} {:<30} {:<24} {:<12} {}{}",
            action,
            name.map(|n| match identity { Some(i) if i != "default" => format!("{n}@{i}"), _ => n }).unwrap_or_default(),
            project.map(|p| util::short(&p)).unwrap_or_default(),
            agent.unwrap_or_default(),
            detail.unwrap_or_default(),
            grant.map(|g| format!(" [via {g}]")).unwrap_or_default()
        );
    }
    Ok(0)
}

// ---------- rotation ----------

/// The identity a name resolves to here, the way `need` resolves it: explicit flag, else
/// the project's binding, else `default`. Without this a `--identity`-less command silently
/// targets the wrong key in a project bound to `work`.
fn resolve_identity(app: &App, project: &std::path::Path, name: &str, explicit: &Option<String>) -> Result<String> {
    if let Some(i) = explicit { return Ok(i.clone()); }
    let bound = match app.db.find_workspace(project)? { Some(w) => app.db.binding(&w.id, name)?, None => None };
    Ok(bound.unwrap_or_else(|| "default".into()))
}

#[derive(Args)]
pub struct RotateArgs {
    pub name: String,
    /// Which identity (defaults to this project's binding, else `default`).
    #[arg(long)]
    pub identity: Option<String>,
    #[arg(long)]
    pub project: Option<PathBuf>,
    /// Why (shown on the card when an agent asks).
    #[arg(long)]
    pub why: Option<String>,
}

/// Mark a key for replacement and file the paste card now. The old value stays in the
/// stash until the new one lands; every project still holding it is rewritten then.
///
/// From an agent (the user told it to replace a key) it files the Replace card without
/// marking the key stale: the old key keeps working until the person pastes the new one, and
/// declining the card changes nothing. Only a key this directory received or was granted can
/// be asked for, so the command says nothing about the rest of the stash.
pub fn rotate(a: RotateArgs) -> Result<i32> {
    let app = App::open()?;
    if !util::looks_human() {
        if a.project.is_some() {
            bail!("--project is for a person at a terminal; an agent asks for the project it runs in");
        }
        let project = tokenstash_core::project::current();
        let agent = util::agent_from(&None);
        let identity = resolve_identity(&app, &project, &a.name, &a.identity)?;
        if !util::keys_here(&app.db, &project)?.contains(&(a.name.clone(), identity.clone())) {
            bail!("this directory has not received {}@{identity}, so there is nothing here to replace; `tokenstash need {}` requests it", a.name, a.name);
        }
        let t = tokenstash_core::actions::request_rotation(&app.ctx(), &project, &agent, &a.name, &identity, a.why.as_deref())?;
        let outcome = tokenstash_core::need::Outcome::Pending { name: a.name.clone(), identity: identity.clone(), task_id: t.id.clone(), title: t.title.clone(), url: t.url.clone() };
        crate::cmd::need::notify_pending(&app, &project, &agent, std::slice::from_ref(&outcome));
        let state = crate::notify::inbox_state(&app.cfg);
        let card = util::inbox_url_agent(&app.cfg, Some(&app.db), Some(&t.id), state);
        println!("⏳ {} replacement requested (card {})", a.name, t.id);
        println!("  next: {}", crate::guide::rotation_next(&a.name, &t, &card, &app.cfg));
        return Ok(tokenstash_core::exit::PENDING);
    }
    let project = util::project_from(&a.project);
    let agent = "human".to_string();
    let identity = resolve_identity(&app, &project, &a.name, &a.identity)?;
    let t = tokenstash_core::tasks::rotate(&app.ctx(), &project, &agent, &a.name, &identity)?;
    let state = crate::notify::ensure_inbox(&app.cfg);
    crate::notify::desktop(&app.cfg, &format!("Replace {}", a.name), "you asked to rotate it", &util::inbox_notice(&app.cfg, Some(&t.id), state));
    println!("⏳ {}@{identity} marked for rotation — task {} → {}", a.name, t.id, util::inbox_url_tty(&app.cfg, Some(&app.db), Some(&t.id), state, util::Stream::Stdout));
    println!("  paste the NEW key first; revoke the old one in the dashboard after it says stored");
    Ok(tokenstash_core::exit::PENDING)
}

#[derive(Args)]
pub struct ReportBadArgs {
    pub name: String,
    /// Which identity (defaults to this project's binding, else `default`).
    #[arg(long)]
    pub identity: Option<String>,
    /// HTTP status the provider returned (401, 403, ...).
    #[arg(long)]
    pub status: Option<u16>,
    /// Accepted for convenience and discarded: provider error text is agent-controlled and
    /// may echo a key, so nothing from it is stored or shown.
    #[arg(long)]
    pub message: Option<String>,
}

/// Agent-facing. The project is the current directory, never an argument: a report only
/// counts from a project that received the key, and letting the caller name one would let a
/// hostile repo borrow another project's standing. Always prints the same line whatever
/// happened: the agent learns the outcome from its next `need` (card vs inject), never from
/// here — otherwise this is a stash-existence oracle.
pub fn report_bad(a: ReportBadArgs) -> Result<i32> {
    let app = App::open()?;
    let project = tokenstash_core::project::current();
    let agent = util::agent_from(&None);
    let identity = resolve_identity(&app, &project, &a.name, &a.identity)?;
    let _ = tokenstash_core::tasks::report_bad(&app.ctx(), &project, &agent, &a.name, &identity, a.status)?;
    println!("ok — run `tokenstash need {}` again; if the key is dead the user will be asked for a replacement", a.name);
    Ok(0)
}

#[derive(Args)]
pub struct CheckArgs {
    /// Only these names (default: every key with a registry liveness check).
    pub names: Vec<String>,
    /// Only re-test keys currently marked stale (and un-mark them if the provider accepts).
    #[arg(long)]
    pub stale_only: bool,
    #[arg(long)]
    pub json: bool,
}

/// Sweep the stash through the registry's liveness probes. Human-only: it sends every key
/// to its provider and prints an inventory, so it refuses to run for an agent or a pipe.
pub fn check(a: CheckArgs) -> Result<i32> {
    // --json is for a script the human runs (`check --json > report.json`): stdout is not a
    // terminal then, so the guard is on stdin instead.
    use std::io::IsTerminal;
    let app = App::open()?;
    // A person checks every key (--json is for their own script, so stdout may be a file and
    // the terminal check is on stdin). An agent checks the keys this directory received or was
    // granted: the same request verify-on-use sends before a delivery, and nothing about the
    // rest of the stash.
    let person = !tokenstash_core::project::agent_environment() && std::io::stdin().is_terminal() && (a.json || std::io::stdout().is_terminal());
    let rows = if person {
        sweep(&app, &a.names, a.stale_only, !a.json)?
    } else {
        let here: Vec<(String, String)> = util::keys_here(&app.db, &tokenstash_core::project::current())?.into_iter().filter(|(n, _)| a.names.is_empty() || a.names.contains(n)).collect();
        let stale_only = a.stale_only;
        let pairs: Vec<(String, String)> = here.into_iter().filter(|(n, i)| !stale_only || app.db.get_secret(n, i).ok().flatten().is_some_and(|m| m.stale)).collect();
        if pairs.is_empty() && !a.json {
            println!("nothing to check here: this directory has not received any of those keys (an agent checks only the keys its directory received or was granted)");
            return Ok(0);
        }
        sweep_pairs(&app, &pairs, !a.json)?
    };
    if a.json {
        println!("{}", serde_json::to_string_pretty(&rows.iter().map(|(n, i, st, stale)| serde_json::json!({ "name": n, "identity": i, "result": st, "stale": stale })).collect::<Vec<_>>())?);
    }
    Ok(0)
}

/// The liveness sweep shared by `check` and `import`: every key with a registry check (or
/// only `names`), probed sequentially with polite pacing. Rejected → stale, Ok → verified,
/// Unknown → untouched. Never prints a value.
pub fn sweep(app: &App, names: &[String], stale_only: bool, print: bool) -> Result<Vec<(String, String, String, bool)>> {
    sweep_where(app, Probe::Network, &|m| (names.is_empty() || names.contains(&m.name)) && (!stale_only || m.stale), print)
}

/// The sweep over exactly the (name, identity) pairs given — what `import` and
/// `--from-env` touched, and nothing else of the same name.
pub fn sweep_pairs(app: &App, pairs: &[(String, String)], print: bool) -> Result<Vec<(String, String, String, bool)>> {
    sweep_where(app, Probe::Network, &|m| pairs.iter().any(|(n, i)| n == &m.name && i == &m.identity), print)
}

/// The sweep's result for a key stored while its request was out. The answer was about the
/// old key, so the key now stored was not checked.
const REPLACED_DURING_CHECK: &str = "replaced during the check; not checked";

fn sweep_where(app: &App, probe: Probe, select: &dyn Fn(&tokenstash_core::db::SecretMeta) -> bool, print: bool) -> Result<Vec<(String, String, String, bool)>> {
    let ctx = Ctx { probe, ..app.ctx() };
    let mut rows = vec![];
    for m in app.db.list_secrets()? {
        if !select(&m) { continue; }
        let Some(check) = tokenstash_core::registry::lookup(&m.name).and_then(|p| p.check.clone()) else {
            rows.push((m.name.clone(), m.identity.clone(), "no check".to_string(), m.stale));
            continue;
        };
        let Some(v) = app.stash.get(&stash_key(&m.name, &m.identity))? else {
            rows.push((m.name.clone(), m.identity.clone(), "not in stash".to_string(), m.stale));
            continue;
        };
        let verdict = ctx.probe.run(&check, &v, tokenstash_core::validate::TIMEOUT_HUMAN).unwrap_or_else(|| Liveness::Unknown("probing is off".into()));
        // A verdict is recorded only if the stash still holds the value just probed, under
        // the index write lock. A key pasted while the request was out is not judged by its
        // predecessor's answer. An Unknown records nothing, so it does not wait for the lock.
        let judge = |record: &dyn Fn() -> Result<String>| -> Result<String> {
            Ok(tokenstash_core::tasks::if_still_stored(&ctx, &m.name, &m.identity, Some(&v), record)?.unwrap_or_else(|| REPLACED_DURING_CHECK.to_string()))
        };
        let status = match verdict {
            Liveness::Ok => judge(&|| { app.db.set_verified(&m.name, &m.identity)?; Ok("ok".to_string()) })?,
            Liveness::Rejected(code) => judge(&|| {
                let reason = format!("rejected by the provider (HTTP {code}) on {} during a check", tokenstash_core::now());
                app.db.mark_stale(&m.name, &m.identity, true, Some(&reason), Some(tokenstash_core::db::STALE_PROBE))?;
                app.db.audit(None, None, "check.rejected", Some(&m.name), Some(&m.identity), Some(&format!("HTTP {code}")))?;
                Ok(format!("REJECTED (HTTP {code}) → stale"))
            })?,
            // Nothing to record, so no lock. A plain re-read still keeps the old key's answer
            // off the row of a key stored while the request was out. A re-read that fails
            // cannot tell, so the row keeps the provider's answer and the check goes on.
            Liveness::Unknown(e) => match app.stash.get(&stash_key(&m.name, &m.identity)) {
                Ok(now) if now.as_ref().map(|n| n.expose_secret()) != Some(v.expose_secret()) => REPLACED_DURING_CHECK.to_string(),
                _ => format!("unknown ({})", e.chars().take(40).collect::<String>()),
            },
        };
        let stale_now = app.db.get_secret(&m.name, &m.identity)?.map(|x| x.stale).unwrap_or(false);
        rows.push((m.name.clone(), m.identity.clone(), status, stale_now));
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    if print {
        if rows.is_empty() { println!("nothing to check"); return Ok(rows); }
        println!("{:<36} {:<10} RESULT", "NAME", "IDENTITY");
        for (n, i, st, _) in &rows { println!("{n:<36} {i:<10} {st}"); }
        let stale = rows.iter().filter(|r| r.3).count();
        if stale > 0 { println!("\n{stale} stale — the next `tokenstash need` for each asks for a replacement (or run `tokenstash rotate NAME`)"); }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use std::time::Duration;
    use tokenstash_core::stash::{FileStash, Stash};
    use tokenstash_core::{db, registry, Db};

    /// An App on a scratch home with the file stash, holding one OpenAI key.
    fn app_with_key(tag: &str, value: &str) -> (App, PathBuf) {
        let home = std::env::temp_dir().join(format!("tokenstash-admin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("TOKENSTASH_HOME", &home);
        let app = App { cfg: Config::default(), db: Db::open(&home.join("t.db")).unwrap(), stash: Box::new(FileStash::new().unwrap()) };
        app.stash.set(&stash_key("OPENAI_API_KEY", "default"), &SecretString::from(value.to_string())).unwrap();
        app.db.upsert_secret(&db::SecretMeta { name: "OPENAI_API_KEY".into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: tokenstash_core::now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
        (app, home)
    }

    fn done(home: &std::path::Path) {
        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(home);
    }

    /// An Unknown verdict records nothing, so `check` reports it without waiting for the
    /// index write lock. A store holding that lock past the busy timeout must not turn
    /// "unknown" into a failed `check`.
    #[test]
    fn an_unknown_check_does_not_wait_for_the_index_lock() {
        let _g = crate::inbox_auth::env_lock();
        let (app, home) = app_with_key("unknown", "sk-live-aaaaaaaaaaaaaaaaaaaa");
        // Another process holds the index write lock until the sweep has returned.
        let db_path = home.join("t.db");
        let (held, wait_held) = std::sync::mpsc::channel();
        let (release, wait_release) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let other = Db::open(&db_path).unwrap();
            other.locked(|| { held.send(()).unwrap(); let _ = wait_release.recv_timeout(Duration::from_secs(20)); Ok(()) }).unwrap();
        });
        wait_held.recv().unwrap();
        let unknown = |_: &registry::Check| Liveness::Unknown("HTTP 503".into());
        let started = std::time::Instant::now();
        let rows = sweep_where(&app, Probe::Stub(&unknown), &|_| true, false);
        let waited = started.elapsed();
        release.send(()).unwrap();
        holder.join().unwrap();
        let rows = rows.unwrap();
        assert!(rows[0].2.starts_with("unknown"), "{rows:?}");
        assert!(waited < Duration::from_secs(2), "the sweep waited {waited:?} for a lock it had no use for");
        done(&home);
    }

    /// The sweep records a verdict only if the stash still holds the value it sent. A key
    /// stored while the request was out is reported as not judged and stays as stored.
    #[test]
    fn a_check_verdict_for_a_replaced_key_is_not_recorded() {
        let _g = crate::inbox_auth::env_lock();
        let (app, home) = app_with_key("replaced", "sk-old-aaaaaaaaaaaaaaaaaaaaa");
        let human = FileStash::new().unwrap();
        let calls = std::cell::Cell::new(0);
        let rejecting = |_: &registry::Check| {
            calls.set(calls.get() + 1);
            human.set(&stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-new-bbbbbbbbbbbbbbbbbbbbb".to_string())).unwrap();
            Liveness::Rejected(401)
        };
        let rows = sweep_where(&app, Probe::Stub(&rejecting), &|_| true, false).unwrap();
        assert_eq!(calls.get(), 1, "one request per key");
        assert_eq!(rows[0].2, REPLACED_DURING_CHECK, "{rows:?}");
        assert!(!app.db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale, "the old key's 401 is not recorded against the new one");
        done(&home);
    }

    /// An Unknown records nothing, but the report must not print the old key's "unknown"
    /// beside a key stored while the request was out. That key was never checked.
    #[test]
    fn an_unknown_for_a_replaced_key_reports_the_replacement_as_not_checked() {
        let _g = crate::inbox_auth::env_lock();
        let (app, home) = app_with_key("replaced-unknown", "sk-old-aaaaaaaaaaaaaaaaaaaaa");
        let human = FileStash::new().unwrap();
        let unreachable = |_: &registry::Check| {
            human.set(&stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-new-bbbbbbbbbbbbbbbbbbbbb".to_string())).unwrap();
            Liveness::Unknown("HTTP 503".into())
        };
        let rows = sweep_where(&app, Probe::Stub(&unreachable), &|_| true, false).unwrap();
        assert_eq!(rows[0].2, REPLACED_DURING_CHECK, "{rows:?}");
        done(&home);
    }

    /// The file stash, with every second read failing: the keyring went away between the
    /// read the probe used and the re-read for the report.
    struct RereadFails { inner: FileStash, reads: std::cell::Cell<u32> }

    impl Stash for RereadFails {
        fn backend(&self) -> &'static str { "reread-fails" }
        fn get(&self, key: &str) -> Result<Option<SecretString>> {
            let n = self.reads.get();
            self.reads.set(n + 1);
            if n % 2 == 1 {
                bail!("the keyring is unavailable");
            }
            self.inner.get(key)
        }
        fn set(&self, key: &str, value: &SecretString) -> Result<()> { self.inner.set(key, value) }
        fn delete(&self, key: &str) -> Result<bool> { self.inner.delete(key) }
    }

    /// The re-read behind an Unknown only decides how the row reads. When it fails, `check`
    /// cannot tell whether the key changed, so it reports the provider's answer for that key
    /// and goes on to the next one.
    #[test]
    fn a_failed_reread_after_an_unknown_does_not_stop_the_check() {
        let _g = crate::inbox_auth::env_lock();
        let (app, home) = app_with_key("reread-fails", "sk-live-aaaaaaaaaaaaaaaaaaaa");
        app.stash.set(&stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_live_bbbbbbbbbbbbbbbbbbbb".to_string())).unwrap();
        app.db.upsert_secret(&db::SecretMeta { name: "GROQ_API_KEY".into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: tokenstash_core::now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
        let app = App { stash: Box::new(RereadFails { inner: FileStash::new().unwrap(), reads: std::cell::Cell::new(0) }), ..app };
        let unknown = |_: &registry::Check| Liveness::Unknown("HTTP 503".into());
        let rows = sweep_where(&app, Probe::Stub(&unknown), &|_| true, false).unwrap();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows.iter().all(|r| r.2 == "unknown (HTTP 503)"), "{rows:?}");
        done(&home);
    }
}
