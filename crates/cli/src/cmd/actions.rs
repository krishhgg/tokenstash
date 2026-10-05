//! Both sides of an action card (see `tokenstash_core::actions`). An agent runs a command
//! that acts for the person, such as `forget` or `init --mode`; it files a card instead of
//! refusing. The person confirms on the card in the inbox, and the inbox carries the action
//! out.

use crate::notify;
use crate::util::{self, App};
use anyhow::{bail, Result};
use std::path::Path;
use tokenstash_core::actions::{self, Action};
use tokenstash_core::config::AgentMode;
use tokenstash_core::db::Task;

/// Agent side: file the card (or find the open one asking the same), notify the person once,
/// and print it the way `need` prints a pending key. Exit 10, like any pending card.
pub fn request(app: &App, project: &Path, agent: &str, action: &Action, why: Option<String>) -> Result<i32> {
    let t = actions::request(&app.ctx(), project, agent, action, why)?;
    print_pending(app, project, agent, &t)
}

/// A card an agent filed for the person, printed with its link and what to do next.
pub fn print_pending(app: &App, project: &Path, agent: &str, t: &Task) -> Result<i32> {
    let state = notify::ensure_inbox(&app.cfg);
    if app.db.mark_notified(&t.id).unwrap_or(true) {
        notify::desktop(&app.cfg, &t.title, &format!("{} · asked by {agent}", tokenstash_core::project::short(project)), &util::inbox_notice(&app.cfg, Some(&t.id), state));
    }
    let card = util::inbox_url_agent(&app.cfg, Some(&app.db), Some(&t.id), state);
    println!("⏳ {} (card {})", t.title, t.id);
    println!("  next: {}", crate::guide::confirm_next(t, &card));
    Ok(tokenstash_core::exit::PENDING)
}

/// How long a claim on an action card holds before it counts as left behind by a process that
/// stopped mid-action. Every action finishes in seconds.
const CLAIM_HOLDS: chrono::Duration = chrono::Duration::minutes(2);

/// Person side, from the inbox's full session or the person's terminal: claim the card, do
/// what it says, then close it. The claim means a second confirm (another tab, a double click)
/// runs nothing: an old forget card confirmed again would delete a key stored since. The card
/// stays pending until the action has run, so if this process stops half way the claim runs
/// out and the person can confirm it again; if the action fails, the claim is given back.
pub fn confirm(app: &App, task: &Task, action: &Action) -> Result<String> {
    use tokenstash_core::db::TaskStatus;
    let stale_before = (chrono::Utc::now() - CLAIM_HOLDS).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    if !app.db.claim_action(&task.id, &stale_before)? {
        match app.db.get_task(&task.id)?.map(|t| t.status) {
            Some(TaskStatus::Pending) => bail!("this card is being carried out right now; reload the page in a minute"),
            _ => bail!("this card was already answered"),
        }
    }
    match perform(app, task, action) {
        Ok(done) => {
            app.db.close_task_if_open(&task.id, TaskStatus::Answered, Some(&done))?;
            app.db.audit(Some(&task.project), Some(&task.agent), "action.confirmed", None, None, Some(&task.expects))?;
            Ok(done)
        }
        Err(e) => {
            app.db.release_action_claim(&task.id)?;
            Err(e)
        }
    }
}

fn perform(app: &App, task: &Task, action: &Action) -> Result<String> {
    match action {
        Action::Forget { name, identity } => Ok(if forget_key(app, name, identity)? {
            format!("Forgot {name}@{identity}")
        } else {
            format!("Nothing was stored for {name}@{identity}")
        }),
        Action::Bind { name, identity } => {
            let project = Path::new(&task.project);
            let Some(ws) = app.db.find_workspace(project)? else {
                bail!("{} has not received any key yet, so there is nothing to bind; ask again after its first request", tokenstash_core::project::short(project));
            };
            app.db.set_binding(&ws.id, name, identity)?;
            app.db.audit(Some(&task.project), Some(&task.agent), "bind", Some(name), Some(identity), Some("confirmed on a card"))?;
            Ok(format!("{} now uses the {identity} copy of {name}", tokenstash_core::project::short(project)))
        }
        Action::Mode(m) => {
            let mode = if m == "explicit" { AgentMode::Explicit } else { AgentMode::Auto };
            crate::cmd::init::apply_choice(Some(mode), None)?;
            Ok(format!("Agent mode is now {mode}; agent sessions started from now on see it"))
        }
        Action::Mcp(on) => {
            // An MCP server is always available to the agent, so registering one ends explicit
            // mode; the card said so.
            // The setting as it is now, not as the inbox read it when it started.
            let explicit = tokenstash_core::Config::load()?.agent_mode == AgentMode::Explicit;
            let mode = (*on && explicit).then_some(AgentMode::Auto);
            crate::cmd::init::apply_choice(mode, Some(*on))?;
            Ok(if *on { "Registered the tokenstash MCP server with your agents".into() } else { "Took the tokenstash MCP server out of your agents".into() })
        }
        Action::Undo => {
            if !crate::cmd::init::undo_quietly()? {
                bail!("some files could not be put back; `tokenstash init --undo` in a terminal shows which");
            }
            Ok("Took tokenstash out of your agents".into())
        }
    }
}

/// Delete a stored key and its index row. True if either existed.
pub fn forget_key(app: &App, name: &str, identity: &str) -> Result<bool> {
    let had = app.stash.delete(&tokenstash_core::stash::stash_key(name, identity))?;
    let meta = app.db.delete_secret(name, identity)?;
    app.db.audit(None, None, "forget", Some(name), Some(identity), None)?;
    Ok(had || meta)
}
