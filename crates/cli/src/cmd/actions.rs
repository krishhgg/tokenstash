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

/// Person side, from the inbox's full session: do what the card says and say what happened.
pub fn perform(app: &App, task: &Task, action: &Action) -> Result<String> {
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
            crate::cmd::init::apply_choice(None, Some(*on))?;
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
