//! Cards for decisions an agent may ask for and only the person may make: forget a stored key,
//! use another identity for a key in one project, change how agents reach tokenstash. The
//! agent runs the command; the person confirms or declines on the card.
//!
//! An action card is a Human card whose `expects` is `action:<verb>`, with its targets in
//! `names`. A version that does not know actions shows it as a plain confirm card, and
//! answering it there changes nothing.

use crate::db::{Task, TaskKind, TaskStatus};
use crate::tasks::{self, Ctx};
use anyhow::{bail, Context, Result};
use std::path::Path;

pub const PREFIX: &str = "action:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Delete a stored key. Every folder loses it; the next request asks again.
    Forget { name: String, identity: String },
    /// Make the card's project use `identity` for `name`.
    Bind { name: String, identity: String },
    /// How agents load the skill on this machine: `auto` or `explicit`.
    Mode(String),
    /// Register (`true`) or take out (`false`) the MCP server for every agent.
    Mcp(bool),
    /// Put the agents' config files back as `init` found them.
    Undo,
}

impl Action {
    pub fn verb(&self) -> &'static str {
        match self {
            Action::Forget { .. } => "forget",
            Action::Bind { .. } => "bind",
            Action::Mode(_) => "mode",
            Action::Mcp(_) => "mcp",
            Action::Undo => "undo",
        }
    }

    fn targets(&self) -> Vec<String> {
        match self {
            Action::Forget { name, identity } | Action::Bind { name, identity } => vec![crate::stash::stash_key(name, identity)],
            Action::Mode(m) => vec![m.clone()],
            Action::Mcp(on) => vec![if *on { "on" } else { "off" }.into()],
            Action::Undo => vec![],
        }
    }

    /// The action a card asks for, or `None` for any other card (and for one whose targets
    /// do not parse: nothing is done on a guess).
    pub fn of(task: &Task) -> Option<Action> {
        if task.kind != TaskKind::Human {
            return None;
        }
        let verb = task.expects.strip_prefix(PREFIX)?;
        let one = || match task.names.as_slice() { [t] => Some(t.as_str()), _ => None };
        let entry = || one().map(tasks::split_identity).filter(|(n, i)| !n.is_empty() && !i.is_empty());
        match verb {
            "forget" => entry().map(|(n, i)| Action::Forget { name: n.into(), identity: i.into() }),
            "bind" => entry().map(|(n, i)| Action::Bind { name: n.into(), identity: i.into() }),
            "mode" => one().filter(|m| matches!(*m, "auto" | "explicit")).map(|m| Action::Mode(m.into())),
            "mcp" => match one()? { "on" => Some(Action::Mcp(true)), "off" => Some(Action::Mcp(false)), _ => None },
            "undo" => task.names.is_empty().then_some(Action::Undo),
            _ => None,
        }
    }

    /// The card's title: what the agent is asking for.
    pub fn title(&self) -> String {
        match self {
            Action::Forget { name, identity } => format!("Forget {}", shown(name, identity)),
            Action::Bind { name, identity } => format!("Use the {identity} copy of {name} in this project"),
            Action::Mode(m) if m == "explicit" => "Load the tokenstash skill only when you invoke it".into(),
            Action::Mode(_) => "Let agents load the tokenstash skill when code needs a key".into(),
            Action::Mcp(true) => "Register tokenstash as an MCP server with your agents".into(),
            Action::Mcp(false) => "Take the tokenstash MCP server out of your agents".into(),
            Action::Undo => "Take tokenstash out of your agents".into(),
        }
    }

    /// What confirming does, said on the card before the person decides.
    pub fn effect(&self) -> String {
        match self {
            Action::Forget { name, identity } => format!("{} is deleted from your stash. Every folder that received it keeps the copy already in its env file, and the next folder that needs it gets a card to paste it again.", shown(name, identity)),
            Action::Bind { name, identity } => format!("From now on this project receives the `{identity}` copy of {name} instead of its current one. If you have not stored a `{identity}` copy yet, its next request asks you for it."),
            Action::Mode(m) if m == "explicit" => "Agents stop loading the tokenstash skill on their own; you invoke it with /tokenstash (or $tokenstash in Codex). Takes effect in agent sessions started after this.".into(),
            Action::Mode(_) => "Agents load the tokenstash skill when code needs a key. Takes effect in agent sessions started after this.".into(),
            Action::Mcp(true) => "Every agent on this machine gets the tokenstash MCP server, pointing at the tokenstash binary that runs this inbox; if agents load the skill only when you invoke it, that switches back to loading it on their own, since an MCP server is always available to them. Takes effect in agent sessions started after this.".into(),
            Action::Mcp(false) => "The tokenstash MCP server is taken out of every agent's config; agents keep using the CLI through the skill.".into(),
            Action::Undo => "Every agent config file `tokenstash init` changed is put back as it found them, and the skill is removed. Your stored keys stay.".into(),
        }
    }

    /// Whether confirming changes something for every project, not only the card's.
    pub fn machine_wide(&self) -> bool {
        !matches!(self, Action::Bind { .. })
    }
}

fn shown(name: &str, identity: &str) -> String {
    if identity == "default" { name.to_string() } else { format!("{name} ({identity})") }
}

/// File the card for `action`, or return the open one already asking for the same thing in
/// this project. Lookup and insert happen under one write lock, so two agents asking at once
/// file one card.
pub fn request(ctx: &Ctx, project: &Path, agent: &str, action: &Action, why: Option<String>) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    // A card past its deadline is not one to hand out again: the agent would relay a link
    // that opens onto "expired", with no new notification.
    ctx.db.expire_overdue()?;
    let expects = format!("{PREFIX}{}", action.verb());
    let title = action.title();
    let names = action.targets();
    ctx.db.conn.execute_batch("BEGIN IMMEDIATE").context("locking the task table")?;
    let existing = match ctx.db.open_human_tasks(&pid, &title, &expects) {
        Ok(e) => e,
        Err(e) => {
            let _ = ctx.db.conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    };
    if let Some(t) = existing.into_iter().find(|t| t.names == names) {
        ctx.db.conn.execute_batch("COMMIT")?;
        return Ok(t);
    }
    let t = Task {
        id: tasks::new_id("h"),
        kind: TaskKind::Human,
        project: pid.clone(),
        agent: agent.into(),
        name: None,
        identity: "default".into(),
        title,
        why: why.map(|w| tasks::clean_text(&w, 500)).filter(|w| !w.is_empty()),
        url: None,
        steps: vec![],
        expects,
        pattern: None,
        names,
        status: TaskStatus::Pending,
        created: crate::now(),
        deadline: tasks::deadline(ctx.cfg),
        answered_at: None,
        note: None,
    };
    if let Err(e) = ctx.db.insert_task(&t).and_then(|_| ctx.db.audit(Some(&pid), Some(agent), "task.action", None, None, Some(&t.expects))) {
        let _ = ctx.db.conn.execute_batch("ROLLBACK");
        return Err(e);
    }
    ctx.db.conn.execute_batch("COMMIT").context("recording the action card")?;
    Ok(t)
}

/// What [`forget`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forgot {
    /// The value, its index row, or both were deleted.
    Deleted,
    /// Nothing was stored under that name.
    NothingStored,
    /// The card's value is gone already: an earlier confirm of the card deleted it, or it was
    /// replaced since the card was first confirmed. `kept` is true when the name holds a newer
    /// value, which stays.
    Gone { kept: bool },
    /// A later confirm of a card whose first confirm found no index row found a value in the
    /// stash with no index row again. It may be a replacement whose store stopped before its
    /// index row, and nothing tells the two apart, so it was kept. A new forget card removes it.
    KeptUnrecorded,
}

/// What a forget card records when nothing was stored under its name.
const NOTHING_STORED: &str = "-";

/// Delete a stored key and its index row. Both deletions run under the index write lock,
/// which a store holds around its stash write and its index row: a store lands wholly before
/// or wholly after, never between them, so no value is left without its row.
///
/// `card` is the forget card being confirmed and the confirm's claim on it. Before deleting
/// anything, the first confirm records on the card which stored value it is about, and that
/// record is committed on its own. A confirm of the card after one that stopped half way
/// (the key deleted, the card still open) deletes only that value: a key stored since stays.
/// A value with no index row has no id to record, so a later confirm deletes no such value.
pub fn forget(ctx: &Ctx, name: &str, identity: &str, card: Option<(&str, &str)>) -> Result<Forgot> {
    let key = crate::stash::stash_key(name, identity);
    let about = match card {
        Some((id, claim)) => {
            let pinned = ctx.db.locked(|| {
                let now = ctx.db.stored_value_id(name, identity)?;
                ctx.db.pin_action_target(id, claim, now.as_deref().unwrap_or(NOTHING_STORED))
            })?;
            Some(pinned.context("another confirm took this card over; reload it")?)
        }
        None => None,
    };
    ctx.db.locked(|| {
        let now = ctx.db.stored_value_id(name, identity)?;
        if let Some((about, first)) = &about {
            if now.as_deref().unwrap_or(NOTHING_STORED) != about {
                return Ok(Forgot::Gone { kept: now.is_some() });
            }
            if !first && about == NOTHING_STORED {
                return Ok(if ctx.stash.get(&key)?.is_some() { Forgot::KeptUnrecorded } else { Forgot::NothingStored });
            }
        }
        let had = ctx.stash.delete(&key)?;
        let meta = ctx.db.delete_secret(name, identity)?;
        ctx.db.audit(None, None, "forget", Some(name), Some(identity), None)?;
        Ok(if had || meta { Forgot::Deleted } else { Forgot::NothingStored })
    })
}

/// An agent asks to replace a key, usually because the user told it to. Unlike a person's
/// `rotate`, the stored key is not marked stale: it keeps working until the person pastes the
/// new one on the Replace card, and declining the card changes nothing.
pub fn request_rotation(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, why: Option<&str>) -> Result<Task> {
    if ctx.db.get_secret(name, identity)?.is_none() {
        bail!("{name}@{identity} is not in the stash; use `tokenstash need {name}` to add it");
    }
    let pid = project.to_string_lossy().to_string();
    ctx.db.audit(Some(&pid), Some(agent), "rotate.requested", Some(name), Some(identity), None)?;
    let asked = match why {
        Some(w) if !w.trim().is_empty() => format!("{agent} asked to replace {name}: {}", w.trim()),
        _ => format!("{agent} asked to replace {name}"),
    };
    let req = tasks::SecretRequest {
        why: Some(format!("{asked}. The current key keeps working until you paste the new one here; paste it first, then revoke the old one in the provider's dashboard.")),
        ..Default::default()
    };
    tasks::create_replacement_task(ctx, project, agent, name, identity, &req)
}
