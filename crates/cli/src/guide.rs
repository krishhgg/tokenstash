//! What an agent should do after each result. One wording for the CLI and the MCP server,
//! so an agent gets the same instruction whichever way it asked.

use std::path::Path;
use tokenstash_core::db::{Task, TaskKind};
use tokenstash_core::need::Outcome;
use tokenstash_core::tasks::EXPECTS_REPLACE;

pub const NO_STAND_IN: &str = "do not supply a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code).";
pub const INSTEAD: &str = "Make the feature optional or report the work blocked on it.";

/// How the agent checks on a pending card later.
#[derive(Clone, Copy)]
pub enum Recheck {
    Cli,
    Mcp,
}

impl Recheck {
    fn later(self, task_id: &str) -> String {
        match self {
            Recheck::Cli => format!("check on card {task_id} later with `tokenstash tasks` (running the same `tokenstash need` again also works, and never notifies the user twice)"),
            Recheck::Mcp => format!("call task_check(\"{task_id}\") later"),
        }
    }
}

/// The card is an approval or a Replace card: the agent's link shows it but cannot answer it.
pub fn needs_full_session(task: Option<&Task>) -> bool {
    task.map(|t| t.kind == TaskKind::Approval || t.expects == EXPECTS_REPLACE).unwrap_or(false)
}

/// `card` is the agent's link to the card (or, with the inbox unavailable, the reason there
/// is none); `task` is the card itself; `waited` is a note about time already spent waiting.
pub fn next(o: &Outcome, env_file: &Path, task: Option<&Task>, card: &str, recheck: Recheck, waited: &str) -> String {
    match o {
        Outcome::Injected { name, unverified, .. } => format!(
            "{name} is in {}. Load it with your runtime (dotenv, process.env, os.environ, or `tokenstash run -- <command>`); never read, print or quote that file.{}",
            env_file.display(),
            if *unverified { " (Could not re-check it with the provider just now.)" } else { "" }
        ),
        Outcome::Pending { name, task_id, .. } => {
            // Why it is pending: a missing key, a stored key waiting for the user's approval
            // for this project, or a stored key the provider rejected (Replace card). The
            // agent must not send the user to acquire a key they already have.
            let why = match task {
                Some(t) if t.kind == TaskKind::Approval => format!("{name} is stored, but this project needs the user's approval to receive it"),
                Some(t) if t.expects == EXPECTS_REPLACE => format!("the stored {name} was rejected by its provider; the user has been asked for a replacement"),
                _ => format!("{name} is not in the stash; the user has been asked to add it"),
            };
            // The agent's link opens one card: it can take a missing key, and it cannot
            // approve. Saying "it works as-is" for an approval card sends the user to an
            // error box.
            let link = if !card.starts_with("http") {
                format!("The inbox is unavailable ({card}); tell the user to run `tokenstash open`.")
            } else if needs_full_session(task) {
                // The link ends its sentence with no punctuation after it, so whoever copies
                // it (the agent, a test) gets the URL and nothing else.
                format!("The user answers it from the desktop notification. This link shows the card, and the card can send that notification again: {card}")
            } else {
                format!("Show the user this link: {card}")
            };
            format!("{why} ({task_id}).{waited} {link} Keep working on everything that does not need it, and {}. Do not wait in a loop, and {NO_STAND_IN}", recheck.later(task_id))
        }
        Outcome::Denied { name, .. } => format!("The user declined {name} for this project. Do not ask again, and {NO_STAND_IN} {INSTEAD}"),
        Outcome::Expired { name, .. } => format!("The request for {name} expired unanswered. Summarise what is blocked and stop; {NO_STAND_IN}"),
    }
}

/// The summary line over several results. "Done" only when every key arrived: a declined or
/// expired key is not done, and an agent reading the summary alone must not take it as such.
pub fn summary(outcomes: &[Outcome], recheck: Recheck) -> &'static str {
    let pending = outcomes.iter().any(|o| o.is_pending());
    let missing = outcomes.iter().any(|o| matches!(o, Outcome::Denied { .. } | Outcome::Expired { .. }));
    match (pending, missing, recheck) {
        (true, _, Recheck::Mcp) => "One or more keys are pending: follow each result's `next`. Show the user the link, keep working, call task_check later.",
        (true, _, Recheck::Cli) => "One or more keys are pending: follow each result's `next`. Show the user the link, keep working, check later with `tokenstash tasks`.",
        (false, true, _) => "Not every key arrived: one or more were declined or expired. Follow each result's `next`; work that needs those keys is blocked.",
        (false, false, _) => "Done — follow each result's `next`.",
    }
}

/// A card an agent filed for the person to confirm (`forget`, `bind`, `init --mode`, ...).
pub fn confirm_next(task: &Task, card: &str) -> String {
    let link = if !card.starts_with("http") {
        format!("The inbox is unavailable ({card}).")
    } else {
        format!("Confirming takes the link in the desktop notification. This link shows the card, and the card can send that notification again: {card}")
    };
    format!(
        "The user has been asked to confirm \"{}\" ({}). {link} Keep working, and check on card {} later with `tokenstash tasks --history`. If the user declines, leave it: do not ask again unless they tell you to.",
        task.title, task.id, task.id
    )
}
