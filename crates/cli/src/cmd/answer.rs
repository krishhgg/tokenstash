use crate::util::{self, App};
use anyhow::{bail, Result};
use clap::Args;
use secrecy::SecretString;
use std::io::Read;
use tokenstash_core::db::TaskKind;
use tokenstash_core::tasks::{self, Actor, AnswerResult};

#[derive(Args)]
pub struct AnswerArgs {
    /// Task id (or unique prefix). Omit to answer the oldest open task in this project.
    pub id: Option<String>,
    /// Read the value from stdin instead of a masked prompt (for scripts/tests).
    #[arg(long)]
    pub stdin: bool,
    /// Skip the provider liveness check.
    #[arg(long)]
    pub skip_check: bool,
    /// Approve (approval tasks): exactly the listed keys.
    #[arg(long)]
    pub allow: bool,
    /// Approve a pairing card broadly: the listed keys plus any registry-confirmed
    /// non-sensitive key for the same identity in this directory.
    #[arg(long)]
    pub allow_broad: bool,
    /// Deny / decline any task.
    #[arg(long)]
    pub deny: bool,
    /// Note for human tasks, or a reason when denying. Returned to the agent word for word:
    /// an answer or a reason, never a secret.
    #[arg(long)]
    pub note: Option<String>,
}

pub fn answer(a: AnswerArgs) -> Result<i32> {
    let app = App::open()?;
    app.db.expire_overdue()?;
    let task = match &a.id {
        Some(id) => app.db.find_task(id)?.ok_or_else(|| anyhow::anyhow!("no task matching '{id}'"))?,
        None => {
            let project = tokenstash_core::project::current();
            app.db.list_tasks(Some(&project.to_string_lossy()), true)?.into_iter().next().ok_or_else(|| anyhow::anyhow!("no open tasks in this project"))?
        }
    };
    // An agent at a shell may answer its own directory's cards and nothing else's: any id is
    // one `tasks --all` away, and a denial or a note is a decision about that directory.
    if std::path::Path::new(&task.project) != tokenstash_core::project::current() {
        util::require_human("answer", "this card belongs to another directory")?;
    }
    let ctx = app.ctx();
    // What the terminal can tell about who is typing. The refusals below explain themselves
    // before the core check runs; the core check is the one that holds either way.
    let actor = if util::looks_human() { Actor::Human } else { Actor::Requester };

    if a.deny {
        tasks::deny(&ctx, &task, a.note.as_deref())?;
        println!("✗ {} denied", task.id);
        return Ok(0);
    }

    match task.kind {
        TaskKind::Secret => {
            // A paste that other directories will receive (a Replace card; a key they hold a
            // grant for) is a decision about them, not about this one.
            if tasks::fans_out(&ctx, &task)? {
                util::require_human("answer", "this key is held by other directories, so the paste reaches them too")?;
            }
            let name = task.name.clone().unwrap_or_default();
            println!("{}  [{}]", task.title, util::short(&task.project));
            if let Some(w) = &task.why { println!("  why: {w}"); }
            if let Some(u) = &task.url { println!("  get it at: {u}"); }
            for (i, s) in task.steps.iter().enumerate() { println!("  {}. {s}", i + 1); }
            let raw = if a.stdin {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.trim().to_string()
            } else {
                rpassword::prompt_password(format!("Paste {name} (input hidden): "))?.trim().to_string()
            };
            if raw.is_empty() {
                bail!("empty value; nothing stored");
            }
            match tasks::answer_secret_by(&ctx, actor, &task, SecretString::from(raw), a.skip_check)? {
                AnswerResult::Stored { injected_to, sensitive, liveness, rotation } => {
                    if let Some(r) = &rotation {
                        for p in &r.rewritten { println!("  also updated → {}", tokenstash_core::project::short(std::path::Path::new(p))); }
                        for (p, why) in &r.skipped { println!("  ! still holds the OLD value: {}, {why}", tokenstash_core::project::short(std::path::Path::new(p))); }
                        if !r.skipped.is_empty() { println!("  fix those before revoking the old key"); }
                    }
                    println!("✓ {name} stored in the {} stash", app.stash.backend());
                    if let Some(l) = liveness { println!("  liveness: {}", describe(&l)); }
                    if sensitive { println!("  tagged sensitive: will ask once per project"); }
                    if let Some(p) = injected_to { println!("  injected → {}", p.display()); }
                }
                _ => unreachable!(),
            }
        }
        TaskKind::Approval => {
            // Approving is the human's decision and nothing else in the product. Without this
            // an agent with a shell reads the card id out of `tokenstash tasks --json` and
            // runs `answer <id> --allow-broad` to grant itself the human's keys, the exact
            // thing the inbox's paste-scope token exists to prevent. Denying stays open: it
            // can only close the agent's own request, never open one.
            util::require_human("answer --allow", "approving a card is your decision, not an agent's")?;
            println!("{}", task.title);
            if let Some(w) = &task.why { println!("  {w}"); }
            println!("  keys: {}", crate::util::approval_names(&task.names).join(", "));
            let decision = if a.allow_broad {
                tasks::Decision::AllowBroad
            } else if a.allow {
                tasks::Decision::Allow
            } else {
                let ans = rpassword::prompt_password("Allow? [y/N] (input hidden) ")?;
                if matches!(ans.trim(), "y" | "Y" | "yes") { tasks::Decision::Allow } else { tasks::Decision::Deny }
            };
            match tasks::answer_approval(&ctx, &task, decision, Some(&task.names))? {
                AnswerResult::Approved { injected, replaced } => {
                    println!("✓ approved; injected {}", if injected.is_empty() { "nothing new".into() } else { injected.join(", ") });
                    if !replaced.is_empty() { println!("  {} rejected by the provider at delivery. A Replace card is waiting", replaced.join(", ")); }
                }
                AnswerResult::Denied => println!("✗ denied"),
                _ => unreachable!(),
            }
        }
        TaskKind::Human if tokenstash_core::actions::Action::of(&task).is_some() => {
            // An action card (forget a key, change the agent mode, ...) is the person's to
            // confirm. Answered here, it does what it says, as the inbox would.
            util::require_human("answer", "confirming this card changes your stash or your agents' setup")?;
            let action = tokenstash_core::actions::Action::of(&task).expect("checked above");
            println!("{}\n  {}", task.title, action.effect());
            let ans = rpassword::prompt_password("Confirm? [y/N] (input hidden) ")?;
            if !matches!(ans.trim(), "y" | "Y" | "yes") {
                tasks::deny(&ctx, &task, None)?;
                println!("✗ declined");
                return Ok(0);
            }
            let done = crate::cmd::actions::confirm(&app, &task, &action)?;
            println!("✓ {done}");
        }
        TaskKind::Human => {
            println!("{}", task.title);
            if let Some(w) = &task.why { println!("  why: {w}"); }
            if let Some(u) = &task.url { println!("  at: {u}"); }
            for (i, s) in task.steps.iter().enumerate() { println!("  {}. {s}", i + 1); }
            let note = match (&a.note, task.expects.as_str()) {
                (Some(n), _) => Some(n.clone()),
                (None, "text") => {
                    let mut s = String::new();
                    // Said before anything is typed: the answer goes to the agent as typed.
                    println!("Your answer is returned to the agent word for word. Do not put a password, a key, or anything private in it; the agent should request secrets with `tokenstash need`.");
                    println!("Enter your answer, then Ctrl-D:");
                    std::io::stdin().read_to_string(&mut s)?;
                    Some(s.trim().to_string())
                }
                _ => None,
            };
            tasks::answer_human(&ctx, &task, note.as_deref())?;
            println!("✓ marked done");
        }
    }
    Ok(0)
}

pub fn describe(l: &tokenstash_core::validate::Liveness) -> String {
    use tokenstash_core::validate::Liveness::*;
    match l {
        Ok => "key accepted by the provider".into(),
        Rejected(c) => format!("rejected (HTTP {c})"),
        Unknown(e) => format!("could not verify ({e}); stored anyway"),
    }
}
