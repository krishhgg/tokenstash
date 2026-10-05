use crate::notify;
use crate::util::{self, App};
use anyhow::Result;
use clap::Args;
use std::time::Duration;
use tokenstash_core::exit;
use tokenstash_core::need::{self, NeedOpts, Outcome};
use tokenstash_core::tasks::{self, HumanRequest, SecretRequest};

#[derive(Args)]
pub struct NeedArgs {
    /// Env var names, e.g. OPENAI_API_KEY RESEND_API_KEY
    #[arg(required = true)]
    pub names: Vec<String>,
    /// Why the agent needs it (shown to the human).
    #[arg(long)]
    pub why: Option<String>,
    /// Where to get it (overrides the registry).
    #[arg(long)]
    pub url: Option<String>,
    /// Step-by-step instructions (repeatable).
    #[arg(long = "step")]
    pub steps: Vec<String>,
    /// Regex the value must match.
    #[arg(long)]
    pub pattern: Option<String>,
    /// Identity label (work/personal). Defaults to the project binding or "default".
    #[arg(long)]
    pub identity: Option<String>,
    /// Wait for the human instead of returning immediately.
    #[arg(long)]
    pub blocking: bool,
    /// Seconds to wait when --blocking.
    #[arg(long, default_value = "600", requires = "blocking")]
    pub timeout: u64,
    /// Agent name for the audit log (auto-detected).
    #[arg(long)]
    pub agent: Option<String>,
    /// Ask again even if the user recently declined this key for this project.
    #[arg(long)]
    pub force: bool,
    /// Machine-readable output.
    #[arg(long)]
    pub json: bool,
}

pub fn need(a: NeedArgs) -> Result<i32> {
    let app = App::open()?;
    // The directory this command runs in is the project: a caller-named path would let a
    // script choose which directory's grants it uses. (Read-only `tasks`/`audit` keep --project.)
    let project = util::project_from(&None);
    let agent = util::agent_from(&a.agent);
    // "Denied" is remembered for a day so a program failing in a loop cannot nag. An agent may
    // ask again over it once per key and project in that window, when the user tells it to:
    // the card says it is a second ask, and a second "no" stands for the rest of the window.
    let mut why = a.why.clone();
    let pid = project.to_string_lossy().to_string();
    // Only a key the person declined here is asked "again"; for any other, --force from an
    // agent is an ordinary request and spends nothing.
    let mut denied: Vec<String> = vec![];
    if a.force && !util::looks_human() {
        for name in &a.names {
            if tokenstash_core::need::denied_here(&app.ctx(), &project, name, a.identity.as_deref())? {
                denied.push(name.clone());
            }
        }
    }
    let ask_again = !denied.is_empty();
    // The one extra ask is reserved before the card is filed, in one step, so two requests
    // at once cannot both take it; one that ends without a card for the key hands it back.
    let mut reserved: Vec<(String, i64)> = vec![];
    if ask_again {
        let since = app.cfg.ttl_since();
        for name in &denied {
            match app.db.reserve_once(&pid, &agent, name, "need.force", &since)? {
                Some(row) => reserved.push((name.clone(), row)),
                None => {
                    for (_, row) in &reserved { app.db.delete_audit_row(*row)?; }
                    anyhow::bail!("{name} was already asked for again once after the user declined it here; that answer stands for {} hours from the first no. Tell the user; do not ask again", app.cfg.task_ttl_hours);
                }
            }
        }
        why = Some(match why {
            Some(w) => format!("Asked again after you declined, because you asked {agent} to. {w}"),
            None => format!("Asked again after you declined, because you asked {agent} to."),
        });
    }
    let opts = NeedOpts {
        req: SecretRequest { why, url: a.url.clone(), steps: a.steps.clone(), pattern: a.pattern.clone() },
        identity: a.identity.clone(),
        blocking: false,
        timeout: Duration::from_secs(a.timeout),
        force: a.force,
        require_approval: false,
        ask_again,
    };
    let outcomes = need::need(&app.ctx(), &project, &agent, &a.names, &opts);
    let mut outcomes = match outcomes {
        Ok(o) => o,
        Err(e) => {
            for (_, row) in &reserved { app.db.delete_audit_row(*row)?; }
            return Err(e);
        }
    };
    // The one extra ask is spent only by a request that filed a card for the key: a request
    // that failed, or found the key already allowed, leaves it for later.
    for (name, row) in &reserved {
        if !outcomes.iter().any(|o| o.is_pending() && o.name() == name) {
            app.db.delete_audit_row(*row)?;
        }
    }

    if outcomes.iter().any(|o| o.is_pending()) {
        notify_pending(&app, &project, &agent, &outcomes);
        if a.blocking {
            // wait on the tasks already filed; never file a second set
            need::wait(&app.ctx(), &project, &mut outcomes, opts.timeout)?;
        }
    }

    // Only probed when something is pending: a hit never needs the inbox.
    let pending = outcomes.iter().any(|o| o.is_pending());
    let state = if pending { notify::inbox_state(&app.cfg) } else { notify::Inbox::Down };
    let env_file = project.join(&app.cfg.env_file);
    // Each result carries its own card link and its own `next`, the same text the MCP tool
    // returns; the top-level `inbox` is the bare index URL, and carries nothing.
    let mut results: Vec<(serde_json::Value, String)> = Vec::with_capacity(outcomes.len());
    for o in &outcomes {
        let mut v = serde_json::to_value(o)?;
        let (task, card) = match o {
            Outcome::Pending { task_id, .. } => {
                let card = util::inbox_url_agent(&app.cfg, Some(&app.db), Some(task_id), state);
                v["inbox"] = serde_json::json!(card);
                (app.db.get_task(task_id)?, card)
            }
            _ => (None, String::new()),
        };
        let next = crate::guide::next(o, &env_file, task.as_ref(), &card, crate::guide::Recheck::Cli, "");
        v["next"] = serde_json::json!(next);
        results.push((v, next));
    }
    if a.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "project": project,
            "env_file": app.cfg.env_file,
            "inbox": util::inbox_url_agent(&app.cfg, Some(&app.db), None, state),
            "results": results.iter().map(|(v, _)| v).collect::<Vec<_>>(),
            "next": crate::guide::summary(&outcomes, crate::guide::Recheck::Cli),
        }))?);
    } else {
        for (o, (_, next)) in outcomes.iter().zip(&results) {
            match o {
                Outcome::Injected { name, written_to, generated, .. } => {
                    let p = std::path::Path::new(written_to);
                    let rel = p.strip_prefix(&project).map(|r| r.display().to_string()).unwrap_or(written_to.clone());
                    println!("✓ {name} {} → {rel}", if *generated { "generated and injected" } else { "injected" });
                }
                Outcome::Pending { name, task_id, .. } => println!("⏳ {name} pending (card {task_id})"),
                Outcome::Denied { name, .. } => println!("✗ {name} denied by the user"),
                Outcome::Expired { name, .. } => println!("✗ {name} expired unanswered"),
            }
            println!("  next: {next}");
        }
    }
    Ok(code_for(&outcomes))
}

pub fn notify_pending(app: &App, project: &std::path::Path, agent: &str, outcomes: &[Outcome]) {
    let state = notify::ensure_inbox(&app.cfg);
    // One notification per card. A polling agent re-runs `need` every few seconds and gets
    // the same card back; the human must not get the same toast back.
    let fresh: Vec<&Outcome> = outcomes.iter().filter(|o| matches!(o, Outcome::Pending { task_id, .. } if app.db.mark_notified(task_id).unwrap_or(true))).collect();
    if fresh.is_empty() {
        return;
    }
    let pending: Vec<&str> = fresh.iter().map(|o| o.name()).collect();
    let first_id = fresh.iter().find_map(|o| match o { Outcome::Pending { task_id, .. } => Some(task_id.clone()), _ => None });
    notify::desktop(
        &app.cfg,
        &format!("{} needs {}", tokenstash_core::project::short(project), pending.join(", ")),
        &format!("requested by {agent}"),
        // The notification is read by the human and nothing else, so it is tokened — but only
        // if `state` says we proved the port is ours. Otherwise it explains itself instead of
        // walking the human, and the token, into whatever is squatting there.
        &util::inbox_notice(&app.cfg, first_id.as_deref(), state),
    );
}

pub fn code_for(outcomes: &[Outcome]) -> i32 {
    if outcomes.iter().any(|o| o.is_pending()) {
        exit::PENDING
    } else if outcomes.iter().any(|o| matches!(o, Outcome::Denied { .. })) {
        exit::DENIED
    } else if outcomes.iter().any(|o| matches!(o, Outcome::Expired { .. })) {
        exit::EXPIRED
    } else {
        exit::INJECTED
    }
}

#[derive(Args)]
pub struct AskArgs {
    /// What you need the human to do.
    pub title: String,
    #[arg(long)]
    pub why: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long = "step")]
    pub steps: Vec<String>,
    /// confirm | text. A `text` answer is returned to the agent — tell the human not to paste secrets into it.
    #[arg(long, default_value = "confirm")]
    pub expects: String,
    #[arg(long)]
    pub blocking: bool,
    /// Seconds to wait when --blocking.
    #[arg(long, default_value = "600", requires = "blocking")]
    pub timeout: u64,
    #[arg(long)]
    pub agent: Option<String>,
    #[arg(long)]
    pub json: bool,
}

pub fn ask(a: AskArgs) -> Result<i32> {
    let app = App::open()?;
    let project = util::project_from(&None);
    let agent = util::agent_from(&a.agent);
    let t = tasks::create_human_task(
        &app.ctx(),
        &project,
        &agent,
        HumanRequest { title: a.title.clone(), why: a.why.clone(), url: a.url.clone(), steps: a.steps.clone(), expects: a.expects.clone() },
    )?;
    let state = notify::ensure_inbox(&app.cfg);
    // The same title returns the same task; it must not return the same toast.
    if app.db.mark_notified(&t.id).unwrap_or(true) {
        notify::desktop(&app.cfg, &t.title, &format!("{} · {agent}", tokenstash_core::project::short(&project)), &util::inbox_notice(&app.cfg, Some(&t.id), state));
    }
    let mut task = t;
    if a.blocking {
        let start = std::time::Instant::now();
        while task.status == tokenstash_core::db::TaskStatus::Pending && start.elapsed().as_secs() < a.timeout {
            std::thread::sleep(Duration::from_millis(500));
            app.db.expire_overdue()?;
            task = app.db.get_task(&task.id)?.unwrap_or(task);
        }
    }
    let state = notify::inbox_state(&app.cfg);
    if a.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "task": task, "inbox": util::inbox_url_agent(&app.cfg, Some(&app.db), Some(&task.id), state) }))?);
    } else {
        println!("{} {} — task {} → {}", status_icon(&task.status), task.title, task.id, util::inbox_url_agent(&app.cfg, Some(&app.db), Some(&task.id), state));
        if let Some(n) = &task.note {
            println!("  note: {n}");
        }
    }
    Ok(match task.status {
        tokenstash_core::db::TaskStatus::Pending => exit::PENDING,
        tokenstash_core::db::TaskStatus::Answered => exit::INJECTED,
        tokenstash_core::db::TaskStatus::Denied => exit::DENIED,
        tokenstash_core::db::TaskStatus::Expired => exit::EXPIRED,
    })
}

pub fn status_icon(s: &tokenstash_core::db::TaskStatus) -> &'static str {
    use tokenstash_core::db::TaskStatus::*;
    match s {
        Pending => "⏳",
        Answered => "✓",
        Denied => "✗",
        Expired => "⌛",
    }
}
