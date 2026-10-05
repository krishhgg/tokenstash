//! tokenstash — Paste a key once. Approve each directory. Keep secrets out of status output.

mod cmd;
mod guide;
mod inbox_auth;
mod notify;
mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tokenstash", version, about = "Paste a key once. Approve each directory. Keep secrets out of status output.")]
#[command(long_about = "Agents run `tokenstash need NAME`. If the key is in your stash and this directory is approved for it, it is written to the project's env file.\nIf not, a task is filed for you: you acquire the key yourself (own account, own signup), paste it once, and the agent resumes.\nA normal delivery writes the value to the env file and returns status (exit code, key name, file) without echoing the value.\nNotes you type on a card are returned to the agent as text; they are not a place to paste a credential.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Request one or more secrets for this project (hit → inject, miss → file a task). Exit 0 injected / 10 pending / 20 denied / 30 expired.
    Need(cmd::need::NeedArgs),
    /// File a non-secret task for the human (DNS record, dashboard toggle, OAuth consent screen…).
    Ask(cmd::need::AskArgs),
    /// Answer a task from the terminal (paste a secret, approve, or mark done).
    Answer(cmd::answer::AnswerArgs),
    /// List open tasks for this project (--all for every project).
    Tasks(cmd::admin::TasksArgs),
    /// List stashed secret names and identities. Never values.
    List(cmd::admin::ListArgs),
    /// Delete a secret from the stash.
    Forget(cmd::admin::ForgetArgs),
    /// Replace a key: marks it stale and asks you for the new value now.
    Rotate(cmd::admin::RotateArgs),
    /// Agent-facing: a provider rejected a key tokenstash injected (401/403). Never ask the user in chat; call this, then `need` again.
    ReportBad(cmd::admin::ReportBadArgs),
    /// Test every stored key against its provider and mark dead ones stale. For a person at a terminal.
    Check(cmd::admin::CheckArgs),
    /// Write every secret to one passphrase-encrypted file, to move to another machine. For a person at a terminal (an agent with a shell can still run it under a pty; keep that in mind).
    Export(cmd::bundle::ExportArgs),
    /// Merge a bundle from `export` into this machine's stash. For a person at a terminal.
    Import(cmd::bundle::ImportArgs),
    /// Bind a secret name to an identity for this project (work vs personal).
    Bind(cmd::admin::BindArgs),
    /// Deprecated since 0.2 (directories pair once instead); kept so `trust rm` can tidy old config.
    #[command(hide = true)]
    Trust(cmd::admin::TrustArgs),
    /// Paired directories and what each may receive; revoke or forget one. For a person at a terminal.
    Workspaces(cmd::admin::WorkspacesArgs),
    /// Show recent audit events (never values).
    Audit(cmd::admin::AuditArgs),
    /// Detect agents and wire them up (MCP server + skill, or a `/tokenstash` command with --mode explicit); choose a stash backend.
    Init(cmd::init::InitArgs),
    /// Check that everything works.
    Doctor,
    /// Run a command with the project's env file loaded; if it dies on a missing key, file the task, wait, inject, restart.
    Run(cmd::run::RunArgs),
    /// Serve the MCP server over stdio (used by agents; configured by `init`).
    Mcp,
    /// Serve the localhost inbox (started automatically when a task is filed).
    Inbox(cmd::inbox::InboxArgs),
    /// Open the inbox in your browser.
    Open,
    /// Print the provider registry (names and signup URLs).
    Registry,
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tokenstash: error: {e:#}");
            tokenstash_core::exit::ERROR
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.cmd {
        Cmd::Need(a) => cmd::need::need(a),
        Cmd::Ask(a) => cmd::need::ask(a),
        Cmd::Answer(a) => cmd::answer::answer(a),
        Cmd::Tasks(a) => cmd::admin::tasks(a),
        Cmd::List(a) => cmd::admin::list(a),
        Cmd::Forget(a) => cmd::admin::forget(a),
        Cmd::Rotate(a) => cmd::admin::rotate(a),
        Cmd::ReportBad(a) => cmd::admin::report_bad(a),
        Cmd::Check(a) => cmd::admin::check(a),
        Cmd::Export(a) => cmd::bundle::export(a),
        Cmd::Import(a) => cmd::bundle::import(a),
        Cmd::Bind(a) => cmd::admin::bind(a),
        Cmd::Trust(a) => cmd::admin::trust(a),
        Cmd::Workspaces(a) => cmd::admin::workspaces(a),
        Cmd::Audit(a) => cmd::admin::audit(a),
        Cmd::Init(a) => cmd::init::init(a),
        Cmd::Doctor => cmd::doctor::doctor(),
        Cmd::Run(a) => cmd::run::run(a),
        Cmd::Mcp => cmd::mcp::serve(),
        Cmd::Inbox(a) => cmd::inbox::serve(a),
        Cmd::Open => {
            // The URL below carries the full inbox session, which approves cards. Printed to
            // a pipe it lands in an agent's context — the one place it must never be.
            util::require_human("open", "it prints the full inbox session, which can approve cards")?;
            let cfg = tokenstash_core::Config::load()?;
            let state = notify::ensure_inbox(&cfg);
            // `open` exists to put a person in front of the inbox, so it carries the session
            // token — but only once ownership is proved. If something else holds the port we
            // launch no browser and print no URL: doing either would hand the squatter the
            // token (in the query string) and the human (into its paste form).
            if let Some(why) = util::inbox_unavailable(&cfg, state) {
                eprintln!("tokenstash: {why}");
                return Ok(tokenstash_core::exit::ERROR);
            }
            let url = util::inbox_url_human(&cfg, None, state);
            let _ = open::that(&url);
            println!("{url}");
            Ok(0)
        }
        Cmd::Registry => {
            for p in tokenstash_core::registry::all() {
                println!("{:<36} {:<22} {}{}", p.name, p.provider, p.url, if p.sensitive { "  [sensitive]" } else { "" });
            }
            println!("\n{} providers. Missing one? https://github.com/kgarg2468/tokenstash/blob/main/CONTRIBUTING.md", tokenstash_core::registry::count());
            Ok(0)
        }
    }
}
