use crate::notify;
use anyhow::Result;
use tokenstash_core::{Config, Db};

pub fn doctor() -> Result<i32> {
    let mut ok = true;
    let check = |label: &str, good: bool, detail: String| {
        println!("{} {:<28} {}", if good { "✓" } else { "✗" }, label, detail);
        good
    };

    let cfg_exists = Config::exists();
    ok &= check("config", cfg_exists, tokenstash_core::config::config_path().display().to_string() + if cfg_exists { "" } else { "  (run `tokenstash init`)" });
    let cfg = Config::load()?;

    match tokenstash_core::stash::open(&cfg) {
        Ok(s) => {
            let probe = match s.backend() {
                "insecure-file" => Ok(()),
                _ => tokenstash_core::stash::probe(s.as_ref()),
            };
            let note = match (&probe, s.note()) {
                (Err(e), _) => format!("  ({e})"),
                (Ok(()), Some(n)) => format!("  ({n})"),
                (Ok(()), None) => String::new(),
            };
            ok &= check("stash backend", probe.is_ok(), format!("{}{note}", s.backend()));
        }
        Err(e) => { ok &= check("stash backend", false, e.to_string()); }
    }

    match Db::open_default() {
        Ok(db) => {
            let n = db.list_secrets().map(|v| v.len()).unwrap_or(0);
            let open = db.list_tasks(None, true).map(|v| v.len()).unwrap_or(0);
            check("database", true, format!("{} secrets indexed, {} open tasks", n, open));
        }
        Err(e) => { ok &= check("database", false, e.to_string()); }
    }

    check("registry", true, format!("{} providers", tokenstash_core::registry::count()));
    if !cfg.trust_roots.is_empty() {
        check("trust roots", true, format!("{} in config, retired in 0.2 — each directory pairs once instead (`tokenstash workspaces`)", cfg.trust_roots.len()));
    }
    // "Not running" is normal — it starts on demand. Someone else holding the port is not:
    // that is the case where a human could be sent to paste a key into another process.
    let inbox = notify::inbox_state(&cfg);
    ok &= check(
        "inbox",
        inbox != notify::Inbox::Foreign,
        // `check` prints to stdout, so the TTY check is stdout's. No card is named, so no
        // database is needed to sign a link.
        format!("{}  {}", crate::util::inbox_url_tty(&cfg, None, None, inbox, crate::util::Stream::Stdout), notify::describe(inbox)),
    );

    check("agent mode", true, crate::cmd::init::describe_mode(cfg.agent_mode).into());
    let home = dirs::home_dir().unwrap_or_default();
    let agents = crate::cmd::init::installed(&home);
    // Auto mode's hooks left behind in explicit mode (or the other way round) mean the agent
    // is not in the mode config says: a registration made by hand after the switch, say.
    let stray = match cfg.agent_mode {
        tokenstash_core::config::AgentMode::Explicit => agents.iter().any(|a| crate::cmd::init::is_auto_wiring(a)),
        tokenstash_core::config::AgentMode::Auto => agents.iter().any(|a| crate::cmd::init::is_explicit_wiring(a)),
    };
    ok &= check("agents", !stray, if agents.is_empty() { "none configured (run `tokenstash init`)".into() } else if stray { format!("{}  (not all in {} mode: re-run `tokenstash init`)", agents.join(", "), cfg.agent_mode) } else { agents.join(", ") });

    let project = tokenstash_core::project::current();
    let standing = match Db::open_default() {
        Ok(db) => db.find_workspace(&project).ok().flatten().map(|w| db.grants_for(&w.id).map(|g| g.len()).unwrap_or(0)),
        Err(_) => None,
    };
    let refused = tokenstash_core::trust::refused_root(&project);
    check("this directory", refused.is_none(), format!("{}  {}", tokenstash_core::project::short(&project), match (refused, standing) {
        (Some(why), _) => format!("is {why} — no keys are delivered here"),
        (None, Some(n)) => format!("paired, {n} grant(s)"),
        (None, None) => "not paired yet → the first stored key asks once".into(),
    }));
    check("binary", true, std::env::current_exe()?.display().to_string());

    Ok(if ok { 0 } else { 1 })
}
