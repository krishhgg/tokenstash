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
            // With the kernel keyring, an older tokenstash keeps its own copy of a key in each
            // login session it ran in, and while it runs it can put an old value back.
            let keys: Vec<String> = Db::open_default()
                .and_then(|db| db.list_secrets())
                .map(|v| v.iter().map(|m| tokenstash_core::stash::stash_key(&m.name, &m.identity)).collect())
                .unwrap_or_default();
            // One line whenever the backend has copies to look for, so a missing line never
            // stands for a check that found nothing.
            if let Some(found) = s.stray_copies(&keys) {
                let mut detail = vec![];
                // Two keyrings that disagree are a fault, because a read can return the old
                // key now.
                let differ: Vec<&str> = found.copies.iter().filter(|c| c.differs).map(|c| c.key.as_str()).collect();
                if !differ.is_empty() {
                    detail.push(format!(
                        "The user keyring and the persistent keyring hold different values for {}, so a read can return the old key. tokenstash 0.3.0 or earlier, still running in another login session (an inbox or `tokenstash mcp` started before the upgrade), put the other value there. Stop it, then replace the key with `tokenstash rotate NAME` if the old one is in use.",
                        differ.join(", ")
                    ));
                }
                // A copy only another session holds is a note. It does nothing until an older
                // tokenstash runs there, and an upgrade leaves idle sessions holding them.
                let held: Vec<&str> = found.copies.iter().filter(|c| c.elsewhere > 0).map(|c| c.key.as_str()).collect();
                if !held.is_empty() {
                    detail.push(format!(
                        "Other login sessions hold their own copy of {}, left by tokenstash 0.3.0 or earlier. It matters only while an older tokenstash still runs in one of them (an inbox or `tokenstash mcp` started before the upgrade), because it could put the old key back. Stop it, or end that session.",
                        held.join(", ")
                    ));
                }
                if detail.is_empty() {
                    detail.push(format!("None among the {} key(s) checked.", found.checked));
                }
                detail.extend(found.limited);
                ok &= check("older copies", differ.is_empty(), detail.join(" "));
            }
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
        check("trust roots", true, format!("{} in config, retired in 0.2. Each directory pairs once instead (`tokenstash workspaces`)", cfg.trust_roots.len()));
    }
    // "Not running" is normal because it starts on demand. Someone else holding the port is not:
    // that is the case where a human could be sent to paste a key into another process.
    let inbox = notify::inbox_state(&cfg);
    ok &= check(
        "inbox",
        inbox != notify::Inbox::Foreign,
        // `check` prints to stdout, so the TTY check is stdout's. No card is named, so no
        // database is needed to sign a link.
        format!("{}  {}", crate::util::inbox_url_tty(&cfg, None, None, &crate::util::Links::new(&cfg, inbox), crate::util::Stream::Stdout), notify::describe(inbox)),
    );

    match cfg.remote {
        tokenstash_core::config::Remote::Off => {
            check("remote access", true, match crate::remote::looks_remote() {
                Some(why) => format!("off; {why}, so if you open links on another computer, `tokenstash remote tailscale` makes them open there"),
                None => "off (links point at 127.0.0.1)".into(),
            });
        }
        tokenstash_core::config::Remote::Tailscale => {
            let base = crate::remote::base_url(&cfg);
            let login = cfg.remote_login.clone().unwrap_or_default();
            let at = format!("{}:{}", cfg.remote_ip.clone().unwrap_or_default(), cfg.inbox_port);
            ok &= match crate::remote::status() {
                // The address is right; the link opens only if the inbox itself answers there.
                Ok(net) if Some(net.ip.to_string()) == cfg.remote_ip => match (notify::tailnet_state(&cfg), inbox) {
                    (notify::Inbox::Ours, _) => check("remote access", true, format!("tailscale: {base}/ opens as you on devices signed in as {login}")),
                    (notify::Inbox::Foreign, _) => check("remote access", false, format!("tailscale: another process answers on {at} and failed the ownership check, so links point at 127.0.0.1; stop it, then run `tokenstash remote tailscale` again")),
                    (notify::Inbox::Down, notify::Inbox::Down) => check("remote access", true, format!("tailscale: links use {base}/ once the inbox answers there (it is not running; it starts on demand)")),
                    (notify::Inbox::Down, _) => check("remote access", false, format!("tailscale: the inbox runs but does not answer on {at}, so links point at 127.0.0.1; run `tokenstash remote tailscale` again")),
                },
                Ok(net) => check("remote access", false, format!("tailscale: this machine's address is now {}, not {}; run `tokenstash remote tailscale` again", net.ip, cfg.remote_ip.clone().unwrap_or_default())),
                Err(e) => check("remote access", false, format!("tailscale: {e:#}")),
            };
        }
    }
    check("agent mode", true, crate::cmd::init::describe_mode(cfg.agent_mode).into());
    check("mcp server", true, if cfg.mcp { "registered with each agent (`init --mcp`)".into() } else { "off: agents use the CLI (`init --mcp` to register it)".to_string() });
    let home = dirs::home_dir().unwrap_or_default();
    let agents = crate::cmd::init::installed(&home);
    // Wiring that disagrees with config.toml means the agent is not in the mode chosen: a
    // registration made by hand after the switch, or what an earlier version installed.
    let problems: Vec<String> = agents.iter().flat_map(|a| a.problems(cfg.agent_mode, cfg.mcp)).collect();
    let list = agents.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
    ok &= check("agents", problems.is_empty(), if agents.is_empty() {
        "none configured (run `tokenstash init`)".into()
    } else if problems.is_empty() {
        list
    } else {
        format!("{list}  ({}; re-run `tokenstash init`)", problems.join("; "))
    });

    let project = tokenstash_core::project::current();
    let standing = match Db::open_default() {
        Ok(db) => db.find_workspace(&project).ok().flatten().map(|w| db.grants_for(&w.id).map(|g| g.len()).unwrap_or(0)),
        Err(_) => None,
    };
    let refused = tokenstash_core::trust::refused_root(&project);
    check("this directory", refused.is_none(), format!("{}  {}", tokenstash_core::project::short(&project), match (refused, standing) {
        (Some(why), _) => format!("is {why}, so no keys are delivered here"),
        (None, Some(n)) => format!("paired, {n} grant(s)"),
        (None, None) => "not paired yet → the first stored key asks once".into(),
    }));
    check("binary", true, std::env::current_exe()?.display().to_string());

    Ok(if ok { 0 } else { 1 })
}
