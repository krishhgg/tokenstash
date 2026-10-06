//! The commands that widen an agent's reach refuse when they cannot see a person: stdout is
//! a pipe here, which is what an agent's shell looks like.
mod common;

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokenstash-human-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A scratch home: no notifications, an inbox port nobody else uses. Without this the child
/// runs with `Config::default()` and a pending card spawns a real inbox on the developer's
/// port 7433 that stays up for a day.
/// A port nothing holds right now. Tests in one binary run in parallel, and two scratch homes
/// on one port each see the other's inbox as foreign; the name-derived ports collided.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn home(name: &str) -> PathBuf {
    let h = tmp(name);
    let port = free_port();
    std::fs::write(h.join("config.toml"), format!("notifications = false\ninbox_port = {port}\nstash_backend = \"insecure-file\"\nverify_every = \"never\"\n")).unwrap();
    h
}

/// $HOME and the config root are scratch too. `init` installs the skill into the agents'
/// directories under $HOME and keeps its undo record under the fixed config dir, so with the
/// developer's own $HOME a test run rewrites their agent setup.
fn run(home: &PathBuf, cwd: &PathBuf, args: &[&str]) -> std::process::Output {
    let user_home = home.join("user-home");
    std::fs::create_dir_all(&user_home).unwrap();
    common::tokenstash().args(args).current_dir(cwd)
        .env("HOME", &user_home).env("XDG_CONFIG_HOME", user_home.join(".config"))
        .env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE")
        .stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap()
}

#[test]
fn widening_commands_refuse_a_pipe() {
    let home = home("home");
    let proj = tmp("proj");
    for args in [vec!["open"], vec!["tasks", "--all"]] {
        let out = run(&home, &proj, &args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} must refuse: {err}");
        assert!(err.contains("for a person at a terminal"), "{args:?}: {err}");
        assert!(String::from_utf8_lossy(&out.stdout).trim().is_empty(), "{args:?} printed to a pipe: {}", String::from_utf8_lossy(&out.stdout));
    }
    // ...while the agent-facing ones still run.
    let out = run(&home, &proj, &["tasks", "--json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// Paste a value into this directory's own card from a pipe, as an agent may.
fn paste(home: &PathBuf, cwd: &PathBuf, id: &str, value: &str) {
    let mut child = common::tokenstash().args(["answer", id, "--stdin", "--skip-check"]).current_dir(cwd)
        .env("HOME", home.join("user-home")).env("XDG_CONFIG_HOME", home.join("user-home/.config"))
        .env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(format!("{value}\n").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

fn tasks_json(home: &PathBuf, cwd: &PathBuf) -> Vec<serde_json::Value> {
    let out = run(home, cwd, &["tasks", "--json", "--history"]);
    serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap().as_array().unwrap().clone()
}

/// What acts for the person (deleting a key, changing how agents reach tokenstash, asking
/// again after a no) files a card when an agent runs it, and nothing changes until the person
/// confirms it in their inbox.
#[test]
fn an_agent_asks_on_a_card_and_nothing_changes_until_the_person_answers() {
    let home = home("asks");
    let proj = tmp("asks-proj");
    let out = run(&home, &proj, &["need", "OPENAI_API_KEY"]);
    assert_eq!(out.status.code(), Some(10));
    let card = tasks_json(&home, &proj).into_iter().find(|t| t["name"] == "OPENAI_API_KEY").unwrap();
    paste(&home, &proj, card["id"].as_str().unwrap(), "sk-proj-agentpasted0123456789abcdef");

    let out = run(&home, &proj, &["forget", "OPENAI_API_KEY", "--why", "the user asked"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(10), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("Forget OPENAI_API_KEY") && stdout.contains("next:"), "{stdout}");
    let forget: Vec<_> = tasks_json(&home, &proj).into_iter().filter(|t| t["expects"] == "action:forget").collect();
    assert_eq!(forget.len(), 1, "{forget:?}");
    assert_eq!(forget[0]["why"], "the user asked");
    assert_eq!(run(&home, &proj, &["forget", "OPENAI_API_KEY"]).status.code(), Some(10));
    assert_eq!(tasks_json(&home, &proj).iter().filter(|t| t["expects"] == "action:forget").count(), 1, "asking again is the same card");
    assert_eq!(run(&home, &proj, &["need", "OPENAI_API_KEY"]).status.code(), Some(0), "nothing was forgotten");
    // Agent-confirming its own card is refused: that is the person's.
    let out = run(&home, &proj, &["answer", forget[0]["id"].as_str().unwrap()]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("for a person at a terminal"));

    let cfg_before = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert_eq!(run(&home, &proj, &["init", "--mode", "explicit"]).status.code(), Some(10));
    assert_eq!(std::fs::read_to_string(home.join("config.toml")).unwrap(), cfg_before, "the mode changes only on the person's confirm");
    assert!(tasks_json(&home, &proj).iter().any(|t| t["expects"] == "action:mode" && t["names"][0] == "explicit"));

    let out = run(&home, &proj, &["init", "--mode", "auto", "--why", "the user wants it back", "--no-agents"]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("--no-agents"), "a card cannot carry --no-agents");
    assert_eq!(run(&home, &proj, &["init", "--mode", "auto", "--why", "the user wants it back"]).status.code(), Some(10));
    assert!(tasks_json(&home, &proj).iter().any(|t| t["expects"] == "action:mode" && t["names"][0] == "auto" && t["why"] == "the user wants it back"));

    // A replacement the agent asked for is not a rejected key.
    let out = run(&home, &proj, &["rotate", "OPENAI_API_KEY", "--why", "the user thinks it leaked"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(10), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("keeps working") && !stdout.contains("rejected"), "{stdout}");

    // --force on a key nobody declined is an ordinary request and spends nothing.
    assert_eq!(run(&home, &proj, &["need", "GROQ_API_KEY", "--force"]).status.code(), Some(10));
    let groq = tasks_json(&home, &proj).into_iter().find(|t| t["name"] == "GROQ_API_KEY").unwrap();
    assert!(!groq["why"].as_str().unwrap_or("").starts_with("Asked again"), "{groq}");
    assert!(run(&home, &proj, &["answer", groq["id"].as_str().unwrap(), "--deny"]).status.success());
    assert_eq!(run(&home, &proj, &["need", "GROQ_API_KEY", "--force"]).status.code(), Some(10), "the extra ask is still there after the first real no");

    // Asking again after a no: once, and a request that fails does not spend it.
    assert_eq!(run(&home, &proj, &["need", "RESEND_API_KEY"]).status.code(), Some(10));
    let resend = tasks_json(&home, &proj).into_iter().find(|t| t["name"] == "RESEND_API_KEY").unwrap();
    assert!(run(&home, &proj, &["answer", resend["id"].as_str().unwrap(), "--deny"]).status.success());
    assert_eq!(run(&home, &proj, &["need", "RESEND_API_KEY"]).status.code(), Some(20));
    assert!(!run(&home, &proj, &["need", "RESEND_API_KEY", "--identity", "not an identity!", "--force"]).status.success());
    assert_eq!(run(&home, &proj, &["need", "RESEND_API_KEY", "--force"]).status.code(), Some(10));
    let again = tasks_json(&home, &proj).into_iter().find(|t| t["name"] == "RESEND_API_KEY" && t["status"] == "pending").unwrap();
    assert!(again["why"].as_str().unwrap().starts_with("Asked again after you declined"), "{again}");
    assert!(run(&home, &proj, &["answer", again["id"].as_str().unwrap(), "--deny"]).status.success());
    let out = run(&home, &proj, &["need", "RESEND_API_KEY", "--force"]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("already asked for again once"), "{}", String::from_utf8_lossy(&out.stderr));
}

/// Have the person decline this directory's open card for `name`.
fn decline(home: &PathBuf, cwd: &PathBuf, name: &str, identity: &str) {
    let card = tasks_json(home, cwd).into_iter().find(|t| t["name"] == name && t["identity"] == identity && t["status"] == "pending").unwrap();
    assert!(run(home, cwd, &["answer", card["id"].as_str().unwrap(), "--deny"]).status.success());
}

/// Greptile on #63: in one `need A B --force`, only the key the person declined says on its
/// card that it is a second ask. The other key was never declined, so its card is an ordinary
/// first ask with the agent's own reason.
#[test]
fn only_the_declined_key_is_called_a_second_ask() {
    let home = home("again-label");
    let proj = tmp("again-label-proj");
    assert_eq!(run(&home, &proj, &["need", "RESEND_API_KEY"]).status.code(), Some(10));
    decline(&home, &proj, "RESEND_API_KEY", "default");
    let out = run(&home, &proj, &["need", "RESEND_API_KEY", "GROQ_API_KEY", "--force", "--why", "the signup emails"]);
    assert_eq!(out.status.code(), Some(10), "{}", String::from_utf8_lossy(&out.stderr));
    let cards = tasks_json(&home, &proj);
    let again = cards.iter().find(|t| t["name"] == "RESEND_API_KEY" && t["status"] == "pending").unwrap();
    assert!(again["why"].as_str().unwrap().starts_with("Asked again after you declined") && again["why"].as_str().unwrap().ends_with("the signup emails"), "{again}");
    let groq = cards.iter().find(|t| t["name"] == "GROQ_API_KEY").unwrap();
    assert_eq!(groq["why"], "the signup emails", "{groq}");
}

/// Greptile on #65: running the same `need NAME --force` again while its second-ask card waits
/// returns that card, with its `next`, as an ordinary pending result. Once the person answers
/// it, the same command delivers the key.
#[test]
fn asking_again_twice_returns_the_waiting_card() {
    let home = home("again-repeat");
    let proj = tmp("again-repeat-proj");
    assert_eq!(run(&home, &proj, &["need", "RESEND_API_KEY"]).status.code(), Some(10));
    decline(&home, &proj, "RESEND_API_KEY", "default");
    let ask = |extra: &[&str]| {
        let mut args = vec!["need", "RESEND_API_KEY", "--force", "--json"];
        args.extend(extra);
        let out = run(&home, &proj, &args);
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
        (out.status.code(), v)
    };
    let (code, first) = ask(&[]);
    assert_eq!(code, Some(10), "{first}");
    let id = first["results"][0]["task_id"].as_str().unwrap().to_string();
    let (code, repeat) = ask(&[]);
    assert_eq!(code, Some(10), "{repeat}");
    let r = &repeat["results"][0];
    assert_eq!((r["status"].as_str(), r["task_id"].as_str()), (Some("pending"), Some(id.as_str())), "{repeat}");
    assert!(r["next"].as_str().unwrap().contains(&id) && r["inbox"].is_string(), "{repeat}");
    // With another key in the same call, each result keeps its place and the other key is asked.
    let out = run(&home, &proj, &["need", "GROQ_API_KEY", "RESEND_API_KEY", "--force", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((v["results"][0]["name"].as_str(), v["results"][1]["task_id"].as_str()), (Some("GROQ_API_KEY"), Some(id.as_str())), "{v}");
    assert_eq!(tasks_json(&home, &proj).iter().filter(|t| t["name"] == "RESEND_API_KEY").count(), 2, "no third card");
    paste(&home, &proj, &id, "re_askedagain_0123456789abcdef");
    let (code, done) = ask(&[]);
    assert_eq!((code, done["results"][0]["status"].as_str()), (Some(0), Some("injected")), "{done}");
}

/// Greptile on #67: the person declines each identity of a key on its own card, and an agent
/// may ask again once for each.
#[test]
fn each_declined_identity_gets_its_own_ask_again() {
    let home = home("again-identity");
    let proj = tmp("again-identity-proj");
    for identity in ["work", "personal"] {
        assert_eq!(run(&home, &proj, &["need", "GROQ_API_KEY", "--identity", identity]).status.code(), Some(10));
        decline(&home, &proj, "GROQ_API_KEY", identity);
    }
    for identity in ["work", "personal"] {
        let out = run(&home, &proj, &["need", "GROQ_API_KEY", "--identity", identity, "--force"]);
        assert_eq!(out.status.code(), Some(10), "{identity}: {}", String::from_utf8_lossy(&out.stderr));
        let card = tasks_json(&home, &proj).into_iter().find(|t| t["name"] == "GROQ_API_KEY" && t["identity"] == identity && t["status"] == "pending").unwrap();
        assert!(card["why"].as_str().unwrap().starts_with("Asked again after you declined"), "{card}");
    }
}

/// `list` and `audit` show an agent its own directory and nothing else: the rest of the stash
/// and the log are the person's inventory.
#[test]
fn an_agent_sees_only_its_own_directory_in_list_and_audit() {
    let home = home("scoped");
    let a = tmp("scoped-a");
    let b = tmp("scoped-b");
    assert_eq!(run(&home, &a, &["need", "OPENAI_API_KEY"]).status.code(), Some(10));
    let card = tasks_json(&home, &a).into_iter().find(|t| t["name"] == "OPENAI_API_KEY").unwrap();
    paste(&home, &a, card["id"].as_str().unwrap(), "sk-proj-scopedlist0123456789abcdef");
    let in_a = String::from_utf8_lossy(&run(&home, &a, &["list"]).stdout).into_owned();
    assert!(in_a.contains("OPENAI_API_KEY"), "{in_a}");
    let in_b = String::from_utf8_lossy(&run(&home, &b, &["list"]).stdout).into_owned();
    assert!(!in_b.contains("OPENAI_API_KEY") && in_b.contains("has not received any key"), "{in_b}");
    let audit_b = String::from_utf8_lossy(&run(&home, &b, &["audit", "--json"]).stdout).into_owned();
    assert!(!audit_b.contains("OPENAI_API_KEY") && !audit_b.contains(a.file_name().unwrap().to_str().unwrap()), "{audit_b}");
    let audit_a = String::from_utf8_lossy(&run(&home, &a, &["audit", "--json"]).stdout).into_owned();
    assert!(audit_a.contains("OPENAI_API_KEY"), "{audit_a}");
}

#[test]
fn an_agent_cannot_answer_another_directorys_card() {
    let home = home("home-x");
    let theirs = tmp("theirs");
    let mine = tmp("mine");
    let out = run(&home, &theirs, &["need", "OPENAI_API_KEY"]);
    assert_eq!(out.status.code(), Some(10), "{}", String::from_utf8_lossy(&out.stderr));
    let tasks = run(&home, &theirs, &["tasks", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&tasks.stdout).unwrap();
    let id = v.as_array().unwrap()[0]["id"].as_str().unwrap().to_string();
    for (cwd, extra) in [(&mine, vec!["--stdin", "--skip-check"]), (&mine, vec!["--deny"])] {
        let mut args = vec!["answer", id.as_str()];
        args.extend(extra);
        let mut child = common::tokenstash().args(&args).current_dir(cwd)
            .env("TOKENSTASH_HOME", &home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"sk-proj-not-mine-0123456789abcdef0123456789\n").unwrap();
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && err.contains("another directory"), "{args:?}: {err}");
    }
    let still = run(&home, &theirs, &["tasks", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&still.stdout).unwrap();
    assert_eq!(v.as_array().unwrap()[0]["status"], "pending", "nothing changed: {v}");
}

/// `init` sets up the stash and installs the skill for anyone: the skill is fixed text naming
/// no binary. Registering this binary as every agent's MCP server is a person's decision:
/// from a hostile checkout an agent could point every future session at a build that hands
/// values to the model.
#[test]
fn init_registers_the_mcp_server_only_for_a_person() {
    let home = home("home-init");
    let proj = tmp("proj-init");
    let user_home = home.join("user-home");
    std::fs::create_dir_all(user_home.join(".codex")).unwrap();
    let out = run(&home, &proj, &["init"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "init itself succeeds: {}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("stash backend") && stdout.contains("skill installed"), "{stdout}");
    assert!(user_home.join(".agents/skills/tokenstash/SKILL.md").is_file());
    assert!(!user_home.join(".codex/config.toml").exists(), "no MCP server: {stdout}");
    // With the server chosen for this machine, an agent's `init` leaves the registrations alone.
    let cfg = std::fs::read_to_string(home.join("config.toml")).unwrap();
    std::fs::write(home.join("config.toml"), format!("{cfg}mcp = true\n")).unwrap();
    let out = run(&home, &proj, &["init"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && stdout.contains("MCP registrations were left as they are"), "{stdout}");
    assert!(!user_home.join(".codex/config.toml").exists());
    // ...and --no-agents, which scripts use, touches no agent at all.
    std::fs::remove_dir_all(user_home.join(".agents")).unwrap();
    let out = run(&home, &proj, &["init", "--no-agents"]);
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("skill installed") && !user_home.join(".agents").exists());
}

/// Greptile on #68: a checkout re-created at the same path does not show the old one's
/// history to its agent, before or after it pairs again.
#[test]
fn a_recreated_checkout_does_not_read_the_old_ones_audit() {
    let home = home("recreated");
    let proj = tmp("recreated-proj");
    assert_eq!(run(&home, &proj, &["need", "OPENAI_API_KEY"]).status.code(), Some(10));
    let card = tasks_json(&home, &proj).into_iter().find(|t| t["name"] == "OPENAI_API_KEY").unwrap();
    paste(&home, &proj, card["id"].as_str().unwrap(), "sk-proj-oldcheckout0123456789abcdef");
    assert!(String::from_utf8_lossy(&run(&home, &proj, &["audit", "--json"]).stdout).contains("OPENAI_API_KEY"));
    std::fs::remove_dir_all(&proj).unwrap();
    std::fs::create_dir_all(proj.join("other")).unwrap();
    let audit = String::from_utf8_lossy(&run(&home, &proj, &["audit", "--json"]).stdout).into_owned();
    assert!(!audit.contains("OPENAI_API_KEY"), "{audit}");
}

