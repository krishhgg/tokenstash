//! The commands that widen an agent's reach refuse when they cannot see a person: stdout is
//! a pipe here, which is what an agent's shell looks like.
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    Command::new(env!("CARGO_BIN_EXE_tokenstash")).args(args).current_dir(cwd)
        .env("HOME", &user_home).env("XDG_CONFIG_HOME", user_home.join(".config"))
        .env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE")
        .stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap()
}

#[test]
fn widening_commands_refuse_a_pipe() {
    let home = home("home");
    let proj = tmp("proj");
    for args in [
        vec!["open"],
        vec!["list"],
        vec!["audit"],
        vec!["forget", "OPENAI_API_KEY"],
        vec!["tasks", "--all"],
        vec!["need", "OPENAI_API_KEY", "--force"],
    ] {
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_tokenstash")).args(&args).current_dir(cwd)
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
