//! A `need` that files a card starts an inbox in the background, and an inbox with an open
//! card does not exit when idle. It still exits once the process `TOKENSTASH_EXIT_WITH` names
//! has ended (debug builds), and once its home or the database in it is deleted. Each test
//! files a card in a scratch home, checks the inbox is up and stays up, removes one of those,
//! and waits for the inbox's port to close.

mod common;

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Longer than one idle tick of the inbox's main loop, which is one second.
const TICK: Duration = Duration::from_millis(1500);
/// How long the inbox gets to notice and exit.
const EXIT_WITHIN: Duration = Duration::from_secs(5);

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokenstash-inbox-exit-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A scratch home on a free port and a project to file a card from. Both are deleted on
/// drop, which also ends an inbox that a failed assertion left running.
struct World {
    home: PathBuf,
    proj: PathBuf,
    addr: SocketAddr,
}

impl World {
    fn new(name: &str) -> World {
        let home = tmp(&format!("home-{name}"));
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        std::fs::write(home.join("config.toml"), format!("notifications = false\ninbox_port = {port}\nstash_backend = \"insecure-file\"\nverify_every = \"never\"\n")).unwrap();
        World { home, proj: tmp(&format!("proj-{name}")), addr: ([127, 0, 0, 1], port).into() }
    }

    /// File a card with `need`, which starts the inbox. Its `TOKENSTASH_EXIT_WITH` is
    /// `exit_with` when given, else this test process.
    fn file_card(&self, exit_with: Option<u32>) {
        let mut c = common::tokenstash();
        if let Some(pid) = exit_with {
            c.env("TOKENSTASH_EXIT_WITH", pid.to_string());
        }
        let out = c.args(["need", "GROQ_API_KEY", "--agent", "t"]).current_dir(&self.proj)
            .env("TOKENSTASH_HOME", &self.home).env("TOKENSTASH_STASH", "insecure-file")
            .env("HOME", self.home.join("user-home")).env("XDG_CONFIG_HOME", self.home.join("user-home/.config"))
            .env_remove("CLAUDECODE").env_remove("TOKENSTASH_AGENT")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap();
        assert_eq!(out.status.code(), Some(10), "need should file a card: {}", String::from_utf8_lossy(&out.stderr));
        assert!(self.listening(), "the need started no inbox");
        std::thread::sleep(TICK);
        assert!(self.listening(), "the inbox exited before anything it depends on was gone");
    }

    fn listening(&self) -> bool {
        TcpStream::connect_timeout(&self.addr, Duration::from_millis(200)).is_ok()
    }

    /// True once nothing listens on the inbox's port, within [`EXIT_WITHIN`].
    fn inbox_exits(&self) -> bool {
        let started = Instant::now();
        while started.elapsed() < EXIT_WITHIN {
            if !self.listening() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
        let _ = std::fs::remove_dir_all(&self.proj);
    }
}

/// A short-lived process standing in for a test run. Killed and reaped on drop.
struct Parent(Child);
impl Drop for Parent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Debug builds only: a release binary ignores `TOKENSTASH_EXIT_WITH`, and this test is
/// built with the same profile as the binary.
#[cfg(debug_assertions)]
#[test]
fn the_inbox_exits_once_the_process_it_was_started_for_has() {
    let w = World::new("parent");
    let parent = Parent(Command::new("sleep").arg("30").spawn().unwrap());
    w.file_card(Some(parent.0.id()));
    drop(parent);
    assert!(w.inbox_exits(), "the inbox outlived the process named by TOKENSTASH_EXIT_WITH");
}

#[test]
fn the_inbox_exits_once_its_home_is_deleted() {
    let w = World::new("home");
    w.file_card(None);
    std::fs::remove_dir_all(&w.home).unwrap();
    assert!(w.inbox_exits(), "the inbox outlived its home");
}

#[test]
fn the_inbox_exits_once_its_database_is_deleted() {
    let w = World::new("db");
    w.file_card(None);
    for f in ["tokenstash.db", "tokenstash.db-wal", "tokenstash.db-shm"] {
        let _ = std::fs::remove_file(w.home.join(f));
    }
    assert!(w.inbox_exits(), "the inbox outlived its database");
}
