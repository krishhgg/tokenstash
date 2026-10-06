//! A `need` that files a card starts an inbox in the background, and an inbox with an open
//! card does not exit when idle. It still exits once the process `TOKENSTASH_EXIT_WITH` names
//! has ended (debug builds), and once its home or the database in it is deleted or replaced.
//! Each test files a card in a scratch home, checks the inbox is up and stays up, removes or
//! replaces one of those, and waits for the inbox's port to close while sending it requests.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Longer than the inbox's one-second check interval.
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
    port: u16,
}

impl World {
    fn new(name: &str) -> World {
        let home = tmp(&format!("home-{name}"));
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let w = World { home, proj: tmp(&format!("proj-{name}")), port };
        w.write_config(&w.home);
        w
    }

    fn write_config(&self, home: &Path) {
        std::fs::write(home.join("config.toml"), format!("notifications = false\ninbox_port = {}\nstash_backend = \"insecure-file\"\nverify_every = \"never\"\n", self.port)).unwrap();
    }

    fn addr(&self) -> SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }

    /// `need` for one key in `home`, which files a card and starts the inbox unless one is
    /// on the port already. Its `TOKENSTASH_EXIT_WITH` is `exit_with` when given, else this
    /// test process. Returns stdout, where a card link is printed only for an inbox that
    /// proved it serves `home`.
    fn need(&self, home: &Path, exit_with: Option<u32>) -> String {
        let mut c = common::tokenstash();
        if let Some(pid) = exit_with {
            c.env("TOKENSTASH_EXIT_WITH", pid.to_string());
        }
        let out = c.args(["need", "GROQ_API_KEY", "--agent", "t"]).current_dir(&self.proj)
            .env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file")
            .env("HOME", home.join("user-home")).env("XDG_CONFIG_HOME", home.join("user-home/.config"))
            .env_remove("CLAUDECODE").env_remove("TOKENSTASH_AGENT")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap();
        assert_eq!(out.status.code(), Some(10), "need should file a card: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn card_link(&self, out: &str) -> bool {
        out.split_whitespace().any(|w| w.starts_with(&format!("http://127.0.0.1:{}/p/", self.port)) && w.contains("?t="))
    }

    /// File a card in this world's home and check the inbox it started stays up.
    fn file_card(&self, exit_with: Option<u32>) {
        let out = self.need(&self.home, exit_with);
        assert!(self.card_link(&out), "the need started no inbox of its own: {out}");
        std::thread::sleep(TICK);
        assert!(self.answers(), "the inbox exited before anything it depends on was gone");
    }

    /// One complete `/verify` request. True when an HTTP response came back.
    fn answers(&self) -> bool {
        let Ok(mut s) = TcpStream::connect_timeout(&self.addr(), Duration::from_millis(200)) else { return false };
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        if write!(s, "GET /verify?c=probe HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", self.port).is_err() {
            return false;
        }
        let mut reply = Vec::new();
        let _ = s.read_to_end(&mut reply);
        reply.starts_with(b"HTTP/1.1 ")
    }

    /// True once the inbox's port refuses connections, within [`EXIT_WITHIN`]. A reply that
    /// fails or stalls does not count, since only a refused connection shows the port was let
    /// go. It sends a request every 100 ms, so the inbox is never a second without one, and an
    /// exit check that waited for an idle second would never run.
    fn inbox_exits(&self) -> bool {
        let started = Instant::now();
        while started.elapsed() < EXIT_WITHIN {
            match TcpStream::connect_timeout(&self.addr(), Duration::from_millis(200)) {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return true,
                Err(_) => {}
                Ok(probe) => {
                    drop(probe);
                    let _ = self.answers();
                }
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
#[cfg(debug_assertions)]
struct Parent(std::process::Child);
#[cfg(debug_assertions)]
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
    let parent = Parent(std::process::Command::new("sleep").arg("30").spawn().unwrap());
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

/// The home is deleted and made again by another `need` before the inbox looks, so both
/// paths exist when it does. The old inbox still proves the old home's key, the new home
/// gets no links while it runs, and so it has to go; the next `need` then starts an inbox
/// that answers for the new home. The new home is made beside the old one and moved into
/// place, so it is whole by the time the inbox can look. Unix only: elsewhere the inbox
/// tells homes apart by existence alone.
#[cfg(unix)]
#[test]
fn the_inbox_exits_once_its_home_is_made_again() {
    let w = World::new("remade");
    w.file_card(None);
    let fresh = tmp("home-remade-fresh");
    w.write_config(&fresh);
    let out = w.need(&fresh, None);
    assert!(!w.card_link(&out), "the old inbox answered for a home it does not serve: {out}");
    let old = w.home.with_extension("old");
    std::fs::rename(&w.home, &old).unwrap();
    std::fs::rename(&fresh, &w.home).unwrap();
    std::fs::remove_dir_all(&old).unwrap();
    assert!(w.inbox_exits(), "the inbox outlived its home being made again");
    let out = w.need(&w.home, None);
    assert!(w.card_link(&out), "no inbox answers for the new home: {out}");
}
