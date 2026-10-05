//! Desktop notification + make sure the inbox is up. Best effort; never fatal.

use crate::inbox_auth;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use tokenstash_core::Config;

/// What is actually on the inbox port.
///
/// "Something accepted a TCP connection" is not the same as "our inbox is running", and the
/// difference matters: we are about to tell a human to paste an API key into whatever is
/// there. `Ours` is only ever returned after the listener answers a fresh challenge with
/// `HMAC(proof key, nonce)` — a proof it already holds this `TOKENSTASH_HOME`'s proof key.
/// The key itself is never sent, so a squatter on the port learns nothing from being probed;
/// and because the key is never in a URL either, a squatter that collected a stale link
/// cannot answer with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbox {
    /// Verified: this is our inbox for this TOKENSTASH_HOME.
    Ours,
    /// Something is listening but failed the ownership proof.
    Foreign,
    /// Nothing is listening.
    Down,
}

const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);
const IO_TIMEOUT: Duration = Duration::from_millis(1500);
/// A hostile listener must not be able to stream at us forever.
const MAX_REPLY: u64 = 64 * 1024;
/// How long a freshly spawned inbox gets to bind and answer.
const SPAWN_WAIT: Duration = Duration::from_secs(2);

fn addr(cfg: &Config) -> SocketAddr {
    ([127, 0, 0, 1], cfg.inbox_port).into()
}

pub fn inbox_state(cfg: &Config) -> Inbox {
    let Ok(proof) = inbox_auth::ensure_proof_key() else { return Inbox::Down };
    probe(&addr(cfg), &proof)
}

/// What answers on this machine's Tailscale address and the inbox port, proved the same way.
/// `Down` when remote access is off. Links name that address only once it is `Ours`: a
/// process that took the address and port first would otherwise receive the person's paste.
pub fn tailnet_state(cfg: &Config) -> Inbox {
    if cfg.remote != tokenstash_core::config::Remote::Tailscale {
        return Inbox::Down;
    }
    let Some(ip) = cfg.remote_ip.as_deref().and_then(|i| i.parse::<std::net::IpAddr>().ok()) else { return Inbox::Down };
    let Ok(proof) = inbox_auth::ensure_proof_key() else { return Inbox::Down };
    probe(&(ip, cfg.inbox_port).into(), &proof)
}

fn probe(addr: &SocketAddr, proof: &str) -> Inbox {
    let Ok(mut s) = TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) else { return Inbox::Down };
    let nonce = inbox_auth::challenge();
    match challenge(&mut s, addr, &nonce) {
        Some(body) if inbox_auth::ct_eq(body.trim(), &inbox_auth::verify_response(proof, &nonce)) => Inbox::Ours,
        _ => Inbox::Foreign,
    }
}

/// One `GET /verify?c=<nonce>` over a raw socket, returning the response body. Hand-rolled
/// rather than pulling in an HTTP client: one request, one connection, no redirects.
fn challenge(s: &mut TcpStream, addr: &SocketAddr, nonce: &str) -> Option<String> {
    // One deadline for the whole exchange. A read timeout alone restarts with every byte, so
    // a listener that trickled its reply could hold this, and the `need` waiting on it, for
    // as long as it liked.
    let deadline = Instant::now() + IO_TIMEOUT;
    s.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
    write!(s, "GET /verify?c={nonce} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").ok()?;
    s.flush().ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
        s.set_read_timeout(Some(left)).ok()?;
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) if buf.len() + n > MAX_REPLY as usize => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    let text = String::from_utf8(buf).ok()?;
    let (head, body) = text.split_once("\r\n\r\n")?;
    head.starts_with("HTTP/1.1 200").then(|| body.to_string())
}

/// Spawn `tokenstash inbox` detached unless our own, verified inbox is already up.
///
/// Returns what is on the port when we are done, and callers must act on it: this is the
/// single point where the rest of the CLI learns whether it may hand out a credentialed URL.
/// Warning and carrying on is not enough — a caller that then prints `?t=` has given the
/// squatter the session, and the human a link straight to it.
#[must_use]
pub fn ensure_inbox(cfg: &Config) -> Inbox {
    match inbox_state(cfg) {
        Inbox::Ours => return Inbox::Ours,
        Inbox::Foreign => {
            // Do not spawn (the bind would fail) and, more importantly, do not send a human
            // to a URL owned by someone else. Nothing secret was disclosed getting here.
            eprintln!(
                "tokenstash: port {} is held by another process — it failed the inbox ownership check, so nothing was sent to it.\n\
                 Stop that process or set inbox_port in {}.",
                cfg.inbox_port,
                tokenstash_core::config::config_path().display()
            );
            return Inbox::Foreign;
        }
        Inbox::Down => {}
    }
    let Ok(exe) = std::env::current_exe() else { return Inbox::Down };
    let mut c = std::process::Command::new(exe);
    c.arg("inbox").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
    }
    if let Err(e) = c.spawn() {
        eprintln!("tokenstash: could not start the inbox ({e})");
        return Inbox::Down;
    }
    // Measured on the clock, not in attempts: one attempt can itself take CONNECT_TIMEOUT +
    // IO_TIMEOUT against a listener that is slow to answer.
    let until = Instant::now() + SPAWN_WAIT;
    while Instant::now() < until {
        let state = inbox_state(cfg);
        if state == Inbox::Ours {
            return state;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("tokenstash: the inbox did not come up on port {}", cfg.inbox_port);
    // Whatever ended up there, we could not prove it is ours, so nobody downstream may
    // treat it as ours.
    inbox_state(cfg)
}

/// Human-readable inbox status for `doctor`.
pub fn describe(state: Inbox) -> &'static str {
    match state {
        Inbox::Ours => "running (ownership verified)",
        Inbox::Foreign => "PORT HELD BY ANOTHER PROCESS — it failed the ownership check",
        Inbox::Down => "not running (starts on demand)",
    }
}

/// `where_to` is whatever `util::inbox_notice` produced: a session URL when we proved the
/// inbox is ours, or a sentence explaining why there is no link. Never build it here.
/// True when the desktop took the notification; false when notifications are off or there is
/// no desktop to show it on (a server, an SSH login).
pub fn desktop(cfg: &Config, title: &str, body: &str, where_to: &str) -> bool {
    if !cfg.notifications {
        return false;
    }
    notify_rust::Notification::new()
        .appname("tokenstash")
        .summary(title)
        .body(&if where_to.is_empty() { body.to_string() } else { format!("{body}\n{where_to}") })
        .timeout(notify_rust::Timeout::Milliseconds(15000))
        .show()
        .is_ok()
}

/// A listener on 127.0.0.1 that answers `/verify` as our inbox would, with this
/// `TOKENSTASH_HOME`'s proof key, while `honest` is set, and as another process would after
/// that. Returns its port. For tests of what links name.
#[cfg(test)]
pub(crate) fn fake_inbox(honest: std::sync::Arc<std::sync::atomic::AtomicBool>) -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let proof = inbox_auth::ensure_proof_key().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            // The probe writes its request in pieces, so read up to the blank line.
            let mut head = Vec::new();
            let mut chunk = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let nonce = head.split_once("?c=").and_then(|(_, rest)| rest.split(' ').next()).unwrap_or_default();
            let body = if honest.load(std::sync::atomic::Ordering::SeqCst) { inbox_auth::verify_response(&proof, nonce) } else { "not the inbox".into() };
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        }
    });
    port
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A listener that answers one byte at a time must not hold the ownership check open.
    #[test]
    fn a_trickling_listener_cannot_hold_the_ownership_check() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut s, _)) = l.accept() else { return };
            for _ in 0..600 {
                if s.write_all(b"H").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        assert_eq!(probe(&addr, "proof"), Inbox::Foreign);
        assert!(started.elapsed() < IO_TIMEOUT + Duration::from_secs(1), "{:?}", started.elapsed());
    }

    /// ...nor one that accepts and never answers.
    #[test]
    fn a_silent_listener_costs_one_io_timeout() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let _held = l.accept();
            std::thread::sleep(Duration::from_secs(30));
        });
        let started = Instant::now();
        assert_eq!(probe(&addr, "proof"), Inbox::Foreign);
        assert!(started.elapsed() < IO_TIMEOUT + Duration::from_secs(1), "{:?}", started.elapsed());
    }
}
