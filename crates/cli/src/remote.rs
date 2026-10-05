//! Reaching the inbox from another computer over Tailscale.
//!
//! tokenstash often runs on a machine the person reaches over SSH or Tailscale, while they
//! open links on their own computer, where `127.0.0.1` is the wrong machine. With
//! `remote = "tailscale"` the inbox also listens on this machine's Tailscale address, every
//! link names that address, and a request that arrives over the tailnet from another device
//! logged into the owner's Tailscale account counts as the person: Tailscale says which
//! login sent it (`tailscale whois`), and a process on this machine cannot send a request
//! from another device. The inbox still binds 127.0.0.1 as before.
//!
//! Turning it on is not a card for the person to confirm: the person it is for cannot open
//! the inbox until it is on. It only ever lets in the owner's own devices.

use anyhow::{bail, Context, Result};
use clap::Args;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokenstash_core::config::Remote;
use tokenstash_core::Config;

#[derive(Args)]
pub struct RemoteArgs {
    /// `tailscale` to turn it on, `off` to turn it off; nothing to show the current setting.
    pub what: Option<String>,
    /// The Tailscale login whose devices count as you. Defaults to the login this machine is
    /// signed in with; needed when this machine is a tagged node.
    #[arg(long)]
    pub login: Option<String>,
}

/// What `tailscale status --json` says about this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tailnet {
    pub ip: IpAddr,
    /// MagicDNS name without the trailing dot, when MagicDNS is on.
    pub dns_name: Option<String>,
    /// The login this machine is signed in with; `None` for a tagged node.
    pub login: Option<String>,
}

/// The `tailscale` CLI: `TOKENSTASH_TAILSCALE` (tests), `tailscale` on PATH, or the binary
/// inside the macOS app.
fn tailscale_bin() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("TOKENSTASH_TAILSCALE").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    if let Some(paths) = std::env::var_os("PATH") {
        if let Some(p) = std::env::split_paths(&paths).map(|d| d.join("tailscale")).find(|p| p.is_file()) {
            return Some(p);
        }
    }
    let mac = PathBuf::from("/Applications/Tailscale.app/Contents/MacOS/Tailscale");
    mac.is_file().then_some(mac)
}

/// How long one `tailscale` call may take. `whois` runs on the inbox's request thread, so a
/// stalled one would stop every answer, loopback included.
const TAILSCALE_TIMEOUT: Duration = Duration::from_secs(3);

fn tailscale_json(args: &[&str]) -> Result<serde_json::Value> {
    use std::io::Read;
    let bin = tailscale_bin().context("the `tailscale` command is not installed here")?;
    let mut child = std::process::Command::new(&bin).args(args)
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
        .spawn().with_context(|| format!("running {}", bin.display()))?;
    // Read the output on threads so a chatty child cannot fill a pipe and stall the wait.
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let out_t = std::thread::spawn(move || { let mut b = Vec::new(); let _ = stdout.read_to_end(&mut b); b });
    let err_t = std::thread::spawn(move || { let mut b = Vec::new(); let _ = stderr.read_to_end(&mut b); b });
    let deadline = Instant::now() + TAILSCALE_TIMEOUT;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("`tailscale {}` did not answer within {TAILSCALE_TIMEOUT:?}", args.join(" "));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = std::process::Output { status, stdout: out_t.join().unwrap_or_default(), stderr: err_t.join().unwrap_or_default() };
    if !out.status.success() {
        bail!("`tailscale {}` failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    serde_json::from_slice(&out.stdout).with_context(|| format!("`tailscale {}` printed something other than JSON", args.join(" ")))
}

/// This machine on the tailnet, or why it is not on one.
pub fn status() -> Result<Tailnet> {
    let v = tailscale_json(&["status", "--json"])?;
    if v["BackendState"].as_str() != Some("Running") {
        bail!("Tailscale is not connected here (state: {}); run `tailscale up` first", v["BackendState"].as_str().unwrap_or("unknown"));
    }
    let me = &v["Self"];
    let ip = me["TailscaleIPs"].as_array().into_iter().flatten().filter_map(|a| a.as_str()?.parse::<IpAddr>().ok()).find(IpAddr::is_ipv4).context("Tailscale reports no IPv4 address for this machine")?;
    let dns_name = me["DNSName"].as_str().map(|d| d.trim_end_matches('.').to_string()).filter(|d| !d.is_empty());
    let tagged = me["Tags"].as_array().is_some_and(|t| !t.is_empty());
    let login = if tagged {
        None
    } else {
        let uid = me["UserID"].as_i64().map(|u| u.to_string()).unwrap_or_default();
        v["User"][&uid]["LoginName"].as_str().map(String::from)
    };
    Ok(Tailnet { ip, dns_name, login })
}

/// The Tailscale login of the device at `ip`, or `None` for a tagged device or an address
/// Tailscale does not know. Cached for a minute per address: a page load is several requests.
/// A looked-up login and when it was looked up.
type Seen = HashMap<IpAddr, (Option<String>, Instant)>;

pub fn whois(ip: IpAddr) -> Option<String> {
    static CACHE: Mutex<Option<Seen>> = Mutex::new(None);
    const TTL: Duration = Duration::from_secs(60);
    let mut cache = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    let cache = cache.get_or_insert_with(HashMap::new);
    if let Some((login, at)) = cache.get(&ip) {
        if at.elapsed() < TTL {
            return login.clone();
        }
    }
    let login = tailscale_json(&["whois", "--json", &ip.to_string()]).ok().and_then(|v| {
        let tagged = v["Node"]["Tags"].as_array().is_some_and(|t| !t.is_empty());
        if tagged { None } else { v["UserProfile"]["LoginName"].as_str().map(String::from) }
    });
    cache.insert(ip, (login.clone(), Instant::now()));
    login
}

/// The address remote access advertises: this machine's Tailscale name when it is on,
/// loopback otherwise. Not proof that our inbox answers there; links use [`link_base`].
pub fn base_url(cfg: &Config) -> String {
    match (cfg.remote, cfg.remote_host.as_deref().or(cfg.remote_ip.as_deref())) {
        (Remote::Tailscale, Some(host)) => format!("http://{host}:{}", cfg.inbox_port),
        _ => format!("http://127.0.0.1:{}", cfg.inbox_port),
    }
}

/// The address links and notifications use: the Tailscale one only once our inbox has proved
/// it answers there (checked at most every 30 s per process), loopback otherwise.
pub fn link_base(cfg: &Config) -> String {
    static PROVED: Mutex<Option<(String, Instant)>> = Mutex::new(None);
    let remote = base_url(cfg);
    if cfg.remote != Remote::Tailscale {
        return remote;
    }
    let mut proved = PROVED.lock().unwrap_or_else(|p| p.into_inner());
    if proved.as_ref().is_some_and(|(base, at)| *base == remote && at.elapsed() < Duration::from_secs(30)) {
        return remote;
    }
    if crate::notify::tailnet_state(cfg) == crate::notify::Inbox::Ours {
        *proved = Some((remote.clone(), Instant::now()));
        return remote;
    }
    format!("http://127.0.0.1:{}", cfg.inbox_port)
}

/// Why the person may be on another computer, if anything here says so: an SSH login, or a
/// Linux machine with no desktop session.
pub fn looks_remote() -> Option<&'static str> {
    let has = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    if has("SSH_CONNECTION") || has("SSH_CLIENT") || has("SSH_TTY") {
        return Some("this is an SSH login");
    }
    if cfg!(target_os = "linux") && !has("DISPLAY") && !has("WAYLAND_DISPLAY") {
        return Some("this machine has no desktop session");
    }
    None
}

/// What the agent should know when the person may not be able to open a 127.0.0.1 link.
/// Empty when remote access is on, or nothing suggests the person is elsewhere.
pub fn hint(cfg: &Config) -> String {
    if cfg.remote != Remote::Off {
        return String::new();
    }
    let Some(why) = looks_remote() else { return String::new() };
    let port = cfg.inbox_port;
    let tailscale = if tailscale_bin().is_some() {
        "run `tokenstash remote tailscale` (Tailscale is installed here) and give them the new link; "
    } else {
        ""
    };
    format!(" The link points at 127.0.0.1 and {why}, so the user may be on another computer where it does not open. If they are, {tailscale}they can also forward the port with `ssh -L {port}:127.0.0.1:{port} <this machine>` and open the link on their computer.")
}

pub fn remote(a: RemoteArgs) -> Result<i32> {
    let mut cfg = Config::load()?;
    match a.what.as_deref() {
        None => {
            match cfg.remote {
                Remote::Off => {
                    println!("remote access: off; links point at http://127.0.0.1:{}/", cfg.inbox_port);
                    if let Some(why) = looks_remote() {
                        println!("  {why}: if you open links on another computer, `tokenstash remote tailscale` makes them work there");
                    }
                }
                Remote::Tailscale => println!(
                    "remote access: tailscale; links point at {}/ and open as you from any device signed in as {}",
                    base_url(&cfg),
                    cfg.remote_login.as_deref().unwrap_or("(nobody: run `tokenstash remote tailscale --login YOU`)")
                ),
            }
            Ok(0)
        }
        Some("off") => {
            cfg.remote = Remote::Off;
            cfg.remote_host = None;
            cfg.remote_ip = None;
            cfg.remote_login = None;
            cfg.save()?;
            println!("✓ remote access off: the inbox answers on 127.0.0.1 only, and links point there");
            Ok(0)
        }
        Some("tailscale") => {
            let net = status()?;
            let login = match (a.login, net.login) {
                (None, Some(l)) => l,
                (Some(l), Some(owner)) if l == owner => l,
                // Naming someone else as the person on a machine that has an owner hands their
                // devices the full session: the person's own call.
                (Some(l), Some(_)) if crate::util::looks_human() => l,
                (Some(_), Some(owner)) => bail!("this machine is signed in to Tailscale as {owner}; naming another login as the person is for a person at a terminal"),
                (Some(l), None) => l,
                (None, None) => bail!("this machine is a tagged Tailscale node, so it has no owner to recognise; name yours: `tokenstash remote tailscale --login you@example.com`"),
            };
            cfg.remote = Remote::Tailscale;
            cfg.remote_ip = Some(net.ip.to_string());
            cfg.remote_host = Some(net.dns_name.clone().unwrap_or_else(|| net.ip.to_string()));
            cfg.remote_login = Some(login.clone());
            cfg.save()?;
            // A running inbox picks the setting up within a second; start one if none runs. Then
            // prove it answers on the Tailscale address before saying so: something else
            // holding that address and port would get the links.
            let _ = crate::notify::ensure_inbox(&cfg);
            let until = Instant::now() + Duration::from_secs(5);
            let mut state = crate::notify::tailnet_state(&cfg);
            while state != crate::notify::Inbox::Ours && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(200));
                state = crate::notify::tailnet_state(&cfg);
            }
            if state != crate::notify::Inbox::Ours {
                bail!("remote access is on, but the inbox is not answering at {}/ ({}); links stay on 127.0.0.1 until it does. `tokenstash doctor` shows more", base_url(&cfg), match state {
                    crate::notify::Inbox::Foreign => "another process holds that address and port",
                    _ => "nothing answers there yet",
                });
            }
            println!("✓ remote access on: the inbox also answers at {}/", base_url(&cfg));
            println!("  a link opened on any device signed in to Tailscale as {login} opens as you, and can approve");
            println!("  links printed before this point at 127.0.0.1: run the same `tokenstash need` again for a new one");
            Ok(0)
        }
        Some(other) => bail!("{other:?}: use `tokenstash remote tailscale`, `tokenstash remote off`, or no argument to see the setting"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Greptile on #69: a `tailscale` that stalls must not hold the caller (the inbox's
    /// request thread, for `whois`) past the time limit.
    #[cfg(unix)]
    #[test]
    fn a_stalled_tailscale_call_gives_up_on_time() {
        use std::os::unix::fs::PermissionsExt;
        let _g = crate::inbox_auth::env_lock();
        let dir = std::env::temp_dir().join(format!("tokenstash-stalled-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("tailscale");
        std::fs::write(&bin, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("TOKENSTASH_TAILSCALE", &bin);
        let started = Instant::now();
        let err = status().unwrap_err();
        std::env::remove_var("TOKENSTASH_TAILSCALE");
        assert!(started.elapsed() < TAILSCALE_TIMEOUT + Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(format!("{err:#}").contains("did not answer"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn links_name_the_tailnet_host_only_when_remote_access_is_on() {
        let mut cfg = Config { inbox_port: 7433, ..Default::default() };
        assert_eq!(base_url(&cfg), "http://127.0.0.1:7433");
        cfg.remote = Remote::Tailscale;
        cfg.remote_ip = Some("100.68.81.23".into());
        assert_eq!(base_url(&cfg), "http://100.68.81.23:7433");
        cfg.remote_host = Some("box.tail1234.ts.net".into());
        assert_eq!(base_url(&cfg), "http://box.tail1234.ts.net:7433");
    }
}
