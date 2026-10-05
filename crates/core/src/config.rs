use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Retired in 0.2 (nothing is trusted by folder); parsed so a 0.1 config still loads.
    #[serde(default)]
    pub trust_roots: Vec<PathBuf>,
    /// Env file name written into projects.
    #[serde(default = "default_env_file")]
    pub env_file: String,
    /// Localhost inbox port.
    #[serde(default = "default_port")]
    pub inbox_port: u16,
    /// Hours until an unanswered task expires.
    #[serde(default = "default_ttl")]
    pub task_ttl_hours: u64,
    /// Stash backend override: "keyring" | "keyutils" | "insecure-file".
    #[serde(default)]
    pub stash_backend: Option<String>,
    /// Whether to show desktop notifications.
    #[serde(default = "default_true")]
    pub notifications: bool,
    /// Legacy. Agent-facing inbox links always carry a capability scoped to the one card the
    /// link is for; "full" used to make them carry the browser session and is now accepted
    /// (so an old config still loads) but ignored with a warning — the full inbox is
    /// `tokenstash open` or the desktop notification.
    #[serde(default = "default_links")]
    pub inbox_links: String,
    /// How often a key with a registry probe is re-checked with its provider before an agent
    /// `need` delivers it: `24h` (default), `<n>h`, `<n>m`, `always`, or `never`. One free
    /// authenticated request per key per window; a rejected key becomes a Replace card
    /// before the agent ever sees a 401.
    #[serde(default)]
    pub verify_every: VerifyEvery,
    /// How agents reach tokenstash. Either way `init` installs one skill that documents the
    /// CLI. `auto` (default): the agent sees the skill's one-line description and loads it
    /// when code needs a key. `explicit`: the skill loads only when the person invokes it
    /// (`/tokenstash`, or `$tokenstash` in Codex).
    /// Not written while it is the default, so a config this version saved still loads in
    /// 0.2 (which rejects unknown fields) unless explicit mode was chosen.
    #[serde(default, skip_serializing_if = "AgentMode::is_auto")]
    pub agent_mode: AgentMode,
    /// Also register tokenstash as an MCP server with each agent (`init --mcp`). Off by
    /// default: agents run the CLI. Not written while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mcp: bool,
    /// Where the inbox can be reached besides 127.0.0.1 (`tokenstash remote tailscale`).
    /// `tailscale`: it also listens on this machine's Tailscale address, every link uses
    /// `remote_host`, and a request from another device logged into `remote_login` counts as
    /// the person. Not written while off.
    #[serde(default, skip_serializing_if = "Remote::is_off")]
    pub remote: Remote,
    /// The name links use: the MagicDNS name, or the Tailscale address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
    /// This machine's Tailscale address, where the inbox listens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// The Tailscale login whose other devices count as the person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_login: Option<String>,
}

/// See [`Config::remote`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Remote {
    #[default]
    Off,
    Tailscale,
}

impl Remote {
    pub fn is_off(&self) -> bool { *self == Remote::Off }
}

/// See [`Config::agent_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    #[default]
    Auto,
    Explicit,
}

impl AgentMode {
    pub fn is_auto(&self) -> bool { *self == AgentMode::Auto }
    pub fn as_str(self) -> &'static str {
        match self { AgentMode::Auto => "auto", AgentMode::Explicit => "explicit" }
    }
}

impl std::fmt::Display for AgentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }
}

/// Parsed at load time so an invalid value is a config error, not a silent default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyEvery {
    Always,
    Never,
    Every(std::time::Duration),
}

impl Default for VerifyEvery {
    fn default() -> Self { VerifyEvery::Every(std::time::Duration::from_secs(24 * 3600)) }
}

impl VerifyEvery {
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        let s = s.trim();
        match s {
            "always" => return Ok(VerifyEvery::Always),
            "never" => return Ok(VerifyEvery::Never),
            _ => {}
        }
        let bad = || format!("verify_every: expected \"always\", \"never\", \"<n>h\" or \"<n>m\", got {s:?}");
        let (num, per_unit) = if let Some(n) = s.strip_suffix('h') { (n, 3600u64) } else if let Some(n) = s.strip_suffix('m') { (n, 60u64) } else { return Err(bad()) };
        if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let n: u64 = num.parse().map_err(|_| bad())?;
        if n == 0 {
            return Err("verify_every: the interval must be at least 1m (use \"always\" for every call)".into());
        }
        let secs = n.checked_mul(per_unit).filter(|&x| x <= 366 * 24 * 3600).ok_or_else(|| format!("verify_every: {s} is longer than a year; use \"never\""))?;
        Ok(VerifyEvery::Every(std::time::Duration::from_secs(secs)))
    }
}

impl std::fmt::Display for VerifyEvery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyEvery::Always => write!(f, "always"),
            VerifyEvery::Never => write!(f, "never"),
            VerifyEvery::Every(d) => {
                let s = d.as_secs();
                if s % 3600 == 0 { write!(f, "{}h", s / 3600) } else { write!(f, "{}m", s / 60) }
            }
        }
    }
}

impl serde::Serialize for VerifyEvery {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for VerifyEvery {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        VerifyEvery::parse(&s).map_err(serde::de::Error::custom)
    }
}

fn default_links() -> String { "paste".into() }

fn default_env_file() -> String { ".env.local".into() }
fn default_port() -> u16 { 7433 }
fn default_ttl() -> u64 { 24 }
fn default_true() -> bool { true }

impl Default for Config {
    fn default() -> Self {
        Self {
            trust_roots: vec![],
            env_file: default_env_file(),
            inbox_port: default_port(),
            task_ttl_hours: default_ttl(),
            stash_backend: None,
            notifications: true,
            inbox_links: default_links(),
            verify_every: VerifyEvery::default(),
            agent_mode: AgentMode::Auto,
            mcp: false,
            remote: Remote::Off,
            remote_host: None,
            remote_ip: None,
            remote_login: None,
        }
    }
}

/// `$TOKENSTASH_HOME` or the default.
pub fn config_dir() -> PathBuf {
    if let Ok(p) = std::env::var("TOKENSTASH_HOME") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    default_config_dir()
}

/// The default home, ignoring `TOKENSTASH_HOME`: `~/.config/tokenstash` on Linux,
/// `~/Library/Application Support/tokenstash` on macOS. For state that is about the machine
/// rather than one home (the init undo manifest).
pub fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from("/nonexistent")).join(".config"))
        .join("tokenstash")
}

pub fn config_path() -> PathBuf { config_dir().join("config.toml") }

/// Somewhere to keep state, or a clear error. Without `$HOME`, an XDG config dir or
/// `TOKENSTASH_HOME` (a container, a bare systemd unit) there is nowhere to write, and
/// every command must say so rather than panic.
pub fn require_home() -> Result<()> {
    if std::env::var("TOKENSTASH_HOME").map(|v| !v.is_empty()).unwrap_or(false) || dirs::config_dir().is_some() || dirs::home_dir().is_some() {
        return Ok(());
    }
    anyhow::bail!("no home directory to keep state in: set TOKENSTASH_HOME to a private directory")
}
pub fn db_path() -> PathBuf { config_dir().join("tokenstash.db") }

impl Config {
    /// Start of the window in which a denial or an unanswered card still counts, RFC 3339.
    pub fn ttl_since(&self) -> String {
        (chrono::Utc::now() - chrono::Duration::hours(self.task_ttl_hours as i64)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    pub fn load() -> Result<Self> {
        require_home()?;
        let p = config_path();
        if !p.exists() {
            return Ok(Self::default());
        }
        let s = fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        toml::from_str(&s).with_context(|| format!("parsing {}", p.display()))
    }

    /// Change the saved config: under a lock, the file is read again, `f` changes the fields
    /// its command owns, and the result is written. Saving a copy loaded earlier would put
    /// back whatever another command changed in between (`init` undoing a `remote off`).
    pub fn update<T>(f: impl FnOnce(&mut Config) -> Result<T>) -> Result<T> {
        require_home()?;
        let dir = config_dir();
        fs::create_dir_all(&dir)?;
        restrict_dir(&dir);
        crate::fsutil::with_lock(&config_path(), || {
            let mut cfg = Self::load()?;
            let out = f(&mut cfg)?;
            fs::write(config_path(), toml::to_string_pretty(&cfg)?)?;
            Ok(out)
        })
    }

    pub fn exists() -> bool { config_path().exists() }
}

#[cfg(unix)]
fn restrict_dir(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
}
