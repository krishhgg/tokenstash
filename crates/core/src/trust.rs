//! Trust model v2: trust only humans create.
//!
//! The unit of trust is a grant: (workspace, key name, stash identity). A workspace is a
//! directory the human paired keys into; the first time a stored key is wanted there, one
//! card lists exactly what would be delivered and the human says yes, no, or "any
//! non-sensitive registry key for this identity here". Pasting a missing key grants that
//! one key. Nothing is inferred from folders, remotes or repo names.
//!
//! A stash miss is self-gating (a human is asked). A stash hit is delivered when the
//! workspace holds a grant for it, or when the workspace's env file already carries the
//! same value (a copy that brought its `.env.local` along), which is a delivery check, not
//! a grant: it opens this delivery of this key and nothing else.

use crate::db::{Db, Workspace, GRANT_BROAD};
use anyhow::Result;
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum Gate {
    /// Deliver. `source` names the grant that authorised it (for the audit row).
    Open { source: String },
    NeedsApproval { reason: GateReason },
}

#[derive(Debug, Clone, PartialEq)]
pub enum GateReason {
    /// First delivery of stored keys into this workspace: one batched pairing card.
    Pairing,
    /// Sensitive or unregistered key: its own exact grant, per workspace.
    Sensitive,
}

/// What the human must have said for this delivery. `sensitive` is the index bit OR the
/// registry tag (the index is stricter: `sensitive_pattern` at paste time); `registered`
/// is whether the registry knows the name at all. A `run`-derived request never reaches
/// this: it gets a one-time approval upstream, every invocation.
pub fn gate(db: &Db, ws: &Workspace, name: &str, identity: &str, sensitive: bool, registered: bool) -> Result<Gate> {
    // A record whose directory was re-created holds grants for a directory that no longer
    // exists: nothing applies until a human pairs the new one.
    if ws.fingerprint_ok {
        if let Some(source) = db.grant_source(&ws.id, name, identity)? {
            return Ok(Gate::Open { source });
        }
    }
    if sensitive || !registered {
        return Ok(Gate::NeedsApproval { reason: GateReason::Sensitive });
    }
    if ws.fingerprint_ok && db.has_broad_grant(&ws.id, identity)? {
        return Ok(Gate::Open { source: GRANT_BROAD.into() });
    }
    Ok(Gate::NeedsApproval { reason: GateReason::Pairing })
}

/// Does a broad grant cover this key? Only registry-confirmed, non-sensitive names.
pub fn broad_applies(sensitive: bool, registered: bool) -> bool {
    !sensitive && registered
}

/// Already-on-disk equivalence: the workspace's env file holds `NAME=` with exactly the
/// stash value. That proves this directory already received this value, so delivering it
/// again is not a new decision. It is checked, never stored: it does not authorise future
/// values (rotation follows grants only) and never applies to sensitive/unregistered keys.
///
/// The file must be a regular file (no symlink, because a hostile repo can commit
/// `.env.local -> ../other/.env.local`), owned by this user, and not tracked by git.
pub fn on_disk_equivalent(project: &Path, env_file: &str, name: &str, value: &SecretString) -> bool {
    let Ok(path) = crate::envfile::resolve(project, env_file) else { return false };
    let Ok(md) = std::fs::symlink_metadata(&path) else { return false };
    if !md.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.uid() != crate::envfile::euid() {
            return false;
        }
    }
    if crate::envfile::is_git_tracked(project, &path) {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(&path) else { return false };
    let want = value.expose_secret().as_bytes();
    let mut found = false;
    for line in text.lines() {
        if let Some((k, v)) = crate::envfile::parse_line(line) {
            if k == name {
                found = constant_time_eq(v.as_bytes(), want);
            }
        }
    }
    found
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Directories that are never a workspace: the human did not open an agent "in their home
/// directory" as a project; a server or CLI started there is misconfigured, and pairing
/// keys into it would make every later `cd` a delivery. Returns the reason, or None.
/// Both sides are compared canonically.
pub fn refused_root(root: &Path) -> Option<String> {
    let canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if canon == Path::new("/") {
        return Some("the filesystem root".into());
    }
    // Order matters only for the message: the most specific reason first. Unix-only
    // (Windows profile/AppData roots are not covered; tokenstash does not run there yet).
    let mut refused: Vec<(PathBuf, &str, bool)> = vec![]; // (dir, why, exact_only)
    for shared in ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp"] {
        refused.push((PathBuf::from(shared), "a shared temporary directory", true));
    }
    if let Some(home) = dirs::home_dir() {
        refused.push((home.clone(), "your home directory", true));
        for d in [".ssh", ".aws", ".kube", ".local", ".vscode", ".windsurf", ".claude", ".codex", ".cursor", ".gemini"] {
            refused.push((home.join(d), "a tool or credential directory", false));
        }
    }
    // The tokenstash home (this one and the default one) and every ancestor: a project
    // that contains the stash index is not a project.
    for start in [crate::config::config_dir(), crate::config::default_config_dir()] {
        let mut d = Some(start);
        while let Some(p) = d {
            refused.push((p.clone(), "a directory containing the tokenstash home", true));
            d = p.parent().map(|x| x.to_path_buf()).filter(|x| x != Path::new("/"));
        }
    }
    for (dir, why, exact_only) in refused {
        let dir = dir.canonicalize().unwrap_or(dir);
        let hit = if exact_only { canon == dir } else { canon.starts_with(&dir) };
        if hit {
            return Some(why.to_string());
        }
    }
    None
}

