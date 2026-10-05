//! `init`: pick a stash backend, install the tokenstash skill for the agents on this machine.
//!
//! Agents use tokenstash through its CLI, and one skill documents it: `~/.claude/skills` for
//! Claude Code, `~/.agents/skills` for Codex and Gemini CLI, `~/.cursor/skills` for Cursor.
//! Two modes. `auto`: the agent sees the skill's one-line description and loads it when code
//! needs a key. `explicit`: the skill loads only when the person invokes it (`/tokenstash`,
//! or `$tokenstash` in Codex). Nothing goes into AGENTS.md or CLAUDE.md in either mode, and
//! the sections, prompts and commands earlier versions installed are taken out. The MCP
//! server is registered only on request (`--mcp`). Choosing the mode, registering the server
//! and undoing are a person's decisions: an agent with a shell could otherwise put automatic
//! mode back, or point every agent at a binary of its choosing.

use anyhow::Result;
use clap::Args;
use std::fs;
use std::path::{Path, PathBuf};
use tokenstash_core::config::AgentMode;
use tokenstash_core::Config;

pub const SKILL_MD: &str = include_str!("../../skill/SKILL.md");
/// Read by the agent on demand, from beside SKILL.md.
pub const SKILL_FILES: [(&str, &str); 2] = [
    ("reference.md", include_str!("../../skill/reference.md")),
    ("troubleshooting.md", include_str!("../../skill/troubleshooting.md")),
];
/// Codex reads a skill's invocation policy from this file beside SKILL.md.
const CODEX_POLICY: &str = "agents/openai.yaml";
const CODEX_EXPLICIT: &str = "policy:\n  allow_implicit_invocation: false\n";

#[derive(Args)]
pub struct InitArgs {
    /// How agents load the skill: `auto` (when code needs a key) or `explicit` (only when you
    /// invoke it: /tokenstash, or $tokenstash in Codex). Remembered in config.toml, so a later
    /// `init` without --mode keeps it. For a person at a terminal.
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,
    /// Also register tokenstash as an MCP server with each agent. Remembered; not available in
    /// explicit mode. For a person at a terminal.
    #[arg(long, conflicts_with = "no_mcp")]
    pub mcp: bool,
    /// Take the MCP server registrations out again (the default). For a person at a terminal.
    #[arg(long)]
    pub no_mcp: bool,
    /// Print the skill file for the mode and exit (no files touched).
    #[arg(long)]
    pub print_skill: bool,
    /// Don't touch any agent config; just set up the stash.
    #[arg(long)]
    pub no_agents: bool,
    /// Retired (0.4): tokenstash no longer writes AGENTS.md sections; init takes out the ones
    /// it wrote. Accepted and ignored with a notice.
    #[arg(long, hide = true)]
    pub project: bool,
    /// Retired (0.4) with `--project`.
    #[arg(long, hide = true)]
    pub print_snippet: bool,
    /// Retired (0.2): directories pair once instead; accepted and ignored with a notice.
    #[arg(long = "trust", hide = true)]
    pub trust: Vec<PathBuf>,
    /// Undo a previous `init`: restore every agent config file it changed (from the backups
    /// it took), remove the skill files and MCP registrations. Leaves the stash alone.
    /// For a person at a terminal.
    #[arg(long)]
    pub undo: bool,
    /// Why (shown on the card when an agent asks for --mode, --mcp, --no-mcp or --undo).
    #[arg(long)]
    pub why: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode { Auto, Explicit }

impl From<Mode> for AgentMode {
    fn from(m: Mode) -> Self { match m { Mode::Auto => AgentMode::Auto, Mode::Explicit => AgentMode::Explicit } }
}

/// An MCP registration explicit mode took out that init had not made: the user's own
/// `claude mcp add`, a Cursor entry written by hand. Undo puts the entry back — the entry,
/// not the file, so nothing the user changed in that file since is lost.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Removed {
    file: PathBuf,
    /// `mcpServers` (a JSON config's top level), `projects/<path>` (a Claude local-scope
    /// registration in `~/.claude.json`), `mcp_servers` (Codex's config.toml), or `section`
    /// (a marked tokenstash section an AGENTS.md held before init).
    key: String,
    /// The entry as JSON text, for TOML a document holding just `[mcp_servers.tokenstash]`,
    /// for a section its text.
    value: String,
}

/// What `init` did to files it does not own, so `--undo` can put them back exactly.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Manifest {
    /// (path, backup) — `backup` is `None` when the file did not exist before.
    files: Vec<(PathBuf, Option<PathBuf>)>,
    /// Skill directories init created.
    dirs: Vec<PathBuf>,
    /// `claude mcp add` was run, so `claude mcp remove` undoes it.
    claude_mcp_registered: bool,
    #[serde(default)]
    entries: Vec<Removed>,
    /// The MCP entry init wrote into each shared config, as JSON. Undo takes out only an entry
    /// that still matches: one the person changed or re-added since is theirs.
    #[serde(default)]
    wrote: Vec<(PathBuf, serde_json::Value)>,
    /// Where this manifest and its backups live. Not part of the record.
    #[serde(skip)]
    root: PathBuf,
}

/// The manifest records changes to the user's GLOBAL agent configs, so it lives in one fixed
/// place — the default config dir — no matter what `TOKENSTASH_HOME` a given shell has set.
/// Otherwise an init run with a scratch home and an `--undo` run without it (or the other way
/// round) never see each other's record, and undo reports "nothing to undo" over a fully
/// wired machine.
fn manifest_root() -> PathBuf { tokenstash_core::config::default_config_dir() }

impl Manifest {
    fn path(&self) -> PathBuf { self.root.join("init.manifest.json") }

    fn load() -> Result<Self> {
        let root = manifest_root();
        let p = root.join("init.manifest.json");
        // Older versions kept the manifest inside TOKENSTASH_HOME. If the fixed location has
        // none and the current home has one, adopt it (move, so there is one record).
        if !p.exists() {
            let legacy = tokenstash_core::config::config_dir().join("init.manifest.json");
            if legacy != p && legacy.exists() {
                if let Some(d) = p.parent() { fs::create_dir_all(d)?; }
                fs::rename(&legacy, &p).or_else(|_| fs::copy(&legacy, &p).map(|_| ()).and_then(|_| fs::remove_file(&legacy)))?;
                println!("(moved the init undo record from {} to {})", legacy.display(), p.display());
            }
        }
        Self::load_at(root)
    }

    /// Absent → empty. Present but unreadable/invalid → an error: silently treating a corrupt
    /// manifest as "nothing recorded" would let `--undo` say there is nothing to undo, or a
    /// re-run of `init` overwrite the only restoration points.
    fn load_at(root: PathBuf) -> Result<Self> {
        let p = root.join("init.manifest.json");
        let mut m: Self = match fs::read_to_string(&p) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| anyhow::anyhow!(
                "{} is unreadable ({e}). It records what a previous init changed so --undo can restore it; fix or move it, do not delete it, before running init again", p.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", p.display())),
        };
        m.root = root;
        Ok(m)
    }
    fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.is_empty() && !self.claude_mcp_registered && self.entries.is_empty()
    }
    /// [`Manifest::mutate`] for a shared config, remembering the tokenstash entry the change
    /// wrote. Not read back from the file: another writer may have changed it already, and
    /// undo would then take out their entry as init's.
    fn mutate_entry(&mut self, p: &Path, f: impl FnOnce() -> Result<serde_json::Value>) -> Result<()> {
        let mut made = None;
        self.mutate(p, || { made = Some(f()?); Ok(()) })?;
        if let Some(e) = made {
            self.wrote.retain(|(q, _)| q != p);
            self.wrote.push((p.to_path_buf(), e));
            self.save()?;
        }
        Ok(())
    }
    fn wrote_for(&self, p: &Path) -> Option<&serde_json::Value> {
        self.wrote.iter().find(|(q, _)| q == p).map(|(_, e)| e)
    }
    fn save(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        tokenstash_core::fsutil::write_atomic_private(&self.path(), &serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
    fn recorded(&self, p: &Path) -> bool { self.files.iter().any(|(q, _)| q == p) }
    /// Back up `p`, run the mutation, and record the file ONLY if the mutation succeeded —
    /// a failed merge changed nothing, so `--undo` must not later "restore" a stale copy
    /// over work the user did afterwards. The manifest is saved after every recorded
    /// change, so a crash mid-way still leaves an undo record for what was already done.
    /// Idempotent across re-runs: the backup taken by the FIRST init is the one that
    /// matters, later runs keep it.
    fn mutate(&mut self, p: &Path, f: impl FnOnce() -> Result<()>) -> Result<()> {
        if self.recorded(p) {
            return f();
        }
        let backup = if p.exists() {
            let dir = self.root.join("init-backups");
            fs::create_dir_all(&dir)?;
            let b = dir.join(backup_name(p));
            fs::copy(p, &b)?;
            Some(b)
        } else { None };
        // Record the intent durably BEFORE changing the file: if the manifest cannot be
        // written, the file is not touched at all, so there is never a changed file without
        // an undo record. If the change then fails, the record is withdrawn.
        self.files.push((p.to_path_buf(), backup));
        self.save()?;
        if let Err(e) = f() {
            self.files.pop();
            if let Err(e2) = self.save() {
                // The file is unchanged but its record is still on disk: say so, so the
                // user does not run --undo over later edits believing init touched it.
                return Err(e.context(format!(
                    "{} was NOT changed, but its undo record could not be withdrawn from {} ({e2}); remove that entry before running init --undo",
                    p.display(), self.path().display()
                )));
            }
            return Err(e);
        }
        Ok(())
    }

    fn record_dir(&mut self, d: &Path) -> Result<()> {
        if !self.dirs.iter().any(|q| q == d) {
            self.dirs.push(d.to_path_buf());
            self.save()?;
        }
        Ok(())
    }

    /// Put one recorded file back the way init found it — the backup, or nothing — and drop
    /// its record. For a file the other agent mode owns when modes switch: the file is
    /// tokenstash's own (a `tokenstash.md` prompt, a skill file), so restoring the original is
    /// the right move, unlike the shared configs where only the entry is taken out. A file
    /// that is not in the manifest is not init's to touch: `Ok(false)`.
    fn release(&mut self, p: &Path) -> Result<bool> {
        let Some(i) = self.files.iter().position(|(q, _)| q == p) else { return Ok(false) };
        let (_, backup) = self.files[i].clone();
        match &backup {
            Some(b) if b.exists() => restore(b, p)?,
            Some(b) => anyhow::bail!("backup of {} missing at {}", p.display(), b.display()),
            None => remove_file_if_present(p)?,
        }
        self.files.remove(i);
        self.save()?;
        Ok(true)
    }

    /// Init's entry is out of a shared config it held a whole-file record for, so the record
    /// is retired: whatever else the file holds is the user's — put there before init or
    /// after it — and restoring a copy would overwrite it. What init itself replaced — a
    /// tokenstash entry the user had before init, a marked section in an AGENTS.md — comes
    /// back through an entry record instead. A file init created that holds nothing else is
    /// removed rather than left as a stub. A backup that cannot be read keeps the whole-file
    /// record: the only way back it offers is the one there is.
    fn retire(&mut self, p: &Path) -> Result<()> {
        let Some(i) = self.files.iter().position(|(q, _)| q == p) else { return Ok(()) };
        match self.files[i].1.clone() {
            Some(b) => match original_entry(&b) {
                Ok(Some((key, value))) => self.entries.push(Removed { file: p.to_path_buf(), key, value }),
                Ok(None) => {}
                Err(e) => {
                    println!("! {}: its backup could not be read ({e:#}); the whole-file undo record is kept", p.display());
                    return Ok(());
                }
            },
            None => if effectively_empty(p) { remove_file_if_present(p)?; },
        }
        self.files.remove(i);
        self.save()?;
        Ok(())
    }
}

/// What a backup holds that init's wiring replaced: the user's own registration (as an
/// entry record's key and value), or an AGENTS.md's marked section. `None` for a backup
/// without one; an error for a backup that cannot be read or parsed.
fn original_entry(backup: &Path) -> Result<Option<(String, String)>> {
    let s = fs::read_to_string(backup).map_err(|e| anyhow::anyhow!("reading {}: {e}", backup.display()))?;
    let name = backup.to_string_lossy();
    if name.ends_with(".toml") {
        let doc: toml_edit::DocumentMut = s.parse().map_err(|e| anyhow::anyhow!("{} does not parse: {e}", backup.display()))?;
        let Some(item) = doc.get("mcp_servers").and_then(|m| m.get("tokenstash")).cloned() else { return Ok(None) };
        let mut snip = toml_edit::DocumentMut::new();
        let mut t = toml_edit::Table::new();
        t.set_implicit(true);
        t.insert("tokenstash", item);
        snip.insert("mcp_servers", toml_edit::Item::Table(t));
        return Ok(Some(("mcp_servers".into(), snip.to_string())));
    }
    if name.ends_with(".json") {
        let v: serde_json::Value = serde_json::from_str(&s).map_err(|e| anyhow::anyhow!("{} does not parse: {e}", backup.display()))?;
        return Ok(v.get("mcpServers").and_then(|m| m.get("tokenstash")).map(|e| ("mcpServers".into(), e.to_string())));
    }
    Ok(section_of(&s).map(|sec| ("section".into(), sec.to_string())))
}

/// A marked section (marks included) holding exactly text a tokenstash release wrote.
fn is_shipped_section(section: &str) -> bool {
    section.strip_prefix(SNIPPET_MARK).and_then(|r| r.strip_prefix('\n')).and_then(|r| r.strip_suffix(SNIPPET_END)).and_then(|r| r.strip_suffix('\n')).is_some_and(|body| SHIPPED_SECTIONS.contains(&body))
}

/// The first marked section of an AGENTS.md, marks included.
fn section_of(s: &str) -> Option<&str> {
    let start = s.find(SNIPPET_MARK)?;
    let end = start + s[start..].find(SNIPPET_END)? + SNIPPET_END.len();
    Some(&s[start..end])
}

fn remove_file_if_present(p: &Path) -> Result<()> {
    match fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A skill directory init created, once its files are gone: every file init wrote there has
/// a record of its own and is removed (or restored) through that, before this runs. Here only
/// directories go, and only empty ones: a file the user added stays, and the directory with it.
fn remove_skill_dir(d: &Path) -> Result<()> {
    let _ = fs::remove_dir(d.join("agents"));
    match fs::remove_dir(d) {
        Ok(()) => println!("✓ removed {}", d.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("✓ removed {}", d.display()),
        Err(_) => println!("! left {}: it holds files init did not write", d.display()),
    }
    Ok(())
}


/// Nothing but what init's own wiring leaves behind once its entry is gone: `{}` or
/// `{"mcpServers": {}}`, a bare `[mcp_servers]` header, a blank AGENTS.md. Anything else —
/// another key, an empty table of the user's, a comment — is theirs, and the file stays.
fn effectively_empty(p: &Path) -> bool {
    match fs::read_to_string(p) {
        Ok(s) => effectively_empty_text(p, &s),
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// [`effectively_empty`] for text about to be written to `p`.
fn effectively_empty_text(p: &Path, s: &str) -> bool {
    match p.extension().and_then(|e| e.to_str()) {
        Some("json") => serde_json::from_str::<serde_json::Value>(s).map(|v| v == serde_json::json!({}) || v == serde_json::json!({ "mcpServers": {} })).unwrap_or(false),
        Some("toml") => { let t = s.trim(); t.is_empty() || t == "[mcp_servers]" }
        _ => s.trim().is_empty(),
    }
}

fn undo() -> Result<i32> {
    let m = Manifest::load()?;
    undo_with(m, which("claude"), &dirs::home_dir().unwrap_or_default())
}

/// `claude_cli`: `claude` is on PATH, so init's own registration can be removed through it.
/// A parameter, not a lookup, like `home`, so a test on a fake home never reaches the real one.
fn undo_with(m: Manifest, claude_cli: bool, home: &Path) -> Result<i32> {
    if m.is_empty() {
        println!("nothing to undo: no init manifest at {}", m.path().display());
        println!("(if that init ran with a custom TOKENSTASH_HOME under an older version, run --undo with the same TOKENSTASH_HOME set: the record is adopted from there)");
        return Ok(0);
    }
    // Each completed step is removed from the on-disk manifest immediately, so a retry after
    // a crash or a failed save never repeats a step already done (which would restore a
    // stale backup over an edit made in between). Whatever fails stays recorded for retry.
    let mut cur = m;
    let mut i = 0;
    while i < cur.files.len() {
        let (p, backup) = cur.files[i].clone();
        let r: Result<()> = if is_shared(&p) {
            undo_shared(&p, backup.as_deref(), cur.wrote_for(&p).cloned())
        } else {
            match &backup {
                Some(b) if b.exists() => restore(b, &p),
                Some(b) => Err(anyhow::anyhow!("backup missing at {}", b.display())),
                None => remove_file_if_present(&p),
            }
        };
        match r {
            Ok(()) => {
                println!("✓ {} {}", if backup.is_some() { "restored" } else { "removed" }, p.display());
                cur.files.remove(i);
                cur.save()?;
            }
            Err(e) => { println!("! {}: {e} (kept in the manifest; re-run --undo to retry)", p.display()); i += 1; }
        }
    }
    let mut i = 0;
    while i < cur.dirs.len() {
        let d = cur.dirs[i].clone();
        match remove_skill_dir(&d) {
            Ok(()) => { cur.dirs.remove(i); cur.save()?; }
            Err(e) => { println!("! {}: {e} (kept in the manifest)", d.display()); i += 1; }
        }
    }
    // Init's own CLI registration goes before any entry comes back: `reinsert` yields to a
    // tokenstash entry already present, and init's would be mistaken for the user's. A flag
    // left set by a run that crashed after removing the registration is settled by looking:
    // confirmed absence is completion, an unreadable file is not.
    if cur.claude_mcp_registered && matches!(json_server_state(&home.join(".claude.json"), false), Ok(false)) {
        cur.claude_mcp_registered = false;
        cur.save()?;
    }
    if cur.claude_mcp_registered {
        let ok = claude_cli && claude_mcp(&["remove", "-s", "user", "tokenstash"])?;
        if ok { println!("✓ claude mcp remove tokenstash"); cur.claude_mcp_registered = false; cur.save()?; } else {
            println!("! could not run `claude mcp remove -s user tokenstash` (kept in the manifest; run it by hand or re-run --undo with `claude` on PATH)");
        }
    }
    let mut i = 0;
    while i < cur.entries.len() {
        let r = cur.entries[i].clone();
        if cur.claude_mcp_registered && r.file.file_name().is_some_and(|n| n == ".claude.json") {
            println!("! {}: the tokenstash entry waits until init's own registration is removed (kept in the manifest)", r.file.display());
            i += 1;
            continue;
        }
        match reinsert(&r) {
            Ok(()) => { println!("✓ put the tokenstash {} back in {}", if r.key == "section" { "section" } else { "MCP entry" }, r.file.display()); cur.entries.remove(i); cur.save()?; }
            Err(e) => { println!("! {}: {e} (kept in the manifest; re-run --undo to retry)", r.file.display()); i += 1; }
        }
    }
    let all_done = cur.is_empty();
    if all_done {
        let _ = fs::remove_file(cur.path());
    }
    println!("\nThe stash, config and database were not touched (`tokenstash forget NAME` removes secrets).");
    Ok(if all_done { 0 } else { 1 })
}

/// A backup's file name: a digest of the whole path, then the file's own name for a person
/// looking in the folder. Flattening the path (`/` → `_`) made `/a_b/c` and `/a/b_c` one
/// backup, and undo then restored one project's file into the other.
fn backup_name(p: &Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(p.as_os_str().as_encoded_bytes());
    let short: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("{short}-{}", p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
}

/// Replace `p` with `contents` in one step: written beside it, then renamed over it, keeping
/// the file's permissions. A full disk or a crash leaves the old file, never half of a new
/// one; `~/.claude.json` is also written by every running Claude Code session.
fn write_file(p: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    write_file_as(p, contents, None)
}

/// [`write_file`], giving a new file `perms` (a restore takes the backup's: a private config
/// deleted since init must not come back readable by everyone under the umask).
fn write_file_as(p: &Path, contents: impl AsRef<[u8]>, perms: Option<fs::Permissions>) -> Result<()> {
    use std::io::Write;
    let target = landing(p)?;
    let p = target.as_path();
    // A file with more than one name (a hard link, as some dotfile managers make) is
    // rewritten in place, so every name keeps showing the same file: a rename would give
    // only this name the new text. That one write is not atomic.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::metadata(p).is_ok_and(|md| md.is_file() && md.nlink() > 1) {
            let mut f = fs::OpenOptions::new().write(true).truncate(true).open(p).map_err(|e| anyhow::anyhow!("writing {}: {e}", p.display()))?;
            f.write_all(contents.as_ref())?;
            f.sync_all()?;
            return Ok(());
        }
    }
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    // A name nobody can guess, created only if nothing is there: a link planted at a
    // predictable temporary path in a shared directory would otherwise redirect the write.
    let tmp = dir.join(format!(".{}.tokenstash-{}-{:016x}", p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), std::process::id(), rand::random::<u64>()));
    let perms = fs::metadata(p).ok().map(|md| md.permissions()).or(perms);
    let written = (|| -> Result<()> {
        let mut open = fs::OpenOptions::new();
        open.write(true).create_new(true);
        // Created with the final file's mode, never wider: a private config's copy is
        // private before anyone else could open it.
        #[cfg(unix)]
        if let Some(perms) = &perms {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            open.mode(perms.mode() & 0o777);
        }
        let mut f = open.open(&tmp)?;
        if let Some(perms) = &perms {
            f.set_permissions(perms.clone())?;
        }
        f.write_all(contents.as_ref())?;
        f.sync_all()?;
        fs::rename(&tmp, p)?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written.map_err(|e| e.context(format!("writing {}", p.display())))
}

/// Where a write to `p` lands. A config that is a link (dotfiles kept in a repository) is
/// written at the end of its chain of links, which then stays as it was; that file need
/// not exist (a link whose file is gone gets the file back where the chain points).
fn landing(p: &Path) -> Result<PathBuf> {
    let mut at = p.to_path_buf();
    // The same limit as the kernel's for following links.
    for _ in 0..40 {
        match fs::symlink_metadata(&at) {
            Ok(md) if md.file_type().is_symlink() => {
                let to = fs::read_link(&at)?;
                at = if to.is_absolute() { to } else { at.parent().unwrap_or(Path::new(".")).join(to) };
            }
            _ => return Ok(at),
        }
    }
    anyhow::bail!("{} is a loop of links; nothing was written", p.display())
}

/// Put a backup back in place, atomically and byte for byte: what init replaced need not be
/// text.
fn restore(backup: &Path, p: &Path) -> Result<()> {
    let bytes = fs::read(backup).map_err(|e| anyhow::anyhow!("reading {}: {e}", backup.display()))?;
    write_file_as(p, bytes, fs::metadata(backup).ok().map(|m| m.permissions()))
}

/// A file other tools and the person also write: an agent's config or an AGENTS.md. Undo
/// takes tokenstash's entry out of it rather than putting an old copy back over it.
fn is_shared(p: &Path) -> bool {
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    name.ends_with(".json") || name == "config.toml" || name == "AGENTS.md"
}

/// The tokenstash MCP entry a JSON or TOML config holds, as JSON; `None` without one.
fn mcp_entry(p: &Path) -> Result<Option<serde_json::Value>> {
    if p.file_name().is_some_and(|n| n == "config.toml") {
        let doc: toml::Value = match fs::read_to_string(p) {
            Ok(s) => toml::from_str(&s).map_err(|e| anyhow::anyhow!("{} is not valid TOML ({e})", p.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        return Ok(doc.get("mcp_servers").and_then(|m| m.get("tokenstash")).map(serde_json::to_value).transpose()?);
    }
    Ok(read_json(p)?.get("mcpServers").and_then(|m| m.get("tokenstash")).cloned())
}

/// Undo for a shared file. Everything is read and the new text worked out first, and the
/// file is written once at the end, so an unreadable backup or a crash leaves the file as it
/// was rather than half undone. In the file as it is now:
/// - the tokenstash MCP entry goes if it is still the one init wrote (`wrote`; an older
///   record without it counts any entry as init's); one the person changed since stays;
/// - an AGENTS.md section goes if it is text a release shipped; one the person edited stays;
/// - what the backup held under that name comes back, where init's was taken out;
/// - a file init created that holds nothing else is removed.
///
/// A file that is gone is restored from its backup, as before.
fn undo_shared(p: &Path, backup: Option<&Path>, wrote: Option<serde_json::Value>) -> Result<()> {
    if !p.exists() {
        return match backup {
            Some(b) if b.exists() => restore(b, p),
            Some(b) => Err(anyhow::anyhow!("backup missing at {}", b.display())),
            None => Ok(()),
        };
    }
    let original = match backup {
        Some(b) => original_entry(b)?,
        None => None,
    };
    let text = fs::read_to_string(p).map_err(|e| anyhow::anyhow!("reading {}: {e}", p.display()))?;
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let out = if name == "AGENTS.md" {
        // Only sections that are text a release shipped go; any other section (the person's
        // own, or one of ours they edited) stays exactly where it is.
        let mut s = strip_sections_where(&text, is_shipped_section)?;
        if s != text && !s.contains(SNIPPET_MARK) {
            if let Some((_, value)) = original.filter(|(k, _)| k == "section") {
                if !s.is_empty() && !s.ends_with('\n') { s.push('\n'); }
                if !s.is_empty() { s.push('\n'); }
                s.push_str(&value);
                s.push('\n');
            }
        }
        s
    } else {
        let current = mcp_entry(p)?;
        let ours = match (&current, &wrote) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(c), Some(w)) => c == w,
        };
        if !ours {
            // The person changed or removed the tokenstash entry: nothing of init's to take
            // out, so the file stays byte for byte (not even reformatted).
            text.clone()
        } else if name == "config.toml" {
            let mut doc: toml_edit::DocumentMut = text.parse().map_err(|e| anyhow::anyhow!("{} is not valid TOML ({e})", p.display()))?;
            if let Some(servers) = doc.get_mut("mcp_servers").and_then(|s| s.as_table_like_mut()) {
                servers.remove("tokenstash");
            }
            if let Some((_, value)) = original.filter(|(k, _)| k == "mcp_servers") {
                let snip: toml_edit::DocumentMut = value.parse().map_err(|e| anyhow::anyhow!("the saved entry does not parse ({e})"))?;
                if let Some(item) = snip.get("mcp_servers").and_then(|m| m.get("tokenstash")).cloned() {
                    let servers = doc.entry("mcp_servers").or_insert(toml_edit::table());
                    if let Some(servers) = servers.as_table_like_mut() { servers.insert("tokenstash", item); }
                }
            }
            let out = doc.to_string();
            toml::from_str::<toml::Value>(&out).map_err(|e| anyhow::anyhow!("refusing to write {}: result would not parse ({e})", p.display()))?;
            out
        } else {
            let mut v: serde_json::Value = if text.trim().is_empty() { serde_json::json!({}) } else { serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("{} is not valid JSON ({e})", p.display()))? };
            if let Some(m) = v.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
                m.remove("tokenstash");
            }
            if let Some((_, value)) = original.filter(|(k, _)| k == "mcpServers") {
                let entry: serde_json::Value = serde_json::from_str(&value).map_err(|e| anyhow::anyhow!("the saved entry does not parse ({e})"))?;
                if let Some(root) = v.as_object_mut() {
                    if let Some(m) = root.entry("mcpServers").or_insert(serde_json::json!({})).as_object_mut() {
                        m.insert("tokenstash".into(), entry);
                    }
                }
            }
            serde_json::to_string_pretty(&v)?
        }
    };
    if backup.is_none() && effectively_empty_text(p, &out) {
        return remove_file_if_present(p);
    }
    if out != text {
        write_file(p, &out)?;
    }
    Ok(())
}

/// Put a removed registration back where it was, unless a tokenstash entry is there already
/// (the user re-added one since; theirs wins). The file, and its directory, may be gone by
/// now (an agent uninstalled in between): they are recreated around the entry.
fn reinsert(r: &Removed) -> Result<()> {
    if let Some(d) = r.file.parent() { fs::create_dir_all(d)?; }
    if r.key == "section" {
        // Read once; only a missing file is empty text. Anything else that cannot be read
        // (not UTF-8, say) is an error, not a blank to overwrite.
        let mut s = match fs::read_to_string(&r.file) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", r.file.display())),
        };
        if s.contains(SNIPPET_MARK) { return Ok(()); }
        if !s.is_empty() && !s.ends_with('\n') { s.push('\n'); }
        if !s.is_empty() { s.push('\n'); }
        s.push_str(&r.value);
        s.push('\n');
        write_file(&r.file, &s)?;
        return Ok(());
    }
    if r.key == "mcp_servers" {
        let mut doc = read_toml(&r.file)?;
        let snip: toml_edit::DocumentMut = r.value.parse().map_err(|e| anyhow::anyhow!("the saved entry does not parse ({e})"))?;
        let item = snip.get("mcp_servers").and_then(|m| m.get("tokenstash")).cloned().ok_or_else(|| anyhow::anyhow!("the saved entry holds no mcp_servers.tokenstash"))?;
        let servers = doc.entry("mcp_servers").or_insert(toml_edit::table());
        let Some(servers) = servers.as_table_like_mut() else { anyhow::bail!("mcp_servers is not a table") };
        if servers.get("tokenstash").is_none() { servers.insert("tokenstash", item); }
        let out = doc.to_string();
        toml::from_str::<toml::Value>(&out).map_err(|e| anyhow::anyhow!("refusing to write: result would not parse ({e})"))?;
        write_file(&r.file, &out)?;
        return Ok(());
    }
    let value: serde_json::Value = serde_json::from_str(&r.value).map_err(|e| anyhow::anyhow!("the saved entry does not parse ({e})"))?;
    let mut v = read_json(&r.file)?;
    let root = v.as_object_mut().ok_or_else(|| anyhow::anyhow!("root is not a JSON object"))?;
    let scope = match r.key.strip_prefix("projects/") {
        Some(path) => root.entry("projects").or_insert(serde_json::json!({})).as_object_mut().ok_or_else(|| anyhow::anyhow!("projects is not an object"))?
            .entry(path).or_insert(serde_json::json!({})).as_object_mut().ok_or_else(|| anyhow::anyhow!("projects entry is not an object"))?,
        None => root,
    };
    let m = scope.entry("mcpServers").or_insert(serde_json::json!({})).as_object_mut().ok_or_else(|| anyhow::anyhow!("mcpServers is not an object"))?;
    m.entry("tokenstash").or_insert(value);
    write_file(&r.file, &serde_json::to_string_pretty(&v)?)?;
    Ok(())
}

/// How long `claude mcp add` or `claude mcp remove` may run. An action card that runs one
/// holds its claim meanwhile, so a hung `claude` must not hold it for as long as the inbox runs.
const CLAUDE_MCP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Run `claude mcp ARGS`. True if it succeeded, false if it failed or could not start, and an
/// error if it ran past [`CLAUDE_MCP_TIMEOUT`]: the child is killed, and a confirm that ran it
/// gives its card back.
fn claude_mcp(args: &[&str]) -> Result<bool> {
    claude_mcp_with(Path::new("claude"), args, CLAUDE_MCP_TIMEOUT)
}

fn claude_mcp_with(claude: &Path, args: &[&str], limit: std::time::Duration) -> Result<bool> {
    let Ok(mut child) = std::process::Command::new(claude).arg("mcp").args(args)
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() else { return Ok(false) };
    // The output goes nowhere, so no pipe can fill and stall the child: polling is enough.
    let deadline = std::time::Instant::now() + limit;
    loop {
        if let Some(s) = child.try_wait()? {
            return Ok(s.success());
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("`claude mcp {}` did not finish within {limit:?} and was stopped", args.join(" "));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}


/// The machine `init` wires: where the agents' configs are, which binary to point them at.
struct Wiring {
    home: PathBuf,
    exe: String,
    /// A non-default `TOKENSTASH_HOME`, named in the skill and baked into any MCP
    /// registration, or the agent's commands and this shell would use two different homes.
    ts_home: Option<String>,
    /// `claude` is on PATH, so an MCP registration can go through `claude mcp` instead of the file.
    claude_cli: bool,
}

impl Wiring {
    fn claude_present(&self) -> bool { self.home.join(".claude").is_dir() || self.claude_cli }
    fn claude_skill_dir(&self) -> PathBuf { self.home.join(".claude/skills/tokenstash") }
    fn claude_json(&self) -> PathBuf { self.home.join(".claude.json") }
    /// The user skills directory Codex and Gemini CLI both read.
    fn agents_skill_dir(&self) -> PathBuf { self.home.join(".agents/skills/tokenstash") }
    fn agents_present(&self) -> bool { self.codex().is_dir() || self.gemini().is_dir() || self.home.join(".agents").is_dir() }
    fn codex(&self) -> PathBuf { self.home.join(".codex") }
    /// Before 0.4: a section here in auto mode.
    fn codex_agents(&self) -> PathBuf { self.home.join(".codex/AGENTS.md") }
    /// Before 0.4: the explicit-mode command, `/prompts:tokenstash`.
    fn codex_prompt(&self) -> PathBuf { self.home.join(".codex/prompts/tokenstash.md") }
    fn cursor(&self) -> PathBuf { self.home.join(".cursor") }
    fn cursor_skill_dir(&self) -> PathBuf { self.home.join(".cursor/skills/tokenstash") }
    fn gemini(&self) -> PathBuf { self.home.join(".gemini") }
    /// Before 0.4: the explicit-mode command.
    fn gemini_command(&self) -> PathBuf { self.home.join(".gemini/commands/tokenstash.toml") }
}

/// Write a skill directory: SKILL.md, the reference files beside it, and, for the copy Codex
/// reads in explicit mode, its invocation policy. The directory is recorded when init creates
/// it and each file when init writes it, so undo puts back exactly what was there. A policy
/// file init wrote earlier goes again when the mode no longer wants it.
fn write_skill_dir(manifest: &mut Manifest, dir: &Path, text: &str, policy: bool) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        manifest.record_dir(dir)?;
    }
    let mut files: Vec<(PathBuf, &str)> = vec![(dir.join("SKILL.md"), text)];
    files.extend(SKILL_FILES.iter().map(|(n, t)| (dir.join(n), *t)));
    if policy {
        files.push((dir.join(CODEX_POLICY), CODEX_EXPLICIT));
    }
    for (p, t) in files {
        manifest.mutate(&p, || {
            if let Some(d) = p.parent() { fs::create_dir_all(d)?; }
            write_file(&p, t)
        })?;
    }
    if !policy && manifest.release(&dir.join(CODEX_POLICY))? {
        let _ = fs::remove_dir(dir.join("agents"));
    }
    Ok(())
}

/// Take out what earlier versions installed and this one does not: the AGENTS.md sections
/// (the global Codex one, and each one `init --project` wrote), the Codex custom prompt and
/// the Gemini CLI command. The skill replaces all of them. A section init did not write (the
/// user's own, with tokenstash's marks) goes too, and is recorded so undo puts it back.
fn retire_legacy(manifest: &mut Manifest, w: &Wiring) -> Result<()> {
    let cagents = w.codex_agents();
    let projects: Vec<PathBuf> = manifest.files.iter().map(|(p, _)| p.clone()).filter(|p| p.file_name().is_some_and(|n| n == "AGENTS.md") && *p != cagents).collect();
    for p in std::iter::once(cagents.clone()).chain(projects) {
        let current = match fs::read_to_string(&p) {
            Ok(text) if text.contains(SNIPPET_MARK) => {
                let section = section_of(&text).map(String::from);
                manifest.mutate(&p, || strip_snippet(&p))?;
                println!("✓ removed the tokenstash section from {}", p.display());
                section
            }
            Ok(_) => None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => anyhow::bail!("reading {}: {e}", p.display()),
        };
        let kept = manifest.entries.len();
        manifest.retire(&p)?;
        // `retire` keeps the section the file held before init first touched it. The one just
        // taken out decides on its own: text tokenstash shipped is not the user's and is not
        // kept, wherever it came from; anything else (edited since, or never init's) is kept
        // for undo, whatever the backup says.
        let mut i = 0;
        manifest.entries.retain(|e| { i += 1; i <= kept || !(e.file == p && e.key == "section" && is_shipped_section(&e.value)) });
        if let Some(sec) = current.filter(|s| !is_shipped_section(s)) {
            if !manifest.entries.iter().any(|e| e.file == p && e.key == "section" && e.value == sec) {
                manifest.entries.push(Removed { file: p.clone(), key: "section".into(), value: sec });
            }
        }
        manifest.save()?;
    }
    for (name, p) in [("Codex", w.codex_prompt()), ("Gemini CLI", w.gemini_command())] {
        if manifest.release(&p)? {
            println!("✓ {name}: removed the old /tokenstash command ({}); the skill replaces it", p.display());
        }
    }
    Ok(())
}

/// The skill for `mode`, for every agent present.
fn install_skills(manifest: &mut Manifest, w: &Wiring, mode: AgentMode) -> Result<Vec<PathBuf>> {
    let home = w.ts_home.as_deref();
    let explicit = mode == AgentMode::Explicit;
    let mut touched = vec![];
    if w.claude_present() {
        write_skill_dir(manifest, &w.claude_skill_dir(), &skill_text(mode, Target::Claude, home), false)?;
        touched.push(w.claude_skill_dir());
        println!("✓ Claude Code: skill installed; {}", if explicit { "it loads when you type /tokenstash" } else { "it loads when code needs a key" });
    }
    if w.agents_present() {
        write_skill_dir(manifest, &w.agents_skill_dir(), &skill_text(mode, Target::Agents, home), explicit)?;
        touched.push(w.agents_skill_dir());
        println!(
            "✓ Codex and Gemini CLI: skill installed in {}; {}",
            w.agents_skill_dir().display(),
            if explicit { "Codex loads it when you type $tokenstash; Gemini CLI asks you before loading it" } else { "it loads when code needs a key" }
        );
    }
    if w.cursor().is_dir() {
        write_skill_dir(manifest, &w.cursor_skill_dir(), &skill_text(mode, Target::Claude, home), false)?;
        touched.push(w.cursor_skill_dir());
        println!("✓ Cursor: skill installed; {}", if explicit { "it loads when you type /tokenstash" } else { "it loads when code needs a key" });
    }
    Ok(touched)
}

/// `--mcp`: register the server with every agent present. The skill still documents the CLI;
/// the server is a second way in.
fn register_mcp(manifest: &mut Manifest, w: &Wiring) -> Result<Vec<PathBuf>> {
    let mut touched = vec![];
    if w.claude_present() {
        let cj = w.claude_json();
        // The CLI registers cleanly when present. The desktop app ships without `claude`
        // on PATH, so fall back to writing the same user-scope entry into ~/.claude.json
        // ourselves — otherwise a desktop-only user is left with a printed command.
        let added = if w.claude_cli && !manifest.claude_mcp_registered && !manifest.recorded(&cj) && json_has_server(&cj, false) {
            // Already registered by someone else (the user, an older install): not ours
            // to remove on --undo, so no record is taken.
            if let Some(h) = &w.ts_home {
                println!("! Claude Code: an existing tokenstash MCP registration was left as is; it may not use TOKENSTASH_HOME={h}. To re-register: claude mcp remove -s user tokenstash && tokenstash init --mcp");
            }
            true
        } else if w.claude_cli {
            // Record before registering, like every other mutation: a registration
            // with no durable record could never be undone.
            manifest.claude_mcp_registered = true;
            manifest.save()?;
            let mut args: Vec<String> = vec!["add".into(), "-s".into(), "user".into()];
            if let Some(h) = &w.ts_home { args.push("-e".into()); args.push(format!("TOKENSTASH_HOME={h}")); }
            args.extend(["tokenstash".into(), "--".into(), w.exe.clone(), "mcp".into()]);
            // A time-out is an error and keeps the record: the stopped command may have
            // registered the server, and a record can be undone.
            let ok = claude_mcp(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
            if !ok { manifest.claude_mcp_registered = false; manifest.save()?; }
            ok
        } else {
            match manifest.mutate_entry(&cj, || merge_mcp_json_typed(&cj, &w.exe, true, w.ts_home.as_deref())) {
                Ok(()) => { touched.push(cj); true }
                Err(e) => { println!("! Claude Code: left {} untouched — {e}", cj.display()); false }
            }
        };
        if added {
            println!("✓ Claude Code: MCP server registered");
        } else {
            println!("! Claude Code: register the MCP server with: claude mcp add -s user tokenstash -- {} mcp", w.exe);
        }
    }
    let codex = w.codex();
    if codex.is_dir() {
        let ctoml = codex.join("config.toml");
        match manifest.mutate_entry(&ctoml, || merge_codex_toml(&ctoml, &w.exe, w.ts_home.as_deref())) {
            Ok(()) => { touched.push(ctoml.clone()); println!("✓ Codex: MCP server registered ({})", ctoml.display()) }
            Err(e) => println!("! Codex: left {} untouched — {e}", ctoml.display()),
        }
    }
    let cursor = w.cursor();
    if cursor.is_dir() {
        let cj = cursor.join("mcp.json");
        match manifest.mutate_entry(&cj, || merge_mcp_json(&cj, &w.exe, w.ts_home.as_deref())) {
            Ok(()) => { touched.push(cj.clone()); println!("✓ Cursor: MCP server registered ({})", cj.display()) }
            Err(e) => println!("! Cursor: left {} untouched — {e}", cj.display()),
        }
    }
    let gemini = w.gemini();
    if gemini.is_dir() {
        let gj = gemini.join("settings.json");
        match manifest.mutate_entry(&gj, || merge_mcp_json(&gj, &w.exe, w.ts_home.as_deref())) {
            Ok(()) => { touched.push(gj.clone()); println!("✓ Gemini CLI: MCP server registered ({})", gj.display()) }
            Err(e) => println!("! Gemini CLI: left {} untouched — {e}", gj.display()),
        }
    }
    Ok(touched)
}

/// Take every tokenstash MCP registration out. Only the tokenstash entry leaves a shared
/// config; the rest of the file is the user's. A registration init did not make (the user's
/// own `claude mcp add`, at user or local scope) goes too, since with it the agent calls
/// tokenstash through MCP rather than the CLI the skill describes, and is recorded entry by
/// entry so undo puts it back.
fn unregister_mcp(manifest: &mut Manifest, w: &Wiring) -> Result<()> {
    remove_json_server(manifest, &w.claude_json(), "Claude Code", true)?;
    remove_toml_server(manifest, &w.codex().join("config.toml"))?;
    remove_json_server(manifest, &w.cursor().join("mcp.json"), "Cursor", false)?;
    remove_json_server(manifest, &w.gemini().join("settings.json"), "Gemini CLI", false)?;
    Ok(())
}

/// Take `tokenstash` out of a JSON config's `mcpServers` — and, for `~/.claude.json`, out of
/// every project's local-scope `mcpServers` too, which is where a plain `claude mcp add`
/// puts it. Init's own entry just goes; anyone else's is recorded for undo. An entry that
/// is already gone (an interrupted earlier run, the user) still settles the bookkeeping:
/// the CLI flag and the whole-file record are reconciled either way.
fn remove_json_server(manifest: &mut Manifest, p: &Path, name: &str, claude: bool) -> Result<()> {
    let recorded = manifest.recorded(p);
    if json_server_state(p, claude)? {
        let mut v = read_json(p)?;
        let mut removed: Vec<(String, serde_json::Value)> = vec![];
        if let Some(m) = v.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
            if let Some(x) = m.remove("tokenstash") { removed.push(("mcpServers".into(), x)); }
        }
        if claude {
            if let Some(projects) = v.get_mut("projects").and_then(|s| s.as_object_mut()) {
                for (path, proj) in projects.iter_mut() {
                    if let Some(m) = proj.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
                        if let Some(x) = m.remove("tokenstash") { removed.push((format!("projects/{path}"), x)); }
                    }
                }
            }
        }
        // The user-scope entry is init's when init wrote this file, or registered through
        // the CLI; either way it is not user data and undo must not bring it back.
        let own_user_scope = recorded || (claude && manifest.claude_mcp_registered);
        for (key, value) in removed {
            if key == "mcpServers" && own_user_scope { continue; }
            manifest.entries.push(Removed { file: p.to_path_buf(), key, value: value.to_string() });
        }
        // The records first: an entry recorded but still present is re-inserted by undo only
        // if absent, so a crash between the two leaves nothing wrong. Ownership of init's
        // registration is given up only once it is gone.
        manifest.save()?;
        write_file(p, &serde_json::to_string_pretty(&v)?)?;
        println!("✓ {name}: MCP server removed from {}", p.display());
    }
    if claude && manifest.claude_mcp_registered && !json_server_state(p, false)? {
        manifest.claude_mcp_registered = false;
        manifest.save()?;
    }
    if recorded { manifest.retire(p)?; }
    Ok(())
}

/// Same for Codex's `mcp_servers.tokenstash`, keeping the user's comments and formatting.
fn remove_toml_server(manifest: &mut Manifest, p: &Path) -> Result<()> {
    let recorded = manifest.recorded(p);
    if toml_server_state(p)? {
        let mut doc = read_toml(p)?;
        let item = doc.get_mut("mcp_servers").and_then(|s| s.as_table_like_mut()).and_then(|s| s.remove("tokenstash"));
        if let (Some(item), false) = (item, recorded) {
            let mut snip = toml_edit::DocumentMut::new();
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            t.insert("tokenstash", item);
            snip.insert("mcp_servers", toml_edit::Item::Table(t));
            manifest.entries.push(Removed { file: p.to_path_buf(), key: "mcp_servers".into(), value: snip.to_string() });
            manifest.save()?;
        }
        let out = doc.to_string();
        let back: toml::Value = toml::from_str(&out).map_err(|e| anyhow::anyhow!("refusing to write {}: result would not parse ({e})", p.display()))?;
        if back.get("mcp_servers").and_then(|m| m.get("tokenstash")).is_some() {
            anyhow::bail!("refusing to write {}: could not take the tokenstash entry out cleanly; edit it by hand", p.display());
        }
        write_file(p, &out)?;
        println!("✓ Codex: MCP server removed from {}", p.display());
    }
    if recorded { manifest.retire(p)?; }
    Ok(())
}

pub fn init(a: InitArgs) -> Result<i32> {
    let env_home = std::env::var("TOKENSTASH_HOME").ok().filter(|h| !h.is_empty());
    if a.print_snippet {
        anyhow::bail!("--print-snippet is retired: tokenstash no longer writes AGENTS.md sections. The skill documents the CLI; `tokenstash init --print-skill` prints it");
    }
    // Printing follows the mode chosen for this machine unless one is named, so text
    // redirected into a file by hand is the text init would have written.
    if a.print_skill {
        let mode = match a.mode { Some(m) => m.into(), None => Config::load()?.agent_mode };
        print!("{}", skill_text(mode, Target::Claude, env_home.as_deref()));
        return Ok(0);
    }
    if a.mcp && a.mode == Some(Mode::Explicit) {
        anyhow::bail!("explicit mode has no MCP server: with one registered, the agent calls tokenstash on its own. Use `tokenstash init --mode auto --mcp`, or leave out --mcp");
    }
    // Undo restores what init found; the mode and the MCP server decide how agents reach
    // tokenstash. All three are the person's call: asked for from an agent's shell, each
    // becomes a card the person confirms in their inbox.
    if (a.undo || a.mode.is_some() || a.mcp || a.no_mcp) && !crate::util::looks_human() {
        return request_choice(&a);
    }
    if a.undo {
        crate::util::require_human("init --undo", "it puts agent wiring back the way init found it")?;
        return undo();
    }
    if a.mode.is_some() {
        crate::util::require_human("init --mode", "how agents reach tokenstash is your decision")?;
    }
    if a.mcp || a.no_mcp {
        crate::util::require_human("init --mcp", "it registers this binary as every agent's MCP server")?;
    }
    let mut cfg = Config::load()?;
    let fresh = !Config::exists();
    let mode: AgentMode = a.mode.map(Into::into).unwrap_or(cfg.agent_mode);
    if a.mcp && mode == AgentMode::Explicit {
        anyhow::bail!("explicit mode has no MCP server: with one registered, the agent calls tokenstash on its own. Use `tokenstash init --mode auto --mcp`, or leave out --mcp");
    }
    let mut manifest = Manifest::load()?;

    // 1. stash backend: probe and pin it so later calls don't re-probe
    let stash = tokenstash_core::stash::open(&cfg)?;
    let backend = stash.backend();
    if cfg.stash_backend.is_none() && backend != "insecure-file" {
        cfg.stash_backend = Some(match backend { "secret-service" | "os-keychain" => "keyring".into(), b => b.into() });
    }
    println!("✓ stash backend: {backend}{}", stash.note().map(|n| format!("  ({n})")).unwrap_or_default());

    // 2. trust: nothing is inferred and nothing is added. The first time a directory asks
    // for stored keys the human approves exactly which ones; that is the whole model.
    // The mode and the MCP choice are remembered here too, so a later plain `init` keeps them.
    // Only what this command line chose is written. The rest is read again under the lock,
    // so a mode or MCP card the person confirmed while init probed the stash stands.
    let before = cfg.agent_mode;
    let pinned = cfg.stash_backend.clone();
    cfg = Config::update(|c| {
        if c.stash_backend.is_none() { c.stash_backend = pinned; }
        choose(c, a.mode, a.mcp, a.no_mcp)?;
        Ok(c.clone())
    })?;
    let mode = cfg.agent_mode;
    let switched = !fresh && mode != before;
    tokenstash_core::Db::open_default()?;
    if !a.trust.is_empty() {
        println!("! --trust is retired: directories are not trusted by folder any more. The first stored key a directory asks for shows you one card; approve it and those keys are silent there.");
    }
    if !cfg.trust_roots.is_empty() {
        println!("! trust_roots in config.toml no longer apply (retired in 0.2); `tokenstash trust rm <dir>` tidies them");
    }
    println!("✓ trust: each directory pairs once (`tokenstash workspaces` lists them)");
    println!("✓ agent mode: {}", describe_mode(mode));
    if a.project {
        println!("! --project is retired: tokenstash no longer writes AGENTS.md sections, and init takes out the ones it wrote");
    }

    // 3. agents
    let mut touched: Vec<PathBuf> = vec![];
    if !a.no_agents {
        let home = dirs::home_dir().unwrap_or_default();
        // An agent runs tokenstash from its own environment, not this shell's. If this init
        // runs against a non-default TOKENSTASH_HOME, the skill names it (and any MCP
        // registration carries it), or the agent and this shell use two different homes.
        let w = Wiring { home, exe: std::env::current_exe()?.display().to_string(), ts_home: env_home, claude_cli: which("claude") };
        if let Some(h) = &w.ts_home {
            println!("  (the skill tells agents to use TOKENSTASH_HOME={h}, the home this shell uses)");
        }
        // Registering the server points every future agent session at this binary. Run by an
        // agent from a hostile checkout (`cargo build && ./target/debug/tokenstash init`) that
        // would be a binary that hands values to the model, so it stays a person's call. The
        // skill is fixed text naming no binary, and taking the server out only narrows what
        // an agent can reach, so anyone may do those.
        let mcp = if !cfg.mcp {
            Some(false)
        } else if crate::util::looks_human() {
            Some(true)
        } else {
            println!("! the MCP registrations were left as they are: registering this binary as every agent's MCP server is for a person at a terminal");
            None
        };
        touched = wire(&mut manifest, &w, mode, mcp)?;
    }

    if !touched.is_empty() {
        println!("\nWritten outside {} (undo with `tokenstash init --undo`):", tokenstash_core::config::config_dir().display());
        for t in &touched { println!("    {}", t.display()); }
        if switched || cfg.mcp || tokenstash_core::project::detect_agent() != "unknown" {
            println!("\nRestart any open agent session: agents read their skills and MCP servers when a session starts.");
        }
    }

    println!("\nKeys are re-checked with their provider before an agent gets them (once a day, one free read-only request, verify_every in config.toml) so a revoked key becomes a Replace card instead of a 401.");
    if fresh {
        match mode {
            AgentMode::Auto => println!("\nNext: ask your agent for something that needs an API key. It runs `tokenstash need NAME`, and you answer on a card in your browser."),
            AgentMode::Explicit => println!("\nNext: in your agent, type   /tokenstash OPENAI_API_KEY   ($tokenstash in Codex)"),
        }
    }
    Ok(0)
}

/// An agent asked to change how agents reach tokenstash: one card per change, for the person
/// to confirm in their inbox. Nothing changes until they do.
fn request_choice(a: &InitArgs) -> Result<i32> {
    use tokenstash_core::actions::Action;
    if a.no_agents {
        // A confirmed card re-wires the agents; "remember the choice but leave the agents
        // alone" is not something a card can carry, so it stays a person's command.
        anyhow::bail!("`--no-agents` with --mode, --mcp or --undo is for a person at a terminal; leave it out to file the card");
    }
    let app = crate::util::App::open()?;
    let project = tokenstash_core::project::current();
    let agent = crate::util::agent_from(&None);
    let mut asked = vec![];
    if a.undo {
        asked.push(Action::Undo);
    } else {
        if let Some(m) = a.mode {
            asked.push(Action::Mode(match m { Mode::Auto => "auto", Mode::Explicit => "explicit" }.into()));
        }
        if a.mcp {
            asked.push(Action::Mcp(true));
        } else if a.no_mcp {
            asked.push(Action::Mcp(false));
        }
    }
    let mut code = 0;
    for action in &asked {
        code = crate::cmd::actions::request(&app, &project, &agent, action, a.why.clone())?;
    }
    Ok(code)
}

/// What `init`'s flags change in the config as it is now: the mode only with `--mode`, the
/// MCP choice only with `--mcp` or `--no-mcp` (or explicit mode, which has no server).
fn choose(c: &mut Config, mode: Option<Mode>, mcp: bool, no_mcp: bool) -> Result<()> {
    if let Some(m) = mode { c.agent_mode = m.into(); }
    if mcp && c.agent_mode == AgentMode::Explicit {
        anyhow::bail!("explicit mode has no MCP server: with one registered, the agent calls tokenstash on its own. Use `tokenstash init --mode auto --mcp`, or leave out --mcp");
    }
    if mcp { c.mcp = true; } else if no_mcp || c.agent_mode == AgentMode::Explicit { c.mcp = false; }
    Ok(())
}

/// What a confirmed action card changes: the mode or the MCP server. The person decided on
/// the card in their inbox, so this does what `init --mode` or `init --mcp` does at their
/// terminal, for the binary that serves the inbox.
pub fn apply_choice(mode: Option<AgentMode>, mcp: Option<bool>) -> Result<()> {
    let mut manifest = Manifest::load()?;
    let cfg = Config::update(|cfg| {
        if let Some(m) = mode {
            cfg.agent_mode = m;
            if m == AgentMode::Explicit {
                cfg.mcp = false;
            }
        }
        if let Some(on) = mcp {
            if on && cfg.agent_mode == AgentMode::Explicit {
                anyhow::bail!("explicit mode has no MCP server: switch to auto mode first");
            }
            cfg.mcp = on;
        }
        Ok(cfg.clone())
    })?;
    let w = Wiring {
        home: dirs::home_dir().unwrap_or_default(),
        exe: std::env::current_exe()?.display().to_string(),
        ts_home: std::env::var("TOKENSTASH_HOME").ok().filter(|h| !h.is_empty()),
        claude_cli: which("claude"),
    };
    wire(&mut manifest, &w, cfg.agent_mode, Some(cfg.mcp))?;
    Ok(())
}

/// `init --undo` for a confirmed card. True when everything was put back.
pub fn undo_quietly() -> Result<bool> {
    Ok(undo()? == 0)
}

/// Install the skill for `mode` and take out what earlier versions installed instead.
/// `mcp`: register the MCP server (`Some(true)`), take it out (`Some(false)`), or leave the
/// registrations as they are (`None`).
fn wire(manifest: &mut Manifest, w: &Wiring, mode: AgentMode, mcp: Option<bool>) -> Result<Vec<PathBuf>> {
    retire_legacy(manifest, w)?;
    let mut touched = install_skills(manifest, w, mode)?;
    match mcp {
        Some(true) => touched.extend(register_mcp(manifest, w)?),
        Some(false) => unregister_mcp(manifest, w)?,
        None => {}
    }
    Ok(touched)
}

pub fn describe_mode(mode: AgentMode) -> &'static str {
    match mode {
        AgentMode::Auto => "auto: agents load the tokenstash skill when code needs a key",
        AgentMode::Explicit => "explicit: agents load the tokenstash skill only when you invoke it (/tokenstash, or $tokenstash in Codex)",
    }
}

/// What is installed for one agent, read from the files rather than the manifest, so wiring
/// done by hand shows too.
#[derive(Debug, PartialEq, Eq)]
pub struct Installed {
    pub agent: &'static str,
    pub skill: Option<AgentMode>,
    pub mcp: bool,
    /// What an earlier version installed and this one takes out.
    pub legacy: Vec<&'static str>,
}

impl Installed {
    /// Where this agent's wiring disagrees with what config.toml chose.
    pub fn problems(&self, mode: AgentMode, mcp: bool) -> Vec<String> {
        let mut out = vec![];
        if self.skill.is_none() {
            out.push(format!("{}: no tokenstash skill, so the agent has no instructions for the CLI", self.agent));
        }
        if let Some(m) = self.skill.filter(|m| *m != mode) {
            out.push(format!("{}: the skill is in {m} mode, config.toml says {mode}", self.agent));
        }
        if self.mcp != mcp {
            out.push(format!("{}: {}", self.agent, if self.mcp { "an MCP server is registered, config.toml says none" } else { "no MCP server, config.toml says mcp = true" }));
        }
        if !self.legacy.is_empty() {
            out.push(format!("{}: left over from an earlier version: {}", self.agent, self.legacy.join(", ")));
        }
        out
    }
}

impl std::fmt::Display for Installed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = vec![];
        if let Some(m) = self.skill { parts.push(format!("skill: {m}")); }
        if self.mcp { parts.push("mcp".into()); }
        parts.extend(self.legacy.iter().map(|l| format!("old {l}")));
        write!(f, "{} ({})", self.agent, parts.join(", "))
    }
}

/// The skill's mode in `dir`: explicit when Claude Code's and Cursor's frontmatter flag says
/// so, or, for the copy Codex reads (`codex`), when its policy file turns implicit loading off.
fn skill_mode(dir: &Path, codex: bool) -> Option<AgentMode> {
    let s = fs::read_to_string(dir.join("SKILL.md")).ok()?;
    let explicit = if codex {
        fs::read_to_string(dir.join(CODEX_POLICY)).map(|p| p.contains("allow_implicit_invocation: false")).unwrap_or(false)
    } else {
        frontmatter(&s).contains("disable-model-invocation: true")
    };
    Some(if explicit { AgentMode::Explicit } else { AgentMode::Auto })
}

/// What is installed for each agent on this machine, for `doctor`. An agent with nothing
/// installed is left out.
pub fn installed(home: &Path) -> Vec<Installed> {
    let shared = skill_mode(&home.join(".agents/skills/tokenstash"), true);
    let mut codex_legacy = vec![];
    if has_snippet(&home.join(".codex/AGENTS.md")) { codex_legacy.push("AGENTS.md section"); }
    // The 0.3 commands told the agent to run `tokenstash need`; a file of the same name that
    // does not is the user's own.
    let ours = |p: &str| fs::read_to_string(home.join(p)).map(|s| s.contains("tokenstash need")).unwrap_or(false);
    if ours(".codex/prompts/tokenstash.md") { codex_legacy.push("prompt"); }
    let mut gemini_legacy = vec![];
    if ours(".gemini/commands/tokenstash.toml") { gemini_legacy.push("command"); }
    let all = [
        Installed { agent: "claude-code", skill: skill_mode(&home.join(".claude/skills/tokenstash"), false), mcp: json_has_server(&home.join(".claude.json"), true), legacy: vec![] },
        Installed { agent: "codex", skill: shared.filter(|_| home.join(".codex").is_dir()), mcp: toml_has_server(&home.join(".codex/config.toml")), legacy: codex_legacy },
        Installed { agent: "cursor", skill: skill_mode(&home.join(".cursor/skills/tokenstash"), false), mcp: json_has_server(&home.join(".cursor/mcp.json"), false), legacy: vec![] },
        Installed { agent: "gemini-cli", skill: shared.filter(|_| home.join(".gemini").is_dir()), mcp: json_has_server(&home.join(".gemini/settings.json"), false), legacy: gemini_legacy },
    ];
    all.into_iter().filter(|i| i.skill.is_some() || i.mcp || !i.legacy.is_empty()).collect()
}

/// Set `mcp_servers.tokenstash` in Codex's config.toml with `toml_edit`, which preserves
/// the user's comments and formatting and understands every header spelling (quoted keys,
/// whitespace, inline tables, nested subtables) — an earlier line-scanning version got a
/// steady stream of those wrong. An existing entry is replaced wholesale so the env
/// (TOKENSTASH_HOME) is current. If the file cannot be parsed it is left untouched.
fn merge_codex_toml(p: &Path, exe: &str, ts_home: Option<&str>) -> Result<serde_json::Value> {
    let mut doc = read_toml(p)?;
    let servers = doc.entry("mcp_servers").or_insert(toml_edit::table());
    let Some(servers) = servers.as_table_like_mut() else {
        anyhow::bail!("{}: mcp_servers is not a table; add the MCP server by hand", p.display());
    };
    let mut entry = toml_edit::Table::new();
    entry.insert("command", toml_edit::value(exe));
    let mut args = toml_edit::Array::new();
    args.push("mcp");
    entry.insert("args", toml_edit::value(args));
    if let Some(h) = ts_home {
        let mut env = toml_edit::InlineTable::new();
        env.insert("TOKENSTASH_HOME", h.into());
        entry.insert("env", toml_edit::value(env));
    }
    servers.insert("tokenstash", toml_edit::Item::Table(entry));
    let out = doc.to_string();
    // Belt and braces: the result must parse back with exactly our command.
    let back: toml::Value = toml::from_str(&out).map_err(|e| anyhow::anyhow!("refusing to write {}: result would not parse ({e})", p.display()))?;
    let Some(ours) = back.get("mcp_servers").and_then(|m| m.get("tokenstash")).filter(|t| t.get("command").and_then(|c| c.as_str()) == Some(exe)) else {
        anyhow::bail!("refusing to write {}: could not set the tokenstash entry cleanly; edit it by hand", p.display());
    };
    let ours = serde_json::to_value(ours)?;
    if let Some(parent) = p.parent() { fs::create_dir_all(parent)?; }
    write_file(p, &out)?;
    Ok(ours)
}

fn read_toml(p: &Path) -> Result<toml_edit::DocumentMut> {
    let existing = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    existing.parse().map_err(|e| anyhow::anyhow!("{} is not valid TOML ({e}); fix it or add the MCP server by hand", p.display()))
}

/// Whether Codex's config holds a tokenstash entry. `Ok(false)` for a missing file; an
/// unreadable or unparseable one is an error, not an absence — bookkeeping that treated it as
/// one would give up records over a file whose state is unknown.
fn toml_server_state(p: &Path) -> Result<bool> {
    let s = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", p.display())),
    };
    let d: toml_edit::DocumentMut = s.parse().map_err(|e| anyhow::anyhow!("{} is not valid TOML ({e}); fix it or take the MCP server out by hand", p.display()))?;
    Ok(d.get("mcp_servers").and_then(|m| m.get("tokenstash")).is_some())
}

/// For display (`doctor`): unknown reads as absent.
fn toml_has_server(p: &Path) -> bool { toml_server_state(p).unwrap_or(false) }

/// Add `mcpServers.tokenstash` to a JSON config owned by another tool. If the file exists
/// but cannot be parsed as a JSON object, refuse rather than replace it.
fn merge_mcp_json(p: &Path, exe: &str, ts_home: Option<&str>) -> Result<serde_json::Value> {
    merge_mcp_json_typed(p, exe, false, ts_home)
}

/// Same, with `"type": "stdio"` — the shape Claude Code writes into `~/.claude.json`.
/// Returns the entry written.
fn merge_mcp_json_typed(p: &Path, exe: &str, typed: bool, ts_home: Option<&str>) -> Result<serde_json::Value> {
    let mut v = read_json(p)?;
    let root = v.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} root is not a JSON object", p.display()))?;
    let servers = root.entry("mcpServers").or_insert(serde_json::json!({}));
    let m = servers.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} has a non-object mcpServers", p.display()))?;
    let mut entry = if typed { serde_json::json!({ "type": "stdio", "command": exe, "args": ["mcp"] }) } else { serde_json::json!({ "command": exe, "args": ["mcp"] }) };
    if let Some(h) = ts_home {
        entry["env"] = serde_json::json!({ "TOKENSTASH_HOME": h });
    }
    m.insert("tokenstash".into(), entry.clone());
    if let Some(parent) = p.parent() { fs::create_dir_all(parent)?; }
    write_file(p, &serde_json::to_string_pretty(&v)?)?;
    Ok(entry)
}

fn read_json(p: &Path) -> Result<serde_json::Value> {
    Ok(match fs::read_to_string(p) {
        Ok(s) if s.trim().is_empty() => serde_json::json!({}),
        Ok(s) => serde_json::from_str(&s).map_err(|e| anyhow::anyhow!("{} is not valid JSON ({e}); fix it or add the MCP server by hand", p.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => return Err(e.into()),
    })
}

/// A tokenstash entry under `mcpServers`, or — `~/.claude.json`, where `claude mcp add`
/// without `-s user` puts it — under any project's `mcpServers`. Same contract as
/// [`toml_server_state`]: unknown is an error, not an absence.
fn json_server_state(p: &Path, claude: bool) -> Result<bool> {
    let s = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", p.display())),
    };
    if s.trim().is_empty() { return Ok(false); }
    let v: serde_json::Value = serde_json::from_str(&s).map_err(|e| anyhow::anyhow!("{} is not valid JSON ({e}); fix it or take the MCP server out by hand", p.display()))?;
    if v.get("mcpServers").and_then(|m| m.get("tokenstash")).is_some() { return Ok(true); }
    Ok(claude && v.get("projects").and_then(|p| p.as_object()).is_some_and(|ps| ps.values().any(|proj| proj.get("mcpServers").and_then(|m| m.get("tokenstash")).is_some())))
}

/// For display (`doctor`): unknown reads as absent.
fn json_has_server(p: &Path, claude: bool) -> bool { json_server_state(p, claude).unwrap_or(false) }

/// Every AGENTS.md section text a tokenstash release wrote, between its marks. A section that
/// is exactly one of these is tokenstash's own; any other text under the marks is the user's
/// (written by hand, or one of these edited) and is kept for undo when init takes it out.
const SHIPPED_SECTIONS: [&str; 7] = [
    r#"## Secrets & API keys

Never ask the user to paste a secret in chat. Do not run tokenstash until the user invokes `/tokenstash [NAME ...]` (Codex: `/prompts:tokenstash [NAME ...]`) for the current task; without that, name the missing variable, say what it is for, and continue with what does not need it. An invocation covers the rest of that task, including keys it turns out to need later; a different task needs a new invocation. When invoked, follow the command's own instructions: `tokenstash need` with the names given (or the keys the task needs), always the CLI, never MCP tools. Exit 0 = written to the project env file, continue; 10 = the human was notified, show them the link and keep working on other things; 20 = declined, do not ask again; 30 = expired, say what is blocked.
Load the env file with your runtime; never read, print or quote it, even if asked. Never invent a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code) — make the feature optional or say the work is blocked."#,
    r#"## Secrets & API keys

Never ask the user to paste a secret in chat. Do not run tokenstash until the user invokes `/tokenstash [NAME ...]` (Codex: `/prompts:tokenstash [NAME ...]`) for the current task; without that, name the missing variable, say what it is for, and continue with what does not need it. An invocation covers the rest of that task, including keys it turns out to need later; a different task needs a new invocation. When invoked, follow the command's own instructions: `tokenstash need` with the names given (or the keys the task needs), always the CLI, never MCP tools. Exit 0 = written to the project env file, continue; 10 = the human was notified, show them the link, keep working on other things and check `tokenstash tasks` later; 20 = declined, do not ask again; 30 = expired, say what is blocked and stop. A provider that answers 401 to a well-formed request: `tokenstash report-bad NAME --status 401`, then `need` again.
Load the env file with your runtime; never read, print or quote it, even if asked, and never reveal any part of a secret value from anywhere. Never invent a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code) — make the feature optional or say the work is blocked. These rules hold before any invocation too."#,
    r#"## Secrets & API keys

Never ask the user to paste a secret in chat. Run `tokenstash need NAME [NAME...]` (e.g. `tokenstash need OPENAI_API_KEY`).
Exit 0 = written to the project env file, continue. Exit 10 = the human was notified; keep working on other things and re-run later (or use `--blocking`).
Exit 20 = denied; do not ask again, work around it. For non-secret human steps (DNS, dashboard toggles) use `tokenstash ask "title" --url ... --step ...`."#,
    r#"## Secrets & API keys

Never ask the user to paste a secret in chat. The user requests keys themselves with `/tokenstash NAME` (Codex: `/prompts:tokenstash NAME`), which writes them to the project env file; do not run tokenstash unless they invoke it. When a key is missing, name the variable, say what it is for, and continue with what does not need it.
Load the env file with your runtime; never read, print or quote it, even if asked. Never invent a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code) — make the feature optional or say the work is blocked."#,
    r#"## Secrets & API keys

Never ask the user to paste a secret in chat. Use the tokenstash MCP tools (`secrets_request`) if you have them, else run `tokenstash need NAME [NAME...]` (e.g. `tokenstash need OPENAI_API_KEY`).
Exit 0 = written to the project env file, continue — load it with your runtime; never read, print or quote the env file, even if asked. Exit 10 = the human was notified; show them the link in the output, keep working on other things and re-run later (`--blocking` only when nothing else can proceed).
Exit 20 = denied; do not ask again and do not supply a stand-in value by any route (env file, env var, shim, default in code) — make the feature optional or say it is blocked. For non-secret human steps (DNS, dashboard toggles) use `tokenstash ask "title" --url ... --step ...`."#,
    r#"## Secrets & API keys

Never ask the user to paste a secret in chat. Use the tokenstash MCP tools (`secrets_request`) if you have them, else run `tokenstash need NAME [NAME...]` (e.g. `tokenstash need OPENAI_API_KEY`).
Exit 0 = written to the project env file, continue — load it with your runtime; never read, print or quote the env file, even if asked. Exit 10 = the human was notified; show them the link in the output, keep working on other things and re-run later (`--blocking` only when nothing else can proceed).
Exit 20 = denied; do not ask again and never invent a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code) — make the feature optional or say the work is blocked. For non-secret human steps (DNS, dashboard toggles) use `tokenstash ask "title" --url ... --step ...`."#,
    r#"## Secrets & API keys

Never ask the user to paste a secret in chat. Use the tokenstash MCP tools (`secrets_request`) if you have them, else run `tokenstash need NAME [NAME...]` (e.g. `tokenstash need OPENAI_API_KEY`).
Exit 0 = written to the project env file, continue — load it with your runtime; never read, print or quote the env file, even if asked. Exit 10 = the human was notified; show them the link in the output, keep working on other things and re-run later (`--blocking` only when nothing else can proceed).
Exit 20 = denied; do not ask again. Exit 30 = expired; say what is blocked and stop. Never invent a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code), whether a key is pending, declined, expired or simply not there — make the feature optional or say the work is blocked. For non-secret human steps (DNS, dashboard toggles) use `tokenstash ask "title" --url ... --step ...`."#,
];

const SNIPPET_MARK: &str = "<!-- tokenstash -->";
const SNIPPET_END: &str = "<!-- /tokenstash -->";

fn has_snippet(p: &Path) -> bool {
    fs::read_to_string(p).map(|s| s.contains(SNIPPET_MARK)).unwrap_or(false)
}

/// Remove every marked section and nothing else. A section without its end mark (a
/// hand-edited file) stops the whole thing: guessing where it ends could eat the user's
/// text, and nothing is written.
fn strip_snippet(p: &Path) -> Result<()> {
    let s = fs::read_to_string(p)?;
    let out = strip_sections(&s).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
    write_file(p, &out)
}

/// The text without its marked sections. A section without its end mark (a hand-edited
/// file) is an error: guessing where it ends could eat the user's text.
fn strip_sections(text: &str) -> Result<String> {
    strip_sections_where(text, |_| true)
}

/// [`strip_sections`] for the sections `take` picks (each given with its marks); the others
/// stay exactly as they are.
fn strip_sections_where(text: &str, take: impl Fn(&str) -> bool) -> Result<String> {
    let mut s = text.to_string();
    let mut from = 0;
    while let Some(rel) = s[from..].find(SNIPPET_MARK) {
        let start = from + rel;
        let Some(end_rel) = s[start..].find(SNIPPET_END) else {
            anyhow::bail!("a tokenstash section has no closing `{SNIPPET_END}`; remove it by hand");
        };
        let mut end = start + end_rel + SNIPPET_END.len();
        if !take(&s[start..end]) {
            from = end;
            continue;
        }
        if s[end..].starts_with('\n') { end += 1; }
        // The blank line set_snippet put before the section goes with it; so does one that
        // separated a section at the top of the file from the text under it.
        let mut start = start;
        if s[..start].ends_with("\n\n") { start -= 1; } else if start == 0 && s[end..].starts_with('\n') { end += 1; }
        s = format!("{}{}", &s[..start], &s[end..]);
    }
    Ok(s)
}

fn frontmatter(skill: &str) -> &str {
    skill.strip_prefix("---\n").and_then(|rest| rest.find("\n---\n").map(|i| &rest[..i])).unwrap_or("")
}

fn body(skill: &str) -> &str {
    skill.strip_prefix("---\n").and_then(|rest| rest.find("\n---\n").map(|i| &rest[i + 5..])).unwrap_or(skill)
}

/// Which copy of the skill. Claude Code and Cursor honour `disable-model-invocation`. The
/// shared `~/.agents/skills` copy is read by Codex, whose policy lives in `agents/openai.yaml`,
/// and by Gemini CLI, which asks the person before it loads any skill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target { Claude, Agents }

/// One set of rules and one CLI description, two ways in. Auto mode's skill is `SKILL.md` as
/// shipped. Explicit mode's says it loads only on the person's invocation, and opens with
/// what the invocation covers. Everything after the title is the same text either way.
pub fn skill_text(mode: AgentMode, target: Target, ts_home: Option<&str>) -> String {
    let home = match ts_home {
        Some(h) => format!("\nThis machine keeps its stash under `TOKENSTASH_HOME={h}`: set that in the environment of every tokenstash command.\n"),
        None => String::new(),
    };
    match mode {
        AgentMode::Auto => SKILL_MD.replacen("# tokenstash\n", &format!("# tokenstash\n{home}"), 1),
        AgentMode::Explicit => {
            let (description, invoked) = match target {
                Target::Claude => (
                    "Get API keys and secrets for this project through the tokenstash CLI, without pasting them in chat. /tokenstash NAME [NAME...] requests those keys; bare /tokenstash requests what the current task needs.\ndisable-model-invocation: true",
                    "`/tokenstash $ARGUMENTS`",
                ),
                Target::Agents => (
                    "Get API keys and secrets for this project through the tokenstash CLI, without pasting them in chat. Use only when the user invokes it ($tokenstash in Codex) or asks for tokenstash by name.",
                    "`$tokenstash`, or a request for tokenstash by name",
                ),
            };
            let intro = format!(
                "# tokenstash\n\nThe user invoked this for the current task: {invoked}. Run `tokenstash need` with the key names they gave; with none, request the keys the current task needs. That invocation covers the rest of this task: keys it turns out to need later, checking on cards, steps only the user can do, replacing a rejected key. A different task needs a new invocation.\n{home}"
            );
            format!("---\nname: tokenstash\ndescription: {description}\n---\n\n{}", body(SKILL_MD).replacen("# tokenstash\n", &intro, 1).trim_start_matches('\n'))
        }
    }
}

pub fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tokenstash-init-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// A fake machine: a home with every agent's directory, and a manifest root beside it.
    fn machine(name: &str) -> (Wiring, Manifest) {
        let root = scratch(name);
        let home = root.join("home");
        for d in [".claude", ".codex", ".cursor", ".gemini"] { fs::create_dir_all(home.join(d)).unwrap(); }
        let w = Wiring { home, exe: "/opt/tokenstash".into(), ts_home: None, claude_cli: false };
        let m = Manifest::load_at(root.join("state")).unwrap();
        (w, m)
    }

    fn read(p: &Path) -> String { fs::read_to_string(p).unwrap_or_default() }
    fn write(p: &Path, s: &str) { fs::create_dir_all(p.parent().unwrap()).unwrap(); fs::write(p, s).unwrap(); }
    fn section(text: &str) -> String { format!("{SNIPPET_MARK}\n{text}\n{SNIPPET_END}\n") }
    fn lines(home: &Path) -> Vec<String> { installed(home).iter().map(|i| i.to_string()).collect() }

    const SKILL_ONLY: [&str; 4] = ["claude-code (skill: auto)", "codex (skill: auto)", "cursor (skill: auto)", "gemini-cli (skill: auto)"];
    const WITH_MCP: [&str; 4] = ["claude-code (skill: auto, mcp)", "codex (skill: auto, mcp)", "cursor (skill: auto, mcp)", "gemini-cli (skill: auto, mcp)"];
    const EXPLICIT: [&str; 4] = ["claude-code (skill: explicit)", "codex (skill: explicit)", "cursor (skill: explicit)", "gemini-cli (skill: explicit)"];

    fn mcp_files(w: &Wiring) -> [PathBuf; 4] {
        [w.claude_json(), w.codex().join("config.toml"), w.cursor().join("mcp.json"), w.gemini().join("settings.json")]
    }

    #[test]
    fn every_copy_of_the_skill_keeps_every_rule_and_names_no_mcp_tool() {
        let auto = skill_text(AgentMode::Auto, Target::Claude, None);
        assert_eq!(auto, SKILL_MD);
        assert_eq!(skill_text(AgentMode::Auto, Target::Agents, None), SKILL_MD);
        assert!(!frontmatter(&auto).contains("disable-model-invocation"));
        let claude = skill_text(AgentMode::Explicit, Target::Claude, None);
        assert!(frontmatter(&claude).starts_with("name: tokenstash\n") && frontmatter(&claude).contains("\ndisable-model-invocation: true"), "{claude}");
        assert!(claude.contains("`/tokenstash $ARGUMENTS`") && claude.contains("A different task needs a new invocation"));
        let agents = skill_text(AgentMode::Explicit, Target::Agents, None);
        assert!(!frontmatter(&agents).contains("disable-model-invocation"), "Codex reads its policy from agents/openai.yaml");
        assert!(frontmatter(&agents).contains("$tokenstash") && !agents.contains("$ARGUMENTS"), "{agents}");
        for text in [&auto, &claude, &agents] {
            for rule in ["## Rules", "Never ask the user to paste", "Never read the env file", "Never invent a stand-in value", "| 20 | The user declined", "## When a provider rejects a key", "tokenstash report-bad", "## Steps only the user can do", "reference.md", "troubleshooting.md"] {
                assert!(text.contains(rule), "{rule}");
            }
            for mcp in ["secrets_request", "task_check", "MCP tools"] {
                assert!(!text.contains(mcp), "the skill documents the CLI: {mcp}");
            }
        }
        // Everything after the title is the same text in every mode.
        let after_rules = &SKILL_MD[SKILL_MD.find("## Rules").unwrap()..];
        assert!(claude.ends_with(after_rules) && agents.ends_with(after_rules));
        for mode in [AgentMode::Auto, AgentMode::Explicit] {
            assert!(!skill_text(mode, Target::Claude, None).contains("TOKENSTASH_HOME"));
            let homed = skill_text(mode, Target::Agents, Some("/srv/ts"));
            assert!(homed.contains("`TOKENSTASH_HOME=/srv/ts`: set that in the environment of every tokenstash command"), "{homed}");
        }
    }

    #[test]
    fn auto_mode_installs_the_skill_everywhere_and_nothing_else() {
        let (w, mut m) = machine("auto");
        let touched = wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert_eq!(touched, vec![w.claude_skill_dir(), w.agents_skill_dir(), w.cursor_skill_dir()]);
        for d in [w.claude_skill_dir(), w.agents_skill_dir(), w.cursor_skill_dir()] {
            assert_eq!(read(&d.join("SKILL.md")), SKILL_MD);
            for (name, text) in SKILL_FILES { assert_eq!(read(&d.join(name)), text, "{}", d.display()); }
            assert!(!d.join(CODEX_POLICY).exists());
        }
        for absent in mcp_files(&w).into_iter().chain([w.codex_agents(), w.codex_prompt(), w.gemini_command()]) {
            assert!(!absent.exists(), "auto mode must not write {}", absent.display());
        }
        assert_eq!(lines(&w.home), SKILL_ONLY);
    }

    #[test]
    fn explicit_mode_marks_each_copy_user_only() {
        let (w, mut m) = machine("explicit");
        wire(&mut m, &w, AgentMode::Explicit, Some(false)).unwrap();
        assert!(read(&w.claude_skill_dir().join("SKILL.md")).contains("disable-model-invocation: true"));
        assert!(read(&w.cursor_skill_dir().join("SKILL.md")).contains("disable-model-invocation: true"));
        assert_eq!(read(&w.agents_skill_dir().join(CODEX_POLICY)), CODEX_EXPLICIT);
        for absent in mcp_files(&w) { assert!(!absent.exists(), "{}", absent.display()); }
        assert_eq!(lines(&w.home), EXPLICIT);
        // Back to auto: the policy file init wrote goes, and its directory with it.
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert!(!w.agents_skill_dir().join("agents").exists());
        assert_eq!(lines(&w.home), SKILL_ONLY);
        assert!(!m.files.iter().any(|(p, _)| p.ends_with(CODEX_POLICY)));
    }

    /// `--mcp` registers the server with every agent; turning it off takes init's entries
    /// out, leaves the user's other entries exactly as they were, and removes files init
    /// created for the server alone.
    #[test]
    fn the_mcp_server_comes_and_goes_and_the_users_entries_stay() {
        let (w, mut m) = machine("mcp");
        let codex_toml = "# mine\nmodel = \"o3\"\n\n[mcp_servers.github]\ncommand = \"gh-mcp\"\n";
        write(&w.codex().join("config.toml"), codex_toml);
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"}}}");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        assert!(json_has_server(&w.claude_json(), true) && toml_has_server(&w.codex().join("config.toml")));
        assert!(json_has_server(&w.cursor().join("mcp.json"), false) && json_has_server(&w.gemini().join("settings.json"), false));
        assert_eq!(lines(&w.home), WITH_MCP);

        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert!(!w.claude_json().exists() && !w.gemini().join("settings.json").exists(), "created for the server alone");
        assert!(read(&w.cursor().join("mcp.json")).contains("gh-mcp") && !json_has_server(&w.cursor().join("mcp.json"), false));
        assert_eq!(read(&w.codex().join("config.toml")), codex_toml, "only the tokenstash entry leaves");
        assert_eq!(lines(&w.home), SKILL_ONLY);
        // No shared config keeps a whole-file record once init's entry is out: an undo after
        // the user edits it must not restore a stale copy.
        for p in mcp_files(&w) { assert!(!m.recorded(&p), "{} still recorded: {:?}", p.display(), m.files); }
        assert!(m.entries.is_empty(), "nothing foreign was removed: {:?}", m.entries);
        // Leaving the registrations alone (`None`) touches none of them.
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        wire(&mut m, &w, AgentMode::Auto, None).unwrap();
        assert_eq!(lines(&w.home), WITH_MCP);
    }

    /// What 0.3 installed (the global Codex section, a project section, the explicit-mode
    /// prompt and command) is taken out; the user's own text around it stays, and a file of
    /// theirs that an old init replaced comes back.
    #[test]
    fn what_earlier_versions_installed_is_taken_out() {
        let (w, mut m) = machine("legacy");
        write(&w.codex_agents(), "# My rules\n\nBe brief.\n");
        let cagents = w.codex_agents();
        m.mutate(&cagents, || { fs::write(&cagents, format!("# My rules\n\nBe brief.\n\n{}", section(SHIPPED_SECTIONS[0])))?; Ok(()) }).unwrap();
        let proj = scratch("legacy-app").join("AGENTS.md");
        write(&proj, "# App\n");
        m.mutate(&proj, || { fs::write(&proj, format!("# App\n\n{}", section(SHIPPED_SECTIONS[1])))?; Ok(()) }).unwrap();
        write(&w.codex_prompt(), "my own prompt");
        let prompt = w.codex_prompt();
        m.mutate(&prompt, || { fs::write(&prompt, "---\ndescription: tokenstash\n---\n\nRun `tokenstash need` with the names given.\n")?; Ok(()) }).unwrap();
        let command = w.gemini_command();
        m.mutate(&command, || { write(&command, "prompt = \"Run `tokenstash need` with the names given.\"\n"); Ok(()) }).unwrap();
        assert!(lines(&w.home).iter().any(|l| l.contains("old AGENTS.md section") && l.contains("old prompt")), "{:?}", lines(&w.home));

        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert_eq!(read(&w.codex_agents()), "# My rules\n\nBe brief.\n");
        assert_eq!(read(&proj), "# App\n");
        assert_eq!(read(&w.codex_prompt()), "my own prompt", "the user's file an old init replaced comes back");
        assert!(!w.gemini_command().exists());
        assert_eq!(lines(&w.home), SKILL_ONLY);
        assert!(m.entries.is_empty(), "the sections were init's own: undo must not bring them back: {:?}", m.entries);
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert_eq!(read(&w.codex_agents()), "# My rules\n\nBe brief.\n");
        assert_eq!(read(&proj), "# App\n");
    }

    /// Whatever the history, undo puts the machine back as init found it.
    #[test]
    fn undo_after_switching_restores_the_original_files() {
        let (w, mut m) = machine("undo");
        let codex_toml = "[mcp_servers.github]\ncommand = \"gh-mcp\"\n";
        write(&w.codex().join("config.toml"), codex_toml);
        write(&w.home.join(".agents/skills/other/SKILL.md"), "keep");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        wire(&mut m, &w, AgentMode::Explicit, Some(false)).unwrap();
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        wire(&mut m, &w, AgentMode::Explicit, Some(false)).unwrap();
        let root = m.root.clone();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert!(!root.join("init.manifest.json").exists());
        assert_eq!(read(&w.codex().join("config.toml")), codex_toml);
        for gone in [w.claude_skill_dir(), w.agents_skill_dir(), w.cursor_skill_dir(), w.claude_json(), w.codex_agents(), w.cursor().join("mcp.json"), w.gemini().join("settings.json")] {
            assert!(!gone.exists(), "{} should be gone", gone.display());
        }
        assert_eq!(read(&w.home.join(".agents/skills/other/SKILL.md")), "keep", "the shared skills dir is not init's");
        assert!(installed(&w.home).is_empty());
    }

    /// Astra: a whole-file record kept after the server is taken out turns a later undo into
    /// a delete or a stale restore over whatever the user put in the file, before or after.
    #[test]
    fn the_users_edits_before_and_after_the_switch_survive_undo() {
        let (w, mut m) = machine("edit-around");
        let original = "[mcp_servers.github]\ncommand = \"gh-mcp\"\n";
        write(&w.codex().join("config.toml"), original);
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"}}}");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        // While the server is registered the user adds a server to Cursor's file and an
        // empty setting to the Gemini file init created.
        let mut cursor: serde_json::Value = serde_json::from_str(&read(&w.cursor().join("mcp.json"))).unwrap();
        cursor["mcpServers"]["linear"] = serde_json::json!({ "command": "linear-mcp" });
        write(&w.cursor().join("mcp.json"), &cursor.to_string());
        let mut gemini: serde_json::Value = serde_json::from_str(&read(&w.gemini().join("settings.json"))).unwrap();
        gemini["theme"] = serde_json::json!([]);
        write(&w.gemini().join("settings.json"), &gemini.to_string());
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert!(read(&w.cursor().join("mcp.json")).contains("linear-mcp") && !json_has_server(&w.cursor().join("mcp.json"), false));
        assert!(w.gemini().join("settings.json").exists() && read(&w.gemini().join("settings.json")).contains("theme"), "the user's addition keeps the file");
        assert!(m.files.iter().all(|(p, _)| !p.ends_with("mcp.json") && !p.ends_with("settings.json") && !p.ends_with("config.toml")), "{:?}", m.files);
        // Afterwards the user adds to Codex's config.toml.
        write(&w.codex().join("config.toml"), &format!("{original}\n[mcp_servers.linear]\ncommand = \"linear-mcp\"\n"));
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert!(read(&w.cursor().join("mcp.json")).contains("linear-mcp") && read(&w.cursor().join("mcp.json")).contains("gh-mcp"));
        assert!(read(&w.gemini().join("settings.json")).contains("theme"));
        assert!(read(&w.codex().join("config.toml")).contains("linear-mcp") && read(&w.codex().join("config.toml")).contains("gh-mcp"));
    }

    /// The user had their own registration before init; `--mcp` replaced it. Turning the
    /// server off takes init's out, and undo brings the user's back as an entry, not as a copy
    /// of the file from before init.
    #[test]
    fn a_registration_init_replaced_comes_back_as_an_entry() {
        let (w, mut m) = machine("replaced");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}");
        write(&w.codex().join("config.toml"), "[mcp_servers.tokenstash]\ncommand = \"/old/tokenstash\"\n");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        assert!(read(&w.cursor().join("mcp.json")).contains("/opt/tokenstash"));
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert!(!json_has_server(&w.cursor().join("mcp.json"), false) && !toml_has_server(&w.codex().join("config.toml")));
        assert_eq!(m.entries.len(), 2, "{:?}", m.entries);
        let mut cursor: serde_json::Value = serde_json::from_str(&read(&w.cursor().join("mcp.json"))).unwrap();
        cursor["mcpServers"]["linear"] = serde_json::json!({ "command": "linear-mcp" });
        write(&w.cursor().join("mcp.json"), &cursor.to_string());
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        let cursor: serde_json::Value = serde_json::from_str(&read(&w.cursor().join("mcp.json"))).unwrap();
        assert_eq!(cursor["mcpServers"]["tokenstash"]["command"], "/old/tokenstash");
        assert_eq!(cursor["mcpServers"]["linear"]["command"], "linear-mcp");
        let codex: toml::Value = toml::from_str(&read(&w.codex().join("config.toml"))).unwrap();
        assert_eq!(codex["mcp_servers"]["tokenstash"]["command"].as_str(), Some("/old/tokenstash"));
    }

    /// Greptile: an AGENTS.md section init wrote that the user edited since is theirs now.
    /// The backup predates the section, so the text has to be kept when it is taken out, or
    /// the edit is gone for good.
    #[test]
    fn an_edited_section_init_wrote_comes_back_on_undo() {
        let (w, mut m) = machine("edited-section");
        write(&w.codex_agents(), "# My rules\n");
        let cagents = w.codex_agents();
        m.mutate(&cagents, || { fs::write(&cagents, format!("# My rules\n\n{}", section(SHIPPED_SECTIONS[0])))?; Ok(()) }).unwrap();
        let edited = section(&format!("{}\nAlso: use the work identity for Stripe.", SHIPPED_SECTIONS[0]));
        write(&w.codex_agents(), &format!("# My rules\n\n{edited}"));
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert_eq!(read(&w.codex_agents()), "# My rules\n");
        assert!(m.entries.iter().any(|e| e.key == "section" && e.value.contains("work identity for Stripe")), "{:?}", m.entries);
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert!(read(&w.codex_agents()).contains("Also: use the work identity for Stripe."));
    }

    /// An unrecorded section holding exactly what a release shipped is an init whose record
    /// is gone (a machine set up by an old version): tokenstash's own, so undo leaves it out.
    #[test]
    fn a_shipped_section_without_a_record_does_not_come_back() {
        let (w, mut m) = machine("shipped-unrecorded");
        write(&w.codex_agents(), &format!("# Rules\n\n{}", section(SHIPPED_SECTIONS[2])));
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert_eq!(read(&w.codex_agents()), "# Rules\n");
        assert!(!m.entries.iter().any(|e| e.key == "section"), "{:?}", m.entries);
    }

    /// Greptile: a skill directory init created may since hold the user's own files, including
    /// one with the name of a file init writes elsewhere.
    #[test]
    fn a_users_file_in_a_skill_dir_init_created_is_left_alone() {
        let (w, mut m) = machine("skill-extra");
        wire(&mut m, &w, AgentMode::Explicit, Some(false)).unwrap();
        write(&w.cursor_skill_dir().join("helper.sh"), "#!/bin/sh");
        write(&w.claude_skill_dir().join("notes.md"), "mine");
        write(&w.claude_skill_dir().join(CODEX_POLICY), "mine too");
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        for d in [w.cursor_skill_dir(), w.claude_skill_dir()] {
            assert!(!d.join("SKILL.md").exists() && !d.join("reference.md").exists() && !d.join("troubleshooting.md").exists());
        }
        assert_eq!(read(&w.cursor_skill_dir().join("helper.sh")), "#!/bin/sh");
        assert_eq!(read(&w.claude_skill_dir().join("notes.md")), "mine");
        assert_eq!(read(&w.claude_skill_dir().join(CODEX_POLICY)), "mine too", "init never wrote this one");
        assert!(!w.agents_skill_dir().exists());
    }

    /// A registration the user made is removed (agents use the CLI unless the person asks for
    /// the server) and recorded as an entry, so undo puts the entry back without touching the
    /// rest of the file, including what the user changed in it since.
    #[test]
    fn a_registration_init_did_not_make_is_removed_and_undo_puts_the_entry_back() {
        let (w, mut m) = machine("foreign");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\",\"args\":[\"mcp\"]},\"github\":{\"command\":\"gh-mcp\"}}}");
        // Claude: one at user scope, one at local scope (a plain `claude mcp add` in a project).
        write(&w.claude_json(), "{\"mcpServers\":{\"tokenstash\":{\"type\":\"stdio\",\"command\":\"/old/tokenstash\",\"args\":[\"mcp\"]}},\"projects\":{\"/home/u/app\":{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\",\"args\":[\"mcp\"]},\"other\":{\"command\":\"x\"}},\"history\":[1]}}}");
        // (A comment directly above the tokenstash header is that entry's, and goes with it.)
        write(&w.codex().join("config.toml"), "# keep me\nmodel = \"o3\"\n\n# theirs\n[mcp_servers.tokenstash]\ncommand = \"/old/tokenstash\"\nargs = [\"mcp\"]\n\n[mcp_servers.github]\ncommand = \"gh-mcp\"\n");
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert!(!json_has_server(&w.cursor().join("mcp.json"), false) && !json_has_server(&w.claude_json(), true) && !toml_has_server(&w.codex().join("config.toml")));
        assert!(read(&w.cursor().join("mcp.json")).contains("gh-mcp"));
        assert!(read(&w.claude_json()).contains("\"other\"") && read(&w.claude_json()).contains("history"));
        let codex = read(&w.codex().join("config.toml"));
        assert!(codex.contains("# keep me") && codex.contains("model = \"o3\"") && codex.contains("[mcp_servers.github]") && !codex.contains("# theirs"), "{codex}");
        assert_eq!(m.entries.len(), 4, "{:?}", m.entries);
        assert!(m.files.iter().all(|(p, _)| !p.ends_with(".claude.json") && !p.ends_with("mcp.json") && !p.ends_with("config.toml")), "foreign files get entry records, not whole-file ones: {:?}", m.files);
        assert_eq!(lines(&w.home), SKILL_ONLY);
        // The user changes the files afterwards...
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"},\"linear\":{\"command\":\"linear-mcp\"}}}");
        // ...and undo brings the entries back beside those changes.
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        let cursor: serde_json::Value = serde_json::from_str(&read(&w.cursor().join("mcp.json"))).unwrap();
        assert_eq!(cursor["mcpServers"]["tokenstash"]["command"], "/old/tokenstash");
        assert_eq!(cursor["mcpServers"]["linear"]["command"], "linear-mcp");
        let claude: serde_json::Value = serde_json::from_str(&read(&w.claude_json())).unwrap();
        assert_eq!(claude["mcpServers"]["tokenstash"]["type"], "stdio");
        assert_eq!(claude["projects"]["/home/u/app"]["mcpServers"]["tokenstash"]["command"], "/old/tokenstash");
        assert_eq!(claude["projects"]["/home/u/app"]["history"][0], 1);
        let codex = read(&w.codex().join("config.toml"));
        assert!(codex.contains("# keep me") && codex.contains("# theirs") && toml_has_server(&w.codex().join("config.toml")) && codex.contains("[mcp_servers.github]"), "{codex}");
        let back: toml::Value = toml::from_str(&codex).unwrap();
        assert_eq!(back["mcp_servers"]["tokenstash"]["command"].as_str(), Some("/old/tokenstash"));
    }

    /// Astra: init registered through `claude mcp add`, and the server is taken out with the
    /// CLI gone (a desktop-only session). The entry is init's, so it just goes: no record that
    /// undo would turn back into a registration, and the CLI flag does not linger either.
    #[test]
    fn an_entry_init_registered_through_the_cli_is_not_user_data() {
        let (w, mut m) = machine("cli-owned");
        // What `claude mcp add -s user` leaves behind, plus the user's own local-scope entry.
        write(&w.claude_json(), "{\"mcpServers\":{\"tokenstash\":{\"type\":\"stdio\",\"command\":\"/opt/tokenstash\",\"args\":[\"mcp\"]}},\"projects\":{\"/home/u/app\":{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}}}");
        m.claude_mcp_registered = true;
        m.save().unwrap();
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert!(!m.claude_mcp_registered);
        assert_eq!(m.entries.len(), 1, "{:?}", m.entries);
        assert!(m.entries[0].key.starts_with("projects/"));
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        let claude: serde_json::Value = serde_json::from_str(&read(&w.claude_json())).unwrap();
        assert!(claude["mcpServers"].get("tokenstash").is_none(), "init's own registration must not come back: {claude}");
        assert_eq!(claude["projects"]["/home/u/app"]["mcpServers"]["tokenstash"]["command"], "/old/tokenstash");
    }

    /// Astra: ownership of init's CLI registration is given up only once it is gone; one
    /// already gone (an interrupted run, the user) settles the flag without a write.
    #[test]
    fn the_cli_flag_is_reconciled_with_what_the_file_holds() {
        let (w, mut m) = machine("cli-flag");
        m.claude_mcp_registered = true;
        m.save().unwrap();
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert!(!m.claude_mcp_registered && m.entries.is_empty());
    }

    /// Astra: the user's registration → server off (recorded as an entry) → server on through
    /// the CLI (init's own registration, flag set) → undo. Init's registration must go before
    /// the entry comes back, or the entry would yield to it and be dropped. With no `claude`
    /// on PATH the removal cannot happen, so the entry waits and undo reports unfinished.
    #[test]
    fn undo_keeps_the_users_entry_until_inits_registration_is_gone() {
        let (w, mut m) = machine("undo-order");
        write(&w.claude_json(), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}");
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert_eq!(m.entries.len(), 1);
        // What `claude mcp add -s user` would do when the server is turned back on.
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        write(&w.claude_json(), "{\"mcpServers\":{\"tokenstash\":{\"type\":\"stdio\",\"command\":\"/opt/tokenstash\",\"args\":[\"mcp\"]}}}");
        m.files.retain(|(p, _)| p != &w.claude_json());
        m.claude_mcp_registered = true;
        m.save().unwrap();
        let root = m.root.clone();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 1, "unfinished: init's registration is still there");
        let left = Manifest::load_at(root).unwrap();
        assert!(left.claude_mcp_registered && left.entries.len() == 1, "{left:?}");
        assert!(read(&w.claude_json()).contains("/opt/tokenstash") && !read(&w.claude_json()).contains("/old/tokenstash"));
    }

    /// Greptile: the agent's config directory may be gone by the time of undo.
    #[test]
    fn undo_recreates_a_config_directory_removed_in_between() {
        let (w, mut m) = machine("dir-gone");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}");
        write(&w.codex().join("config.toml"), "[mcp_servers.tokenstash]\ncommand = \"/old/tokenstash\"\n");
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        fs::remove_dir_all(w.cursor()).unwrap();
        fs::remove_dir_all(w.codex()).unwrap();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        let cursor: serde_json::Value = serde_json::from_str(&read(&w.cursor().join("mcp.json"))).unwrap();
        assert_eq!(cursor["mcpServers"]["tokenstash"]["command"], "/old/tokenstash");
        assert!(toml_has_server(&w.codex().join("config.toml")));
    }

    /// A manifest written by the previous version has no `entries`; it still loads.
    #[test]
    fn a_manifest_without_entries_loads() {
        let root = scratch("legacy-manifest");
        fs::write(root.join("init.manifest.json"), "{\"files\":[[\"/x/AGENTS.md\",null]],\"dirs\":[],\"claude_mcp_registered\":false}").unwrap();
        let m = Manifest::load_at(root).unwrap();
        assert_eq!(m.files.len(), 1);
        assert!(m.entries.is_empty() && !m.is_empty());
    }

    /// Astra: a marked section the global AGENTS.md held that init never recorded (one the
    /// user wrote, or an init whose record is gone) is theirs as far as init knows: it goes,
    /// and comes back on undo.
    #[test]
    fn an_unrecorded_agents_section_comes_back_on_undo() {
        let (w, mut m) = machine("old-section");
        write(&w.codex_agents(), &format!("# Rules\n\n{}", section("## Keys\n\nmy own wording")));
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert_eq!(read(&w.codex_agents()), "# Rules\n");
        assert!(m.entries.iter().any(|r| r.key == "section" && r.value.contains("my own wording")), "{:?}", m.entries);
        write(&w.codex_agents(), "# Rules\n\nBe brief.\n");
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert_eq!(read(&w.codex_agents()), format!("# Rules\n\nBe brief.\n\n{}", section("## Keys\n\nmy own wording")));
    }

    /// Astra: an AGENTS.md that exists but cannot be read as text is not blank; undo must not
    /// overwrite it with the saved section, and the entry must stay for a retry.
    #[test]
    fn undo_does_not_overwrite_an_unreadable_agents_file_with_the_section() {
        let (w, mut m) = machine("bad-utf8");
        write(&w.codex_agents(), &format!("# Rules\n\n{}", section("## Keys\n\nmine")));
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert!(m.entries.iter().any(|r| r.key == "section"));
        let bytes = b"# Rules\n\xff\xfe not text\n".to_vec();
        fs::write(w.codex_agents(), &bytes).unwrap();
        let root = m.root.clone();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 1, "unfinished: the section could not be put back");
        assert_eq!(fs::read(w.codex_agents()).unwrap(), bytes, "left exactly as found");
        assert!(Manifest::load_at(root).unwrap().entries.iter().any(|r| r.key == "section"));
    }

    /// Astra: a config that cannot be parsed is unknown, not empty. Taking the server out
    /// stops with an error and every record stays, instead of ownership being given up or
    /// the whole-file record retired over a registration that is still there.
    #[test]
    fn an_unreadable_config_stops_the_change_and_keeps_the_records() {
        let (w, mut m) = machine("unparseable");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        write(&w.cursor().join("mcp.json"), "{ not json");
        let err = wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap_err();
        assert!(err.to_string().contains("mcp.json") && err.to_string().contains("not valid JSON"), "{err:#}");
        // The files before it in the order were settled; the unreadable one and everything
        // after it keep their records, and nothing was recorded as removed.
        assert!(m.recorded(&w.cursor().join("mcp.json")) && m.recorded(&w.gemini().join("settings.json")), "{:?}", m.files);
        assert!(m.entries.is_empty());
        assert_eq!(read(&w.cursor().join("mcp.json")), "{ not json", "left exactly as found");
        // Same for the flag: an unreadable ~/.claude.json does not settle it.
        let (w2, mut m2) = machine("unparseable-claude");
        write(&w2.claude_json(), "{ not json");
        m2.claude_mcp_registered = true;
        m2.save().unwrap();
        assert!(wire(&mut m2, &w2, AgentMode::Auto, Some(false)).is_err());
        assert!(m2.claude_mcp_registered);
    }

    /// Astra: a backup that cannot be read keeps the whole-file record rather than dropping
    /// the only way back.
    #[test]
    fn an_unreadable_backup_keeps_the_whole_file_record() {
        let (w, mut m) = machine("bad-backup");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        let backup = m.files.iter().find(|(p, _)| p == &w.cursor().join("mcp.json")).unwrap().1.clone().unwrap();
        fs::write(&backup, "{ corrupt").unwrap();
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert!(m.recorded(&w.cursor().join("mcp.json")) && m.entries.is_empty(), "{:?} {:?}", m.files, m.entries);
    }

    /// Astra: a flag left set by a run that crashed after removing init's registration must
    /// not make undo wait forever; confirmed absence settles it.
    #[test]
    fn undo_settles_a_stale_cli_flag_by_looking() {
        let (w, mut m) = machine("stale-flag");
        write(&w.claude_json(), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}},\"projects\":{\"/a\":{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}}}");
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert_eq!(m.entries.len(), 2);
        m.claude_mcp_registered = true;
        m.save().unwrap();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        let claude: serde_json::Value = serde_json::from_str(&read(&w.claude_json())).unwrap();
        assert_eq!(claude["mcpServers"]["tokenstash"]["command"], "/old/tokenstash");
        assert_eq!(claude["projects"]["/a"]["mcpServers"]["tokenstash"]["command"], "/old/tokenstash");
    }

    #[test]
    fn the_section_is_stripped_exactly_and_a_hand_edited_one_is_left_alone() {
        let d = scratch("snippet");
        let p = d.join("AGENTS.md");
        fs::write(&p, format!("# Rules\n\n{}", section("x"))).unwrap();
        strip_snippet(&p).unwrap();
        assert_eq!(read(&p), "# Rules\n");
        // Section first, user text after it.
        fs::write(&p, format!("{}\n# After\n", section("x"))).unwrap();
        strip_snippet(&p).unwrap();
        assert_eq!(read(&p), "# After\n");
        // No closing mark: refuse.
        fs::write(&p, format!("{SNIPPET_MARK}\nedited by hand\n")).unwrap();
        assert!(strip_snippet(&p).is_err());
        assert!(read(&p).contains("edited by hand"));
    }

    #[test]
    fn a_non_default_home_reaches_the_skill_and_the_server() {
        let (mut w, mut m) = machine("ts-home");
        w.ts_home = Some("/srv/ts".into());
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        assert!(read(&w.claude_json()).contains("\"TOKENSTASH_HOME\": \"/srv/ts\""));
        assert!(read(&w.codex().join("config.toml")).contains("TOKENSTASH_HOME = \"/srv/ts\""));
        wire(&mut m, &w, AgentMode::Explicit, Some(false)).unwrap();
        assert!(!w.codex().join("config.toml").exists());
        for d in [w.claude_skill_dir(), w.agents_skill_dir(), w.cursor_skill_dir()] {
            assert!(read(&d.join("SKILL.md")).contains("TOKENSTASH_HOME=/srv/ts"), "{}", d.display());
        }
    }

    #[test]
    fn doctor_names_what_disagrees_with_the_config() {
        let skill = Installed { agent: "codex", skill: Some(AgentMode::Auto), mcp: false, legacy: vec![] };
        assert!(skill.problems(AgentMode::Auto, false).is_empty());
        assert_eq!(skill.problems(AgentMode::Explicit, false), vec!["codex: the skill is in auto mode, config.toml says explicit"]);
        let old = Installed { agent: "codex", skill: None, mcp: true, legacy: vec!["prompt"] };
        assert_eq!(old.problems(AgentMode::Auto, false), vec!["codex: no tokenstash skill, so the agent has no instructions for the CLI", "codex: an MCP server is registered, config.toml says none", "codex: left over from an earlier version: prompt"]);
        // Greptile: the server alone, with the skill deleted, is not a healthy agent.
        assert_eq!(Installed { agent: "cursor", skill: None, mcp: true, legacy: vec![] }.problems(AgentMode::Auto, true), vec!["cursor: no tokenstash skill, so the agent has no instructions for the CLI"]);
        assert_eq!(old.to_string(), "codex (mcp, old prompt)");
    }

    #[test]
    fn effectively_empty_means_only_what_init_leaves_behind() {
        let d = scratch("empty");
        let j = d.join("a.json");
        for (text, empty) in [("{}", true), ("{\"mcpServers\":{}}", true), ("{\"mcpServers\":{},\"theme\":[]}", false), ("{\"mcpServers\":{\"x\":{}}}", false), ("[]", false)] {
            fs::write(&j, text).unwrap();
            assert_eq!(effectively_empty(&j), empty, "{text}");
        }
        let t = d.join("c.toml");
        for (text, empty) in [("", true), ("[mcp_servers]\n", true), ("# mine\n[mcp_servers]\n", false), ("[mcp_servers]\n[other]\n", false), ("model = \"o3\"\n", false)] {
            fs::write(&t, text).unwrap();
            assert_eq!(effectively_empty(&t), empty, "{text:?}");
        }
        assert!(effectively_empty(&d.join("missing.json")));
    }

    /// Greptile on #69: a plain `init` keeps the mode and MCP choice the config holds now,
    /// so a card the person confirmed while init ran is not undone.
    #[test]
    fn a_plain_init_keeps_the_choices_the_config_holds() {
        let mut c = Config { agent_mode: AgentMode::Explicit, ..Config::default() };
        choose(&mut c, None, false, false).unwrap();
        assert_eq!(c.agent_mode, AgentMode::Explicit);
        let mut c = Config { mcp: true, ..Config::default() };
        choose(&mut c, None, false, false).unwrap();
        assert!(c.mcp);
        choose(&mut c, Some(Mode::Explicit), false, false).unwrap();
        assert!(c.agent_mode == AgentMode::Explicit && !c.mcp, "explicit mode has no server");
        assert!(choose(&mut c, None, true, false).is_err(), "no server in explicit mode");
    }

    /// Codex review #7: undo after `--mcp` used to put the whole pre-init file back, losing a
    /// server the user added since. Only tokenstash's entry goes now, and what the file held
    /// under that name before init comes back.
    #[test]
    fn undo_takes_out_only_tokenstashs_entry_and_keeps_later_edits() {
        let (w, mut m) = machine("undo-entries");
        write(&w.codex().join("config.toml"), "# mine\n[mcp_servers.github]\ncommand = \"gh-mcp\"\n");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        assert!(m.recorded(&w.codex().join("config.toml")) && m.recorded(&w.cursor().join("mcp.json")));
        let codex = format!("{}\n[mcp_servers.linear]\ncommand = \"linear-mcp\"\n", read(&w.codex().join("config.toml")));
        write(&w.codex().join("config.toml"), &codex);
        let mut cursor: serde_json::Value = serde_json::from_str(&read(&w.cursor().join("mcp.json"))).unwrap();
        cursor["mcpServers"]["linear"] = serde_json::json!({ "command": "linear-mcp" });
        write(&w.cursor().join("mcp.json"), &cursor.to_string());
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        let codex = read(&w.codex().join("config.toml"));
        assert!(codex.contains("# mine") && codex.contains("gh-mcp") && codex.contains("linear-mcp") && !toml_has_server(&w.codex().join("config.toml")), "{codex}");
        let cursor: serde_json::Value = serde_json::from_str(&read(&w.cursor().join("mcp.json"))).unwrap();
        assert_eq!(cursor["mcpServers"]["linear"]["command"], "linear-mcp");
        assert_eq!(cursor["mcpServers"]["tokenstash"]["command"], "/old/tokenstash", "the entry init replaced comes back");
        assert!(!w.claude_json().exists() && !w.gemini().join("settings.json").exists(), "files init created for the server alone are gone");
    }

    /// Codex review #8: two paths that flatten to the same name get two backups.
    #[test]
    fn backups_of_different_paths_never_share_a_name() {
        let a = backup_name(Path::new("/tmp/a_b/c/AGENTS.md"));
        let b = backup_name(Path::new("/tmp/a/b_c/AGENTS.md"));
        assert_ne!(a, b);
        assert!(a.ends_with("-AGENTS.md") && b.ends_with("-AGENTS.md"));
    }

    /// Codex review #10: a write replaces the file in one step and keeps its permissions.
    #[test]
    fn a_config_write_is_atomic_and_keeps_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("atomic");
        let p = d.join("config.toml");
        fs::write(&p, "old = 1\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        write_file(&p, "new = 2\n").unwrap();
        assert_eq!(read(&p), "new = 2\n");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1, "no temporary file left behind");
    }

    /// Greptile on #70: a config kept as a link stays a link, and the file it points to is
    /// what changes.
    #[test]
    fn a_linked_config_is_written_through_and_stays_a_link() {
        let d = scratch("linked");
        let real = d.join("dotfiles/config.toml");
        write(&real, "model = \"o3\"\n");
        let link = d.join("codex/config.toml");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_file(&link, "model = \"o4\"\n").unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(read(&real), "model = \"o4\"\n");
    }

    /// Greptile on #70: an entry the person changed or re-added after `init --mcp` is theirs,
    /// and undo leaves it.
    #[test]
    fn undo_leaves_an_entry_the_person_changed_since() {
        let (w, mut m) = machine("changed-entry");
        write(&w.codex().join("config.toml"), "[mcp_servers.github]\ncommand = \"gh-mcp\"\n");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        let changed = read(&w.codex().join("config.toml")).replace("/opt/tokenstash", "/usr/local/bin/tokenstash");
        write(&w.codex().join("config.toml"), &changed);
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        let after = read(&w.codex().join("config.toml"));
        assert!(after.contains("/usr/local/bin/tokenstash") && after.contains("gh-mcp"), "{after}");
    }

    /// Greptile on #70: undo reads everything before it writes, so a backup it cannot read
    /// leaves the file exactly as it was.
    #[test]
    fn an_unreadable_backup_leaves_the_file_untouched() {
        let (w, mut m) = machine("bad-backup-undo");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"}}}");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        let backup = m.files.iter().find(|(p, _)| p == &w.cursor().join("mcp.json")).unwrap().1.clone().unwrap();
        fs::write(&backup, "{ corrupt").unwrap();
        let before = read(&w.cursor().join("mcp.json"));
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 1, "unfinished");
        assert_eq!(read(&w.cursor().join("mcp.json")), before, "nothing was half undone");
    }

    /// Greptile on #70: undo straight from an older record keeps a section the person edited,
    /// as an upgrade does.
    #[test]
    fn undo_keeps_an_edited_section_from_an_older_record() {
        let (w, mut m) = machine("old-record-edited");
        let proj = scratch("old-record-app").join("AGENTS.md");
        write(&proj, "# App\n");
        m.mutate(&proj, || { fs::write(&proj, format!("# App\n\n{}", section(SHIPPED_SECTIONS[0])))?; Ok(()) }).unwrap();
        let edited = format!("# App\n\n{}", section(&format!("{}\nMine: never use the prod key.", SHIPPED_SECTIONS[0])));
        write(&proj, &edited);
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert_eq!(read(&proj), edited, "the person's edit stays");
    }

    /// Greptile on #70: a file init replaced need not be text; undo puts the original bytes back.
    #[test]
    fn undo_restores_a_replaced_file_byte_for_byte() {
        let (w, mut m) = machine("bytes");
        let original = b"---\nname: mine\n---\n\xff\xfe not utf-8\n".to_vec();
        fs::create_dir_all(w.claude_skill_dir()).unwrap();
        fs::write(w.claude_skill_dir().join("SKILL.md"), &original).unwrap();
        wire(&mut m, &w, AgentMode::Auto, Some(false)).unwrap();
        assert_eq!(read(&w.claude_skill_dir().join("SKILL.md")), SKILL_MD);
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert_eq!(fs::read(w.claude_skill_dir().join("SKILL.md")).unwrap(), original);
    }

    /// Greptile on #70: a private config deleted since init comes back private, not with
    /// the umask's permissions.
    #[test]
    fn a_restored_private_config_keeps_its_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (w, mut m) = machine("private");
        let p = w.cursor().join("mcp.json");
        write(&p, "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\",\"env\":{\"TOKEN\":\"x\"}}}}");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        fs::remove_file(&p).unwrap();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert!(read(&p).contains("gh-mcp"));
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// Greptile on #70: undo takes out the section a release shipped and keeps a section of
    /// the person's own under the same marks.
    #[test]
    fn undo_keeps_the_persons_own_section_after_a_shipped_one() {
        let (w, mut m) = machine("two-sections");
        let proj = scratch("two-sections-app").join("AGENTS.md");
        write(&proj, "# App\n");
        m.mutate(&proj, || { fs::write(&proj, format!("# App\n\n{}", section(SHIPPED_SECTIONS[0])))?; Ok(()) }).unwrap();
        let mine = section("Mine: never use the prod key.");
        write(&proj, &format!("{}\n{mine}", read(&proj)));
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        let after = read(&proj);
        assert!(after.contains("Mine: never use the prod key.") && !after.contains(SHIPPED_SECTIONS[0]), "{after}");
        assert!(after.starts_with("# App\n"), "{after}");
    }

    /// Greptile on #70: a linked config whose file was deleted since init is restored where
    /// the link points, and the link stays.
    #[test]
    fn a_dangling_linked_config_is_restored_at_its_target() {
        let (w, mut m) = machine("dangling");
        let real = scratch("dangling-dotfiles").join("config.toml");
        write(&real, "[mcp_servers.github]\ncommand = \"gh-mcp\"\n");
        let link = w.codex().join("config.toml");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        assert!(toml_has_server(&real));
        fs::remove_file(&real).unwrap();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "still a link");
        assert_eq!(read(&real), "[mcp_servers.github]\ncommand = \"gh-mcp\"\n");
    }

    /// Greptile on #70: a config with nothing of init's left in it is not rewritten, so its
    /// formatting stays as the person left it.
    #[test]
    fn undo_does_not_reformat_a_config_it_does_not_change() {
        let (w, mut m) = machine("compact");
        let p = w.cursor().join("mcp.json");
        write(&p, "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"}}}");
        wire(&mut m, &w, AgentMode::Auto, Some(true)).unwrap();
        let compact = "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"},\"linear\":{\"command\":\"linear-mcp\"}}}";
        write(&p, compact);
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert_eq!(read(&p), compact);
    }

    /// Greptile on #70: a config linked through a second link to a deleted file is restored
    /// at the end of the chain, and both links stay links.
    #[test]
    fn a_chain_of_links_is_followed_to_its_end() {
        let d = scratch("chain");
        let real = d.join("dotfiles/config.toml");
        let middle = d.join("middle/config.toml");
        let link = d.join("codex/config.toml");
        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::create_dir_all(middle.parent().unwrap()).unwrap();
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("../dotfiles/config.toml", &middle).unwrap();
        std::os::unix::fs::symlink(&middle, &link).unwrap();
        write_file(&link, "model = \"o4\"\n").unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert!(fs::symlink_metadata(&middle).unwrap().file_type().is_symlink());
        assert_eq!(read(&real), "model = \"o4\"\n");
    }

    /// A loop of links is reported, and nothing is written.
    #[test]
    fn a_loop_of_links_writes_nothing() {
        let d = scratch("loop");
        std::os::unix::fs::symlink(d.join("b"), d.join("a")).unwrap();
        std::os::unix::fs::symlink(d.join("a"), d.join("b")).unwrap();
        assert!(write_file(&d.join("a"), "x").is_err());
        assert_eq!(fs::read_dir(&d).unwrap().count(), 2, "no file or temporary file left");
    }

    /// Greptile on #70: a config with a second name through a hard link is changed under
    /// both names.
    #[test]
    fn a_hard_linked_config_changes_under_every_name() {
        let d = scratch("hardlink");
        let a = d.join("dotfiles/config.toml");
        let b = d.join("codex/config.toml");
        write(&a, "model = \"o3\"\n");
        fs::create_dir_all(b.parent().unwrap()).unwrap();
        fs::hard_link(&a, &b).unwrap();
        write_file(&b, "model = \"o4\"\n").unwrap();
        assert_eq!(read(&a), "model = \"o4\"\n");
        assert_eq!(read(&b), "model = \"o4\"\n");
    }

    /// Greptile on #70: init records the entry it wrote, not what the file holds a moment
    /// later, so an edit made in between is the person's and undo leaves it.
    #[test]
    fn init_records_the_entry_it_wrote_not_a_later_edit() {
        let (w, mut m) = machine("record-made");
        let p = w.cursor().join("mcp.json");
        write(&p, "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"}}}");
        let theirs = "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"},\"tokenstash\":{\"command\":\"/usr/local/bin/tokenstash\",\"args\":[\"mcp\"]}}}";
        m.mutate_entry(&p, || {
            let made = merge_mcp_json(&p, &w.exe, None)?;
            // Another writer changes the entry right after init wrote it.
            write(&p, theirs);
            Ok(made)
        }).unwrap();
        assert_eq!(m.wrote_for(&p).unwrap()["command"], w.exe.as_str());
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert_eq!(read(&p), theirs, "their entry stays");
    }

    /// A `claude mcp` that hangs is stopped at the time limit and returns an error, so an
    /// action card that runs it is given back and the person can decline it, instead of
    /// staying claimed for as long as the inbox runs. One that finishes reports how it exited.
    #[cfg(unix)]
    #[test]
    fn a_hung_claude_mcp_is_stopped_at_the_time_limit() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        let dir = scratch("hung-claude");
        let fake = |name: &str, script: &str| {
            let bin = dir.join(name).join("claude");
            fs::create_dir_all(bin.parent().unwrap()).unwrap();
            fs::write(&bin, script).unwrap();
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
            bin
        };
        let hung = fake("hung", "#!/bin/sh\nexec sleep 30\n");
        let limit = Duration::from_millis(300);
        let started = Instant::now();
        let err = claude_mcp_with(&hung, &["add", "-s", "user", "tokenstash"], limit).unwrap_err();
        assert!(started.elapsed() < limit + Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(format!("{err:#}").contains("did not finish"), "{err:#}");
        assert!(claude_mcp_with(&fake("ok", "#!/bin/sh\nexit 0\n"), &["remove"], limit).unwrap());
        assert!(!claude_mcp_with(&fake("fails", "#!/bin/sh\nexit 1\n"), &["remove"], limit).unwrap());
        assert!(!claude_mcp_with(&dir.join("missing/claude"), &["remove"], limit).unwrap(), "one that cannot start is a failure, as before");
        let _ = fs::remove_dir_all(&dir);
    }
}
