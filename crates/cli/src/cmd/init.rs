//! `init`: pick a stash backend, wire up agents.
//!
//! Two agent modes. `auto` registers the MCP server and installs a skill the agent loads on
//! its own, so keys are requested whenever code needs one. `explicit` installs only a slash
//! command the person types (`/tokenstash`), which runs the CLI: nothing an agent reads
//! unprompted mentions tokenstash, so a session in which it is never typed never touches it.
//! Switching modes removes the other mode's wiring, or the agent would keep calling tokenstash
//! on its own after the person asked it not to. Choosing a mode, writing project instructions
//! and undoing are a person's decisions: an agent with a shell could otherwise put automatic
//! mode back.

use anyhow::Result;
use clap::Args;
use std::fs;
use std::path::{Path, PathBuf};
use tokenstash_core::config::AgentMode;
use tokenstash_core::Config;

pub const SKILL_MD: &str = include_str!("../../SKILL.md");

#[derive(Args)]
pub struct InitArgs {
    /// How agents reach tokenstash: `auto` (registers the MCP server; the agent asks on its own)
    /// or `explicit` (a `/tokenstash` command you type; runs the CLI; nothing automatic).
    /// Remembered in config.toml, so a later `init` without --mode keeps it. For a person at a terminal.
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,
    /// Also write an AGENTS.md section for the mode into the current project. For a person at a terminal.
    #[arg(long)]
    pub project: bool,
    /// Print the AGENTS.md section and exit (no files touched).
    #[arg(long)]
    pub print_snippet: bool,
    /// Print the skill file for the mode and exit (no files touched).
    #[arg(long)]
    pub print_skill: bool,
    /// Don't touch any agent config; just set up the stash.
    #[arg(long)]
    pub no_agents: bool,
    /// Retired (0.2): directories pair once instead; accepted and ignored with a notice.
    #[arg(long = "trust", hide = true)]
    pub trust: Vec<PathBuf>,
    /// Undo a previous `init`: restore every agent config file it changed (from the backups
    /// it took), remove the skill files, commands and MCP registrations. Leaves the stash alone.
    /// For a person at a terminal.
    #[arg(long)]
    pub undo: bool,
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
            let name = p.to_string_lossy().replace(['/', '\\'], "_");
            let b = dir.join(name);
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
            Some(b) if b.exists() => { fs::copy(b, p)?; }
            Some(b) => anyhow::bail!("backup of {} missing at {}", p.display(), b.display()),
            None => remove_file_if_present(p)?,
        }
        self.files.remove(i);
        self.save()?;
        Ok(true)
    }

    /// Remove a skill directory init created: its SKILL.md, then the directory if that was
    /// all it held. Anything else in there is not init's (a script the user added), so the
    /// directory stays with it and the record is dropped either way.
    fn release_dir(&mut self, d: &Path) -> Result<bool> {
        let Some(i) = self.dirs.iter().position(|q| q == d) else { return Ok(false) };
        remove_skill_dir(d)?;
        self.files.retain(|(p, _)| !p.starts_with(d));
        self.dirs.remove(i);
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

/// SKILL.md out, then the directory if it is empty; a directory holding the user's other
/// files is left, and said so.
fn remove_skill_dir(d: &Path) -> Result<()> {
    remove_file_if_present(&d.join("SKILL.md"))?;
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
    let s = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) => return e.kind() == std::io::ErrorKind::NotFound,
    };
    match p.extension().and_then(|e| e.to_str()) {
        Some("json") => serde_json::from_str::<serde_json::Value>(&s).map(|v| v == serde_json::json!({}) || v == serde_json::json!({ "mcpServers": {} })).unwrap_or(false),
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
        let r: Result<()> = match &backup {
            Some(b) if b.exists() => fs::copy(b, &p).map(|_| ()).map_err(Into::into),
            Some(b) => Err(anyhow::anyhow!("backup missing at {}", b.display())),
            None => remove_file_if_present(&p),
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
        let ok = claude_cli && claude_mcp(&["remove", "-s", "user", "tokenstash"]);
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
        fs::write(&r.file, s)?;
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
        fs::write(&r.file, out)?;
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
    fs::write(&r.file, serde_json::to_string_pretty(&v)?)?;
    Ok(())
}

fn claude_mcp(args: &[&str]) -> bool {
    std::process::Command::new("claude").arg("mcp").args(args)
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

/// The machine `init` wires: where the agents' configs are, which binary to point them at.
struct Wiring {
    home: PathBuf,
    exe: String,
    /// A non-default `TOKENSTASH_HOME`, baked into every registration and named in every
    /// command, or the agent's session and this shell would use two different homes.
    ts_home: Option<String>,
    /// `claude` is on PATH, so registration can go through `claude mcp` instead of the file.
    claude_cli: bool,
}

impl Wiring {
    fn claude_present(&self) -> bool { self.home.join(".claude").is_dir() || self.claude_cli }
    fn claude_skill_dir(&self) -> PathBuf { self.home.join(".claude/skills/tokenstash") }
    fn claude_json(&self) -> PathBuf { self.home.join(".claude.json") }
    fn codex(&self) -> PathBuf { self.home.join(".codex") }
    fn codex_agents(&self) -> PathBuf { self.home.join(".codex/AGENTS.md") }
    fn codex_prompt(&self) -> PathBuf { self.home.join(".codex/prompts/tokenstash.md") }
    fn cursor(&self) -> PathBuf { self.home.join(".cursor") }
    fn cursor_skill_dir(&self) -> PathBuf { self.home.join(".cursor/skills/tokenstash") }
    fn gemini(&self) -> PathBuf { self.home.join(".gemini") }
    fn gemini_command(&self) -> PathBuf { self.home.join(".gemini/commands/tokenstash.toml") }
}

/// Write a skill directory's SKILL.md, recording the directory when init creates it, or
/// just the file when the directory was already there (a hand-written skill, an older init)
/// so undo restores exactly that.
fn write_skill(manifest: &mut Manifest, dir: &Path, text: &str) -> Result<PathBuf> {
    let md = dir.join("SKILL.md");
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        manifest.record_dir(dir)?;
    }
    manifest.mutate(&md, || Ok(fs::write(&md, text)?))?;
    Ok(md)
}

/// Auto mode: MCP registrations, the auto-loading skill, the AGENTS.md section.
fn wire_auto(manifest: &mut Manifest, w: &Wiring) -> Result<Vec<PathBuf>> {
    let mut touched = vec![];
    if w.claude_present() {
        touched.push(write_skill(manifest, &w.claude_skill_dir(), SKILL_MD)?);
        let cj = w.claude_json();
        // The CLI registers cleanly when present. The desktop app ships without `claude`
        // on PATH, so fall back to writing the same user-scope entry into ~/.claude.json
        // ourselves — otherwise a desktop-only user is left with a printed command.
        let added = if w.claude_cli && !manifest.claude_mcp_registered && !manifest.recorded(&cj) && json_has_server(&cj, false) {
            // Already registered by someone else (the user, an older install): not ours
            // to remove on --undo, so no record is taken.
            if let Some(h) = &w.ts_home {
                println!("! Claude Code: an existing tokenstash MCP registration was left as is; it may not use TOKENSTASH_HOME={h}. To re-register: claude mcp remove -s user tokenstash && tokenstash init");
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
            let ok = claude_mcp(&args.iter().map(String::as_str).collect::<Vec<_>>());
            if !ok { manifest.claude_mcp_registered = false; manifest.save()?; }
            ok
        } else {
            match manifest.mutate(&cj, || merge_mcp_json_typed(&cj, &w.exe, true, w.ts_home.as_deref())) {
                Ok(()) => { touched.push(cj); true }
                Err(e) => { println!("! Claude Code: left {} untouched — {e}", cj.display()); false }
            }
        };
        let mcp_note = if added { ", MCP server registered".to_string() } else { format!("; register MCP with: claude mcp add -s user tokenstash -- {} mcp", w.exe) };
        println!("✓ Claude Code: skill installed{mcp_note}");
    }

    let codex = w.codex();
    if codex.is_dir() {
        let (ctoml, cagents) = (codex.join("config.toml"), w.codex_agents());
        match manifest.mutate(&ctoml, || merge_codex_toml(&ctoml, &w.exe, w.ts_home.as_deref())) {
            Ok(()) => {
                manifest.mutate(&cagents, || set_snippet(&cagents, AgentMode::Auto))?;
                touched.push(ctoml.clone());
                touched.push(cagents.clone());
                println!("✓ Codex: MCP server ({}) + usage section ({})", ctoml.display(), cagents.display());
            }
            Err(e) => println!("! Codex: left {} untouched — {e}", ctoml.display()),
        }
    }

    let cursor = w.cursor();
    if cursor.is_dir() {
        let cj = cursor.join("mcp.json");
        match manifest.mutate(&cj, || merge_mcp_json(&cj, &w.exe, w.ts_home.as_deref())) {
            Ok(()) => { touched.push(cj.clone()); println!("✓ Cursor: MCP server registered ({})", cj.display()) }
            Err(e) => println!("! Cursor: left {} untouched — {e}", cj.display()),
        }
    }

    let gemini = w.gemini();
    if gemini.is_dir() {
        let gj = gemini.join("settings.json");
        match manifest.mutate(&gj, || merge_mcp_json(&gj, &w.exe, w.ts_home.as_deref())) {
            Ok(()) => { touched.push(gj.clone()); println!("✓ Gemini CLI: MCP server registered ({})", gj.display()) }
            Err(e) => println!("! Gemini CLI: left {} untouched — {e}", gj.display()),
        }
    }
    Ok(touched)
}

/// Explicit mode: a user-invoked command per agent, running the CLI. No MCP server, no
/// section in the global AGENTS.md, nothing the agent loads on its own.
fn wire_explicit(manifest: &mut Manifest, w: &Wiring) -> Result<Vec<PathBuf>> {
    let mut touched = vec![];
    let home = w.ts_home.as_deref();
    if w.claude_present() {
        touched.push(write_skill(manifest, &w.claude_skill_dir(), &skill_text(AgentMode::Explicit, home))?);
        println!("✓ Claude Code: /tokenstash installed (only you can invoke it)");
    }
    if w.codex().is_dir() {
        let p = w.codex_prompt();
        manifest.mutate(&p, || {
            if let Some(d) = p.parent() { fs::create_dir_all(d)?; }
            Ok(fs::write(&p, codex_prompt_text(home))?)
        })?;
        touched.push(p.clone());
        println!("✓ Codex: /prompts:tokenstash installed ({})", p.display());
    }
    if w.cursor().is_dir() {
        touched.push(write_skill(manifest, &w.cursor_skill_dir(), &skill_text(AgentMode::Explicit, home))?);
        println!("✓ Cursor: /tokenstash installed (only you can invoke it)");
    }
    if w.gemini().is_dir() {
        let p = w.gemini_command();
        manifest.mutate(&p, || {
            if let Some(d) = p.parent() { fs::create_dir_all(d)?; }
            Ok(fs::write(&p, gemini_command_text(home)?)?)
        })?;
        touched.push(p.clone());
        println!("✓ Gemini CLI: /tokenstash installed ({})", p.display());
    }
    Ok(touched)
}

/// Take auto mode's wiring out: every MCP registration and the global AGENTS.md section.
/// Only the tokenstash entry leaves a shared config; the rest of the file is the user's. A
/// registration init did not make (the user's own `claude mcp add`, at user or local scope)
/// goes too — leaving it would keep the agent calling tokenstash on its own, which is what
/// explicit mode is against — and is recorded entry by entry so undo puts it back.
fn unwire_auto(manifest: &mut Manifest, w: &Wiring) -> Result<()> {
    remove_json_server(manifest, &w.claude_json(), "Claude Code", true)?;
    remove_toml_server(manifest, &w.codex().join("config.toml"))?;
    let cagents = w.codex_agents();
    match fs::read_to_string(&cagents) {
        Ok(text) if text.contains(SNIPPET_MARK) => {
            manifest.mutate(&cagents, || strip_snippet(&cagents))?;
            println!("✓ Codex: usage section removed from {}", cagents.display());
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => anyhow::bail!("reading {}: {e}", cagents.display()),
    }
    manifest.retire(&cagents)?;
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
        fs::write(p, serde_json::to_string_pretty(&v)?)?;
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
        fs::write(p, out)?;
        println!("✓ Codex: MCP server removed from {}", p.display());
    }
    if recorded { manifest.retire(p)?; }
    Ok(())
}

/// Take explicit mode's wiring out: the prompt, the command and the Cursor skill. Each is
/// tokenstash's own file, so it goes back to what init found (usually nothing). The Claude
/// skill is not removed: auto mode rewrites it.
fn unwire_explicit(manifest: &mut Manifest, w: &Wiring) -> Result<()> {
    for (name, p) in [("Codex", w.codex_prompt()), ("Gemini CLI", w.gemini_command())] {
        if manifest.release(&p)? {
            println!("✓ {name}: /tokenstash command removed ({})", p.display());
        } else if p.exists() {
            println!("! {name}: {} was not written by init; remove it yourself if it is not yours", p.display());
        }
    }
    let d = w.cursor_skill_dir();
    if manifest.release_dir(&d)? || manifest.release(&d.join("SKILL.md"))? {
        println!("✓ Cursor: /tokenstash skill removed ({})", d.display());
    } else if d.exists() {
        println!("! Cursor: {} was not written by init; remove it yourself if it is not yours", d.display());
    }
    Ok(())
}

/// Every project AGENTS.md `init --project` wrote a section into gets the section for the
/// mode now chosen: one left saying "ask tokenstash whenever a key is needed" would undo
/// explicit mode in that project.
fn resync_project_snippets(manifest: &mut Manifest, w: &Wiring, mode: AgentMode) -> Result<()> {
    let files: Vec<PathBuf> = manifest.files.iter().map(|(p, _)| p.clone()).filter(|p| p.file_name().is_some_and(|n| n == "AGENTS.md") && *p != w.codex_agents()).collect();
    for p in files {
        if has_snippet(&p) && !snippet_is(&p, mode) {
            manifest.mutate(&p, || set_snippet(&p, mode))?;
            println!("✓ {}: tokenstash section rewritten for {} mode", p.display(), mode);
        }
    }
    Ok(())
}

pub fn init(a: InitArgs) -> Result<i32> {
    let env_home = std::env::var("TOKENSTASH_HOME").ok().filter(|h| !h.is_empty());
    // Printing follows the mode chosen for this machine unless one is named, so text
    // redirected into a file by hand is the text init would have written.
    let print_mode = || -> Result<AgentMode> { match a.mode { Some(m) => Ok(m.into()), None => Ok(Config::load()?.agent_mode) } };
    if a.print_snippet { print!("{}", snippet_for(print_mode()?)); return Ok(0); }
    if a.print_skill { print!("{}", skill_text(print_mode()?, env_home.as_deref())); return Ok(0); }
    // Undo restores what init found, which can be automatic wiring explicit mode took out;
    // the mode and a project's instructions decide how agents reach tokenstash. All three
    // are the person's call, not an agent's.
    if a.undo {
        crate::util::require_human("init --undo", "it puts agent wiring back the way init found it")?;
        return undo();
    }
    if a.mode.is_some() {
        crate::util::require_human("init --mode", "how agents reach tokenstash is your decision")?;
    }
    if a.project {
        crate::util::require_human("init --project", "it writes instructions the agents in this project follow")?;
    }
    let mut cfg = Config::load()?;
    let fresh = !Config::exists();
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
    // The mode is remembered here too, so a later plain `init` keeps it.
    let mode: AgentMode = a.mode.map(Into::into).unwrap_or(cfg.agent_mode);
    let switched = !fresh && mode != cfg.agent_mode;
    cfg.agent_mode = mode;
    cfg.save()?;
    tokenstash_core::Db::open_default()?;
    if !a.trust.is_empty() {
        println!("! --trust is retired: directories are not trusted by folder any more. The first stored key a directory asks for shows you one card; approve it and those keys are silent there.");
    }
    if !cfg.trust_roots.is_empty() {
        println!("! trust_roots in config.toml no longer apply (retired in 0.2); `tokenstash trust rm <dir>` tidies them");
    }
    println!("✓ trust: each directory pairs once (`tokenstash workspaces` lists them)");
    println!("✓ agent mode: {}", describe_mode(mode));

    // 3. agents
    let mut touched: Vec<PathBuf> = vec![];
    let mut code = 0;
    // Registering points every future agent session at this binary. Run by an agent from a
    // hostile checkout (`cargo build && ./target/debug/tokenstash init`) that would be a
    // binary that hands values to the model. The stash and config are set up either way.
    let register_agents = !a.no_agents && match crate::util::require_human("init", "it registers this binary as every agent's MCP server") {
        Ok(()) => true,
        Err(e) => { println!("! {e:#}\n  Agents were not registered; the stash and config are ready. (--no-agents silences this.)"); false }
    };
    let home = dirs::home_dir().unwrap_or_default();
    // An agent spawns the MCP server from its own environment, not this shell's. If this
    // init is running against a non-default TOKENSTASH_HOME, bake it into every
    // registration and name it in every command, or the server and the CLI silently use
    // two different homes.
    let w = Wiring { home, exe: std::env::current_exe()?.display().to_string(), ts_home: env_home, claude_cli: which("claude") };
    if register_agents {
        if let Some(h) = &w.ts_home {
            println!("  (agents are pointed at TOKENSTASH_HOME={h}, the home this shell uses)");
        }
        touched = wire(&mut manifest, &w, mode)?;
        if mode == AgentMode::Explicit {
            let mut stray: Vec<String> = installed(&w.home).into_iter().filter(|a| is_auto_wiring(a)).collect();
            stray.extend(stray_project_sections(&manifest, &w, mode).iter().map(|p| format!("section in {}", p.display())));
            if !stray.is_empty() {
                println!("! automatic wiring is still in place: {}. Take it out by hand, then re-run `tokenstash init`.", stray.join(", "));
                code = 1;
            }
        }
    }

    if a.project {
        let p = std::env::current_dir()?.join("AGENTS.md");
        manifest.mutate(&p, || set_snippet(&p, mode))?;
        touched.push(p.clone());
        println!("✓ wrote the tokenstash section for {mode} mode to {}", p.display());
    }

    if !touched.is_empty() {
        println!("\nFiles outside {} that init wrote (undo with `tokenstash init --undo`):", tokenstash_core::config::config_dir().display());
        for t in &touched { println!("    {}", t.display()); }
        // MCP servers are loaded when an agent session starts; skill files are picked up
        // live. Installing from inside a running session leaves the agent told to use tools it
        // cannot see yet — the desktop-app tests hit exactly this.
        let inside = tokenstash_core::project::detect_agent() != "unknown";
        if inside {
            println!("\n⚠ You are running inside an agent session. Restart it: MCP tools are loaded when a session starts, so this one cannot see tokenstash yet.");
        } else if switched {
            println!("\nRestart any open agent session: MCP tools are loaded when a session starts, so a running one keeps the old mode.");
        } else {
            println!("\nIf an agent session is already open, restart it — MCP tools are loaded when a session starts.");
        }
    }

    println!("\nKeys are re-checked with their provider before an agent gets them (once a day, one free read-only request, verify_every in config.toml) so a revoked key becomes a Replace card instead of a 401.");
    if fresh {
        match mode {
            AgentMode::Auto => println!("\nNext: from any project, run   tokenstash need OPENAI_API_KEY"),
            AgentMode::Explicit => println!("\nNext: in your agent, type   /tokenstash OPENAI_API_KEY   (Codex: /prompts:tokenstash)"),
        }
    }
    Ok(code)
}

/// Wire one mode and take the other's wiring out. Explicit first removes, then installs:
/// nothing automatic may be left once the command is in place, and the command never
/// depends on it. Auto first removes the commands (the Claude skill file is shared, and the
/// rewrite must win), then installs. Project sections follow the mode either way.
fn wire(manifest: &mut Manifest, w: &Wiring, mode: AgentMode) -> Result<Vec<PathBuf>> {
    let touched = match mode {
        AgentMode::Auto => {
            unwire_explicit(manifest, w)?;
            wire_auto(manifest, w)?
        }
        AgentMode::Explicit => {
            unwire_auto(manifest, w)?;
            wire_explicit(manifest, w)?
        }
    };
    resync_project_snippets(manifest, w, mode)?;
    Ok(touched)
}

pub fn describe_mode(mode: AgentMode) -> &'static str {
    match mode {
        AgentMode::Auto => "auto — agents ask tokenstash on their own (MCP server + skill)",
        AgentMode::Explicit => "explicit — agents use tokenstash only when you type /tokenstash (CLI; no MCP server)",
    }
}

/// What is installed for each agent on this machine, for `doctor`: "claude-code (skill: auto,
/// mcp)", "codex (prompt)", "gemini-cli (command)". Read from the files, not the manifest,
/// so a registration made by hand shows too.
pub fn installed(home: &Path) -> Vec<String> {
    let mut out = vec![];
    let skill_mode = |dir: &Path| -> Option<&'static str> {
        let s = fs::read_to_string(dir.join("SKILL.md")).ok()?;
        Some(if frontmatter(&s).contains("disable-model-invocation: true") { "skill: explicit" } else { "skill: auto" })
    };
    let mut claude = vec![];
    if let Some(m) = skill_mode(&home.join(".claude/skills/tokenstash")) { claude.push(m); }
    if json_has_server(&home.join(".claude.json"), true) { claude.push("mcp"); }
    if !claude.is_empty() { out.push(format!("claude-code ({})", claude.join(", "))); }
    let mut codex = vec![];
    if toml_has_server(&home.join(".codex/config.toml")) { codex.push("mcp"); }
    if has_snippet(&home.join(".codex/AGENTS.md")) { codex.push("snippet"); }
    if home.join(".codex/prompts/tokenstash.md").is_file() { codex.push("prompt"); }
    if !codex.is_empty() { out.push(format!("codex ({})", codex.join(", "))); }
    let mut cursor = vec![];
    if json_has_server(&home.join(".cursor/mcp.json"), false) { cursor.push("mcp"); }
    if let Some(m) = skill_mode(&home.join(".cursor/skills/tokenstash")) { cursor.push(m); }
    if !cursor.is_empty() { out.push(format!("cursor ({})", cursor.join(", "))); }
    let mut gemini = vec![];
    if json_has_server(&home.join(".gemini/settings.json"), false) { gemini.push("mcp"); }
    if home.join(".gemini/commands/tokenstash.toml").is_file() { gemini.push("command"); }
    if !gemini.is_empty() { out.push(format!("gemini-cli ({})", gemini.join(", "))); }
    out
}

/// An `installed()` line that means the agent reaches tokenstash without being asked.
pub fn is_auto_wiring(line: &str) -> bool {
    line.contains("mcp") || line.contains("snippet") || line.contains("skill: auto")
}

/// ...and one that belongs to explicit mode.
pub fn is_explicit_wiring(line: &str) -> bool {
    line.contains("prompt") || line.contains("command") || line.contains("skill: explicit")
}

/// Set `mcp_servers.tokenstash` in Codex's config.toml with `toml_edit`, which preserves
/// the user's comments and formatting and understands every header spelling (quoted keys,
/// whitespace, inline tables, nested subtables) — an earlier line-scanning version got a
/// steady stream of those wrong. An existing entry is replaced wholesale so the env
/// (TOKENSTASH_HOME) is current. If the file cannot be parsed it is left untouched.
fn merge_codex_toml(p: &Path, exe: &str, ts_home: Option<&str>) -> Result<()> {
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
    if back.get("mcp_servers").and_then(|m| m.get("tokenstash")).and_then(|t| t.get("command")).and_then(|c| c.as_str()) != Some(exe) {
        anyhow::bail!("refusing to write {}: could not set the tokenstash entry cleanly; edit it by hand", p.display());
    }
    if let Some(parent) = p.parent() { fs::create_dir_all(parent)?; }
    fs::write(p, out)?;
    Ok(())
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
fn merge_mcp_json(p: &Path, exe: &str, ts_home: Option<&str>) -> Result<()> {
    merge_mcp_json_typed(p, exe, false, ts_home)
}

/// Same, with `"type": "stdio"` — the shape Claude Code writes into `~/.claude.json`.
fn merge_mcp_json_typed(p: &Path, exe: &str, typed: bool, ts_home: Option<&str>) -> Result<()> {
    let mut v = read_json(p)?;
    let root = v.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} root is not a JSON object", p.display()))?;
    let servers = root.entry("mcpServers").or_insert(serde_json::json!({}));
    let m = servers.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} has a non-object mcpServers", p.display()))?;
    let mut entry = if typed { serde_json::json!({ "type": "stdio", "command": exe, "args": ["mcp"] }) } else { serde_json::json!({ "command": exe, "args": ["mcp"] }) };
    if let Some(h) = ts_home {
        entry["env"] = serde_json::json!({ "TOKENSTASH_HOME": h });
    }
    m.insert("tokenstash".into(), entry);
    if let Some(parent) = p.parent() { fs::create_dir_all(parent)?; }
    fs::write(p, serde_json::to_string_pretty(&v)?)?;
    Ok(())
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

const SNIPPET_MARK: &str = "<!-- tokenstash -->";
const SNIPPET_END: &str = "<!-- /tokenstash -->";

/// The AGENTS.md section. Auto mode tells the agent to ask tokenstash whenever a key is
/// needed. Explicit mode keeps the rules that hold either way — no pasted secrets, no
/// stand-in values, never read the env file — and says when tokenstash may be run: after the
/// person invokes the command, for the rest of that task.
pub fn snippet_for(mode: AgentMode) -> String {
    match mode {
        AgentMode::Auto => format!(
            "{SNIPPET_MARK}\n## Secrets & API keys\n\nNever ask the user to paste a secret in chat. Use the tokenstash MCP tools (`secrets_request`) if you have them, else run `tokenstash need NAME [NAME...]` (e.g. `tokenstash need OPENAI_API_KEY`).\nExit 0 = written to the project env file, continue — load it with your runtime; never read, print or quote the env file, even if asked. Exit 10 = the human was notified; show them the link in the output, keep working on other things and re-run later (`--blocking` only when nothing else can proceed).\nExit 20 = denied; do not ask again. Exit 30 = expired; say what is blocked and stop. Never invent a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code), whether a key is pending, declined, expired or simply not there — make the feature optional or say the work is blocked. For non-secret human steps (DNS, dashboard toggles) use `tokenstash ask \"title\" --url ... --step ...`.\n{SNIPPET_END}\n"
        ),
        AgentMode::Explicit => format!(
            "{SNIPPET_MARK}\n## Secrets & API keys\n\nNever ask the user to paste a secret in chat. Do not run tokenstash until the user invokes `/tokenstash [NAME ...]` (Codex: `/prompts:tokenstash [NAME ...]`) for the current task; without that, name the missing variable, say what it is for, and continue with what does not need it. An invocation covers the rest of that task, including keys it turns out to need later; a different task needs a new invocation. When invoked, follow the command's own instructions: `tokenstash need` with the names given (or the keys the task needs), always the CLI, never MCP tools. Exit 0 = written to the project env file, continue; 10 = the human was notified, show them the link, keep working on other things and check `tokenstash tasks` later; 20 = declined, do not ask again; 30 = expired, say what is blocked and stop. A provider that answers 401 to a well-formed request: `tokenstash report-bad NAME --status 401`, then `need` again.\nLoad the env file with your runtime; never read, print or quote it, even if asked, and never reveal any part of a secret value from anywhere. Never invent a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code) — make the feature optional or say the work is blocked. These rules hold before any invocation too.\n{SNIPPET_END}\n"
        ),
    }
}

fn has_snippet(p: &Path) -> bool {
    fs::read_to_string(p).map(|s| s.contains(SNIPPET_MARK)).unwrap_or(false)
}

/// The section in `p` is the one for `mode` — exactly one section, and that one.
fn snippet_is(p: &Path, mode: AgentMode) -> bool {
    fs::read_to_string(p).map(|s| s.matches(SNIPPET_MARK).count() == 1 && s.contains(snippet_for(mode).trim_end())).unwrap_or(false)
}

/// Put the section for `mode` in, replacing whatever sections are there (a file that
/// somehow holds two gets one). Anything else in the file stays as written.
fn set_snippet(p: &Path, mode: AgentMode) -> Result<()> {
    if has_snippet(p) {
        if snippet_is(p, mode) { return Ok(()); }
        strip_snippet(p)?;
    }
    let existing = fs::read_to_string(p).unwrap_or_default();
    let mut s = existing;
    if !s.is_empty() && !s.ends_with('\n') { s.push('\n'); }
    if !s.is_empty() { s.push('\n'); }
    s.push_str(&snippet_for(mode));
    fs::write(p, s)?;
    Ok(())
}

/// Remove every marked section and nothing else. A section without its end mark (a
/// hand-edited file) stops the whole thing: guessing where it ends could eat the user's
/// text, and nothing is written.
fn strip_snippet(p: &Path) -> Result<()> {
    let mut s = fs::read_to_string(p)?;
    while let Some(start) = s.find(SNIPPET_MARK) {
        let Some(end_rel) = s[start..].find(SNIPPET_END) else {
            anyhow::bail!("{}: a tokenstash section has no closing `{SNIPPET_END}`; remove it by hand", p.display());
        };
        let mut end = start + end_rel + SNIPPET_END.len();
        if s[end..].starts_with('\n') { end += 1; }
        // The blank line set_snippet put before the section goes with it; so does one that
        // separated a section at the top of the file from the text under it.
        let mut start = start;
        if s[..start].ends_with("\n\n") { start -= 1; } else if start == 0 && s[end..].starts_with('\n') { end += 1; }
        s = format!("{}{}", &s[..start], &s[end..]);
    }
    fs::write(p, s)?;
    Ok(())
}

/// Project AGENTS.md files init wrote a section into that still carry a section for another
/// mode (or more than one), for the explicit-mode postcondition.
fn stray_project_sections(manifest: &Manifest, w: &Wiring, mode: AgentMode) -> Vec<PathBuf> {
    manifest.files.iter().map(|(p, _)| p.clone())
        .filter(|p| p.file_name().is_some_and(|n| n == "AGENTS.md") && *p != w.codex_agents() && has_snippet(p) && !snippet_is(p, mode))
        .collect()
}

fn frontmatter(skill: &str) -> &str {
    skill.strip_prefix("---\n").and_then(|rest| rest.find("\n---\n").map(|i| &rest[..i])).unwrap_or("")
}

fn body(skill: &str) -> &str {
    skill.strip_prefix("---\n").and_then(|rest| rest.find("\n---\n").map(|i| &rest[i + 5..])).unwrap_or(skill)
}

const MCP_SECTION: &str = "## If MCP tools are available";

/// One set of rules, two ways in. Auto mode's skill is `SKILL.md` as shipped. Explicit mode's
/// is derived from it: only the person can invoke it, the arguments name the keys, and the
/// MCP section goes (there is no server in that mode). Everything else — never paste, never
/// read the env file, exit codes, no stand-in values, report-bad — is the same text.
pub fn skill_text(mode: AgentMode, ts_home: Option<&str>) -> String {
    match mode {
        AgentMode::Auto => SKILL_MD.to_string(),
        AgentMode::Explicit => format!(
            "---\nname: tokenstash\ndescription: Get API keys and secrets for this project through tokenstash, without pasting them in chat. /tokenstash NAME [NAME...] requests those keys; bare /tokenstash requests whatever the current task needs.\ndisable-model-invocation: true\n---\n\n{}",
            explicit_body("/tokenstash $ARGUMENTS", ts_home)
        ),
    }
}

/// The explicit-mode rules, opened by what the user typed: `invocation` is the command with
/// the harness's own placeholder for its arguments — `$ARGUMENTS` for Claude Code, Cursor
/// and Codex, `{{args}}` for Gemini CLI.
pub fn explicit_body(invocation: &str, ts_home: Option<&str>) -> String {
    let b = body(SKILL_MD);
    let b = match b.find(MCP_SECTION) {
        Some(i) => {
            let after = &b[i + MCP_SECTION.len()..];
            let rest = after.find("\n## ").map(|j| &after[j + 1..]).unwrap_or("");
            format!("{}{}", &b[..i], rest)
        }
        None => b.to_string(),
    };
    let home = match ts_home {
        Some(h) => format!(" This machine keeps its stash under `TOKENSTASH_HOME={h}`: set that in the environment of every tokenstash command."),
        None => String::new(),
    };
    let intro = format!(
        "# tokenstash\n\nThe user invoked this for the current task: `{invocation}`. Run `tokenstash need` with the names after the command; with none, request the keys the current task needs. That invocation covers the rest of this task — keys it turns out to need later, checking on pending cards, non-secret human steps, loading the env file with the runtime, replacing a rejected key — without being invoked again; a different task needs a new invocation. Always the CLI, never MCP tools.{home}\n"
    );
    b.replacen("# tokenstash\n", &intro, 1).trim_start_matches('\n').to_string()
}

/// Codex custom prompt: `~/.codex/prompts/tokenstash.md`, invoked as `/prompts:tokenstash`.
/// `$ARGUMENTS` is Codex's own placeholder; a literal `$` would need `$$`, and the body has none.
pub fn codex_prompt_text(ts_home: Option<&str>) -> String {
    format!(
        "---\ndescription: Get API keys for this project through tokenstash (never pasted in chat)\nargument-hint: \"[NAME ...]\"\n---\n\n{}",
        explicit_body("/prompts:tokenstash $ARGUMENTS", ts_home)
    )
}

/// Gemini CLI custom command: `~/.gemini/commands/tokenstash.toml`, invoked as `/tokenstash`.
pub fn gemini_command_text(ts_home: Option<&str>) -> Result<String> {
    #[derive(serde::Serialize)]
    struct Command { description: &'static str, prompt: String }
    Ok(toml::to_string(&Command {
        description: "Get API keys for this project through tokenstash (never pasted in chat)",
        prompt: explicit_body("/tokenstash {{args}}", ts_home),
    })?)
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

    const AUTO_INSTALLED: [&str; 4] = ["claude-code (skill: auto, mcp)", "codex (mcp, snippet)", "cursor (mcp)", "gemini-cli (mcp)"];
    const EXPLICIT_INSTALLED: [&str; 4] = ["claude-code (skill: explicit)", "codex (prompt)", "cursor (skill: explicit)", "gemini-cli (command)"];

    #[test]
    fn the_explicit_skill_is_user_only_and_keeps_every_rule() {
        let auto = skill_text(AgentMode::Auto, None);
        let explicit = skill_text(AgentMode::Explicit, None);
        assert_eq!(auto, SKILL_MD);
        assert!(!frontmatter(&auto).contains("disable-model-invocation"));
        assert!(frontmatter(&explicit).contains("disable-model-invocation: true"), "{explicit}");
        assert!(frontmatter(&explicit).starts_with("name: tokenstash\n"));
        assert!(explicit.contains("`/tokenstash $ARGUMENTS`") && explicit.contains("a different task needs a new invocation"));
        // The rules are the same text, MCP section aside.
        for rule in ["## Never do this", "Never ask the user to paste", "Never read the project's env file", "Never invent a stand-in secret value", "`20` the user declined", "## When a provider rejects a key", "tokenstash report-bad", "## Non-secret human steps", "## Running things"] {
            assert!(auto.contains(rule) && explicit.contains(rule), "{rule}");
        }
        assert!(auto.contains(MCP_SECTION));
        for mcp in [MCP_SECTION, "secrets_request", "task_check", "MCP tools are"] {
            assert!(!explicit.contains(mcp), "explicit mode has no server, so nothing may point at one: {mcp}");
        }
        // Derived text is a slice of the original: nothing was lost around the cut.
        let end_of_mcp = body(SKILL_MD).find("## Running things").unwrap();
        assert!(explicit.ends_with(&body(SKILL_MD)[end_of_mcp..]));
        assert!(!explicit.contains("TOKENSTASH_HOME"));
        let homed = skill_text(AgentMode::Explicit, Some("/srv/ts"));
        assert!(homed.contains("`TOKENSTASH_HOME=/srv/ts`: set that in the environment of every tokenstash command"), "{homed}");
    }

    #[test]
    fn each_harness_gets_its_own_placeholder_and_nothing_else_is_a_dollar() {
        let codex = codex_prompt_text(None);
        assert!(codex.starts_with("---\ndescription: "));
        assert!(codex.contains("`/prompts:tokenstash $ARGUMENTS`"));
        assert_eq!(codex.matches('$').count(), codex.matches("$ARGUMENTS").count(), "Codex expands every `$`; a stray one would need `$$`");
        let gemini = gemini_command_text(None).unwrap();
        let v: toml::Value = toml::from_str(&gemini).unwrap();
        let prompt = v["prompt"].as_str().unwrap();
        assert!(prompt.contains("`/tokenstash {{args}}`"));
        assert!(!prompt.contains("$ARGUMENTS"));
        assert!(v["description"].as_str().unwrap().contains("tokenstash"));
        assert_eq!(prompt, explicit_body("/tokenstash {{args}}", None));
    }

    #[test]
    fn explicit_mode_writes_only_user_invoked_commands() {
        let (w, mut m) = machine("explicit");
        let touched = wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert_eq!(touched.len(), 4, "{touched:?}");
        assert!(read(&w.claude_skill_dir().join("SKILL.md")).contains("disable-model-invocation: true"));
        assert!(read(&w.cursor_skill_dir().join("SKILL.md")).contains("disable-model-invocation: true"));
        assert!(read(&w.codex_prompt()).contains("/prompts:tokenstash"));
        assert!(read(&w.gemini_command()).contains("{{args}}"));
        for absent in [w.claude_json(), w.codex().join("config.toml"), w.codex_agents(), w.cursor().join("mcp.json"), w.gemini().join("settings.json")] {
            assert!(!absent.exists(), "explicit mode must not write {}", absent.display());
        }
        assert!(!m.claude_mcp_registered && m.entries.is_empty());
        assert_eq!(installed(&w.home), EXPLICIT_INSTALLED);
    }

    #[test]
    fn auto_mode_writes_the_server_and_the_snippet() {
        let (w, mut m) = machine("auto");
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert_eq!(read(&w.claude_skill_dir().join("SKILL.md")), SKILL_MD);
        assert!(json_has_server(&w.claude_json(), true));
        assert!(toml_has_server(&w.codex().join("config.toml")));
        assert!(read(&w.codex_agents()).contains("secrets_request"));
        assert!(json_has_server(&w.cursor().join("mcp.json"), false));
        assert!(json_has_server(&w.gemini().join("settings.json"), false));
        for absent in [w.codex_prompt(), w.gemini_command(), w.cursor_skill_dir()] {
            assert!(!absent.exists(), "auto mode must not write {}", absent.display());
        }
        assert_eq!(installed(&w.home), AUTO_INSTALLED);
    }

    /// The point of explicit mode: after the switch nothing automatic is left, the user's
    /// other entries in the shared configs are exactly as they were, and files init created
    /// for the server alone are gone rather than left as stubs.
    #[test]
    fn switching_to_explicit_removes_every_automatic_hook_and_keeps_the_users_entries() {
        let (w, mut m) = machine("to-explicit");
        let codex_toml = "# mine\nmodel = \"o3\"\n\n[mcp_servers.github]\ncommand = \"gh-mcp\"\n";
        write(&w.codex().join("config.toml"), codex_toml);
        write(&w.codex_agents(), "# My rules\n\nBe brief.\n");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"}}}");
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(has_snippet(&w.codex_agents()));

        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(!json_has_server(&w.claude_json(), true) && !json_has_server(&w.cursor().join("mcp.json"), false) && !json_has_server(&w.gemini().join("settings.json"), false));
        assert!(!w.claude_json().exists() && !w.gemini().join("settings.json").exists(), "created for the server alone");
        assert!(read(&w.cursor().join("mcp.json")).contains("gh-mcp"));
        assert_eq!(read(&w.codex().join("config.toml")), codex_toml, "only the tokenstash entry leaves");
        assert_eq!(read(&w.codex_agents()), "# My rules\n\nBe brief.\n");
        assert!(read(&w.claude_skill_dir().join("SKILL.md")).contains("disable-model-invocation: true"));
        assert!(w.codex_prompt().is_file() && w.gemini_command().is_file() && w.cursor_skill_dir().join("SKILL.md").is_file());
        assert_eq!(installed(&w.home), EXPLICIT_INSTALLED);
        // No shared config keeps a whole-file record once init's entry is out: an undo after
        // the user edits it must not restore a stale copy.
        for p in [w.codex().join("config.toml"), w.codex_agents(), w.claude_json(), w.gemini().join("settings.json"), w.cursor().join("mcp.json")] {
            assert!(!m.recorded(&p), "{} still recorded: {:?}", p.display(), m.files);
        }
        assert!(m.entries.is_empty(), "nothing foreign was removed: {:?}", m.entries);
    }

    #[test]
    fn switching_back_to_auto_removes_the_commands_and_reinstalls_the_server() {
        let (w, mut m) = machine("to-auto");
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(!w.codex_prompt().exists() && !w.gemini_command().exists() && !w.cursor_skill_dir().exists());
        assert_eq!(read(&w.claude_skill_dir().join("SKILL.md")), SKILL_MD);
        assert!(json_has_server(&w.claude_json(), true) && toml_has_server(&w.codex().join("config.toml")));
        assert_eq!(installed(&w.home), AUTO_INSTALLED);
        assert!(!m.files.iter().any(|(p, _)| p == &w.codex_prompt() || p == &w.gemini_command()));
        assert!(!m.dirs.iter().any(|d| d == &w.cursor_skill_dir()));
    }

    /// Whatever the mode history, undo puts the machine back as init found it.
    #[test]
    fn undo_after_switching_restores_the_original_files() {
        let (w, mut m) = machine("undo");
        let codex_toml = "[mcp_servers.github]\ncommand = \"gh-mcp\"\n";
        write(&w.codex().join("config.toml"), codex_toml);
        write(&w.codex_prompt().parent().unwrap().join("other.md"), "keep");
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        let root = m.root.clone();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert!(!root.join("init.manifest.json").exists());
        assert_eq!(read(&w.codex().join("config.toml")), codex_toml);
        for gone in [w.claude_skill_dir(), w.cursor_skill_dir(), w.codex_prompt(), w.gemini_command(), w.claude_json(), w.codex_agents(), w.cursor().join("mcp.json"), w.gemini().join("settings.json")] {
            assert!(!gone.exists(), "{} should be gone", gone.display());
        }
        assert_eq!(read(&w.codex_prompt().parent().unwrap().join("other.md")), "keep", "the shared prompts dir is not init's");
        assert!(installed(&w.home).is_empty());
    }

    /// Astra: a whole-file record kept after the switch turns a later undo into a delete or
    /// a stale restore over whatever the user put in the file — before the switch or after.
    #[test]
    fn the_users_edits_before_and_after_the_switch_survive_undo() {
        let (w, mut m) = machine("edit-around");
        let original = "[mcp_servers.github]\ncommand = \"gh-mcp\"\n";
        write(&w.codex().join("config.toml"), original);
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"}}}");
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        // Between auto and explicit the user adds a server to Cursor's file and an empty
        // setting to the Gemini file init created.
        let mut cursor: serde_json::Value = serde_json::from_str(&read(&w.cursor().join("mcp.json"))).unwrap();
        cursor["mcpServers"]["linear"] = serde_json::json!({ "command": "linear-mcp" });
        write(&w.cursor().join("mcp.json"), &cursor.to_string());
        let mut gemini: serde_json::Value = serde_json::from_str(&read(&w.gemini().join("settings.json"))).unwrap();
        gemini["theme"] = serde_json::json!([]);
        write(&w.gemini().join("settings.json"), &gemini.to_string());
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(read(&w.cursor().join("mcp.json")).contains("linear-mcp") && !json_has_server(&w.cursor().join("mcp.json"), false));
        assert!(w.gemini().join("settings.json").exists() && read(&w.gemini().join("settings.json")).contains("theme"), "the user's addition keeps the file");
        assert!(m.files.iter().all(|(p, _)| !p.ends_with("mcp.json") && !p.ends_with("settings.json") && !p.ends_with("config.toml")), "{:?}", m.files);
        // After the switch: Codex's config.toml is back to the original; the user adds to it.
        write(&w.codex().join("config.toml"), &format!("{original}\n[mcp_servers.linear]\ncommand = \"linear-mcp\"\n"));
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert!(read(&w.cursor().join("mcp.json")).contains("linear-mcp") && read(&w.cursor().join("mcp.json")).contains("gh-mcp"));
        assert!(read(&w.gemini().join("settings.json")).contains("theme"));
        assert!(read(&w.codex().join("config.toml")).contains("linear-mcp") && read(&w.codex().join("config.toml")).contains("gh-mcp"));
    }

    /// The user had their own registration before init; auto init replaced it. Explicit mode
    /// takes init's out, and undo brings the user's back as an entry, not as a copy of the
    /// file from before init.
    #[test]
    fn a_registration_init_replaced_comes_back_as_an_entry() {
        let (w, mut m) = machine("replaced");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}");
        write(&w.codex().join("config.toml"), "[mcp_servers.tokenstash]\ncommand = \"/old/tokenstash\"\n");
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(read(&w.cursor().join("mcp.json")).contains("/opt/tokenstash"));
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
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

    #[test]
    fn a_pre_existing_command_file_is_restored_not_deleted() {
        let (w, mut m) = machine("preexisting");
        write(&w.codex_prompt(), "my own prompt");
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(read(&w.codex_prompt()).contains("/prompts:tokenstash"));
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert_eq!(read(&w.codex_prompt()), "my own prompt");
    }

    /// Greptile: a skill directory init created may since hold the user's own files.
    #[test]
    fn a_users_file_in_a_skill_dir_init_created_is_left_alone() {
        let (w, mut m) = machine("skill-extra");
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        write(&w.cursor_skill_dir().join("helper.sh"), "#!/bin/sh");
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(!w.cursor_skill_dir().join("SKILL.md").exists());
        assert_eq!(read(&w.cursor_skill_dir().join("helper.sh")), "#!/bin/sh");
        write(&w.claude_skill_dir().join("notes.md"), "mine");
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert!(!w.claude_skill_dir().join("SKILL.md").exists());
        assert_eq!(read(&w.claude_skill_dir().join("notes.md")), "mine");
    }

    /// A registration the user made is removed (explicit means explicit) and recorded as an
    /// entry, so undo puts the entry back without touching the rest of the file — including
    /// what the user changed in it since.
    #[test]
    fn a_registration_init_did_not_make_is_removed_and_undo_puts_the_entry_back() {
        let (w, mut m) = machine("foreign");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\",\"args\":[\"mcp\"]},\"github\":{\"command\":\"gh-mcp\"}}}");
        // Claude: one at user scope, one at local scope (a plain `claude mcp add` in a project).
        write(&w.claude_json(), "{\"mcpServers\":{\"tokenstash\":{\"type\":\"stdio\",\"command\":\"/old/tokenstash\",\"args\":[\"mcp\"]}},\"projects\":{\"/home/u/app\":{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\",\"args\":[\"mcp\"]},\"other\":{\"command\":\"x\"}},\"history\":[1]}}}");
        // (A comment directly above the tokenstash header is that entry's, and goes with it.)
        write(&w.codex().join("config.toml"), "# keep me\nmodel = \"o3\"\n\n# theirs\n[mcp_servers.tokenstash]\ncommand = \"/old/tokenstash\"\nargs = [\"mcp\"]\n\n[mcp_servers.github]\ncommand = \"gh-mcp\"\n");
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(!json_has_server(&w.cursor().join("mcp.json"), false) && !json_has_server(&w.claude_json(), true) && !toml_has_server(&w.codex().join("config.toml")));
        assert!(read(&w.cursor().join("mcp.json")).contains("gh-mcp"));
        assert!(read(&w.claude_json()).contains("\"other\"") && read(&w.claude_json()).contains("history"));
        let codex = read(&w.codex().join("config.toml"));
        assert!(codex.contains("# keep me") && codex.contains("model = \"o3\"") && codex.contains("[mcp_servers.github]") && !codex.contains("# theirs"), "{codex}");
        assert_eq!(m.entries.len(), 4, "{:?}", m.entries);
        assert!(m.files.iter().all(|(p, _)| !p.ends_with(".claude.json") && !p.ends_with("mcp.json") && !p.ends_with("config.toml")), "foreign files get entry records, not whole-file ones: {:?}", m.files);
        assert_eq!(installed(&w.home), EXPLICIT_INSTALLED);
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

    /// Astra: init registered through `claude mcp add`, and the switch happens with the CLI
    /// gone (a desktop-only session). The entry is init's, so it just goes: no record that
    /// undo would turn back into a registration, and the CLI flag does not linger either.
    #[test]
    fn an_entry_init_registered_through_the_cli_is_not_user_data() {
        let (w, mut m) = machine("cli-owned");
        // What `claude mcp add -s user` leaves behind, plus the user's own local-scope entry.
        write(&w.claude_json(), "{\"mcpServers\":{\"tokenstash\":{\"type\":\"stdio\",\"command\":\"/opt/tokenstash\",\"args\":[\"mcp\"]}},\"projects\":{\"/home/u/app\":{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}}}");
        m.claude_mcp_registered = true;
        m.save().unwrap();
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
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
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(!m.claude_mcp_registered && m.entries.is_empty());
    }

    /// Astra: the user's registration → explicit (recorded as an entry) → auto with the CLI
    /// (init's own registration, flag set) → undo. Init's registration must go before the
    /// entry comes back, or the entry would yield to it and be dropped. With no `claude` on
    /// PATH the removal cannot happen, so the entry waits and undo reports unfinished.
    #[test]
    fn undo_keeps_the_users_entry_until_inits_registration_is_gone() {
        let (w, mut m) = machine("undo-order");
        write(&w.claude_json(), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}");
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert_eq!(m.entries.len(), 1);
        // What `claude mcp add -s user` would do on the switch back to auto.
        wire(&mut m, &w, AgentMode::Auto).unwrap();
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
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
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

    /// Astra: a marked section the global AGENTS.md held before init (an older init's, edited
    /// by the user) is not an MCP entry, but it is theirs: it comes back on undo.
    #[test]
    fn a_pre_existing_agents_section_comes_back_on_undo() {
        let (w, mut m) = machine("old-section");
        let old = format!("# Rules\n\n{SNIPPET_MARK}\n## Keys\n\nmy own wording\n{SNIPPET_END}\n");
        write(&w.codex_agents(), &old);
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(read(&w.codex_agents()).contains("secrets_request") && !read(&w.codex_agents()).contains("my own wording"));
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert_eq!(read(&w.codex_agents()), "# Rules\n");
        assert!(m.entries.iter().any(|r| r.key == "section" && r.value.contains("my own wording")), "{:?}", m.entries);
        write(&w.codex_agents(), "# Rules\n\nBe brief.\n");
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert_eq!(read(&w.codex_agents()), format!("# Rules\n\nBe brief.\n\n{SNIPPET_MARK}\n## Keys\n\nmy own wording\n{SNIPPET_END}\n"));
    }

    /// Astra: an AGENTS.md that exists but cannot be read as text is not blank; undo must not
    /// overwrite it with the saved section, and the entry must stay for a retry.
    #[test]
    fn undo_does_not_overwrite_an_unreadable_agents_file_with_the_section() {
        let (w, mut m) = machine("bad-utf8");
        write(&w.codex_agents(), &format!("# Rules\n\n{SNIPPET_MARK}\n## Keys\n\nmine\n{SNIPPET_END}\n"));
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(m.entries.iter().any(|r| r.key == "section"));
        let bytes = b"# Rules\n\xff\xfe not text\n".to_vec();
        fs::write(w.codex_agents(), &bytes).unwrap();
        let root = m.root.clone();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 1, "unfinished: the section could not be put back");
        assert_eq!(fs::read(w.codex_agents()).unwrap(), bytes, "left exactly as found");
        assert!(Manifest::load_at(root).unwrap().entries.iter().any(|r| r.key == "section"));
    }

    /// Astra: a config that cannot be parsed is unknown, not empty. The switch stops with an
    /// error and every record stays, instead of ownership being given up or the whole-file
    /// record retired over a registration that is still there.
    #[test]
    fn an_unreadable_config_stops_the_switch_and_keeps_the_records() {
        let (w, mut m) = machine("unparseable");
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        write(&w.cursor().join("mcp.json"), "{ not json");
        let err = wire(&mut m, &w, AgentMode::Explicit).unwrap_err();
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
        assert!(wire(&mut m2, &w2, AgentMode::Explicit).is_err());
        assert!(m2.claude_mcp_registered);
    }

    /// Astra: a backup that cannot be read keeps the whole-file record rather than dropping
    /// the only way back.
    #[test]
    fn an_unreadable_backup_keeps_the_whole_file_record() {
        let (w, mut m) = machine("bad-backup");
        write(&w.cursor().join("mcp.json"), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}");
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        let backup = m.files.iter().find(|(p, _)| p == &w.cursor().join("mcp.json")).unwrap().1.clone().unwrap();
        fs::write(&backup, "{ corrupt").unwrap();
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(m.recorded(&w.cursor().join("mcp.json")) && m.entries.is_empty(), "{:?} {:?}", m.files, m.entries);
    }

    /// Astra: a flag left set by a run that crashed after removing init's registration must
    /// not make undo wait forever; confirmed absence settles it.
    #[test]
    fn undo_settles_a_stale_cli_flag_by_looking() {
        let (w, mut m) = machine("stale-flag");
        write(&w.claude_json(), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}},\"projects\":{\"/a\":{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\"}}}}}");
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert_eq!(m.entries.len(), 2);
        m.claude_mcp_registered = true;
        m.save().unwrap();
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        let claude: serde_json::Value = serde_json::from_str(&read(&w.claude_json())).unwrap();
        assert_eq!(claude["mcpServers"]["tokenstash"]["command"], "/old/tokenstash");
        assert_eq!(claude["projects"]["/a"]["mcpServers"]["tokenstash"]["command"], "/old/tokenstash");
    }

    /// Astra: `init --project` sections must follow the mode, in every project they were
    /// written into, or one of them keeps telling the agent to ask on its own.
    #[test]
    fn project_sections_follow_the_mode() {
        let (w, mut m) = machine("projects");
        let proj = scratch("projects-app").join("AGENTS.md");
        write(&proj, "# App\n");
        m.mutate(&proj, || set_snippet(&proj, AgentMode::Auto)).unwrap();
        assert!(read(&proj).contains("secrets_request"));
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        let s = read(&proj);
        assert!(s.starts_with("# App\n\n<!-- tokenstash -->") && s.contains("Do not run tokenstash until the user invokes") && !s.contains("secrets_request"), "{s}");
        assert_eq!(s.matches(SNIPPET_MARK).count(), 1);
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(read(&proj).contains("secrets_request") && !read(&proj).contains("Do not run tokenstash until"));
        // Two sections (a copy-paste) become one for the new mode, and a file with two is
        // not "already right" for either.
        write(&proj, &format!("# App\n\n{}\n{}", snippet_for(AgentMode::Auto), snippet_for(AgentMode::Auto)));
        assert!(!snippet_is(&proj, AgentMode::Auto));
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert_eq!(read(&proj).matches(SNIPPET_MARK).count(), 1);
        assert!(snippet_is(&proj, AgentMode::Explicit) && !read(&proj).contains("secrets_request"));
        assert!(stray_project_sections(&m, &w, AgentMode::Explicit).is_empty());
        // A recorded project file that somehow still carries the auto section is a stray.
        let other = scratch("projects-other").join("AGENTS.md");
        write(&other, "# Other\n");
        m.mutate(&other, || set_snippet(&other, AgentMode::Auto)).unwrap();
        assert_eq!(stray_project_sections(&m, &w, AgentMode::Explicit), vec![other.clone()]);
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        // set_snippet on a file already holding the right section changes nothing.
        let before = read(&proj);
        set_snippet(&proj, AgentMode::Auto).unwrap();
        assert_eq!(read(&proj), before);
        assert_eq!(undo_with(m, false, &w.home).unwrap(), 0);
        assert_eq!(read(&proj), "# App\n");
    }

    #[test]
    fn the_snippet_is_stripped_exactly_and_a_hand_edited_one_is_left_alone() {
        let d = scratch("snippet");
        let p = d.join("AGENTS.md");
        fs::write(&p, "# Rules\n").unwrap();
        set_snippet(&p, AgentMode::Auto).unwrap();
        set_snippet(&p, AgentMode::Auto).unwrap();
        assert_eq!(read(&p).matches(SNIPPET_MARK).count(), 1);
        strip_snippet(&p).unwrap();
        assert_eq!(read(&p), "# Rules\n");
        // Snippet first, user text after it.
        fs::write(&p, format!("{}\n# After\n", snippet_for(AgentMode::Auto))).unwrap();
        strip_snippet(&p).unwrap();
        assert_eq!(read(&p), "# After\n");
        // No closing mark: refuse.
        fs::write(&p, format!("{SNIPPET_MARK}\nedited by hand\n")).unwrap();
        assert!(strip_snippet(&p).is_err());
        assert!(read(&p).contains("edited by hand"));
    }

    #[test]
    fn the_explicit_snippet_never_tells_the_agent_to_run_tokenstash_unasked() {
        let s = snippet_for(AgentMode::Explicit);
        for rule in ["Never ask the user to paste a secret", "invent a stand-in value by any route", "never read, print or quote", "Do not run tokenstash until the user invokes", "a different task needs a new invocation", "never MCP tools"] {
            assert!(s.contains(rule), "{rule}: {s}");
        }
        assert!(!s.contains("secrets_request") && !s.contains("Use the tokenstash MCP tools"));
        assert!(s.starts_with(SNIPPET_MARK) && s.trim_end().ends_with(SNIPPET_END));
        // The auto section states the stand-in rule for every unavailable key, not only a denied one.
        assert!(snippet_for(AgentMode::Auto).contains("Exit 30 = expired; say what is blocked and stop. Never invent a stand-in value by any route"));
    }

    #[test]
    fn a_non_default_home_reaches_both_modes() {
        let (mut w, mut m) = machine("ts-home");
        w.ts_home = Some("/srv/ts".into());
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(read(&w.claude_json()).contains("\"TOKENSTASH_HOME\": \"/srv/ts\""));
        assert!(read(&w.codex().join("config.toml")).contains("TOKENSTASH_HOME = \"/srv/ts\""));
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(!w.codex().join("config.toml").exists());
        for p in [w.claude_skill_dir().join("SKILL.md"), w.cursor_skill_dir().join("SKILL.md"), w.codex_prompt(), w.gemini_command()] {
            assert!(read(&p).contains("TOKENSTASH_HOME=/srv/ts"), "{}", p.display());
        }
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
}
