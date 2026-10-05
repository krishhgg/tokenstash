//! `export` / `import`: move a stash between machines as one passphrase-encrypted file.
//! Human-only, interactive: the passphrase is prompted (never a flag, never an env var — both
//! land in `ps`, shell history, crash reports), and the export is confirmed twice so a typo
//! cannot brick the only copy.

use crate::util::App;
use anyhow::{bail, Context, Result};
use clap::Args;
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};
use tokenstash_core::bundle::{self, Binding, Entry, Payload_};
use tokenstash_core::stash::stash_key;

#[derive(Args)]
pub struct ExportArgs {
    /// Where to write the bundle (default: ./tokenstash.bundle).
    #[arg(short, long)]
    pub out: Option<PathBuf>,
    /// Instead of writing a bundle: scan a directory tree for env files and import the keys
    /// found there into the stash (onboarding). Interactive, for a person at a terminal — the
    /// table is an inventory of what you have, and a pty defeats the terminal check.
    #[arg(long, value_name = "DIR", conflicts_with = "out")]
    pub from_env: Option<PathBuf>,
    /// With --from-env: identity for everything imported.
    #[arg(long, default_value = "default", requires = "from_env")]
    pub identity: String,
    /// With --from-env: skip the liveness sweep afterwards (see import --no-verify).
    #[arg(long, requires = "from_env")]
    pub no_verify: bool,
}

pub fn export(a: ExportArgs) -> Result<i32> {
    if let Some(dir) = a.from_env {
        return from_env(FromEnvArgs { dir, identity: a.identity, no_verify: a.no_verify });
    }
    crate::util::require_human("export", "it handles every value in the stash")?;
    let app = App::open()?;
    let out = a.out.unwrap_or_else(|| PathBuf::from("tokenstash.bundle"));
    let out = if out.is_absolute() { out } else { std::env::current_dir()?.join(out) };
    let out = refuse_bad_destination(&out, &app.cfg.env_file)?;
    let secrets = app.db.list_secrets()?;
    if secrets.is_empty() {
        println!("nothing indexed in this home; nothing to export");
        return Ok(0);
    }
    let mut entries = Vec::with_capacity(secrets.len());
    let mut missing = 0usize;
    for m in &secrets {
        match app.stash.get(&stash_key(&m.name, &m.identity))? {
            Some(v) => entries.push(Entry { name: m.name.clone(), identity: m.identity.clone(), value: v.expose_secret().to_string(), provider: m.provider.clone(), sensitive: m.sensitive, source_url: m.source_url.clone(), created: m.created.clone(), last_used: m.last_used.clone(), stale: m.stale, stale_reason: m.stale_reason.clone(), stale_source: m.stale_source.clone(), verify_off: m.verify_off }),
            None => missing += 1,
        }
    }
    let bindings = app.db.list_bindings()?.into_iter().map(|(project, name, identity)| Binding { project, name, identity }).collect();
    let payload = Payload_ { created: tokenstash_core::now(), tool_version: env!("CARGO_PKG_VERSION").into(), entries, bindings };

    println!("Exporting {} of {} indexed secrets{} to {}", payload.entries.len(), secrets.len(), if missing > 0 { format!(" ({missing} indexed but not in the stash, skipped)") } else { String::new() }, out.display());
    println!("Choose a passphrase (12+ characters), or press Enter to generate one.");
    let pw = rpassword::prompt_password("passphrase: ")?;
    let pw = if pw.is_empty() {
        // `require_human` above already proved stdout is a terminal, so the generated
        // passphrase cannot land in a file or a pipe.
        let g = bundle::generate_passphrase();
        println!("\nGenerated passphrase — write it down now, it is shown once:\n\n    {}\n", g.expose_secret());
        g
    } else {
        let again = rpassword::prompt_password("again: ")?;
        if again != pw { bail!("passphrases do not match; nothing written"); }
        SecretString::from(pw)
    };
    let bytes = bundle::seal(&payload, &pw)?;
    tokenstash_core::fsutil::write_atomic_private_bytes(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;
    app.db.audit(None, None, "export", None, None, Some(&format!("{} entries to {}", payload.entries.len(), out.display())))?;
    println!("✓ wrote {} ({} bytes, 0600). Move it with your own channel; delete it when the import is done.", out.display(), bytes.len());
    Ok(0)
}

/// A bundle holds every value: never into a device/pipe, a git-tracked path, a checkout
/// owned by someone else (owned_git_root's hard error propagates), or a project's env-file
/// name (a bundle is not an env file, and that name is what agents read).
fn refuse_bad_destination(p: &Path, env_file: &str) -> Result<PathBuf> {
    let Some(file_name) = p.file_name() else { bail!("{} is not a file path", p.display()) };
    if file_name.to_string_lossy() == env_file {
        bail!("refusing to write the bundle as {}: that is the env-file name agents read", p.display());
    }
    // Resolve the parent first: the checks below and the rename that follows must look at
    // the same directory, and a symlinked parent would otherwise let the rename land in a
    // checkout the lexical check never saw.
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let parent = parent.canonicalize().with_context(|| format!("{} does not exist", parent.display()))?;
    let resolved = parent.join(file_name);
    if resolved.starts_with("/dev") || resolved.starts_with("/proc") || resolved.starts_with("/sys") { bail!("refusing to write the bundle to {}", resolved.display()); }
    if let Some(root) = tokenstash_core::envfile::owned_git_root(&parent)? {
        if tokenstash_core::envfile::is_git_tracked(&root, &resolved) {
            bail!("{} is tracked by git; refusing to write a bundle there", resolved.display());
        }
        eprintln!("note: {} is inside a git repo — make sure the bundle is never committed", resolved.display());
    }
    Ok(resolved)
}

#[derive(Args)]
pub struct ImportArgs {
    pub bundle: PathBuf,
    /// On a conflict (same name, different value) keep what this machine has.
    #[arg(long, conflicts_with = "replace")]
    pub keep_existing: bool,
    /// On a conflict, take the bundle's value.
    #[arg(long)]
    pub replace: bool,
    /// Skip the liveness sweep after import. Imported keys are then not re-checked before use
    /// either, until `tokenstash check` accepts them.
    #[arg(long)]
    pub no_verify: bool,
    /// Also apply the bundle's project bindings (which identity a project uses). Off by
    /// default: a binding changes which value a project receives, so it is listed, not applied.
    #[arg(long)]
    pub apply_bindings: bool,
}

pub fn import(a: ImportArgs) -> Result<i32> {
    crate::util::require_human("import", "it handles every value in the stash")?;
    let app = App::open()?;
    let size = std::fs::metadata(&a.bundle).with_context(|| format!("reading {}", a.bundle.display()))?.len();
    if size as usize > bundle::MAX_BUNDLE_BYTES {
        bail!("{} is {size} bytes; a bundle is never that large", a.bundle.display());
    }
    let bytes = std::fs::read(&a.bundle).with_context(|| format!("reading {}", a.bundle.display()))?;
    let pw = SecretString::from(rpassword::prompt_password("passphrase: ")?);
    let payload = bundle::open(&bytes, &pw)?;
    println!("bundle from {} ({} entries, {} bindings)", payload.created, payload.entries.len(), payload.bindings.len());

    // 1. validate everything before touching anything: one bad entry refuses the whole file
    if payload.entries.len() > bundle::MAX_ENTRIES {
        bail!("bundle has {} entries; refusing more than {}", payload.entries.len(), bundle::MAX_ENTRIES);
    }
    for e in &payload.entries {
        bundle::validate_entry(e).context("refusing the whole import")?;
        // What a paste would have rejected, an import rejects too.
        if let Some(pat) = tokenstash_core::registry::lookup(&e.name).and_then(|p| p.pattern.as_ref()) {
            if !tokenstash_core::validate::matches_pattern(pat, &SecretString::from(e.value.clone()))? {
                bail!("entry {}@{} does not match the expected shape for {}; refusing the whole import", e.name, e.identity, e.name);
            }
        }
    }
    // 2. resolve conflicts, one question per name, before applying
    #[derive(PartialEq)] enum Plan { Add, Skip, Replace, CarryRotation }
    let mut plan: Vec<(Plan, &Entry)> = vec![];
    for e in &payload.entries {
        let existing = app.stash.get(&stash_key(&e.name, &e.identity))?;
        let p = match existing {
            None => Plan::Add,
            Some(v) if v.expose_secret() == e.value => {
                // Same value: nothing to store, but a rotation the user asked for on the
                // other machine must not be lost here. Decided now, written in the apply
                // step with everything else — planning changes nothing.
                if e.stale && e.stale_reason.as_deref().unwrap_or("").starts_with(tokenstash_core::db::Db::ROTATE_REASON)
                    && !app.db.get_secret(&e.name, &e.identity)?.map(|m| m.stale).unwrap_or(false)
                { Plan::CarryRotation } else { Plan::Skip }
            }
            Some(_) => {
                if a.keep_existing { Plan::Skip } else if a.replace { Plan::Replace } else {
                    let local = app.db.get_secret(&e.name, &e.identity)?;
                    print!("{}@{} differs from what this machine has (here: stored {}{}; bundle: stored {}{}) — replace it? [y/N] ",
                        e.name, e.identity,
                        local.as_ref().map(|m| m.created.clone()).unwrap_or_default(), if local.as_ref().map(|m| m.stale).unwrap_or(false) { ", STALE" } else { "" },
                        e.created, if e.stale { ", stale" } else { "" });
                    use std::io::Write;
                    std::io::stdout().flush()?;
                    let mut ans = String::new();
                    std::io::stdin().read_line(&mut ans)?;
                    if ans.trim().eq_ignore_ascii_case("y") { Plan::Replace } else { Plan::Skip }
                }
            }
        };
        plan.push((p, e));
    }
    // 3. apply: stash first (the value's home), then the index. No approvals — import is not
    //    per-project consent. No env-file writes.
    let (mut added, mut replaced, mut skipped) = (0, 0, 0);
    for (p, e) in &plan {
        match p {
            Plan::Skip => { skipped += 1; continue; }
            Plan::CarryRotation => {
                app.db.mark_stale(&e.name, &e.identity, true, e.stale_reason.as_deref(), Some(stale_source_of(e)))?;
                println!("  {}@{}: same value, marked for rotation as on the exporting machine", e.name, e.identity);
                skipped += 1;
                continue;
            }
            Plan::Add => added += 1,
            Plan::Replace => replaced += 1,
        }
        apply_entry(&app, e, &format!("from {}", a.bundle.display()), a.no_verify)?;
    }
    let mut bound = 0;
    for b in &payload.bindings {
        let dir = Path::new(&b.project);
        if !dir.is_absolute() || !dir.is_dir() { continue; }
        if a.apply_bindings {
            // Bindings hang off workspaces now; a directory that was never paired here
            // gets its binding when it is (the value is listed, not applied).
            let Some(ws) = app.db.find_workspace(dir)? else {
                println!("  binding NOT applied (directory not paired on this machine yet): {} → {}@{}", tokenstash_core::project::short(dir), b.name, b.identity);
                continue;
            };
            app.db.set_binding(&ws.id, &b.name, &b.identity)?;
            bound += 1;
            println!("  binding applied: {} → {}@{}", tokenstash_core::project::short(dir), b.name, b.identity);
        } else {
            println!("  binding NOT applied (use --apply-bindings): {} → {}@{}", tokenstash_core::project::short(dir), b.name, b.identity);
        }
    }
    println!("✓ {added} added, {replaced} replaced, {skipped} unchanged; {bound} of {} bindings applied", payload.bindings.len());
    // Keys that arrived stale are already a miss; verifying them gains nothing, and a probe
    // saying "still live" must not un-stale a rotation the user asked for on the old machine.
    // Also re-probe a key that was skipped as identical but is stale HERE and fresh in the
    // bundle: the other machine may have a working copy of the same value.
    let mut pairs: Vec<(String, String)> = plan.iter().filter(|(p, e)| *p != Plan::Skip && !e.stale).map(|(_, e)| (e.name.clone(), e.identity.clone())).collect();
    for (p, e) in &plan {
        if *p == Plan::Skip && !e.stale && app.db.get_secret(&e.name, &e.identity)?.map(|m| m.stale && m.stale_source.as_deref() != Some(tokenstash_core::db::STALE_ROTATE)).unwrap_or(false) {
            pairs.push((e.name.clone(), e.identity.clone()));
        }
    }
    drop(plan);
    drop(payload);

    // 4. verify after everything is stored, never before: a network failure must not leave a
    //    half-imported stash. Same sweep as `tokenstash check`.
    if !a.no_verify && !pairs.is_empty() {
        println!("verifying imported keys against their providers (--no-verify to skip)…");
        crate::cmd::admin::sweep_pairs(&app, &pairs, true)?;
    }
    println!("delete {} when you are done with it", a.bundle.display());
    Ok(0)
}

/// Store one entry: stash first (the value's home), then the index, then an audit row with
/// the source. Never an approval, never an env-file write. Shared by `import` and
/// `export --from-env`.
/// The bundle carries the display reason only; the human's rotation is the one source
/// that must survive the trip (a probe saying "live" must not cancel it on the new machine).
fn stale_source_of(e: &Entry) -> &'static str {
    match e.stale_source.as_deref() {
        Some(tokenstash_core::db::STALE_ROTATE) => tokenstash_core::db::STALE_ROTATE,
        Some(tokenstash_core::db::STALE_PROBE) => tokenstash_core::db::STALE_PROBE,
        Some(_) => tokenstash_core::db::STALE_REPORT,
        // older bundle: only the human's rotation has a fixed text
        None if e.stale_reason.as_deref().unwrap_or("").starts_with(tokenstash_core::db::Db::ROTATE_REASON) => tokenstash_core::db::STALE_ROTATE,
        None => tokenstash_core::db::STALE_REPORT,
    }
}

pub fn apply_entry(app: &App, e: &Entry, source: &str, no_verify: bool) -> Result<()> {
    let provider = tokenstash_core::registry::lookup(&e.name);
    let value = SecretString::from(e.value.clone());
    // Sensitivity is re-derived here exactly as a paste derives it; the source cannot
    // downgrade a registry-sensitive name or a live-mode value.
    let by_registry = tokenstash_core::registry::is_sensitive(provider, &value)?;
    // The stash write, its index row and the audit line share the index write lock, as a
    // store's do. A probe verdict reads the stash and updates the row under that lock
    // (`tasks::if_still_stored`), so it cannot read the old value, miss this write, and then
    // record the old key's answer against the imported one.
    app.db.locked(|| {
        app.stash.set(&stash_key(&e.name, &e.identity), &value)?;
        app.db.upsert_secret(&tokenstash_core::db::SecretMeta {
            name: e.name.clone(), identity: e.identity.clone(),
            provider: e.provider.clone().or_else(|| provider.map(|p| p.provider.clone())),
            sensitive: e.sensitive || by_registry,
            source_url: e.source_url.clone().or_else(|| provider.map(|p| p.url.clone())),
            created: e.created.clone(), last_used: e.last_used.clone(), stale: e.stale,
            last_verified: None,
            stale_reason: if e.stale { e.stale_reason.clone().or_else(|| Some("stale at the source".into())) } else { None },
            stale_source: if e.stale { Some(stale_source_of(e).into()) } else { None },
            next_probe: None,
            // An import that skipped the sweep is the human saying "do not check these": the
            // sweep, when it runs, clears this for every key the provider accepts.
            verify_off: no_verify || e.verify_off,
        })?;
        app.db.audit(None, None, "import", Some(&e.name), Some(&e.identity), Some(source))
    })
}

/// Built from `ExportArgs` (`export --from-env DIR`); not a clap surface of its own.
pub struct FromEnvArgs {
    /// Directory tree to scan for .env / .env.local / .env.{stage} / .envrc files.
    pub dir: PathBuf,
    /// Identity for everything imported (distinct values under one name get a numbered suffix).
    pub identity: String,
    /// Skip the liveness sweep afterwards.
    pub no_verify: bool,
}

/// Onboarding: find the keys already scattered across a person's projects and stash the
/// ones they tick. Human-only and interactive by design — the table is an inventory of
/// what the person has, and ticking rows is consent. There is no MCP tool for this and
/// no non-interactive switch.
pub fn from_env(a: FromEnvArgs) -> Result<i32> {
    crate::util::require_human("export --from-env", "it handles every value in the stash")?;
    let app = App::open()?;
    let root = a.dir.canonicalize().with_context(|| format!("{} does not exist", a.dir.display()))?;
    println!("scanning {} …", tokenstash_core::envcrawl::display_path(&root));
    let c = tokenstash_core::envcrawl::crawl(&root);
    for p in &c.problems { eprintln!("  note: {p}"); }
    if c.candidates.is_empty() {
        println!("scanned {} env files; nothing that looks like a key", c.files_scanned);
        return Ok(0);
    }
    println!("scanned {} env files; {} distinct values found\n", c.files_scanned, c.candidates.len());
    use tokenstash_core::envcrawl::{display_path, is_ambiguous, Confidence};
    let short = |p: &Path| display_path(Path::new(&tokenstash_core::project::short(p)));
    // What each row means, decided once: ticked by default only when it is a registry match
    // with exactly one value for that name and nothing in the stash yet.
    let mut ticked: Vec<bool> = vec![];
    let mut differs: Vec<bool> = vec![];
    for (i, cand) in c.candidates.iter().enumerate() {
        let identity = tokenstash_core::envcrawl::identity_for(&c.candidates, i, &a.identity);
        let existing = app.stash.get(&stash_key(&cand.name, &identity))?;
        let ambiguous = is_ambiguous(&c.candidates, i);
        let (default_on, note) = match (&cand.confidence, &existing) {
            (_, Some(v)) if v.expose_secret() == cand.value.expose_secret() => (false, "already in the stash".to_string()),
            (_, Some(_)) => (false, "DIFFERS from the stash — you will be asked before it replaces anything".to_string()),
            (Confidence::Registry, None) if ambiguous => (false, format!("{} — several different values under this name; pick the real one", cand.provider.clone().unwrap_or_default())),
            (Confidence::Registry, None) => (true, cand.provider.clone().unwrap_or_default()),
            (Confidence::RegistryShapeMismatch, None) => (false, format!("{} — does not look like a real key (placeholder?)", cand.provider.clone().unwrap_or_default())),
            (Confidence::Heuristic, None) => (false, "unregistered; looks like a secret".to_string()),
        };
        ticked.push(default_on);
        differs.push(matches!((&cand.confidence, &existing), (_, Some(v)) if v.expose_secret() != cand.value.expose_secret()));
        // The row is identified by its number, its name and where it was found — never by any
        // part of the value. A first-and-last-characters preview is still a piece of the key,
        // and this table is printed to a terminal an agent may be driving through a pty.
        let srcs: Vec<String> = cand.sources.iter().take(3).map(|p| short(p)).collect();
        let more = if cand.sources.len() > 3 { format!(" +{} more", cand.sources.len() - 3) } else { String::new() };
        let which = if ambiguous { format!(" (value #{} of the {} found under this name)", identity_index(&c.candidates, i), c.candidates.iter().filter(|x| x.name == cand.name).count()) } else { String::new() };
        let alias = if cand.aliases.is_empty() { String::new() } else { format!(" (also as {})", cand.aliases.join(", ")) };
        println!("{:>3}. [{}] {}{}{}{}  {}", i + 1, if default_on { "x" } else { " " }, cand.name, which, alias, if cand.sensitive { "  SENSITIVE (asks once per project)" } else { "" }, note);
        println!("       in {}{}", srcs.join(", "), more);
    }
    let on: Vec<String> = ticked.iter().enumerate().filter(|(_, t)| **t).map(|(i, _)| (i + 1).to_string()).collect();
    println!("\nticked by default: {}", if on.is_empty() { "none".into() } else { on.join(" ") });
    println!("Type numbers to toggle (e.g. `3 7`, `1-5`), `all`, `none`; Enter when done; `q` to quit.");
    loop {
        print!("> ");
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let t = line.trim();
        if t == "q" { println!("nothing imported"); return Ok(0); }
        if t.is_empty() { break; }
        // `all` never flips a row that would replace something already in the stash
        if t == "all" { for (i, x) in ticked.iter_mut().enumerate() { if !differs[i] { *x = true; } } }
        else if t == "none" { ticked.iter_mut().for_each(|x| *x = false); }
        else {
            for tok in t.split_whitespace() {
                if let Some((lo, hi)) = tok.split_once('-') {
                    if let (Ok(lo), Ok(hi)) = (lo.parse::<usize>(), hi.parse::<usize>()) {
                        for n in lo.max(1)..=hi.min(ticked.len()) { ticked[n - 1] = !ticked[n - 1]; }
                        continue;
                    }
                }
                match tok.parse::<usize>() { Ok(n) if n >= 1 && n <= ticked.len() => ticked[n - 1] = !ticked[n - 1], _ => println!("  ? {tok}") }
            }
        }
        let on: Vec<String> = ticked.iter().enumerate().filter(|(_, t)| **t).map(|(i, _)| (i + 1).to_string()).collect();
        println!("  ticked: {}", if on.is_empty() { "none".into() } else { on.join(" ") });
    }
    // Explicit confirmation, with the rows named: a stray Enter must not import anything.
    let chosen: Vec<usize> = (0..ticked.len()).filter(|&i| ticked[i]).collect();
    if chosen.is_empty() { println!("nothing ticked; nothing imported"); return Ok(0); }
    println!("\nabout to import {} key(s):", chosen.len());
    for &i in &chosen {
        let identity = tokenstash_core::envcrawl::identity_among(&c.candidates, i, &a.identity, |j| ticked[j]);
        let replaces = app.stash.get(&stash_key(&c.candidates[i].name, &identity))?.map(|v| v.expose_secret() != c.candidates[i].value.expose_secret()).unwrap_or(false);
        println!("  {}@{}{}", c.candidates[i].name, identity, if replaces { "  (REPLACES the value in the stash — you will be asked)" } else { "" });
    }
    print!("proceed? [y/N] ");
    { use std::io::Write; std::io::stdout().flush()?; }
    let mut ans = String::new();
    std::io::stdin().read_line(&mut ans)?;
    if !ans.trim().eq_ignore_ascii_case("y") { println!("nothing imported"); return Ok(0); }
    // Validate every chosen row before anything is written: one bad row must not leave the
    // earlier ones stored. Shape-mismatch rows are dropped here with a message, exactly as
    // a paste would refuse them.
    let mut prepared: Vec<(usize, Entry)> = vec![];
    for &i in &chosen {
        let cand = &c.candidates[i];
        let identity = tokenstash_core::envcrawl::identity_among(&c.candidates, i, &a.identity, |j| ticked[j]);
        let e = Entry { name: cand.name.clone(), identity: identity.clone(), value: cand.value.expose_secret().to_string(), provider: cand.provider.clone(), sensitive: cand.sensitive, source_url: None, created: tokenstash_core::now(), last_used: None, stale: false, stale_reason: None, stale_source: None, verify_off: false };
        bundle::validate_entry(&e).with_context(|| format!("row {} ({}@{})", i + 1, cand.name, identity))?;
        if let Some(pat) = tokenstash_core::registry::lookup(&e.name).and_then(|p| p.pattern.as_ref()) {
            if !tokenstash_core::validate::matches_pattern(pat, &cand.value)? {
                println!("  {}@{}: skipped — the value does not look like a {} key (a paste would be refused too)", e.name, identity, cand.provider.clone().unwrap_or_default());
                continue;
            }
        }
        prepared.push((i, e));
    }
    let mut n = 0;
    let mut pairs = vec![];
    for (i, e) in prepared {
        let cand = &c.candidates[i];
        let identity = e.identity.clone();
        // The identity is final only now (numbered over the ticked set), so the "does this
        // replace something" question is asked against THAT identity, not the preview's.
        let existing = app.stash.get(&stash_key(&cand.name, &identity))?;
        let replaces = existing.as_ref().map(|v| v.expose_secret() != cand.value.expose_secret()).unwrap_or(false);
        if existing.as_ref().map(|v| v.expose_secret() == cand.value.expose_secret()).unwrap_or(false) {
            println!("  {}@{}: already in the stash", cand.name, identity);
            continue;
        }
        if replaces {
            // replacing a stash value is a per-key decision, and never a silent one
            let local = app.db.get_secret(&cand.name, &identity)?;
            if local.as_ref().map(|m| m.stale && m.stale_source.as_deref() == Some(tokenstash_core::db::STALE_ROTATE)).unwrap_or(false) {
                println!("  {}@{}: skipped — you asked to rotate this key; paste the NEW one via `tokenstash rotate`, not an old env file", cand.name, identity);
                continue;
            }
            print!("  {}@{} differs from the stash (stored {}); replace it with the value from {}? [y/N] ", cand.name, identity, local.map(|m| m.created).unwrap_or_default(), short(&cand.sources[0]));
            { use std::io::Write; std::io::stdout().flush()?; }
            let mut ans = String::new();
            std::io::stdin().read_line(&mut ans)?;
            if !ans.trim().eq_ignore_ascii_case("y") { println!("  kept the stash value"); continue; }
        }
        apply_entry(&app, &e, &format!("from {}", display_path(&cand.sources[0])), a.no_verify)?;
        n += 1;
        pairs.push((cand.name.clone(), identity));
    }
    println!("✓ {n} imported. Each directory asks once (a pairing card) before it receives any of them.");
    if !a.no_verify && !pairs.is_empty() {
        println!("verifying against providers (--no-verify to skip)…");
        crate::cmd::admin::sweep_pairs(&app, &pairs, true)?;
    }
    Ok(0)
}

/// 1-based position of row `idx` among the rows that share its name, for telling several
/// values under one name apart without showing any of them.
fn identity_index(candidates: &[tokenstash_core::envcrawl::Candidate], idx: usize) -> usize {
    let name = &candidates[idx].name;
    (0..=idx).filter(|&i| &candidates[i].name == name).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokenstash_core::stash::{FileStash, Stash};
    use tokenstash_core::{Config, Db};

    fn entry(value: &str) -> Entry {
        Entry {
            name: "OPENAI_API_KEY".into(), identity: "default".into(), value: value.into(), provider: None, sensitive: false,
            source_url: None, created: tokenstash_core::now(), last_used: None, stale: false, stale_reason: None, stale_source: None, verify_off: false,
        }
    }

    /// An import writes the stash under the index write lock, as a store does. A probe
    /// verdict holds that lock from its stash read to its update, so the import waits for it
    /// rather than replacing the key in between and receiving the old key's verdict.
    #[test]
    fn an_import_writes_the_stash_under_the_index_lock() {
        let _g = crate::inbox_auth::env_lock();
        let home = std::env::temp_dir().join(format!("tokenstash-import-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("TOKENSTASH_HOME", &home);
        let key = stash_key("OPENAI_API_KEY", "default");
        let app = App { cfg: Config::default(), db: Db::open(&home.join("t.db")).unwrap(), stash: Box::new(FileStash::new().unwrap()) };
        app.stash.set(&key, &SecretString::from("sk-old-aaaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
        // A verdict in another process reads the stash under the lock, waits for its
        // provider, and reads again where it would record its answer.
        let db_path = home.join("t.db");
        let probed = key.clone();
        let (held, wait_held) = std::sync::mpsc::channel();
        let verdict = std::thread::spawn(move || {
            let other = Db::open(&db_path).unwrap();
            let stash = FileStash::new().unwrap();
            other.locked(|| {
                let before = stash.get(&probed)?.map(|v| v.expose_secret().to_string());
                held.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(300));
                let after = stash.get(&probed)?.map(|v| v.expose_secret().to_string());
                Ok((before, after))
            }).unwrap()
        });
        wait_held.recv().unwrap();
        apply_entry(&app, &entry("sk-new-bbbbbbbbbbbbbbbbbbbbb"), "test", true).unwrap();
        let (before, after) = verdict.join().unwrap();
        assert_eq!(before, after, "the import changed the stash while a verdict held the lock");
        assert_eq!(app.stash.get(&key).unwrap().unwrap().expose_secret(), "sk-new-bbbbbbbbbbbbbbbbbbbbb", "it lands once the lock is free");
        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }
}
