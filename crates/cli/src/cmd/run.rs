//! `run`: zero-config shim. Load the env file, run the command; if it fails mentioning a known
//! env var that isn't set, file the task, wait for the human, inject, and restart.
//!
//! The program's own output chooses which key gets requested, and that output may be
//! attacker-influenced. So requests that originate here are never silent: every stash hit
//! goes through an approval task (`<program> wants OPENAI_API_KEY. Allow?`) on every
//! invocation, regardless of earlier approvals. The human authorizes the injection, not the
//! child process. Once approved the key is in the env file, so a later run does not fail
//! on it and nothing is re-asked in normal use.

use crate::cmd::need::notify_pending;
use crate::util::{self, App};
use anyhow::{bail, Result};
use clap::Args;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;
use secrecy::SecretString;
use tokenstash_core::need::{self, NeedOpts};
use tokenstash_core::redact::Redactor;
use tokenstash_core::tasks::SecretRequest;

#[derive(Args)]
pub struct RunArgs {
    /// Command to run (use `--` before it).
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
    /// Max restarts after injecting a missing key.
    #[arg(long, default_value = "3")]
    pub retries: u32,
    /// Seconds to wait for the human each time.
    #[arg(long, default_value = "900")]
    pub timeout: u64,
}

pub fn run(a: RunArgs) -> Result<i32> {
    let app = App::open()?;
    let project = tokenstash_core::project::current();
    let agent = util::agent_from(&None);
    let env_path = project.join(&app.cfg.env_file);
    let mut attempts = 0;
    loop {
        let extra = load_env(&env_path);
        let (code, output) = spawn(&a.command, &extra)?;
        if code == 0 || attempts >= a.retries {
            return Ok(code);
        }
        let missing = find_missing(&output, &extra);
        if missing.is_empty() {
            return Ok(code);
        }
        attempts += 1;
        eprintln!("\ntokenstash: command failed and mentioned {}, asking you to approve it", missing.join(", "));
        // argv[0] only: arguments may carry secrets (curl -H "Authorization: ...") and `why`
        // is persisted and shown in task views.
        let program = std::path::Path::new(&a.command[0]).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| a.command[0].clone());
        let why = format!("`{program}` exited {code} and its output named this variable");
        let opts = NeedOpts {
            req: SecretRequest { why: Some(why), ..Default::default() },
            blocking: false,
            timeout: Duration::from_secs(a.timeout),
            require_approval: true, // program output must not authorize injection on its own
            ..Default::default()
        };
        let mut outcomes = need::need(&app.ctx(), &project, &agent, &missing, &opts)?;
        if outcomes.iter().any(|o| o.is_pending()) {
            let links = notify_pending(&app, &project, &agent, &outcomes);
            // This line goes to STDERR, so the TTY check has to be stderr's. `run` is
            // routinely used with stdout redirected and stderr on the terminal, and the
            // reverse.
            eprintln!("tokenstash: waiting for you → {}", util::inbox_url_tty(&app.cfg, Some(&app.db), None, &links, util::Stream::Stderr));
            // wait on the approval task just filed; calling need again would file another
            need::wait(&app.ctx(), &project, &mut outcomes, opts.timeout)?;
        }
        if let Some(o) = outcomes.iter().find(|o| !matches!(o, need::Outcome::Injected { .. })) {
            bail!("{} was not provided ({}); not restarting", o.name(), match o {
                need::Outcome::Denied { .. } => "denied",
                need::Outcome::Expired { .. } => "expired",
                _ => "pending",
            });
        }
        eprintln!("tokenstash: approved and injected, restarting\n");
    }
}

fn load_env(path: &std::path::Path) -> HashMap<String, String> {
    // A regular file only: a symlink a repo commits as `.env.local` must not feed another
    // project's values into the child, and a FIFO must not hang the run.
    let Some(s) = tokenstash_core::envfile::read_regular_file(path) else { return HashMap::new() };
    s.lines().filter_map(tokenstash_core::envfile::parse_line).collect()
}

/// Run, teeing output to the terminal and capturing it for diagnosis. Every line passes
/// through a redactor seeded with the values we injected and with inherited secret-looking
/// env values: a child that echoes its environment or prints a stack trace must not put a
/// secret on an agent-visible stream.
///
/// Limitation, on purpose: this is line-level and defends against accidental echo only. The
/// child holds the value by design, so a hostile child can always encode or fragment it.
/// The defense against a hostile child is upstream. Program-derived requests always need
/// a fresh human approval, so it cannot obtain a credential it was not granted.
fn spawn(cmd: &[String], extra: &HashMap<String, String>) -> Result<(i32, String)> {
    let mut redactor = Redactor::new();
    for v in extra.values() {
        redactor.add(&SecretString::from(v.clone()));
    }
    // The child also inherits our own environment, and we cannot know which of those
    // variables are secrets by name (SESSION_COOKIE, MYAPP_DSN, ...). So every inherited
    // value is treated as redactable unless it is a well-known benign variable or looks like
    // a filesystem path/list. Over-redacting an echoed benign value is harmless; missing a
    // secret is not.
    //
    // Values from the env file are secrets tokenstash delivered, so each line of a multi-line
    // one is masked too. An inherited value gets that only when its name says it is a secret
    // (a registry name, or one with KEY, TOKEN, SECRET, PASSWORD, ... in it), which covers a
    // deploy key a CI job exports as SSH_PRIVATE_KEY, or when it holds a PEM block, which
    // covers the same key exported as SSH_IDENTITY. The rest are redacted only because they
    // are not on the benign list, and that takes in multi-line build configuration (nix-shell's
    // `buildPhase`, `shellHook`). Masking each of its lines would hide `return 0;` or
    // `make install` in the child's errors, so those keep the whole-value match.
    for (k, v) in std::env::vars() {
        if !should_redact_inherited(&k, &v) {
            continue;
        }
        let secret_by_name = tokenstash_core::registry::lookup(&k).is_some() || tokenstash_core::envcrawl::secret_ish_name(&k.to_ascii_uppercase());
        let split = secret_by_name || tokenstash_core::redact::holds_pem_block(&v);
        let v = SecretString::from(v);
        if split {
            redactor.add(&v);
        } else {
            redactor.add_whole_value(&v);
        }
    }
    let redactor = std::sync::Arc::new(redactor);
    let mut c = Command::new(&cmd[0]);
    c.args(&cmd[1..]).envs(extra).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn()?;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let (r1, r2) = (redactor.clone(), redactor.clone());
    let t1 = std::thread::spawn(move || tee(out, false, &r1));
    let t2 = std::thread::spawn(move || tee(err, true, &r2));
    let status = child.wait()?;
    let mut captured = t1.join().unwrap_or_default();
    captured.push_str(&t2.join().unwrap_or_default());
    Ok((status.code().unwrap_or(1), captured))
}

const BENIGN_ENV: &[&str] = &[
    "PATH", "HOME", "PWD", "OLDPWD", "SHELL", "TERM", "TERM_PROGRAM", "COLORTERM", "LANG", "LANGUAGE", "USER", "LOGNAME",
    "DISPLAY", "WAYLAND_DISPLAY", "TMPDIR", "TMP", "TEMP", "EDITOR", "VISUAL", "PAGER", "HOSTNAME", "SHLVL", "_",
    "CARGO_HOME", "RUSTUP_HOME", "GOPATH", "NODE_ENV", "RUST_LOG", "RUST_BACKTRACE", "CI", "TZ", "MANPATH", "INFOPATH",
    "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE", "XDG_DATA_DIRS", "XDG_CONFIG_DIRS", "SSH_AUTH_SOCK",
    "TERMINFO", "LS_COLORS", "LESS", "LESSOPEN", "LESSCLOSE", "GIT_EDITOR", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT",
];

fn should_redact_inherited(name: &str, value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if tokenstash_core::registry::lookup(name).is_some() {
        return true; // known secret names always count, whatever the value looks like (the Redactor handles short values as whole tokens)
    }
    if value.chars().count() < tokenstash_core::tasks::MIN_SECRET_CHARS {
        return false;
    }
    let u = name.to_ascii_uppercase();
    if BENIGN_ENV.contains(&u.as_str()) || u.starts_with("LC_") || u.starts_with("XDG_") || u.starts_with("TOKENSTASH_") {
        return false;
    }
    // An exported shell function (`export -f`, RHEL's `which`, Lmod's `module`) is a
    // multi-line value of code, never a secret. Its whole value never matches one line of
    // output, and a function named like `get_token` would count as secret by name and have
    // lines like `return 0;` masked in every compiler error the child prints.
    if u.starts_with("BASH_FUNC_") {
        return false;
    }
    // Redaction replaces the value wherever it appears as a substring, so a variable whose
    // value is an existing DIRECTORY (HOMEBREW_PREFIX=/opt/homebrew, JAVA_HOME, ...) would
    // garble every longer path that starts with it (PATH itself). A secret is never an
    // existing directory, so directories, and colon-lists whose first entry is one, are
    // excluded. Files are not excluded: a path to a secret file is still redacted.
    let first = value.split(':').next().unwrap_or(value);
    let expanded = first.strip_prefix("~/").and_then(|rest| dirs::home_dir().map(|h| h.join(rest)));
    if std::path::Path::new(first).is_dir() || expanded.map(|p| p.is_dir()).unwrap_or(false) {
        return false;
    }
    true
}

fn tee<R: std::io::Read>(r: R, is_err: bool, redactor: &Redactor) -> String {
    let mut buf = String::new();
    for line in BufReader::new(r).lines().map_while(Result::ok) {
        let line = redactor.redact(&line);
        if is_err { let _ = writeln!(std::io::stderr(), "{line}"); } else { let _ = writeln!(std::io::stdout(), "{line}"); }
        buf.push_str(&line);
        buf.push('\n');
    }
    buf
}

/// Env-var-looking tokens in the output that are in the registry and not already set.
fn find_missing(output: &str, present: &HashMap<String, String>) -> Vec<String> {
    let re = regex::Regex::new(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b").unwrap();
    let mut v: Vec<String> = vec![];
    for cap in re.captures_iter(output) {
        let name = cap[1].to_string();
        if present.contains_key(&name) || std::env::var_os(&name).is_some() { continue; }
        if tokenstash_core::registry::lookup(&name).is_none() { continue; }
        if !v.contains(&name) { v.push(name); }
    }
    v
}
