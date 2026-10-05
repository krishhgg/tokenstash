//! `run` forwards the child's output to the agent through a redactor seeded with the values it
//! injected. The child's output reaches that redactor one line at a time, so a multi-line value
//! (a PEM key, a service-account JSON) has to be masked line by line too.
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokenstash-runredact-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A scratch home: no notifications, an inbox port nobody else uses, a file stash.
fn home(name: &str) -> PathBuf {
    let h = tmp(name);
    std::fs::write(h.join("config.toml"), format!("notifications = false\ninbox_port = {}\nstash_backend = \"insecure-file\"\nverify_every = \"never\"\n", free_port())).unwrap();
    h
}

/// `tokenstash run -- sh -c SCRIPT` in `proj`, with `extra_env` set on tokenstash itself.
fn run_sh(home: &Path, proj: &Path, script: &str, extra_env: &[(&str, &str)]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tokenstash")).args(["run", "--", "sh", "-c", script]).current_dir(proj)
        .env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE")
        .envs(extra_env.iter().copied())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap()
}

/// Four 64-character body lines, distinct from each other, in the shape of a PEM body.
fn fake_pem_body() -> Vec<String> {
    (0..4).map(|i| format!("MIIfake{i}").repeat(8)).collect()
}

#[test]
fn run_masks_every_line_of_a_multiline_value_the_child_prints() {
    let body = fake_pem_body();
    // `\n` and `\r\n` line endings, written into the env file the way `need` writes them
    // (escaped inside double quotes).
    for (tag, escaped) in [("lf", "\\n"), ("crlf", "\\r\\n")] {
        let home = home(&format!("home-{tag}"));
        let proj = tmp(&format!("proj-{tag}"));
        let value = format!("-----BEGIN PRIVATE KEY-----{escaped}{}{escaped}-----END PRIVATE KEY-----", body.join(escaped));
        std::fs::write(proj.join(".env.local"), format!("SERVICE_PRIVATE_KEY=\"{value}\"\n")).unwrap();
        // Quoted, unquoted (the shell joins the lines with spaces), and to stderr.
        let out = run_sh(&home, &proj, r#"printf '%s\n' "$SERVICE_PRIVATE_KEY"; echo $SERVICE_PRIVATE_KEY; printf '%s\n' "$SERVICE_PRIVATE_KEY" >&2"#, &[]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{tag}: run failed: {stderr}");
        // The child did print the key: its armor is still there to show where.
        assert!(stdout.contains("-----BEGIN PRIVATE KEY-----") && stdout.contains("[redacted]"), "{tag}: stdout: {stdout}");
        assert!(stderr.contains("-----END PRIVATE KEY-----") && stderr.contains("[redacted]"), "{tag}: stderr: {stderr}");
        for line in &body {
            assert!(!stdout.contains(line.as_str()), "{tag}: a line of the key reached stdout: {stdout}");
            assert!(!stderr.contains(line.as_str()), "{tag}: a line of the key reached stderr: {stderr}");
        }
    }
}

/// A stored value can be long enough to be a secret while each of its lines is not. Those
/// lines are masked where they stand alone, and not inside other words.
#[test]
fn run_masks_short_lines_of_a_multiline_value_as_whole_words() {
    let home = home("home-short");
    let proj = tmp("proj-short");
    std::fs::write(proj.join(".env.local"), "DB_PASSWORD=\"apple\\nberry\"\n").unwrap();
    let out = run_sh(&home, &proj, r#"printf '%s\n' "$DB_PASSWORD"; echo $DB_PASSWORD; echo pineapple blueberry"#, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "run failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout, "[redacted]\n[redacted]\n[redacted] [redacted]\npineapple blueberry\n");
}

/// An inherited variable is redacted when its value is not a known benign one, and that takes
/// in build configuration. Only a name that says "secret" gets each line of its value masked.
#[test]
fn run_masks_lines_of_an_inherited_value_only_when_its_name_says_secret() {
    let home = home("home-inherit");
    let proj = tmp("proj-inherit");
    let body = fake_pem_body();
    let key = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----", body.join("\n"));
    let out = run_sh(&home, &proj, r#"printf '%s\n' "$DEPLOY_SSH_KEY"; echo 'error here: return 0;'"#,
        &[("DEPLOY_SSH_KEY", key.as_str()), ("buildPhase", "runHook preBuild\nreturn 0;\nrunHook postBuild")]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "run failed: {}", String::from_utf8_lossy(&out.stderr));
    for line in &body {
        assert!(!stdout.contains(line.as_str()), "a line of the inherited key reached stdout: {stdout}");
    }
    assert!(stdout.contains("error here: return 0;"), "a line of buildPhase was masked: {stdout}");
}

/// An exported shell function is a multi-line inherited value made of code. Its lines are not
/// secrets, even when the function's name has TOKEN in it, and `return 0;` in a compiler error
/// must reach the agent as written.
#[test]
fn run_leaves_lines_of_an_exported_shell_function_alone() {
    let home = home("home-func");
    let proj = tmp("proj-func");
    let out = run_sh(&home, &proj, r#"echo 'error here: return 0;'"#, &[("BASH_FUNC_get_token%%", "() {  echo probe;\n return 0;\n}")]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "run failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("error here: return 0;"), "stdout: {stdout}");
}
