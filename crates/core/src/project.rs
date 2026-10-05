//! Project identity and caller detection.

use std::path::{Path, PathBuf};

/// Canonical project id: git root if inside a repo, else the directory itself.
pub fn canonical(dir: &Path) -> PathBuf {
    let abs = if dir.is_absolute() { dir.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(dir) };
    let abs = abs.canonicalize().unwrap_or(abs);
    // A foreign-owned checkout still resolves to itself here so the write path can refuse
    // it with a clear error; a shared ancestor (/tmp) is never adopted as the project.
    crate::envfile::owned_git_root(&abs).ok().flatten().unwrap_or(abs)
}

pub fn current() -> PathBuf {
    canonical(&std::env::current_dir().unwrap_or_default())
}

/// Best-effort agent detection from the environment.
pub fn detect_agent() -> String {
    if let Ok(a) = std::env::var("TOKENSTASH_AGENT") {
        // Every path that puts the name on a card or a notification must see the same
        // filtered string, so the filter is applied here, at the one place the name is read.
        return crate::need::clean_agent(&a);
    }
    detect_agent_marker().unwrap_or("unknown").into()
}

/// An agent's own environment marker, or `TOKENSTASH_AGENT` set at all. For deciding whether
/// a person is at the terminal: `TOKENSTASH_AGENT` names the agent on cards, so it may say
/// anything, `unknown` included, but nobody sets it for a person.
pub fn agent_environment() -> bool {
    std::env::var_os("TOKENSTASH_AGENT").is_some() || detect_agent_marker().is_some()
}

fn detect_agent_marker() -> Option<&'static str> {
    let has = |k: &str| std::env::var_os(k).is_some();
    if has("CLAUDECODE") || has("CLAUDE_CODE_ENTRYPOINT") {
        return Some("claude-code");
    }
    if has("CODEX_SANDBOX") || has("CODEX_CI") || has("OPENAI_CODEX") {
        return Some("codex");
    }
    if has("CURSOR_TRACE_ID") || has("CURSOR_AGENT") {
        return Some("cursor");
    }
    if has("GEMINI_CLI") {
        return Some("gemini-cli");
    }
    if has("OPENCODE") {
        return Some("opencode");
    }
    None
}

pub fn short(p: &Path) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Ok(rest) = p.strip_prefix(&home) {
            return format!("~/{}", rest.display());
        }
    }
    p.display().to_string()
}
