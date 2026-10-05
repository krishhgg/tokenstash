//! Last line of defense: scrub any known secret value out of text bound for a human or a model.

use secrecy::{ExposeSecret, SecretString};

/// Values shorter than this are only redacted as whole tokens (surrounded by
/// non-alphanumerics): replacing every "ab" inside other words would garble output.
/// Defense in depth only — `tasks::MIN_SECRET_CHARS` keeps such values out of the stash
/// in the first place, so nothing this short is ever a stored secret.
const SHORT: usize = 4;

pub struct Redactor {
    values: Vec<String>,
}

impl Redactor {
    pub fn new() -> Self {
        Self { values: vec![] }
    }
    pub fn with(mut self, v: &SecretString) -> Self {
        self.add(v);
        self
    }
    /// Register `v`, and also each line of it when it spans several. `run` redacts a child's
    /// output one line at a time, so a printed PEM key or service-account JSON never shows the
    /// whole value to a single `redact` call. Each line is trimmed and kept if it is at least
    /// as long as the shortest secret the stash accepts and is not PEM armor.
    pub fn add(&mut self, v: &SecretString) {
        let s = v.expose_secret();
        if s.is_empty() {
            return;
        }
        // The whole value first, so text that holds all of it becomes one `[redacted]`.
        self.values.push(s.to_string());
        if !s.contains(['\n', '\r']) {
            return;
        }
        for line in s.split(['\n', '\r']).map(str::trim) {
            if line.chars().count() >= crate::tasks::MIN_SECRET_CHARS && !is_pem_armor(line) {
                self.values.push(line.to_string());
            }
        }
    }
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for v in &self.values {
            if !out.contains(v.as_str()) {
                continue;
            }
            if v.chars().count() >= SHORT {
                out = out.replace(v.as_str(), "[redacted]");
            } else {
                out = redact_whole_token(&out, v);
            }
        }
        out
    }
}

/// `-----BEGIN PRIVATE KEY-----` and its END line are the same in every key. Left readable,
/// they show where a masked key was printed.
fn is_pem_armor(line: &str) -> bool {
    (line.starts_with("-----BEGIN ") || line.starts_with("-----END ")) && line.ends_with("-----")
}

/// Replace `v` only where it is not glued to other alphanumerics.
fn redact_whole_token(text: &str, v: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(v) {
        let before_ok = rest[..i].chars().next_back().map(|c| !c.is_alphanumeric()).unwrap_or(true);
        let after_ok = rest[i + v.len()..].chars().next().map(|c| !c.is_alphanumeric()).unwrap_or(true);
        out.push_str(&rest[..i]);
        if before_ok && after_ok {
            out.push_str("[redacted]");
        } else {
            out.push_str(v);
        }
        rest = &rest[i + v.len()..];
    }
    out.push_str(rest);
    out
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

/// Mask for display: first 3 + last 2 characters, never more. Char-based so multibyte
/// values cannot panic on a byte boundary.
pub fn mask(v: &SecretString) -> String {
    let s = v.expose_secret();
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "••••".into();
    }
    let first: String = chars[..3].iter().collect();
    let last: String = chars[chars.len() - 2..].iter().collect();
    format!("{first}…{last}")
}
