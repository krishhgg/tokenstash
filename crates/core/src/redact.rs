//! Last line of defense: scrub any known secret value out of text bound for a human or a model.

use secrecy::{ExposeSecret, SecretString};

/// Values shorter than this are only redacted as whole tokens (surrounded by
/// non-alphanumerics): replacing every "ab" inside other words would garble output.
/// Defense in depth only, because `tasks::MIN_SECRET_CHARS` keeps such values out of the stash
/// in the first place, so nothing this short is ever a stored secret.
const SHORT: usize = 4;

pub struct Redactor {
    patterns: Vec<Pattern>,
}

/// One string to mask. A whole-token pattern is masked only where it is not glued to other
/// alphanumerics.
struct Pattern {
    text: String,
    whole_token: bool,
}

impl Redactor {
    pub fn new() -> Self {
        Self { patterns: vec![] }
    }
    pub fn with(mut self, v: &SecretString) -> Self {
        self.add(v);
        self
    }
    /// Register a secret value, and also each line of it when it spans several. `run` redacts a
    /// child's output one line at a time, so a printed PEM key or service-account JSON never
    /// shows the whole value to a single `redact` call. Lines are trimmed, and PEM armor is
    /// skipped. A line shorter than the shortest secret the stash accepts is masked only where
    /// it stands alone, so the `apple` of `apple\nberry` does not mask `pineapple`.
    ///
    /// Line breaks written as the two characters `\n` or `\r` split lines too. A compact
    /// service-account JSON holds its private key that way, on one line, and a child that
    /// decodes the JSON and prints the key prints it one line at a time.
    pub fn add(&mut self, v: &SecretString) {
        self.add_whole_value(v);
        let s = v.expose_secret();
        for line in s.split(['\n', '\r']) {
            // A value with no line break is one line, registered whole above.
            if line.len() < s.len() {
                self.add_line(line);
            }
            if line.contains("\\n") || line.contains("\\r") {
                for part in line.split("\\n").flat_map(|p| p.split("\\r")) {
                    self.add_line(part);
                }
            }
        }
    }
    fn add_line(&mut self, line: &str) {
        let line = line.trim();
        let short = line.chars().count() < crate::tasks::MIN_SECRET_CHARS;
        // A short line with no letter or digit (`{`, `},`) is structure, and as a whole
        // token it would match wherever it appears.
        if is_pem_armor(line) || (short && !line.chars().any(char::is_alphanumeric)) {
            return;
        }
        self.patterns.push(Pattern { text: line.to_string(), whole_token: short });
    }
    /// Register `v` as one string only. For a value that is only suspected to be a secret,
    /// whose lines on their own may be ordinary text.
    pub fn add_whole_value(&mut self, v: &SecretString) {
        let s = v.expose_secret();
        // Registered before any of its lines, so text that holds the whole value becomes one
        // `[redacted]`.
        if !s.is_empty() {
            self.patterns.push(Pattern { text: s.to_string(), whole_token: s.chars().count() < SHORT });
        }
    }
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for p in &self.patterns {
            if !out.contains(p.text.as_str()) {
                continue;
            }
            out = if p.whole_token { redact_whole_token(&out, &p.text) } else { out.replace(p.text.as_str(), "[redacted]") };
        }
        out
    }
}

/// `-----BEGIN PRIVATE KEY-----` and its END line are the same in every key. Left readable,
/// they show where a masked key was printed.
fn is_pem_armor(line: &str) -> bool {
    (line.starts_with("-----BEGIN ") || line.starts_with("-----END ")) && line.ends_with("-----")
}

/// Does `s` hold a PEM block, a `-----BEGIN X-----` and a later `-----END X-----`? They need
/// not stand on lines of their own, so a key inside a pretty-printed JSON counts. Any label
/// counts, public ones (CERTIFICATE, PUBLIC KEY) too. Masking a certificate's lines costs
/// nothing, and not every secret block says PRIVATE (`-----BEGIN OpenVPN Static key V1-----`).
pub fn holds_pem_block(s: &str) -> bool {
    let mut rest = s;
    while let Some(i) = rest.find("-----BEGIN ") {
        rest = &rest[i + "-----BEGIN ".len()..];
        let Some(j) = rest.find("-----") else { return false };
        let label = &rest[..j];
        if !label.is_empty() && !label.contains(['\n', '\r']) && rest[j..].contains(&format!("-----END {label}-----")) {
            return true;
        }
    }
    false
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
