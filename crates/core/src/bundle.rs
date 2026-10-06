//! Encrypted export/import: one file, one passphrase, so a stash can move to a new machine
//! over any channel the user already owns (AirDrop, USB, scp). Never a server.
//!
//! Format (all integers little-endian):
//!
//! ```text
//! magic "TSTASHBUNDLE" | version u16 | argon2id m_kib u32 | t u32 | p u32 | salt[16] | nonce[24]
//! || XChaCha20-Poly1305( JSON payload, AAD = every header byte above )
//! ```
//!
//! The header is authenticated as AAD: an attacker who rewrites the KDF parameters to
//! something cheap for an offline brute force is caught before the KDF runs with them.
//! Import additionally refuses parameters below a floor, so even a *valid* tag over weak
//! parameters (a tampered exporter) is rejected. The header carries no names, counts or
//! hostnames, so there is nothing to learn without the passphrase. There is deliberately no plaintext
//! export path, not even behind a flag.

use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAGIC: &[u8; 12] = b"TSTASHBUNDLE";
pub const VERSION: u16 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 12 + 2 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;

/// Export defaults (OWASP-class): 64 MiB, 3 passes, 1 lane.
pub const M_KIB: u32 = 64 * 1024;
pub const T_COST: u32 = 3;
pub const P_COST: u32 = 1;
/// Import floor: a header below this is refused even if it authenticates.
pub const MIN_M_KIB: u32 = 19 * 1024;
pub const MIN_T_COST: u32 = 2;
/// Import ceiling: the header is only authenticated AFTER the KDF runs with its parameters,
/// so a stranger's file must not be able to ask for terabytes of memory or years of work.
pub const MAX_M_KIB: u32 = 1024 * 1024;
pub const MAX_T_COST: u32 = 16;
/// Caps on what import will even parse.
pub const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 10_000;

/// Everything a stash is, minus per-machine state. Approvals are deliberately absent:
/// they are consent tied to paths on a machine that no longer exists.
#[derive(Debug, Serialize, Deserialize)]
pub struct Payload_ {
    pub created: String,
    pub tool_version: String,
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub name: String,
    pub identity: String,
    pub value: String,
    pub provider: Option<String>,
    pub sensitive: bool,
    pub source_url: Option<String>,
    pub created: String,
    pub last_used: Option<String>,
    pub stale: bool,
    /// Carried so a key the user asked to rotate stays a rotation on the new machine.
    #[serde(default)]
    pub stale_reason: Option<String>,
    /// Who set the stale flag (`rotate` | `report` | `probe`); absent in bundles written
    /// before it existed, in which case the reason text decides.
    #[serde(default)]
    pub stale_source: Option<String>,
    /// The human stored this past the provider check: verify-on-use stays off for it.
    #[serde(default)]
    pub verify_off: bool,
}

impl Drop for Payload_ {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for e in &mut self.entries {
            e.value.zeroize();
        }
    }
}

/// Names, identities and values a bundle may carry. Import is the first path that can put
/// arbitrary bytes into the stash: a name like `FOO=bar` or a value with a newline would
/// become extra lines in an env file on the next injection.
pub fn validate_entry(e: &Entry) -> Result<()> {
    // The same rule `need` applies, or a key stored on one machine (`my_service_key`) makes
    // the whole bundle unimportable on the next.
    if !crate::need::valid_name(&e.name) {
        bail!("entry name {:?} is not a valid variable name", e.name);
    }
    // One rule, shared with `need`: a bundle exported from one machine must import on
    // another, and two definitions of "identity" drifting apart is how that breaks.
    if !crate::need::valid_identity(&e.identity) {
        bail!("entry {} has an invalid identity {:?}", e.name, e.identity);
    }
    if e.value.chars().count() < crate::tasks::MIN_SECRET_CHARS || e.value.len() > 16 * 1024 {
        bail!("entry {}@{}: value length out of range", e.name, e.identity);
    }
    // Newlines are how a PEM key or a service-account JSON is stored (the env file quotes
    // them); any other control character is not part of a credential.
    if e.value.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')) {
        bail!("entry {}@{}: value contains control characters", e.name, e.identity);
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Binding {
    pub project: String,
    pub name: String,
    pub identity: String,
}

fn derive_key(passphrase: &SecretString, salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m_kib, t, p, Some(32)).map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(key)
}

fn header(m_kib: u32, t: u32, p: u32, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&VERSION.to_le_bytes());
    h.extend_from_slice(&m_kib.to_le_bytes());
    h.extend_from_slice(&t.to_le_bytes());
    h.extend_from_slice(&p.to_le_bytes());
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce);
    h
}

/// Encrypt a payload under a passphrase. The plaintext JSON is zeroized after use.
pub fn seal(payload: &Payload_, passphrase: &SecretString) -> Result<Vec<u8>> {
    if passphrase.expose_secret().chars().count() < 12 {
        bail!("passphrase must be at least 12 characters (or use the generated one)");
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let hdr = header(M_KIB, T_COST, P_COST, &salt, &nonce);
    let key = derive_key(passphrase, &salt, M_KIB, T_COST, P_COST)?;
    let plain = Zeroizing::new(serde_json::to_vec(payload)?);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &hdr })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let mut out = hdr;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a bundle. Refuses: bad magic, unknown major version, KDF parameters below the
/// floor, a header that does not authenticate, a wrong passphrase (indistinguishable from
/// tampering by design, because both are "does not authenticate").
pub fn open(bytes: &[u8], passphrase: &SecretString) -> Result<Payload_> {
    if bytes.len() < HEADER_LEN + 16 {
        bail!("not a tokenstash bundle (too short)");
    }
    if &bytes[..12] != MAGIC {
        bail!("not a tokenstash bundle (bad magic)");
    }
    let version = u16::from_le_bytes([bytes[12], bytes[13]]);
    if version != VERSION {
        bail!("bundle version {version} is not supported by this tokenstash (supports {VERSION}); update tokenstash");
    }
    let u32_at = |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    let (m_kib, t, p) = (u32_at(14), u32_at(18), u32_at(22));
    if m_kib < MIN_M_KIB || t < MIN_T_COST || p == 0 || p > 16 {
        bail!("bundle refuses: its key-derivation parameters are below the safety floor (m={m_kib} KiB, t={t}, p={p}); the file may have been tampered with");
    }
    if m_kib > MAX_M_KIB || t > MAX_T_COST {
        bail!("bundle refuses: its key-derivation parameters are above the ceiling (m={m_kib} KiB, t={t}); not spending that much memory or time on an unauthenticated header");
    }
    if passphrase.expose_secret().is_empty() {
        bail!("empty passphrase");
    }
    let salt: [u8; SALT_LEN] = bytes[26..26 + SALT_LEN].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = bytes[26 + SALT_LEN..HEADER_LEN].try_into().unwrap();
    let hdr = &bytes[..HEADER_LEN];
    let key = derive_key(passphrase, &salt, m_kib, t, p)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plain = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &bytes[HEADER_LEN..], aad: hdr })
            .map_err(|_| anyhow::anyhow!("wrong passphrase, or the bundle was modified"))?,
    );
    serde_json::from_slice(&plain).context("bundle payload is not valid")
}

/// A passphrase the user did not have to invent: 5 groups of 4 from a 31-symbol alphabet
/// (no ambiguous characters), ~99 bits.
pub fn generate_passphrase() -> SecretString {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(24);
    for g in 0..5 {
        if g > 0 { s.push('-'); }
        for _ in 0..4 {
            let i = rng.gen_range(0..ALPHABET.len());
            s.push(ALPHABET[i] as char);
        }
    }
    SecretString::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Payload_ {
        Payload_ {
            created: "2026-08-26T00:00:00Z".into(),
            tool_version: "test".into(),
            entries: vec![Entry { name: "OPENAI_API_KEY".into(), identity: "default".into(), value: "sk-bundlecanary-0123456789abcdef".into(), provider: Some("OpenAI".into()), sensitive: false, source_url: None, created: "2026-08-01T00:00:00Z".into(), last_used: None, stale: false, stale_reason: None, stale_source: None, verify_off: false }],
            bindings: vec![Binding { project: "/old/machine/proj".into(), name: "OPENAI_API_KEY".into(), identity: "default".into() }],
        }
    }

    #[test]
    fn round_trip_and_no_plaintext() {
        let pw = SecretString::from("correct-horse-battery-staple".to_string());
        let bytes = seal(&sample(), &pw).unwrap();
        assert!(!bytes.windows(15).any(|w| w == b"sk-bundlecanary"), "value must not appear in the bundle");
        assert!(!bytes.windows(14).any(|w| w == b"OPENAI_API_KEY"), "names must not appear in the bundle");
        let back = open(&bytes, &pw).unwrap();
        assert_eq!(back.entries[0].value, "sk-bundlecanary-0123456789abcdef");
        assert_eq!(back.bindings.len(), 1);
    }

    #[test]
    fn wrong_passphrase_and_tampering_are_refused() {
        let pw = SecretString::from("correct-horse-battery-staple".to_string());
        let bytes = seal(&sample(), &pw).unwrap();
        assert!(open(&bytes, &SecretString::from("wrong-passphrase-here".to_string())).is_err());
        // flip a ciphertext byte
        let mut t = bytes.clone(); let n = t.len() - 5; t[n] ^= 1;
        assert!(open(&t, &pw).is_err());
        // rewrite the KDF params to something cheap: header is AAD, so it fails to authenticate
        let mut t = bytes.clone(); t[14..18].copy_from_slice(&(MIN_M_KIB).to_le_bytes());
        assert!(open(&t, &pw).is_err());
        // params below the floor are refused before any KDF work
        let mut t = bytes.clone(); t[14..18].copy_from_slice(&1024u32.to_le_bytes());
        let e = open(&t, &pw).unwrap_err().to_string();
        assert!(e.contains("safety floor"), "{e}");
        // unknown version
        let mut t = bytes; t[12..14].copy_from_slice(&99u16.to_le_bytes());
        assert!(open(&t, &pw).unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn ceilings_and_entry_validation() {
        let pw = SecretString::from("correct-horse-battery-staple".to_string());
        let bytes = seal(&sample(), &pw).unwrap();
        let mut t = bytes.clone(); t[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(open(&t, &pw).unwrap_err().to_string().contains("ceiling"), "a stranger's file must not demand terabytes");
        let mut t = bytes.clone(); t[18..22].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(open(&t, &pw).unwrap_err().to_string().contains("ceiling"));
        assert!(open(&bytes, &SecretString::from(String::new())).unwrap_err().to_string().contains("empty"));
        let mut e = sample().entries[0].clone();
        assert!(validate_entry(&e).is_ok());
        e.name = "FOO=bar".into(); assert!(validate_entry(&e).is_err());
        // The rule is `need`'s: a lowercase name stored on one machine imports on the next.
        e.name = "my_service_key".into(); assert!(validate_entry(&e).is_ok());
        e.name = "9LIVES".into(); assert!(validate_entry(&e).is_err());
        e.name = "OPENAI_API_KEY".into(); e.identity = "a@b".into(); assert!(validate_entry(&e).is_err());
        // A newline is a PEM key; the env file quotes it (`envfile::quote`), so it is not an
        // extra line. Any other control character is not part of a credential.
        e.identity = "work".into(); e.value = "-----BEGIN KEY-----\nabcdef0123456789\n-----END KEY-----".into(); assert!(validate_entry(&e).is_ok());
        e.value = "x\u{1b}[31mNODE_OPTIONS=--require evil".into(); assert!(validate_entry(&e).is_err());
        e.value = "short".into(); assert!(validate_entry(&e).is_err());
    }

    #[test]
    fn short_passphrases_are_refused_and_generated_ones_are_not() {
        assert!(seal(&sample(), &SecretString::from("short".to_string())).is_err());
        let g = generate_passphrase();
        assert_eq!(g.expose_secret().len(), 24);
        assert!(seal(&sample(), &g).is_ok());
        assert_ne!(generate_passphrase().expose_secret(), g.expose_secret());
    }
}
