//! Stash adapter: where secret values live. Metadata lives in the DB; values live here.
//!
//! Backends:
//!
//! - `keyring`: OS store via the `keyring` crate (macOS Keychain, Windows Credential Manager,
//!   Linux Secret Service). Default.
//! - `keyutils`: Linux kernel keyring (no daemon needed; survives logout, not reboot).
//!   Auto-selected on Linux when Secret Service is unavailable. See [`KernelKeyring`].
//! - `insecure-file`: 0600 JSON file. ONLY for CI/tests. Requires explicit opt-in via
//!   `TOKENSTASH_STASH=insecure-file` or config. Prints a warning.

use anyhow::{anyhow, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use std::collections::BTreeMap;
use std::path::PathBuf;

const SERVICE: &str = "tokenstash";

/// A path in the form used to decide "same directory": canonical when the directory exists,
/// otherwise with `.` and `..` resolved lexically (a fresh install has no config dir yet, and
/// `canonicalize` fails on a path that does not exist).
fn same_dir_key(p: PathBuf) -> PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => { out.pop(); }
            other => out.push(other),
        }
    }
    out
}

/// The keyring service name. The OS store is per user, while every grant and inbox token
/// is per `TOKENSTASH_HOME`. A process that re-homes tokenstash into a directory it controls
/// gets an empty stash there, not the real keys under a database it can approve against.
/// The default home keeps the plain name, so existing entries are untouched.
pub(crate) fn service() -> String {
    // Both sides canonical: `TOKENSTASH_HOME` spelled through a symlink or a `..` is still
    // the default home, and must not turn into an empty namespace whose index (per home)
    // lists keys that every `need` then misses.
    let canon = same_dir_key(crate::config::config_dir());
    let default = same_dir_key(crate::config::default_config_dir());
    if canon == default {
        return SERVICE.into();
    }
    use sha2::Digest;
    let d = sha2::Sha256::digest(canon.to_string_lossy().as_bytes());
    format!("{SERVICE}-{}", d[..4].iter().map(|b| format!("{b:02x}")).collect::<String>())
}

pub trait Stash {
    fn backend(&self) -> &'static str;
    /// How long values last here, when that is shorter than one might expect (`doctor` and
    /// `init` show it).
    fn note(&self) -> Option<String> {
        None
    }
    fn get(&self, key: &str) -> Result<Option<SecretString>>;
    fn set(&self, key: &str, value: &SecretString) -> Result<()>;
    fn delete(&self, key: &str) -> Result<bool>;
    /// Keys with a copy this backend cannot keep up to date, among `keys` and any other key it
    /// holds for this home. `None` when the backend keeps no such copies. `doctor` shows it.
    fn stray_copies(&self, _keys: &[String]) -> Option<StrayCheck> {
        None
    }
}

/// What [`Stash::stray_copies`] found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StrayCheck {
    /// How many keys it looked at.
    pub checked: usize,
    pub copies: Vec<StrayCopy>,
    /// What it could not look at, and why, when part of the check could not run.
    pub limited: Option<String>,
}

/// A key with a copy its backend cannot keep up to date (see [`Stash::stray_copies`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrayCopy {
    /// `NAME@identity`.
    pub key: String,
    /// The two places a read looks hold different values, so a read can return the old one.
    pub differs: bool,
    /// Live copies that only other login sessions hold. They matter only while an older
    /// tokenstash runs in one of those sessions.
    pub elsewhere: usize,
}

/// Stash key format: `NAME@identity`. Decided day one so identities never need a migration.
pub fn stash_key(name: &str, identity: &str) -> String {
    format!("{name}@{identity}")
}

pub fn open(cfg: &crate::Config) -> Result<Box<dyn Stash>> {
    let backend = std::env::var("TOKENSTASH_STASH")
        .ok()
        .or_else(|| cfg.stash_backend.clone())
        .unwrap_or_else(|| "auto".into());
    match backend.as_str() {
        "insecure-file" => {
            eprintln!("tokenstash: WARNING: using insecure-file stash (plaintext, 0600). For CI/tests only.");
            Ok(Box::new(FileStash::new()?))
        }
        "keyring" => Ok(Box::new(KeyringStash::os_store()?)),
        #[cfg(target_os = "linux")]
        "keyutils" => Ok(Box::new(KernelKeyring)),
        "auto" => auto(),
        other => Err(anyhow!("unknown stash backend '{other}'")),
    }
}

/// OS store if it works; on Linux fall back to the kernel keyring.
pub fn auto() -> Result<Box<dyn Stash>> {
    let s = KeyringStash::os_store()?;
    if s.probe().is_ok() {
        return Ok(Box::new(s));
    }
    #[cfg(target_os = "linux")]
    {
        probe(&KernelKeyring).map_err(|e| anyhow!("no usable Linux keyring (Secret Service unavailable and the kernel keyring failed): {e}"))?;
        return Ok(Box::new(KernelKeyring));
    }
    #[allow(unreachable_code)]
    Err(anyhow!("OS keychain unavailable"))
}

/// Round-trip a throwaway entry through `stash` to confirm the backend works.
pub fn probe(stash: &dyn Stash) -> Result<()> {
    let key = "__tokenstash_probe__";
    stash.set(key, &SecretString::from("ok"))?;
    let got = stash.get(key);
    let _ = stash.delete(key);
    match got? {
        Some(v) if v.expose_secret() == "ok" => Ok(()),
        _ => Err(anyhow!("probe mismatch")),
    }
}

// ---------------- keyring-backed ----------------

pub struct KeyringStash {
    name: &'static str,
}

impl KeyringStash {
    /// Platform OS store (Keychain / Credential Manager / Secret Service).
    pub fn os_store() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            keyring::set_default_credential_builder(keyring::secret_service::default_credential_builder());
            return Ok(Self { name: "secret-service" });
        }
        #[allow(unreachable_code)]
        Ok(Self { name: "os-keychain" })
    }

    /// Round-trip a throwaway entry to confirm the backend works.
    pub fn probe(&self) -> Result<()> {
        let key = "__tokenstash_probe__";
        let e = keyring::Entry::new(&service(), key)?;
        e.set_password("ok")?;
        let got = e.get_password()?;
        let _ = e.delete_credential();
        if got != "ok" {
            return Err(anyhow!("probe mismatch"));
        }
        Ok(())
    }
}

impl Stash for KeyringStash {
    fn backend(&self) -> &'static str {
        self.name
    }
    fn get(&self, key: &str) -> Result<Option<SecretString>> {
        let e = keyring::Entry::new(&service(), key)?;
        match e.get_password() {
            Ok(v) => Ok(Some(SecretString::from(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(anyhow!("keyring read failed: {err}")),
        }
    }
    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        let e = keyring::Entry::new(&service(), key)?;
        e.set_password(value.expose_secret()).map_err(|err| anyhow!("keyring write failed: {err}"))
    }
    fn delete(&self, key: &str) -> Result<bool> {
        let e = keyring::Entry::new(&service(), key)?;
        match e.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(anyhow!("keyring delete failed: {err}")),
        }
    }
}

// ---------------- Linux kernel keyring ----------------

/// The Linux kernel keyring, for a machine with no Secret Service (a headless box, an SSH
/// login). One key object per name, linked into the user keyring and the user's persistent
/// keyring, and updated in place when the value changes.
///
/// tokenstash 0.3.0 and earlier used keyring-rs's keyutils store, which adds each key to the
/// *session* keyring and reads the session copy first. Every login session (an SSH shell,
/// the agent's process tree) ends up holding a copy of its own: a key pasted from one session
/// is shadowed in another by the copy that session read earlier, and that read links the old
/// copy back into the persistent keyring over the new one. So a replaced key kept coming
/// back. Here a read never prefers the session keyring, which is consulted only for keys that
/// older code left nowhere else, and a write updates every copy it can reach, so a process
/// still running the old code and holding a session copy reads the new value too. Entries
/// keep keyring-rs's description, `keyring-rs:<NAME@identity>@<service>`, so keys stored by
/// older versions are found where they are.
///
/// A read that finds the key linked into both rings changes nothing. Any other read moves
/// links (it adopts a key older code left in one ring or in the session keyring, or puts the
/// user keyring's key back into the persistent keyring), and it does so under the writers'
/// lock from a fresh look, so it never links an older object over one a writer in another
/// session stored meanwhile.
///
/// One case this cannot fix. An older tokenstash still running in another login session
/// reads and writes its own session copy, which no other session may write. Its read links
/// that copy into the persistent keyring, and so does its write, after giving the copy the
/// new value. Both leave the user keyring holding one value and the persistent keyring
/// another, and the kernel keeps no time of write to tell which is newer. A read here keeps
/// the user keyring's value, which is right after the old process read and wrong after it
/// wrote. Taking the persistent keyring's value instead would let any old process's read
/// bring an old key back. [`Stash::stray_copies`] finds both states for `doctor`.
///
/// The user keyring lives while any process of this user runs; the persistent keyring
/// survives a logout but is dropped after `/proc/sys/kernel/keys/persistent_keyring_expiry`
/// seconds (three days by default) without use. Neither survives a reboot.
#[cfg(target_os = "linux")]
pub struct KernelKeyring;

#[cfg(target_os = "linux")]
mod kernel {
    use anyhow::{anyhow, Result};
    use linux_keyutils::{Key, KeyError, KeyPermissions, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};

    pub(super) fn description(key: &str) -> String {
        format!("keyring-rs:{key}@{}", super::service())
    }

    fn fail(what: &str, e: KeyError) -> anyhow::Error {
        anyhow!("kernel keyring: {what} failed: {e:?}")
    }

    /// The user keyring. Reached through its special id, so this process possesses it and
    /// every key found through it.
    pub(super) fn user() -> Result<KeyRing> {
        KeyRing::from_special_id(KeyRingIdentifier::User, true).map_err(|e| fail("opening the user keyring", e))
    }

    /// The persistent keyring, linked into the session keyring (which is what lets this
    /// process read the keys in it). Asking for it resets its expiry timer. `None` on a
    /// kernel built without persistent keyrings.
    pub(super) fn persistent() -> Option<KeyRing> {
        KeyRing::get_persistent(KeyRingIdentifier::Session).ok()
    }

    fn session() -> Option<KeyRing> {
        KeyRing::from_special_id(KeyRingIdentifier::Session, false).ok()
    }

    /// "Not there" covers the states a key passes through while it is being invalidated or
    /// after it expired, as keyring-rs found experimentally.
    fn absent(e: KeyError) -> bool {
        matches!(e, KeyError::KeyDoesNotExist | KeyError::KeyExpired | KeyError::KeyRevoked | KeyError::AccessDenied)
    }

    fn find(ring: &KeyRing, desc: &str) -> Result<Option<Key>> {
        match ring.search(desc) {
            Ok(k) => Ok(Some(k)),
            Err(e) if absent(e) => Ok(None),
            Err(e) => Err(fail("search", e)),
        }
    }

    /// The user keyring's key, when the persistent keyring links the same object or the
    /// kernel has no persistent keyring. Reading that key changes no links.
    pub(super) fn settled(user: &KeyRing, persistent: Option<&KeyRing>, desc: &str) -> Result<Option<Key>> {
        let Some(k) = find(user, desc)? else { return Ok(None) };
        match persistent {
            None => Ok(Some(k)),
            Some(p) => Ok((find(p, desc)? == Some(k)).then_some(k)),
        }
    }

    /// The key to read: the user keyring's, else the persistent keyring's, else (keys only
    /// older code stored) whatever the session keyring holds.
    pub(super) fn current(user: &KeyRing, persistent: Option<&KeyRing>, desc: &str) -> Result<Option<Key>> {
        if let Some(k) = find(user, desc)? {
            return Ok(Some(k));
        }
        if let Some(k) = persistent.map(|p| find(p, desc)).transpose()?.flatten() {
            return Ok(Some(k));
        }
        session().map(|s| find(&s, desc)).transpose().map(Option::flatten)
    }

    /// Every distinct key object under `desc` this process can reach, the one [`current`]
    /// would read first.
    pub(super) fn copies(user: &KeyRing, persistent: Option<&KeyRing>, desc: &str) -> Result<Vec<Key>> {
        let mut out: Vec<Key> = vec![];
        for ring in [Some(*user), persistent.copied(), session()].into_iter().flatten() {
            if let Some(k) = find(&ring, desc)? {
                if !out.contains(&k) {
                    out.push(k);
                }
            }
        }
        Ok(out)
    }

    /// [`super::Stash::stray_copies`] for the kernel keyring, given what reading `/proc/keys`
    /// returned. That file lists every key this user may view, in any session. It adds the
    /// keys stored under this home's service name that this home's index does not list (a
    /// lost index, another home with the same service name), which `need` can still read
    /// and adopt. A copy another session holds is visible there but, made by older code,
    /// not writable from here.
    pub(super) fn stray_check(keys: &[String], listing: std::io::Result<String>) -> super::StrayCheck {
        let mut check = super::StrayCheck::default();
        let user = match user() {
            Ok(u) => u,
            Err(e) => {
                check.limited = Some(format!("Nothing was checked ({e:#})."));
                return check;
            }
        };
        let persistent = persistent();
        let mut names = keys.to_vec();
        match &listing {
            Ok(l) => names.extend(stored_keys(l)),
            Err(e) => {
                check.limited = Some(format!("Could not read /proc/keys ({e}), so only the keys this home's index lists were checked, and not for copies other login sessions hold."));
            }
        }
        names.sort();
        names.dedup();
        check.checked = names.len();
        for key in names {
            if let Ok((differs, elsewhere)) = strays(&user, persistent.as_ref(), &description(&key), listing.as_deref().ok()) {
                if differs || elsewhere > 0 {
                    check.copies.push(super::StrayCopy { key, differs, elsewhere });
                }
            }
        }
        check
    }

    /// Whether the user keyring and the persistent keyring link different objects under
    /// `desc` that hold different values, and how many live copies in `listing` (the text
    /// of `/proc/keys`) only other login sessions link.
    fn strays(user: &KeyRing, persistent: Option<&KeyRing>, desc: &str, listing: Option<&str>) -> Result<(bool, usize)> {
        let u = find(user, desc)?;
        let p = persistent.map(|p| find(p, desc)).transpose()?.flatten();
        let differs = match (u, p) {
            (Some(u), Some(p)) if u != p => {
                let (a, b) = (read(u).ok().flatten().map(zeroize::Zeroizing::new), read(p).ok().flatten().map(zeroize::Zeroizing::new));
                matches!((a, b), (Some(a), Some(b)) if a != b)
            }
            _ => false,
        };
        let own = session().map(|s| find(&s, desc)).transpose()?.flatten();
        let elsewhere = listing.map_or(0, |l| listed(l).filter(|(k, d)| *d == desc && ![u, p, own].contains(&Some(*k))).count());
        Ok((differs, elsewhere))
    }

    /// The `NAME@identity` of every key in `listing` stored under this home's service name,
    /// leaving out the backend probe's.
    fn stored_keys(listing: &str) -> Vec<String> {
        let suffix = format!("@{}", super::service());
        listed(listing)
            .filter_map(|(_, d)| d.strip_prefix("keyring-rs:")?.strip_suffix(suffix.as_str()).map(str::to_string))
            .filter(|k| k != "__tokenstash_probe__")
            .collect()
    }

    /// The live `user` keys in `listing`, the text of `/proc/keys`, with their descriptions.
    /// A line reads `serial flags usage timeout perm uid gid type description: length`.
    fn listed(listing: &str) -> impl Iterator<Item = (Key, &str)> {
        listing.lines().filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let [serial, flags, usage, timeout, _perm, _uid, _gid, kind, name, ..] = f.as_slice() else { return None };
            // Instantiated, and not revoked, dead, negative or invalidated; still referenced
            // (a key waiting for the collector has a usage of 0); not expired.
            let live = flags.starts_with('I') && !flags.contains(['R', 'D', 'N', 'i']) && usage.parse::<u32>().is_ok_and(|n| n > 0) && *timeout != "expd";
            if !live || *kind != "user" {
                return None;
            }
            let serial = u32::from_str_radix(serial, 16).ok()?;
            Some((Key::from_id(linux_keyutils::KeySerialId(serial as i32)), name.strip_suffix(':').unwrap_or(name)))
        })
    }

    /// This user may use the key from any session. The kernel checks possession again on
    /// every call that names a key by id, and a session keyring that does not link the user
    /// keyring (a systemd service's private one, `keyctl session`) does not possess what is
    /// in it: with the default "possessor only" permissions such a process finds the key and
    /// then cannot read, update or remove it. This grants this uid nothing it could not get
    /// anyway, since any of its processes can link the persistent keyring into its session.
    fn perms() -> KeyPermissions {
        KeyPermissionsBuilder::builder().posessor(Permission::ALL).user(Permission::ALL).build()
    }

    /// Link `key` into both rings, so it outlives a logout (persistent) and the persistent
    /// keyring's expiry (user). Linking displaces any other key with the same description
    /// from that ring.
    pub(super) fn pin(user: &KeyRing, persistent: Option<&KeyRing>, key: Key) -> Result<()> {
        // A key older code stored still has possessor-only permissions; widen them while
        // this process possesses it (through the persistent keyring), best effort.
        let _ = key.set_perms(perms());
        user.link_key(key).map_err(|e| fail("linking into the user keyring", e))?;
        if let Some(p) = persistent {
            p.link_key(key).map_err(|e| fail("linking into the persistent keyring", e))?;
        }
        Ok(())
    }

    pub(super) fn read(key: Key) -> Result<Option<Vec<u8>>> {
        match key.read_to_vec() {
            Ok(v) => Ok(Some(v)),
            Err(e) if absent(e) => Ok(None),
            Err(e) => Err(fail("read", e)),
        }
    }

    /// A new key, created in the process keyring (always possessed, so its permissions can
    /// be set before anything else can see it), then pinned and unlinked from there. A
    /// failure part-way removes it rather than leaving an unreachable key behind.
    pub(super) fn create(user: &KeyRing, persistent: Option<&KeyRing>, desc: &str, value: &[u8]) -> Result<Key> {
        let scratch = KeyRing::from_special_id(KeyRingIdentifier::Process, true).map_err(|e| fail("opening the process keyring", e))?;
        let key = scratch.add_key(desc, value).map_err(|e| fail("add", e))?;
        let pinned = key.set_perms(perms()).map_err(|e| fail("setting permissions", e)).and_then(|()| pin(user, persistent, key));
        let _ = scratch.unlink_key(key);
        if let Err(e) = pinned {
            let _ = key.invalidate();
            return Err(e);
        }
        Ok(key)
    }

    pub(super) fn update(key: Key, value: &[u8]) -> Result<()> {
        key.update(&value).map_err(|e| fail("update", e))
    }

    pub(super) fn invalidate(key: Key) -> Result<()> {
        match key.invalidate() {
            Ok(()) => Ok(()),
            Err(e) if absent(e) => Ok(()),
            Err(e) => Err(fail("invalidate", e)),
        }
    }
}

#[cfg(target_os = "linux")]
impl KernelKeyring {
    /// Writes and deletes for this home take one lock. Two processes storing the same new
    /// name at once would otherwise each create a key and link it into the two rings in
    /// separate steps, and interleaved links can leave the user keyring holding one value and
    /// the persistent keyring the other.
    fn locked<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
        crate::fsutil::with_lock_elsewhere(std::path::Path::new("kernel-keyring"), f)
    }
}

#[cfg(target_os = "linux")]
impl Stash for KernelKeyring {
    fn backend(&self) -> &'static str {
        "keyutils"
    }
    fn note(&self) -> Option<String> {
        Some(if kernel::persistent().is_some() {
            "Linux kernel keyring: kept until the next reboot; a Secret Service such as gnome-keyring keeps keys across reboots".into()
        } else {
            "Linux kernel keyring without a persistent keyring: keys last only while you have a process running, and not past a reboot; a Secret Service such as gnome-keyring keeps them".into()
        })
    }
    fn get(&self, key: &str) -> Result<Option<SecretString>> {
        let desc = kernel::description(key);
        let (user, persistent) = (kernel::user()?, kernel::persistent());
        let k = match kernel::settled(&user, persistent.as_ref(), &desc)? {
            Some(k) => k,
            None => {
                if kernel::current(&user, persistent.as_ref(), &desc)?.is_none() {
                    return Ok(None);
                }
                #[cfg(test)]
                if let Some(hook) = BEFORE_RELINK.with(|h| h.borrow_mut().take()) {
                    hook();
                }
                // Adopt a key older code left only in the persistent or the session keyring,
                // or pin the user keyring's key into the persistent keyring again, so it
                // outlives the next logout. A writer in another session may store the key
                // after the look above. Under its lock, a fresh look finds what it stored,
                // and the old object is not linked over it. The read does not depend on
                // the links.
                let found = Self::locked(|| {
                    let k = kernel::current(&user, persistent.as_ref(), &desc)?;
                    if let Some(k) = k {
                        let _ = kernel::pin(&user, persistent.as_ref(), k);
                    }
                    Ok(k)
                })?;
                let Some(k) = found else { return Ok(None) };
                k
            }
        };
        let Some(bytes) = kernel::read(k)? else { return Ok(None) };
        let v = String::from_utf8(bytes).map_err(|_| anyhow!("the kernel keyring entry for {key} is not UTF-8"))?;
        Ok(Some(SecretString::from(v)))
    }
    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        let v = value.expose_secret().as_bytes();
        if v.is_empty() {
            return Err(anyhow!("the kernel keyring cannot hold an empty value"));
        }
        let desc = kernel::description(key);
        Self::locked(|| {
            let (user, persistent) = (kernel::user()?, kernel::persistent());
            let copies = kernel::copies(&user, persistent.as_ref(), &desc)?;
            let Some(&keep) = copies.first() else {
                kernel::create(&user, persistent.as_ref(), &desc, v)?;
                return Ok(());
            };
            // Update in place: every session that links this object sees the new value.
            kernel::update(keep, v)?;
            // A shadow (an older session copy) gets the value as well, best effort: this
            // process never reads it, but an older tokenstash in that session does.
            for &k in copies.iter().skip(1) {
                let _ = kernel::update(k, v);
            }
            kernel::pin(&user, persistent.as_ref(), keep)
        })
    }
    fn delete(&self, key: &str) -> Result<bool> {
        let desc = kernel::description(key);
        Self::locked(|| {
            let (user, persistent) = (kernel::user()?, kernel::persistent());
            let copies = kernel::copies(&user, persistent.as_ref(), &desc)?;
            for &k in &copies {
                kernel::invalidate(k)?;
            }
            Ok(!copies.is_empty())
        })
    }
    fn stray_copies(&self, keys: &[String]) -> Option<StrayCheck> {
        Some(kernel::stray_check(keys, std::fs::read_to_string("/proc/keys")))
    }
}

// Test-only: runs once, on this thread, in a kernel keyring read that is about to move
// links, after its first look and before it takes the lock. Tests use it to make another
// session store the key in that gap.
#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static BEFORE_RELINK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

// ---------------- insecure file (tests/CI only) ----------------

pub struct FileStash {
    path: PathBuf,
}

impl FileStash {
    pub fn new() -> Result<Self> {
        let path = crate::config::config_dir().join("insecure-stash.json");
        std::fs::create_dir_all(path.parent().unwrap())?;
        Ok(Self { path })
    }
    fn read(&self) -> Result<BTreeMap<String, String>> {
        if !self.path.exists() {
            return Ok(BTreeMap::new());
        }
        let s = std::fs::read_to_string(&self.path)?;
        // A corrupt file must be an error, not an empty map that the next write persists.
        serde_json::from_str(&s).with_context(|| format!("{} is not valid JSON; refusing to overwrite it", self.path.display()))
    }
    /// Atomic: serialize to a fresh 0600 temp file (O_EXCL, so never through a pre-placed
    /// symlink), fsync, then rename over the destination. A failure at any point leaves the
    /// previous stash intact, and rename replaces a symlink at the destination rather than
    /// following it.
    fn write(&self, m: &BTreeMap<String, String>) -> Result<()> {
        let data = serde_json::to_string(m)?;
        crate::fsutil::write_atomic_private(&self.path, &data)
    }
}

impl Stash for FileStash {
    fn backend(&self) -> &'static str {
        "insecure-file"
    }
    fn get(&self, key: &str) -> Result<Option<SecretString>> {
        Ok(self.read()?.remove(key).map(SecretString::from))
    }
    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        crate::fsutil::with_lock(&self.path, || {
            let mut m = self.read()?;
            m.insert(key.to_string(), value.expose_secret().to_string());
            self.write(&m)
        })
    }
    fn delete(&self, key: &str) -> Result<bool> {
        crate::fsutil::with_lock(&self.path, || {
            let mut m = self.read()?;
            let had = m.remove(key).is_some();
            self.write(&m)?;
            Ok(had)
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod kernel_tests {
    use super::*;
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    const CHILD: &str = "TOKENSTASH_KERNEL_TEST_CHILD";

    /// Run the test `name` again in a child process that has a fresh session keyring of its
    /// own, as a separate login would, and a scratch `TOKENSTASH_HOME` so its keys live under
    /// a service name of their own. True in the child (run the body), false in the parent
    /// once the child has passed. A kernel that refuses keyctl (a container's seccomp
    /// profile) skips the test.
    fn in_own_session(name: &str) -> bool {
        if std::env::var_os(CHILD).is_some() {
            return true;
        }
        let home = std::env::temp_dir().join(format!("tokenstash-kernel-test-{}-{}", std::process::id(), rand::random::<u32>()));
        spawn_session(name, &[("TOKENSTASH_HOME", home.as_os_str())]);
        let _ = std::fs::remove_dir_all(&home);
        false
    }

    /// What the second process in a test does, for tests that start one.
    const ROLE: &str = "TOKENSTASH_KERNEL_TEST_ROLE";

    /// The test `name` again, in a process that will join a session keyring of its own.
    fn session_command(name: &str) -> std::process::Command {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([name, "--exact", "--nocapture", "--test-threads=1"]).env(CHILD, "1");
        // SAFETY: only an async-signal-safe syscall runs between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                // KEYCTL_JOIN_SESSION_KEYRING with no name: a new anonymous session keyring.
                if libc::syscall(libc::SYS_keyctl, 1, std::ptr::null::<libc::c_char>()) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd
    }

    /// Run the test `name` in a new process with a session keyring of its own and `env`
    /// added; assert it ran its body to the end. False if keyctl is refused here.
    fn spawn_session(name: &str, env: &[(&str, &std::ffi::OsStr)]) -> bool {
        let mut cmd = session_command(name);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("skipped: no kernel keyring here ({e})");
                return false;
            }
        };
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success() && text.contains("1 passed"), "child run failed:\n{text}");
        assert!(text.contains(RAN), "the child did not run the test body:\n{text}");
        true
    }

    /// Printed by a child that ran the body to the end, so a silent early return cannot
    /// pass as a pass.
    const RAN: &str = "kernel keyring test body completed";

    /// Printed by a holder (see [`while_another_session_holds`]) once its copy is in place.
    const HELD: &str = "kernel keyring test copy held";

    /// Run the test `name` as a holder (`ROLE=holder`) in a new process with a session
    /// keyring of its own, and call `f` while that process, and so its session keyring and
    /// whatever it linked there, is still alive. The holder prints [`HELD`], then waits for
    /// its stdin to close.
    fn while_another_session_holds(name: &str, f: impl FnOnce()) {
        use std::io::{BufRead, Read};
        let mut child = session_command(name).env(ROLE, "holder").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut text = String::new();
        while !text.contains(HELD) {
            assert_ne!(out.read_line(&mut text).unwrap(), 0, "the holder exited before it held a copy:\n{text}");
        }
        f();
        drop(child.stdin.take());
        out.read_to_string(&mut text).unwrap();
        assert!(child.wait().unwrap().success() && text.contains(RAN), "the holder did not run its body to the end:\n{text}");
    }

    fn value(s: &dyn Stash, key: &str) -> Option<String> {
        s.get(key).unwrap().map(|v| v.expose_secret().to_string())
    }

    /// Removes everything the test left under its name, even when an assertion fails
    /// halfway: the persistent keyring is shared by every session of this user.
    struct Cleanup(&'static str);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = KernelKeyring.delete(self.0);
        }
    }

    /// The state an agent's session was left in by keyring-rs's keyutils store: an old copy
    /// linked straight into the session keyring, while the key pasted from another session
    /// (an SSH shell) is a different object in the persistent keyring. A read must return
    /// the pasted value, and the next write must reach the old copy too.
    #[test]
    fn a_session_copy_does_not_shadow_the_stored_value() {
        if !in_own_session("stash::kernel_tests::a_session_copy_does_not_shadow_the_stored_value") {
            return;
        }
        probe(&KernelKeyring).expect("the kernel keyring works in a session that does not link the user keyring");
        let key = "OPENAI_API_KEY@default";
        let _cleanup = Cleanup(key);
        let desc = kernel::description(key);
        let session = KeyRing::from_special_id(KeyRingIdentifier::Session, false).unwrap();
        let persistent = KeyRing::get_persistent(KeyRingIdentifier::Session).expect("persistent keyring");

        // Older tokenstash stored and read the old value in this session.
        let old = session.add_key(&desc, b"sk-old-value-from-this-session").unwrap();
        persistent.link_key(old).unwrap();
        // The paste from the other session: a separate object, linked into the persistent
        // keyring (displacing the old link there) and nowhere in this session.
        let process = KeyRing::from_special_id(KeyRingIdentifier::Process, true).unwrap();
        let new = process.add_key(&desc, b"sk-new-value-from-another-session").unwrap();
        persistent.link_key(new).unwrap();
        process.unlink_key(new).unwrap();
        assert_ne!(old, new);
        // keyring-rs read the session first and got the old value back.
        assert_eq!(session.search(&desc).unwrap(), old, "the setup must reproduce the shadowing");

        assert_eq!(value(&KernelKeyring, key).as_deref(), Some("sk-new-value-from-another-session"));

        // A replacement written from this session reaches both objects: an older tokenstash
        // still running here reads the session copy, and it now holds the new value.
        KernelKeyring.set(key, &SecretString::from("sk-replacement-value")).unwrap();
        assert_eq!(value(&KernelKeyring, key).as_deref(), Some("sk-replacement-value"));
        let legacy = session.search(&desc).unwrap().read_to_vec().unwrap();
        assert_eq!(legacy, b"sk-replacement-value");

        assert!(KernelKeyring.delete(key).unwrap());
        assert_eq!(value(&KernelKeyring, key), None);
        assert!(!KernelKeyring.delete(key).unwrap());
        println!("{RAN}");
    }

    /// The reported failure, with both logins alive at once: this session (the agent's)
    /// holds an old copy straight in its session keyring, and a second session (an SSH
    /// shell, the inbox) stores a new value while this one is still running. This session
    /// must read the new value.
    #[test]
    fn a_value_stored_from_another_live_session_is_the_one_read_here() {
        const NAME: &str = "stash::kernel_tests::a_value_stored_from_another_live_session_is_the_one_read_here";
        if !in_own_session(NAME) {
            return;
        }
        let key = "OPENAI_API_KEY@default";
        if std::env::var_os(ROLE).is_some() {
            // The second session: a paste, nothing else.
            KernelKeyring.set(key, &SecretString::from("sk-pasted-in-the-other-session")).unwrap();
            println!("{RAN}");
            return;
        }
        probe(&KernelKeyring).expect("the kernel keyring works in a session that does not link the user keyring");
        let _cleanup = Cleanup(key);
        KernelKeyring.set(key, &SecretString::from("sk-first-value")).unwrap();
        // What an older tokenstash in this session left behind: its own copy, straight in
        // the session keyring.
        let session = KeyRing::from_special_id(KeyRingIdentifier::Session, false).unwrap();
        let shadow = session.add_key(&kernel::description(key), b"sk-old-session-copy").unwrap();
        assert_eq!(session.search(&kernel::description(key)).unwrap(), shadow, "the setup must reproduce the shadowing");
        assert!(spawn_session(NAME, &[(ROLE, std::ffi::OsStr::new("writer"))]), "the second session must run");
        assert_eq!(value(&KernelKeyring, key).as_deref(), Some("sk-pasted-in-the-other-session"));
        println!("{RAN}");
    }

    /// Greptile on #61, #63 and #64: a read that finds a key only in this session's keyring (a
    /// copy older code left) links it into the user and persistent keyrings. Another session
    /// can store the key between that read's search and its links. The read must then return
    /// the stored key and leave the old copy out of both keyrings, not link it over the new one.
    #[test]
    fn a_read_does_not_link_a_session_copy_over_a_key_stored_meanwhile() {
        const NAME: &str = "stash::kernel_tests::a_read_does_not_link_a_session_copy_over_a_key_stored_meanwhile";
        if !in_own_session(NAME) {
            return;
        }
        let key = "OPENAI_API_KEY@default";
        if std::env::var_os(ROLE).is_some() {
            // The second session: a paste, nothing else.
            KernelKeyring.set(key, &SecretString::from("sk-stored-from-another-session")).unwrap();
            println!("{RAN}");
            return;
        }
        probe(&KernelKeyring).expect("the kernel keyring works in a session that does not link the user keyring");
        let _cleanup = Cleanup(key);
        let desc = kernel::description(key);
        // What older tokenstash left in this session, and nowhere else.
        let session = KeyRing::from_special_id(KeyRingIdentifier::Session, false).unwrap();
        let old = session.add_key(&desc, b"sk-old-copy-only-in-this-session").unwrap();
        // The read has found that copy; before it links it, the other session stores the key.
        BEFORE_RELINK.with(|h| {
            *h.borrow_mut() = Some(Box::new(|| assert!(spawn_session(NAME, &[(ROLE, std::ffi::OsStr::new("writer"))]), "the second session must run")))
        });
        assert_eq!(value(&KernelKeyring, key).as_deref(), Some("sk-stored-from-another-session"));
        assert!(BEFORE_RELINK.with(|h| h.borrow().is_none()), "the read went through the gap");
        let user = KeyRing::from_special_id(KeyRingIdentifier::User, false).unwrap();
        let persistent = KeyRing::get_persistent(KeyRingIdentifier::Session).unwrap();
        let stored = user.search(&desc).unwrap();
        assert_ne!(stored, old, "the old copy is not linked into the user keyring");
        assert_eq!(persistent.search(&desc).unwrap(), stored, "nor into the persistent keyring");
        println!("{RAN}");
    }

    /// What `doctor`'s check finds for `keys` (the keys the index lists), with `/proc/keys`
    /// read as usual.
    fn found(keys: &[&str]) -> Vec<StrayCopy> {
        let keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
        let check = KernelKeyring.stray_copies(&keys).expect("the kernel keyring checks for copies");
        assert_eq!(check.limited, None, "/proc/keys is readable here");
        check.copies
    }

    /// `/proc/keys` could not be read.
    fn unreadable() -> std::io::Result<String> {
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no /proc here"))
    }

    /// Greptile on #60 and #67: an older tokenstash still running in another login session
    /// reads its own old copy of a key and links it into the persistent keyring, so the user
    /// keyring and the persistent keyring hold different values. `doctor`'s check names the
    /// key while they differ. A read here keeps the user keyring's value and links that key
    /// into the persistent keyring again. A write from that old process leaves the same state
    /// with the newer value in the persistent keyring; the kernel cannot tell the two apart,
    /// so that case is reported, not repaired.
    ///
    /// Greptile on #77: the check also covers a key this home's index does not list, which
    /// `need` can still read and adopt, and still compares the two keyrings when `/proc/keys`
    /// cannot be read, saying what it could not check.
    #[test]
    fn an_old_copy_linked_into_the_persistent_keyring_is_reported_and_not_read() {
        const NAME: &str = "stash::kernel_tests::an_old_copy_linked_into_the_persistent_keyring_is_reported_and_not_read";
        if !in_own_session(NAME) {
            return;
        }
        let key = "OPENAI_API_KEY@default";
        let desc = kernel::description(key);
        if std::env::var_os(ROLE).is_some() {
            // What keyring-rs's keyutils store does when it reads in a session that holds
            // its own copy. It links that copy into the persistent keyring.
            let session = KeyRing::from_special_id(KeyRingIdentifier::Session, false).unwrap();
            let old = session.add_key(&desc, b"sk-old-copy-of-that-session").unwrap();
            KeyRing::get_persistent(KeyRingIdentifier::Session).unwrap().link_key(old).unwrap();
            println!("{RAN}");
            return;
        }
        probe(&KernelKeyring).expect("the kernel keyring works in a session that does not link the user keyring");
        let _cleanup = Cleanup(key);
        KernelKeyring.set(key, &SecretString::from("sk-current-value")).unwrap();
        assert!(found(&[key]).is_empty(), "one object, linked into both keyrings");
        assert!(spawn_session(NAME, &[(ROLE, std::ffi::OsStr::new("old-reader"))]), "the second session must run");
        let user = KeyRing::from_special_id(KeyRingIdentifier::User, false).unwrap();
        let persistent = KeyRing::get_persistent(KeyRingIdentifier::Session).unwrap();
        assert_ne!(user.search(&desc).unwrap(), persistent.search(&desc).unwrap(), "the setup must reproduce the old process's link");

        let differs = vec![StrayCopy { key: key.into(), differs: true, elsewhere: 0 }];
        assert_eq!(found(&[key]), differs);
        assert_eq!(found(&[]), differs, "a key the index does not list is found in the keyrings");
        let blind = kernel::stray_check(&[key.to_string()], unreadable());
        assert_eq!(blind.copies, differs, "the two keyrings are compared without /proc/keys");
        assert!(blind.limited.as_deref().is_some_and(|w| w.starts_with("Could not read /proc/keys (no /proc here)")), "{blind:?}");
        let blind = kernel::stray_check(&[], unreadable());
        assert!(blind.copies.is_empty() && blind.limited.is_some(), "without /proc/keys only indexed keys are checked, and the check says so: {blind:?}");

        assert_eq!(value(&KernelKeyring, key).as_deref(), Some("sk-current-value"));
        assert_eq!(persistent.search(&desc).unwrap(), user.search(&desc).unwrap(), "the read linked the user keyring's key into the persistent keyring again");
        // The old copy may still count as held elsewhere until the kernel collects the dead
        // session keyring that linked it, but the two keyrings agree again.
        assert!(found(&[key]).iter().all(|c| !c.differs));
        println!("{RAN}");
    }

    /// Greptile on #67: a copy that only another login session links cannot be written from
    /// here, so a replacement stored here does not reach it, and an older tokenstash in that
    /// session keeps reading it. `doctor`'s check counts it.
    #[test]
    fn a_copy_only_another_live_session_holds_is_counted() {
        const NAME: &str = "stash::kernel_tests::a_copy_only_another_live_session_holds_is_counted";
        if !in_own_session(NAME) {
            return;
        }
        let key = "OPENAI_API_KEY@default";
        let desc = kernel::description(key);
        if std::env::var_os(ROLE).is_some() {
            // An older tokenstash's session copy, held while the other process checks.
            let session = KeyRing::from_special_id(KeyRingIdentifier::Session, false).unwrap();
            session.add_key(&desc, b"sk-old-copy-of-that-session").unwrap();
            println!("{HELD}");
            let _ = std::io::stdin().read_line(&mut String::new());
            println!("{RAN}");
            return;
        }
        probe(&KernelKeyring).expect("the kernel keyring works in a session that does not link the user keyring");
        let _cleanup = Cleanup(key);
        KernelKeyring.set(key, &SecretString::from("sk-current-value")).unwrap();
        assert!(found(&[key]).is_empty(), "one object, linked into both keyrings");
        while_another_session_holds(NAME, || {
            assert_eq!(found(&[key]), vec![StrayCopy { key: key.into(), differs: false, elsewhere: 1 }]);
            // Without /proc/keys the copy cannot be seen, and the check says so.
            let blind = kernel::stray_check(&[key.to_string()], unreadable());
            assert!(blind.copies.is_empty() && blind.limited.is_some(), "{blind:?}");
            // It is not the key read here.
            assert_eq!(value(&KernelKeyring, key).as_deref(), Some("sk-current-value"));
        });
        println!("{RAN}");
    }

    /// A value written in one session is the value every later session reads, and a
    /// replacement updates the same object instead of adding a second one.
    #[test]
    fn one_object_per_name_updated_in_place() {
        if !in_own_session("stash::kernel_tests::one_object_per_name_updated_in_place") {
            return;
        }
        probe(&KernelKeyring).expect("the kernel keyring works in a session that does not link the user keyring");
        let key = "RESEND_API_KEY@work";
        let _cleanup = Cleanup(key);
        let desc = kernel::description(key);
        KernelKeyring.set(key, &SecretString::from("re_first_value_123")).unwrap();
        let user = KeyRing::from_special_id(KeyRingIdentifier::User, false).unwrap();
        let first = user.search(&desc).unwrap();
        KernelKeyring.set(key, &SecretString::from("re_second_value_456")).unwrap();
        assert_eq!(user.search(&desc).unwrap(), first, "a replacement keeps the same key object");
        let persistent = KeyRing::get_persistent(KeyRingIdentifier::Session).unwrap();
        assert_eq!(persistent.search(&desc).unwrap(), first, "and it is pinned in the persistent keyring too");
        assert_eq!(value(&KernelKeyring, key).as_deref(), Some("re_second_value_456"));
        // Nothing went into the session keyring, so no later session copy can exist.
        let session = KeyRing::from_special_id(KeyRingIdentifier::Session, false).unwrap();
        assert!(!session.get_links(64).unwrap().contains(&first), "the key is not linked into the session keyring");
        assert!(KernelKeyring.delete(key).unwrap());
        assert_eq!(value(&KernelKeyring, key), None);
        println!("{RAN}");
    }
}
