//! Private, atomic file writes. Used for anything that holds a secret value.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Write `contents` to `path` such that:
/// - the file is 0600 from the first byte (created with that mode, O_EXCL temp file);
/// - a pre-existing symlink at `path` is refused, never written through;
/// - the write is atomic: on any failure the previous file is untouched;
/// - the temp file is never left behind.
pub fn write_atomic_private(path: &Path, contents: &str) -> Result<()> {
    write_atomic_private_bytes(path, contents.as_bytes())
}

/// Byte-oriented implementation (the bundle is binary). Same guarantees: refuses a symlink
/// or non-file destination, O_EXCL temp at 0600, fsync, rename, temp removed on any failure.
pub fn write_atomic_private_bytes(path: &Path, contents: &[u8]) -> Result<()> {
    if let Ok(md) = fs::symlink_metadata(path) {
        if md.file_type().is_symlink() {
            bail!("{} is a symlink; refusing to write a secret through it", path.display());
        }
        if !md.is_file() {
            bail!("{} exists and is not a regular file", path.display());
        }
    }
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
    let tmp = dir.join(format!(".{name}.tokenstash-{}.tmp", std::process::id()));
    let _guard = RemoveOnDrop(tmp.clone());

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true); // O_EXCL: fails if anything (incl. a symlink) is there
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(contents)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // belt and braces for filesystems that ignore mode at create
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Serialise writers of a file we must not litter next to. `with_lock` puts the lock
/// beside its target, which is right for tokenstash's own files but wrong for a file inside
/// the user's project: `.env.lock` would show up in their working tree (and, unlike the env
/// file, in no .gitignore). The lock lives in tokenstash's config dir instead, named after
/// the target path so two processes writing the same env file agree on it.
pub fn with_lock_elsewhere<T>(target: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(target.as_os_str().as_encoded_bytes());
    let dir = crate::config::config_dir().join("locks");
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    with_lock(&dir.join(format!("{:x}", digest)), f)
}

/// Cross-process mutual exclusion for read-modify-write of a private file, via an OS
/// advisory lock on a sibling `<name>.lock`. The kernel releases it when the holder exits
/// or dies, so there is no stale-lock heuristic and a live (even suspended) holder is
/// never preempted. Contenders simply wait.
pub fn with_lock<T>(path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let lock_path = path.with_extension("lock");
    let mut opts = fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let lock = opts.open(&lock_path).with_context(|| format!("opening lock {}", lock_path.display()))?;
    lock.lock().with_context(|| format!("locking {}", lock_path.display()))?;
    let out = f();
    let _ = lock.unlock();
    out
}

/// Atomic replace for a non-secret, repo-visible file (e.g. `.gitignore`): O_EXCL temp,
/// fsync, rename. Refuses a symlinked destination. Default (umask) permissions.
pub fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Ok(md) = fs::symlink_metadata(path) {
        if md.file_type().is_symlink() {
            bail!("{} is a symlink; refusing to write through it", path.display());
        }
    }
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
    let tmp = dir.join(format!(".{name}.tokenstash-{}.tmp", std::process::id()));
    let _guard = RemoveOnDrop(tmp.clone());
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

struct RemoveOnDrop(std::path::PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
