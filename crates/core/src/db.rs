use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// (ts, project, agent, action, name, identity, detail) — never a value.
/// (ts, project, agent, action, name, identity, detail, grant_source)
pub type AuditRow = (String, Option<String>, Option<String>, String, Option<String>, Option<String>, Option<String>, Option<String>);

pub struct Db {
    pub(crate) conn: Connection,
}

/// The index holds no values, but task/approval/binding metadata is still private.
#[cfg(unix)]
fn restrict_dir(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(unix)]
fn restrict_file(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if p.exists() {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMeta {
    pub name: String,
    pub identity: String,
    pub provider: Option<String>,
    pub sensitive: bool,
    pub source_url: Option<String>,
    pub created: String,
    pub last_used: Option<String>,
    pub stale: bool,
    /// Last time a liveness probe (paste-time or `check`) accepted this value.
    #[serde(default)]
    pub last_verified: Option<String>,
    /// Why it is stale: `rejected by X (HTTP n) on <date>, reported by <agent> in <project>`,
    /// "you asked to rotate", ... Shown on the replacement card.
    #[serde(default)]
    pub stale_reason: Option<String>,
    /// Who set the stale flag: "rotate" (the human), "report" (an agent's report, probe-
    /// decided when a probe exists), "probe" (verify-on-use or `check`). State transitions
    /// key off this, never off the display text in `stale_reason`.
    #[serde(default)]
    pub stale_source: Option<String>,
    /// Do not probe before this time (RFC 3339). A lease: set before a probe goes on the
    /// wire so a concurrent process does not probe too, then extended by the result.
    #[serde(default)]
    pub next_probe: Option<String>,
    /// Verify-on-use is off for this key: the human stored it with --skip-check / --no-verify,
    /// so a probe that keeps saying "rejected" must not keep filing cards. Cleared by any
    /// probe that says Ok.
    #[serde(default)]
    pub verify_off: bool,
}

/// Grant scopes and sources (trust v2).
/// What `PRAGMA user_version` this build writes and understands.
pub const SCHEMA_VERSION: i64 = 2;

pub const GRANT_KEY: &str = "key";
pub const GRANT_BROAD: &str = "broad";
pub const GRANT_PASTE: &str = "paste";
pub const GRANT_PAIRING: &str = "pairing";
pub const GRANT_SENSITIVE: &str = "sensitive";
pub const GRANT_BACKFILL: &str = "backfill";
/// Not a grant: the value was already in the workspace's env file (delivery marker only).
pub const GRANT_ON_DISK: &str = "on_disk";
/// Not a grant: a one-time approval (`run`).
pub const GRANT_ONCE: &str = "once";

/// A directory the human has paired keys into.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    /// Canonical root path.
    pub root: String,
    pub ino: u64,
    /// Directory birth time, when the filesystem reports one; with it, an inode number
    /// reused by a re-created directory (ext4 does this readily) is still told apart.
    pub btime: Option<String>,
    pub dev: u64,
    pub created: String,
    /// The filesystem gave no birth time: identity rests on the inode alone.
    #[serde(default)]
    pub fingerprint_weak: bool,
    /// The directory at this root is no longer the one on record (re-created, moved
    /// between volumes, shown through a different mount). Its grants do not apply until a
    /// human pairs it again; nothing is deleted by an agent-callable path.
    #[serde(default)]
    pub fingerprint_ok: bool,
}

/// Generated locally (e.g. AUTH_SECRET): stored and delivered, never pasted.
pub const GRANT_GENERATED: &str = "generated";
/// Written by a rotation into a workspace holding an exact/broad grant.
pub const GRANT_ROTATION: &str = "rotation";

pub struct Fingerprint { pub ino: u64, pub btime: Option<String>, pub dev: u64 }

/// (inode, birth time, device) of a directory. `None` if it cannot be stat'ed.
pub fn fingerprint(root: &Path) -> Option<Fingerprint> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(root).ok()?;
    if !md.is_dir() {
        return None;
    }
    let btime = md.created().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| format!("{}.{:09}", d.as_secs(), d.subsec_nanos()));
    Some(Fingerprint { ino: md.ino(), btime, dev: md.dev() })
}

/// Same directory? Inode and birth time; where the filesystem reports no birth time the
/// device joins the inode (a weaker identity, flagged in `workspaces list`).
fn fingerprint_matches(w: &Workspace, fp: &Fingerprint) -> bool {
    w.ino == fp.ino && w.btime == fp.btime && (w.btime.is_some() || w.dev == fp.dev)
}

fn new_workspace_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Values for `SecretMeta::stale_source`.
pub const STALE_ROTATE: &str = "rotate";
pub const STALE_REPORT: &str = "report";
pub const STALE_PROBE: &str = "probe";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Secret,
    Approval,
    Human,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Answered,
    Denied,
    Expired,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Pending => "pending",
            TaskStatus::Answered => "answered",
            TaskStatus::Denied => "denied",
            TaskStatus::Expired => "expired",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "answered" => TaskStatus::Answered,
            "denied" => TaskStatus::Denied,
            "expired" => TaskStatus::Expired,
            _ => TaskStatus::Pending,
        }
    }
}

impl TaskKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskKind::Secret => "secret",
            TaskKind::Approval => "approval",
            TaskKind::Human => "human",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "approval" => TaskKind::Approval,
            "human" => TaskKind::Human,
            _ => TaskKind::Secret,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub kind: TaskKind,
    pub project: String,
    pub agent: String,
    /// Secret name (secret tasks) or None.
    pub name: Option<String>,
    pub identity: String,
    pub title: String,
    pub why: Option<String>,
    pub url: Option<String>,
    pub steps: Vec<String>,
    /// "secret" | "confirm" | "text" | "choice"
    pub expects: String,
    pub pattern: Option<String>,
    /// For approval tasks: the names being gated.
    pub names: Vec<String>,
    pub status: TaskStatus,
    pub created: String,
    pub deadline: String,
    pub answered_at: Option<String>,
    pub note: Option<String>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            restrict_dir(parent)?;
        }
        let conn = Connection::open(path)?;
        restrict_file(path)?;
        // CLI, inbox and MCP server each hold their own connection; a write collision must
        // wait, not error.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode=WAL")?;
        // WAL brings two sidecar files that SQLite creates at umask (0644 on most systems).
        // They hold recently written rows — project paths, key names, identities, grants —
        // so they get the same 0600 as the database itself. The parent dir is already 0700;
        // this makes the files safe on their own if it ever is not.
        for suffix in ["-wal", "-shm"] {
            let side = path.with_file_name(format!("{}{suffix}", path.file_name().unwrap_or_default().to_string_lossy()));
            if side.exists() {
                let _ = restrict_file(&side);
            }
        }
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS secrets (
                name TEXT NOT NULL, identity TEXT NOT NULL, provider TEXT,
                sensitive INTEGER NOT NULL DEFAULT 0, source_url TEXT,
                created TEXT NOT NULL, last_used TEXT, stale INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (name, identity)
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, project TEXT NOT NULL, agent TEXT NOT NULL,
                name TEXT, identity TEXT NOT NULL DEFAULT 'default', title TEXT NOT NULL,
                why TEXT, url TEXT, steps TEXT NOT NULL DEFAULT '[]', expects TEXT NOT NULL DEFAULT 'secret',
                pattern TEXT, names TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'pending',
                created TEXT NOT NULL, deadline TEXT NOT NULL, answered_at TEXT, note TEXT
            );
            CREATE TABLE IF NOT EXISTS approvals (
                project TEXT NOT NULL, name TEXT NOT NULL, created TEXT NOT NULL,
                PRIMARY KEY (project, name)
            );
            CREATE TABLE IF NOT EXISTS bindings (
                project TEXT NOT NULL, name TEXT NOT NULL, identity TEXT NOT NULL,
                PRIMARY KEY (project, name)
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, project TEXT, agent TEXT,
                action TEXT NOT NULL, name TEXT, identity TEXT, detail TEXT
            );
            -- Trust v2: a workspace is a directory the human paired keys into.
            -- Identity is the canonical root; the fingerprint (inode + birth time) tells a
            -- re-created directory at the same path from the original. Old tables stay so a
            -- 0.1 binary can still open this database.
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY, root TEXT NOT NULL UNIQUE, ino INTEGER NOT NULL,
                btime TEXT, dev INTEGER NOT NULL, created TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS grants (
                workspace_id TEXT NOT NULL, name TEXT NOT NULL, identity TEXT NOT NULL,
                scope TEXT NOT NULL, source TEXT NOT NULL, created TEXT NOT NULL,
                PRIMARY KEY (workspace_id, name, identity)
            );
            CREATE TABLE IF NOT EXISTS workspace_bindings (
                workspace_id TEXT NOT NULL, name TEXT NOT NULL, identity TEXT NOT NULL,
                PRIMARY KEY (workspace_id, name)
            );
            "#,
        )?;
        {
            let has: bool = conn.prepare("SELECT 1 FROM pragma_table_info('audit') WHERE name=?1")?.exists(["grant_source"])?;
            if !has {
                if let Err(e) = conn.execute_batch("ALTER TABLE audit ADD COLUMN grant_source TEXT") {
                    if !e.to_string().contains("duplicate column") {
                        return Err(e.into());
                    }
                }
            }
        }
        // Columns added after v0.1.0. SQLite has no ADD COLUMN IF NOT EXISTS; probe first.
        for (col, ddl) in [
            ("last_verified", "ALTER TABLE secrets ADD COLUMN last_verified TEXT"),
            ("stale_reason", "ALTER TABLE secrets ADD COLUMN stale_reason TEXT"),
            ("stale_source", "ALTER TABLE secrets ADD COLUMN stale_source TEXT"),
            ("next_probe", "ALTER TABLE secrets ADD COLUMN next_probe TEXT"),
            ("verify_off", "ALTER TABLE secrets ADD COLUMN verify_off INTEGER NOT NULL DEFAULT 0"),
        ] {
            let has: bool = conn.prepare("SELECT 1 FROM pragma_table_info('secrets') WHERE name=?1")?.exists([col])?;
            if !has {
                // Two processes (CLI + MCP server) can race here; the loser's ALTER fails
                // with "duplicate column", which is success.
                if let Err(e) = conn.execute_batch(ddl) {
                    if !e.to_string().contains("duplicate column") {
                        return Err(e.into());
                    }
                }
            }
        }
        // Cards remember whether their one desktop notification went out (0.2.1+).
        {
            let has: bool = conn.prepare("SELECT 1 FROM pragma_table_info('tasks') WHERE name=?1")?.exists(["notified"])?;
            if !has {
                if let Err(e) = conn.execute_batch("ALTER TABLE tasks ADD COLUMN notified TEXT") {
                    if !e.to_string().contains("duplicate column") {
                        return Err(e.into());
                    }
                }
            }
        }
        // Rows marked stale before `stale_source` existed: the human's rotation is the only
        // one whose display text is a fixed constant, so it is the only one recoverable.
        conn.execute(
            "UPDATE secrets SET stale_source=?1 WHERE stale=1 AND stale_source IS NULL AND stale_reason LIKE ?2",
            params![STALE_ROTATE, format!("{}%", Self::ROTATE_REASON)],
        )?;
        conn.execute("UPDATE secrets SET stale_source=?1 WHERE stale=1 AND stale_source IS NULL", params![STALE_REPORT])?;
        let db = Self { conn };
        db.migrate_v2()?;
        Ok(db)
    }

    /// Data migration to trust v2, once, under one write lock (two processes opening a 0.1
    /// database at the same time must not both backfill). `user_version` 2 marks it done.
    /// Backfills from `approvals` only — never from audit rows, which include one-time
    /// `run` approvals that must not become standing grants.
    fn migrate_v2(&self) -> Result<()> {
        let v: i64 = self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if v > SCHEMA_VERSION {
            // A newer tokenstash wrote this database. Its grants may mean something this
            // build does not implement, and guessing is how an old binary hands out a key
            // the human revoked in a model it never learned. Refuse instead.
            anyhow::bail!(
                "this tokenstash database was written by a newer version (schema {v}, this build understands {SCHEMA_VERSION}). Upgrade tokenstash."
            );
        }
        if v >= SCHEMA_VERSION {
            return Ok(());
        }
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let done = (|| -> Result<()> {
            let v: i64 = self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if v >= SCHEMA_VERSION {
                return Ok(());
            }
            let mut st = self.conn.prepare("SELECT project, name, created FROM approvals")?;
            let rows: Vec<(String, String, String)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<std::result::Result<_, _>>()?;
            drop(st);
            for (project, name, approved_at) in rows {
                let root = Path::new(&project);
                if !root.is_dir() {
                    continue; // a root that no longer exists gets no grant
                }
                // A directory created AFTER the approval is not the one the human approved
                // (re-cloned at the same path before this upgrade): no grant for it.
                if let Some(fp) = fingerprint(root) {
                    if let (Some(bt), Ok(at)) = (fp.btime.as_deref(), chrono::DateTime::parse_from_rfc3339(&approved_at)) {
                        let secs: f64 = bt.parse().unwrap_or(0.0);
                        if secs > at.timestamp() as f64 {
                            continue;
                        }
                    }
                }
                let Some(ws) = self.workspace_for_locked(root)? else { continue };
                let identity = self.legacy_binding(&project, &name)?.unwrap_or_else(|| "default".into());
                if name == "*" {
                    self.grant(&ws.id, "*", &identity, GRANT_BROAD, GRANT_BACKFILL)?;
                } else {
                    self.grant(&ws.id, &name, &identity, GRANT_KEY, GRANT_BACKFILL)?;
                }
            }
            let mut st = self.conn.prepare("SELECT project, name, identity FROM bindings")?;
            let rows: Vec<(String, String, String)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<std::result::Result<_, _>>()?;
            drop(st);
            for (project, name, identity) in rows {
                let root = Path::new(&project);
                if !root.is_dir() {
                    continue;
                }
                if let Some(ws) = self.workspace_for_locked(root)? {
                    self.set_binding(&ws.id, &name, &identity)?;
                }
            }
            self.conn.execute_batch("PRAGMA user_version = 2")?;
            Ok(())
        })();
        match done {
            Ok(()) => { self.conn.execute_batch("COMMIT")?; Ok(()) }
            Err(e) => { let _ = self.conn.execute_batch("ROLLBACK"); Err(e) }
        }
    }

    fn legacy_binding(&self, project: &str, name: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT identity FROM bindings WHERE project=?1 AND name=?2", params![project, name], |r| r.get(0)).optional()?)
    }

    pub fn open_default() -> Result<Self> {
        Self::open(&crate::config::db_path())
    }

    // ---------- secrets index (metadata only; values live in the stash) ----------

    pub fn upsert_secret(&self, m: &SecretMeta) -> Result<()> {
        self.conn.execute(
            "INSERT INTO secrets (name, identity, provider, sensitive, source_url, created, last_used, stale, last_verified, stale_reason, stale_source, next_probe, verify_off)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(name, identity) DO UPDATE SET provider=excluded.provider, sensitive=excluded.sensitive,
               source_url=excluded.source_url, stale=excluded.stale, last_verified=excluded.last_verified, stale_reason=excluded.stale_reason,
               stale_source=excluded.stale_source, next_probe=excluded.next_probe, verify_off=excluded.verify_off,
               created=excluded.created, last_used=COALESCE(excluded.last_used, secrets.last_used)",
            params![m.name, m.identity, m.provider, m.sensitive as i32, m.source_url, m.created, m.last_used, m.stale as i32, m.last_verified, m.stale_reason, m.stale_source, m.next_probe, m.verify_off as i32],
        )?;
        Ok(())
    }

    pub fn get_secret(&self, name: &str, identity: &str) -> Result<Option<SecretMeta>> {
        Ok(self
            .conn
            .query_row(
                "SELECT name, identity, provider, sensitive, source_url, created, last_used, stale, last_verified, stale_reason, stale_source, next_probe, verify_off FROM secrets WHERE name=?1 AND identity=?2",
                params![name, identity],
                |r| {
                    Ok(SecretMeta {
                        name: r.get(0)?,
                        identity: r.get(1)?,
                        provider: r.get(2)?,
                        sensitive: r.get::<_, i32>(3)? != 0,
                        source_url: r.get(4)?,
                        created: r.get(5)?,
                        last_used: r.get(6)?,
                        stale: r.get::<_, i32>(7)? != 0,
                        last_verified: r.get(8)?,
                        stale_reason: r.get(9)?,
                        stale_source: r.get(10)?,
                        next_probe: r.get(11)?,
                        verify_off: r.get::<_, i32>(12)? != 0,
                    })
                },
            )
            .optional()?)
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretMeta>> {
        let mut st = self.conn.prepare(
            "SELECT name, identity, provider, sensitive, source_url, created, last_used, stale, last_verified, stale_reason, stale_source, next_probe, verify_off FROM secrets ORDER BY name, identity",
        )?;
        let rows = st.query_map([], |r| {
            Ok(SecretMeta {
                name: r.get(0)?,
                identity: r.get(1)?,
                provider: r.get(2)?,
                sensitive: r.get::<_, i32>(3)? != 0,
                source_url: r.get(4)?,
                created: r.get(5)?,
                last_used: r.get(6)?,
                stale: r.get::<_, i32>(7)? != 0,
                last_verified: r.get(8)?,
                stale_reason: r.get(9)?,
                stale_source: r.get(10)?,
                next_probe: r.get(11)?,
                verify_off: r.get::<_, i32>(12)? != 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn touch_secret(&self, name: &str, identity: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE secrets SET last_used=?3 WHERE name=?1 AND identity=?2",
            params![name, identity, crate::now()],
        )?;
        Ok(())
    }

    /// Mark a key stale (with the reason the replacement card will show, and who decided)
    /// or fresh again.
    pub fn mark_stale(&self, name: &str, identity: &str, stale: bool, reason: Option<&str>, source: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE secrets SET stale=?3, stale_reason=?4, stale_source=?5 WHERE name=?1 AND identity=?2",
            params![name, identity, stale as i32, if stale { reason } else { None }, if stale { source } else { None }],
        )?;
        Ok(())
    }

    /// Display text for a stale set by the human (`rotate`).
    pub const ROTATE_REASON: &'static str = "you asked to rotate it";

    /// A probe accepted the stored value: record it, clear a probe- or report-set stale
    /// flag, release the probe lease, and re-enable verify-on-use. A rotation the human
    /// asked for survives: the old key is live by design until the new one lands.
    /// When the next routine probe is due follows from `last_verified` and the configured
    /// window, so a config change takes effect immediately; `next_probe` only ever holds a
    /// short lease or backoff.
    pub fn set_verified(&self, name: &str, identity: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE secrets SET last_verified=?3, next_probe=NULL, verify_off=0,
                stale = CASE WHEN stale_source=?4 THEN stale ELSE 0 END,
                stale_reason = CASE WHEN stale_source=?4 THEN stale_reason ELSE NULL END,
                stale_source = CASE WHEN stale_source=?4 THEN stale_source ELSE NULL END
             WHERE name=?1 AND identity=?2",
            params![name, identity, crate::now(), STALE_ROTATE],
        )?;
        Ok(())
    }

    /// Lease / backoff for verify-on-use.
    pub fn set_next_probe(&self, name: &str, identity: &str, at: &str) -> Result<()> {
        self.conn.execute("UPDATE secrets SET next_probe=?3 WHERE name=?1 AND identity=?2", params![name, identity, at])?;
        Ok(())
    }

    /// Claim the right to probe now: succeeds only if no other process holds a live lease.
    /// Returns false when someone else got there first (or the key is gone).
    pub fn claim_probe(&self, name: &str, identity: &str, until: &str) -> Result<bool> {
        let now = crate::now();
        let n = self.conn.execute(
            "UPDATE secrets SET next_probe=?3 WHERE name=?1 AND identity=?2 AND (next_probe IS NULL OR next_probe <= ?4)",
            params![name, identity, until, now],
        )?;
        Ok(n == 1)
    }

    pub fn set_verify_off(&self, name: &str, identity: &str, off: bool) -> Result<()> {
        self.conn.execute("UPDATE secrets SET verify_off=?3 WHERE name=?1 AND identity=?2", params![name, identity, off as i32])?;
        Ok(())
    }

    /// Has this key ever been delivered (stored or injected) into this project? The audit
    /// log is the record. A report of "this key is dead" is only credible from a project
    /// that actually received it.
    pub fn has_delivered(&self, project: &str, name: &str, identity: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE project=?1 AND name=?2 AND identity=?3 AND action IN ('inject','store')",
            params![project, name, identity],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Was this key injected into this project by an approval answered at or after `since`?
    /// The audit row is written by `deliver` after the env file, so it is the proof that the
    /// delivery finished — a value already sitting in the file proves nothing.
    pub fn injected_after_approval_since(&self, project: &str, name: &str, identity: &str, since: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE project=?1 AND name=?2 AND identity=?3 AND action='inject' AND detail='after-approval' AND ts >= ?4",
            params![project, name, identity, since],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// (name, identity) pairs delivered into this project root strictly after `since` (the
    /// current workspace record's creation: an older directory's deliveries are not this
    /// one's, and timestamps are second-resolution so an equal second is excluded too —
    /// a delivery in the record's own creation second is covered by its grant).
    pub fn delivered_names(&self, project: &str, since: &str) -> Result<Vec<(String, String)>> {
        let mut st = self.conn.prepare("SELECT DISTINCT name, identity FROM audit WHERE project=?1 AND action IN ('inject','store') AND name IS NOT NULL AND ts > ?2")?;
        let rows = st.query_map(params![project, since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_else(|| "default".into()))))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Projects that have ever had this key delivered. For re-injecting a rotated value.
    pub fn delivered_projects(&self, name: &str, identity: &str) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT DISTINCT project FROM audit WHERE name=?1 AND identity=?2 AND action IN ('inject','store') AND project IS NOT NULL")?;
        let rows = st.query_map(params![name, identity], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Most recent `report`/`false_report` audit row for (project, name, identity) after `since`.
    pub fn recent_report(&self, project: &str, name: &str, identity: &str, since: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row(
            "SELECT action FROM audit WHERE project=?1 AND name=?2 AND identity=?3 AND action IN ('report','false_report','report.unverified') AND ts >= ?4 ORDER BY id DESC LIMIT 1",
            params![project, name, identity, since],
            |r| r.get::<_, String>(0),
        ).optional()?)
    }

    pub fn delete_secret(&self, name: &str, identity: &str) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM secrets WHERE name=?1 AND identity=?2", params![name, identity])? > 0)
    }

    // ---------- tasks ----------

    pub fn insert_task(&self, t: &Task) -> Result<()> {
        self.conn.execute(
            "INSERT INTO tasks (id, kind, project, agent, name, identity, title, why, url, steps, expects, pattern, names, status, created, deadline, answered_at, note)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                t.id, t.kind.as_str(), t.project, t.agent, t.name, t.identity, t.title, t.why, t.url,
                serde_json::to_string(&t.steps)?, t.expects, t.pattern, serde_json::to_string(&t.names)?,
                t.status.as_str(), t.created, t.deadline, t.answered_at, t.note
            ],
        )?;
        Ok(())
    }

    fn row_to_task(r: &rusqlite::Row) -> rusqlite::Result<Task> {
        let steps: String = r.get(9)?;
        let names: String = r.get(12)?;
        Ok(Task {
            id: r.get(0)?,
            kind: TaskKind::parse(&r.get::<_, String>(1)?),
            project: r.get(2)?,
            agent: r.get(3)?,
            name: r.get(4)?,
            identity: r.get(5)?,
            title: r.get(6)?,
            why: r.get(7)?,
            url: r.get(8)?,
            steps: serde_json::from_str(&steps).unwrap_or_default(),
            expects: r.get(10)?,
            pattern: r.get(11)?,
            names: serde_json::from_str(&names).unwrap_or_default(),
            status: TaskStatus::parse(&r.get::<_, String>(13)?),
            created: r.get(14)?,
            deadline: r.get(15)?,
            answered_at: r.get(16)?,
            note: r.get(17)?,
        })
    }

    const TASK_COLS: &'static str = "id, kind, project, agent, name, identity, title, why, url, steps, expects, pattern, names, status, created, deadline, answered_at, note";

    pub fn get_task(&self, id: &str) -> Result<Option<Task>> {
        let sql = format!("SELECT {} FROM tasks WHERE id=?1", Self::TASK_COLS);
        Ok(self.conn.query_row(&sql, params![id], Self::row_to_task).optional()?)
    }

    /// Resolve a task id: exact match, else a prefix of the id with or without its kind
    /// prefix ("7fa2" and "t_7fa2" both resolve `t_7fa2xx`). An empty or ambiguous prefix
    /// is an error rather than a silent guess — callers answer, approve, or deny by id.
    pub fn find_task(&self, id_or_prefix: &str) -> Result<Option<Task>> {
        let q = id_or_prefix.trim();
        if q.is_empty() {
            anyhow::bail!("task id is empty");
        }
        if !q.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            anyhow::bail!("task id '{q}' contains invalid characters");
        }
        if let Some(t) = self.get_task(q)? {
            return Ok(Some(t));
        }
        let sql = format!("SELECT {} FROM tasks ORDER BY created DESC", Self::TASK_COLS);
        let mut st = self.conn.prepare(&sql)?;
        let matches: Vec<Task> = st
            .query_map([], Self::row_to_task)?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|t| t.id.starts_with(q) || t.id.get(2..).map(|rest| rest.starts_with(q)).unwrap_or(false))
            .collect();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.into_iter().next()),
            n => anyhow::bail!(
                "task id '{q}' is ambiguous ({n} matches: {}). Use a longer prefix.",
                matches.iter().take(5).map(|t| t.id.as_str()).collect::<Vec<_>>().join(", ")
            ),
        }
    }

    /// `find_task`, but the search itself is confined to one project. `find_task` reports an
    /// ambiguous prefix by naming the tasks it matched, and those matches are drawn from
    /// every project — so an agent passing a one-character prefix learns the task ids of
    /// projects it has nothing to do with. Callers that serve an agent use this.
    pub fn find_task_in(&self, project: &str, id_or_prefix: &str) -> Result<Option<Task>> {
        let q = id_or_prefix.trim();
        if q.is_empty() || !q.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Ok(None);
        }
        let mine: Vec<Task> = self.list_tasks(Some(project), false)?;
        if let Some(t) = mine.iter().find(|t| t.id == q) {
            return Ok(Some(t.clone()));
        }
        let mut hits = mine.into_iter().filter(|t| t.id.starts_with(q) || t.id.get(2..).map(|r| r.starts_with(q)).unwrap_or(false));
        match (hits.next(), hits.next()) {
            (Some(t), None) => Ok(Some(t)),
            _ => Ok(None), // no match, or ambiguous: same answer either way, no oracle
        }
    }

    pub fn list_tasks(&self, project: Option<&str>, only_open: bool) -> Result<Vec<Task>> {
        let mut sql = format!("SELECT {} FROM tasks WHERE 1=1", Self::TASK_COLS);
        if only_open {
            sql.push_str(" AND status='pending'");
        }
        if project.is_some() {
            sql.push_str(" AND project=?1");
        }
        sql.push_str(" ORDER BY created ASC");
        let mut st = self.conn.prepare(&sql)?;
        let rows: Vec<Task> = match project {
            Some(p) => st.query_map(params![p], Self::row_to_task)?.collect::<std::result::Result<_, _>>()?,
            None => st.query_map([], Self::row_to_task)?.collect::<std::result::Result<_, _>>()?,
        };
        Ok(rows)
    }

    /// The open human task with this title in this project, if any: a blocking caller that
    /// re-issues its request must not file a second card.
    pub fn open_human_tasks(&self, project: &str, title: &str, expects: &str) -> Result<Vec<Task>> {
        let sql = format!("SELECT {} FROM tasks WHERE kind='human' AND status='pending' AND project=?1 AND title=?2 AND expects=?3 ORDER BY created DESC", Self::TASK_COLS);
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(params![project, title, expects], Self::row_to_task)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Open secret task for this project+name+identity, if any (avoid duplicate tasks).
    /// Identity is part of the key: `OPENAI_API_KEY@work` and `@personal` are different
    /// requests and must never share a task.
    pub fn open_secret_task(&self, project: &str, name: &str, identity: &str) -> Result<Option<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='secret' AND status='pending' AND project=?1 AND name=?2 AND identity=?3 ORDER BY created DESC",
            Self::TASK_COLS
        );
        Ok(self.conn.query_row(&sql, params![project, name, identity], Self::row_to_task).optional()?)
    }

    /// Most recent denied secret task for project+name+identity, if denied after `since`.
    pub fn recent_denial(&self, project: &str, name: &str, identity: &str, since: &str) -> Result<Option<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='secret' AND status='denied' AND project=?1 AND name=?2 AND identity=?3 AND answered_at > ?4 ORDER BY answered_at DESC",
            Self::TASK_COLS
        );
        Ok(self.conn.query_row(&sql, params![project, name, identity, since], Self::row_to_task).optional()?)
    }

    /// The open approval card of one kind (`pairing` | `sensitive`) for a project root.
    pub fn open_approval_task_kind(&self, project: &str, expects: &str) -> Result<Option<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='approval' AND status='pending' AND project=?1 AND expects=?2 ORDER BY created DESC",
            Self::TASK_COLS
        );
        Ok(self.conn.query_row(&sql, params![project, expects], Self::row_to_task).optional()?)
    }

    /// Close a card, but only while it is still open. The answer paths check the status of
    /// the `Task` they were handed, which was read some time ago: two answers racing (an
    /// inbox POST and a `tokenstash answer`, or two browser tabs) would both pass that check
    /// and the second would overwrite the first — turning a committed *denial* into an
    /// approval. Returns false when someone else already closed it.
    pub fn close_task_if_open(&self, id: &str, status: TaskStatus, note: Option<&str>) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE tasks SET status=?2, answered_at=?3, note=COALESCE(?4, note) WHERE id=?1 AND status='pending'",
            params![id, status.as_str(), crate::now(), note],
        )?;
        Ok(n == 1)
    }

    /// The answer's note, set after the card was claimed (what a confirmed action did).
    pub fn set_task_note(&self, id: &str, note: &str) -> Result<()> {
        self.conn.execute("UPDATE tasks SET note=?2 WHERE id=?1", params![id, note])?;
        Ok(())
    }

    /// Claim the one desktop notification a card gets: true the first time, false after. A
    /// polling agent re-runs `need` every few seconds and the card is reused; the human's
    /// attention is not.
    pub fn mark_notified(&self, id: &str) -> Result<bool> {
        Ok(self.conn.execute("UPDATE tasks SET notified=?2 WHERE id=?1 AND notified IS NULL", params![id, crate::now()])? == 1)
    }

    /// Undo a claim that could not be completed. The card is claimed before the value is
    /// stored (so a racing answer cannot overwrite the winner); if storing then fails,
    /// leaving the card "answered" would tell the human it is done when nothing was kept.
    pub fn reopen_task(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE tasks SET status='pending', answered_at=NULL WHERE id=?1 AND status='answered'",
            params![id],
        )?;
        Ok(())
    }

    pub fn set_task_expects(&self, id: &str, expects: &str) -> Result<()> {
        self.conn.execute("UPDATE tasks SET expects=?2 WHERE id=?1", params![id, expects])?;
        Ok(())
    }

    /// Grow an open card. Returns false when the card is no longer pending (the human
    /// answered it between the caller's read and this write): the caller files a new one
    /// rather than ride an answer that never covered these names.
    pub fn update_task_names(&self, id: &str, names: &[String]) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE tasks SET names=?2 WHERE id=?1 AND status='pending'",
            params![id, serde_json::to_string(names)?],
        )?;
        Ok(n == 1)
    }

    /// Mark pending tasks past their deadline as expired. Returns count.
    pub fn expire_overdue(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE tasks SET status='expired' WHERE status='pending' AND deadline < ?1",
            params![crate::now()],
        )?)
    }

    // ---------- workspaces / grants / bindings (trust v2) ----------

    /// Find-or-create the workspace for a root, under the caller's write lock. The root is
    /// the identity; the fingerprint decides whether it is still the same directory: a
    /// mismatch (rm -rf + re-clone, a different mount) revokes the old grants and starts
    /// over — the human never paired keys into THIS directory.
    fn workspace_for_locked(&self, root: &Path) -> Result<Option<Workspace>> {
        let Ok(root) = root.canonicalize() else { return Ok(None) };
        let Some(fp) = fingerprint(&root) else { return Ok(None) };
        let key = root.to_string_lossy().to_string();
        let existing: Option<Workspace> = self.conn.query_row(
            "SELECT id, root, ino, btime, dev, created FROM workspaces WHERE root=?1",
            params![key],
            Self::ws_row,
        ).optional()?;
        if let Some(mut ws) = existing {
            ws.fingerprint_weak = ws.btime.is_none();
            // Same path, different directory (re-created, another mount, moved volumes):
            // the grants were for the old one and do not apply — but an agent-callable
            // path deletes nothing. `repair_workspace` (a human answering the new pairing
            // card) is what revokes and re-records.
            ws.fingerprint_ok = fingerprint_matches(&ws, &fp);
            return Ok(Some(ws));
        }
        let id = new_workspace_id();
        let created = crate::now();
        self.conn.execute(
            "INSERT INTO workspaces (id, root, ino, btime, dev, created) VALUES (?1,?2,?3,?4,?5,?6)",
            params![id, key, fp.ino as i64, fp.btime, fp.dev as i64, created],
        )?;
        Ok(Some(Workspace { id, root: key, ino: fp.ino, fingerprint_weak: fp.btime.is_none(), btime: fp.btime, dev: fp.dev, created, fingerprint_ok: true }))
    }

    /// The workspace for a root, created if this is its first contact. Only the delivery
    /// path (`need`, the MCP bind) may call this; everything path-keyed and read-only
    /// (rotation rewrite, reports, task_check) uses [`Self::find_workspace`].
    pub fn workspace_for(&self, root: &Path) -> Result<Workspace> {
        // Inside a caller's transaction the write lock is already held: no nested BEGIN.
        let own_tx = self.conn.is_autocommit();
        if own_tx {
            self.conn.execute_batch("BEGIN IMMEDIATE")?;
        }
        let r = self.workspace_for_locked(root);
        match r {
            Ok(Some(ws)) => { if own_tx { self.conn.execute_batch("COMMIT")?; } Ok(ws) }
            Ok(None) => { if own_tx { let _ = self.conn.execute_batch("ROLLBACK"); } anyhow::bail!("{} is not a directory that can be paired", root.display()) }
            Err(e) => { if own_tx { let _ = self.conn.execute_batch("ROLLBACK"); } Err(e) }
        }
    }

    /// Read-only lookup: the workspace on record for this root, if the directory is still
    /// the one that was paired. Never creates, never revokes.
    pub fn find_workspace(&self, root: &Path) -> Result<Option<Workspace>> {
        let Ok(root) = root.canonicalize() else { return Ok(None) };
        let key = root.to_string_lossy().to_string();
        let ws: Option<Workspace> = self.conn.query_row(
            "SELECT id, root, ino, btime, dev, created FROM workspaces WHERE root=?1",
            params![key],
            Self::ws_row,
        ).optional()?;
        Ok(ws.filter(|w| fingerprint(&root).map(|fp| fingerprint_matches(w, &fp)).unwrap_or(false)).map(|mut w| { w.fingerprint_ok = true; w }))
    }

    fn ws_row(r: &rusqlite::Row) -> rusqlite::Result<Workspace> {
        let btime: Option<String> = r.get(3)?;
        Ok(Workspace { id: r.get(0)?, root: r.get(1)?, ino: r.get::<_, i64>(2)? as u64, fingerprint_weak: btime.is_none(), btime, dev: r.get::<_, i64>(4)? as u64, created: r.get(5)?, fingerprint_ok: false })
    }

    /// Every workspace on record; `fingerprint_ok` says whether the directory at that root
    /// is still the one paired.
    pub fn list_workspaces(&self) -> Result<Vec<Workspace>> {
        let mut st = self.conn.prepare("SELECT id, root, ino, btime, dev, created FROM workspaces ORDER BY root")?;
        let rows = st.query_map([], Self::ws_row)?;
        let mut all = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        for w in &mut all {
            w.fingerprint_ok = fingerprint(Path::new(&w.root)).map(|fp| fingerprint_matches(w, &fp)).unwrap_or(false);
        }
        Ok(all)
    }

    /// A human is pairing a directory whose record no longer matches it: revoke what was
    /// granted to the old directory and record the new one under a new id.
    pub fn repair_workspace(&self, root: &Path) -> Result<Workspace> {
        let root = root.canonicalize()?;
        let Some(fp) = fingerprint(&root) else { anyhow::bail!("{} is not a directory", root.display()) };
        let key = root.to_string_lossy().to_string();
        let old: Option<String> = self.conn.query_row("SELECT id FROM workspaces WHERE root=?1", params![key], |r| r.get(0)).optional()?;
        if let Some(old) = old {
            self.conn.execute("DELETE FROM grants WHERE workspace_id=?1", params![old])?;
            self.conn.execute("DELETE FROM workspace_bindings WHERE workspace_id=?1", params![old])?;
            self.conn.execute("DELETE FROM workspaces WHERE id=?1", params![old])?;
            self.audit(Some(&key), None, "workspace.replaced", None, None, Some("directory re-created; the human paired the new one, old grants revoked"))?;
        }
        let id = new_workspace_id();
        let created = crate::now();
        self.conn.execute("INSERT INTO workspaces (id, root, ino, btime, dev, created) VALUES (?1,?2,?3,?4,?5,?6)", params![id, key, fp.ino as i64, fp.btime, fp.dev as i64, created])?;
        Ok(Workspace { id, root: key, ino: fp.ino, fingerprint_weak: fp.btime.is_none(), btime: fp.btime, dev: fp.dev, created, fingerprint_ok: true })
    }

    pub fn grant(&self, workspace_id: &str, name: &str, identity: &str, scope: &str, source: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO grants (workspace_id, name, identity, scope, source, created) VALUES (?1,?2,?3,?4,?5,?6)",
            params![workspace_id, name, identity, scope, source, crate::now()],
        )?;
        Ok(())
    }

    /// The exact grant's source, if this workspace holds one for (name, identity).
    pub fn grant_source(&self, workspace_id: &str, name: &str, identity: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row(
            "SELECT source FROM grants WHERE workspace_id=?1 AND name=?2 AND identity=?3",
            params![workspace_id, name, identity],
            |r| r.get(0),
        ).optional()?)
    }

    /// A broad grant: any registry-confirmed non-sensitive key for this identity here.
    pub fn has_broad_grant(&self, workspace_id: &str, identity: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM grants WHERE workspace_id=?1 AND name='*' AND identity=?2 AND scope=?3",
            params![workspace_id, identity, GRANT_BROAD],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// (name, identity, scope, source) for a workspace.
    pub fn grants_for(&self, workspace_id: &str) -> Result<Vec<(String, String, String, String)>> {
        let mut st = self.conn.prepare("SELECT name, identity, scope, source FROM grants WHERE workspace_id=?1 ORDER BY name, identity")?;
        let rows = st.query_map(params![workspace_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Every workspace holding a grant that would open the gate for (name, identity): an
    /// exact grant, or — only for registry-confirmed non-sensitive keys — a broad one. The
    /// set a rotation may rewrite. On-disk equivalence and one-time approvals are not
    /// grants and never appear here.
    pub fn workspaces_granted(&self, name: &str, identity: &str, broad_applies: bool) -> Result<Vec<Workspace>> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT w.id, w.root, w.ino, w.btime, w.dev, w.created FROM workspaces w JOIN grants g ON g.workspace_id = w.id
             WHERE g.identity=?2 AND (g.name=?1 OR (?4 AND g.name='*' AND g.scope=?3)) ORDER BY w.root",
        )?;
        let rows = st.query_map(params![name, identity, GRANT_BROAD, broad_applies], Self::ws_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Drop every grant (and binding) of a workspace. Values already written stay written.
    /// The v1 `approvals` table is left in place by the migration so a 0.1 binary can still
    /// open this database. That also means a 0.1 binary still *honours* it — and it gates on
    /// approvals alone, with no fingerprint check. Revoking has to reach those rows too, or
    /// an older binary someone still has wired into an agent keeps delivering keys the human
    /// took back.
    fn clear_legacy_approvals(&self, workspace_id: &str) -> Result<()> {
        let root: Option<String> = self
            .conn
            .query_row("SELECT root FROM workspaces WHERE id=?1", params![workspace_id], |r| r.get(0))
            .optional()?;
        if let Some(root) = root {
            self.conn.execute("DELETE FROM approvals WHERE project=?1", params![root])?;
        }
        Ok(())
    }

    pub fn revoke_workspace(&self, workspace_id: &str) -> Result<usize> {
        self.clear_legacy_approvals(workspace_id)?;
        let n = self.conn.execute("DELETE FROM grants WHERE workspace_id=?1", params![workspace_id])?;
        Ok(n)
    }

    /// Forget a workspace entirely: its next `need` pairs again. Deny memory (tasks) stays.
    pub fn forget_workspace(&self, workspace_id: &str) -> Result<()> {
        self.clear_legacy_approvals(workspace_id)?;
        self.conn.execute("DELETE FROM grants WHERE workspace_id=?1", params![workspace_id])?;
        self.conn.execute("DELETE FROM workspace_bindings WHERE workspace_id=?1", params![workspace_id])?;
        self.conn.execute("DELETE FROM workspaces WHERE id=?1", params![workspace_id])?;
        Ok(())
    }

    /// Most recent denied approval task for a project after `since`. "Deny" on an approval
    /// card must mean something: without memory, a program failing in a loop files a fresh
    /// card each time until the human clicks through out of fatigue.
    pub fn recent_denied_approvals(&self, project: &str, since: &str) -> Result<Vec<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='approval' AND status='denied' AND project=?1 AND answered_at > ?2 ORDER BY answered_at DESC",
            Self::TASK_COLS
        );
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(params![project, since], Self::row_to_task)?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Identity bound for a name in a workspace (work vs personal), if any.
    pub fn binding(&self, workspace_id: &str, name: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT identity FROM workspace_bindings WHERE workspace_id=?1 AND name=?2",
                params![workspace_id, name],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// (root, name, identity) for every binding, by workspace root.
    pub fn list_bindings(&self) -> Result<Vec<(String, String, String)>> {
        let mut st = self.conn.prepare("SELECT w.root, b.name, b.identity FROM workspace_bindings b JOIN workspaces w ON w.id=b.workspace_id ORDER BY w.root, b.name")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn set_binding(&self, workspace_id: &str, name: &str, identity: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO workspace_bindings (workspace_id, name, identity) VALUES (?1,?2,?3)
             ON CONFLICT(workspace_id, name) DO UPDATE SET identity=excluded.identity",
            params![workspace_id, name, identity],
        )?;
        Ok(())
    }

    // ---------- audit (never values) ----------

    /// An inject row that records which grant authorised it (paste / pairing / broad /
    /// sensitive / on_disk / backfill / once).
    #[allow(clippy::too_many_arguments)]
    pub fn audit_grant(&self, project: Option<&str>, agent: Option<&str>, action: &str, name: Option<&str>, identity: Option<&str>, detail: Option<&str>, grant: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit (ts, project, agent, action, name, identity, detail, grant_source) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![crate::now(), project, agent, action, name, identity, detail, grant],
        )?;
        Ok(())
    }

    pub fn audit(&self, project: Option<&str>, agent: Option<&str>, action: &str, name: Option<&str>, identity: Option<&str>, detail: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit (ts, project, agent, action, name, identity, detail) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![crate::now(), project, agent, action, name, identity, detail],
        )?;
        Ok(())
    }

    pub fn recent_audit(&self, limit: usize) -> Result<Vec<AuditRow>> {
        let mut st = self.conn.prepare(
            "SELECT ts, project, agent, action, name, identity, detail, grant_source FROM audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = st.query_map(params![limit as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The most recent audit rows for one project since `since`, newest first: what an agent
    /// may see of the log. `since` is when the directory now at that path was paired, so a
    /// checkout re-created at the same path does not read the old one's history.
    pub fn recent_audit_for(&self, project: &str, since: &str, limit: usize) -> Result<Vec<AuditRow>> {
        let mut st = self.conn.prepare(
            "SELECT ts, project, agent, action, name, identity, detail, grant_source FROM audit WHERE project=?1 AND ts >= ?2 ORDER BY id DESC LIMIT ?3",
        )?;
        let rows = st.query_map(params![project, since, limit as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Is there an audit row `action` for (project, name) since `since`?
    pub fn audited_since(&self, project: &str, name: &str, action: &str, since: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE project=?1 AND name=?2 AND action=?3 AND ts >= ?4",
            params![project, name, action, since],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Was an on-disk equivalence check for this key refused anywhere since `since`? One
    /// attempt per key per window, across every directory: directories are free to make,
    /// so a per-directory limit would let a planted `NAME=guess` per directory turn the
    /// check into a value-equality oracle.
    pub fn recent_on_disk_miss(&self, project: &str, name: &str, identity: &str, since: &str) -> Result<bool> {
        // One miss closes the check here; a few misses anywhere close it everywhere — so
        // neither a per-directory nor a global guess loop works, and one planted wrong value
        // in a hostile repo does not switch the feature off for every legitimate copy.
        let here: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE project=?1 AND name=?2 AND identity=?3 AND action='on_disk.miss' AND ts >= ?4",
            params![project, name, identity, since],
            |r| r.get(0),
        )?;
        let anywhere: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE name=?1 AND identity=?2 AND action='on_disk.miss' AND ts >= ?3",
            params![name, identity, since],
            |r| r.get(0),
        )?;
        Ok(here > 0 || anywhere >= 3)
    }
}
