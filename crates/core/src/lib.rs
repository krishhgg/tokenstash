//! tokenstash core: stash adapter, task queue, registry, env injection, trust.
//!
//! Invariant: nothing in this crate ever returns a secret value on a path that
//! reaches stdout/stderr/logs. Values move clipboard → keychain → env file.

pub mod actions;
pub mod bundle;
pub mod config;
pub mod db;
pub mod envcrawl;
pub mod envfile;
pub mod fsutil;
pub mod need;
pub mod project;
pub mod redact;
pub mod registry;
pub mod stash;
pub mod tasks;
pub mod trust;
pub mod validate;

#[cfg(test)]
mod tests;

pub use config::Config;
pub use db::Db;

/// Exit codes shared by CLI and MCP wrapper.
pub mod exit {
    pub const INJECTED: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const PENDING: i32 = 10;
    pub const DENIED: i32 = 20;
    pub const EXPIRED: i32 = 30;
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
