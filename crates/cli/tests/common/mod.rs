//! What the integration tests share.

use std::process::Command;

/// The binary under test, tied to this test process. A `need` that files a card starts an
/// inbox in the background, and an inbox with an open card does not exit when idle, so the
/// inboxes behind cards no test answers ran until someone killed them. The inbox inherits
/// `TOKENSTASH_EXIT_WITH` from the command that started it, and a debug build exits once the
/// process it names has ended.
pub fn tokenstash() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_tokenstash"));
    c.env("TOKENSTASH_EXIT_WITH", std::process::id().to_string());
    c
}
