# Contributing

## Add a provider (the most useful PR)

`crates/core/registry/providers.json` is what lets an agent get a key it has never seen before. One object:

```json
{
  "name": "TAVUS_API_KEY",
  "provider": "Tavus",
  "url": "https://platform.tavus.io",
  "steps": ["Sign in or create an account", "Developers → API Keys → Create", "Copy it"],
  "pattern": "^tvs_",
  "check": { "url": "https://tavusapi.com/v2/replicas", "auth": "header:x-api-key" }
}
```

- `name`: the exact env var developers use.
- `url`: where a new user creates the key, as deep a link as possible.
- `steps`: what to click, in order. Write them as if for someone who has never used the product.
- `pattern`: regex for the key format, so a bad paste fails immediately. Optional but valuable.
- `check`: one cheap authenticated request that returns 200 with a valid key and 401 without. Optional.
  `auth` is `bearer` | `header:<Name>` | `prefix:<Scheme>` | `basic-user` | `query:<param>`; `method` defaults to GET.
  403 is read as "live, lacks permission", never as a dead key; if the provider answers something
  other than 401 to a bad key (Google: 400), list it in `reject_status`. Set `at_use: true` only if
  the request is free and read-only enough to run before every delivery. Without it, the check
  runs at paste time only.
- `sensitive: true`: live payment keys, cloud credentials, anything with unbounded spend. These,
  and any name the registry does not know, get their own card per directory; the broad pairing
  button never covers them. Use `sensitive_pattern` when only some values are dangerous (e.g.
  Stripe live vs test).
- `generate: "base64:32"`: for local secrets with no vendor (`AUTH_SECRET`), so no human is involved.

Run `cargo test`. `registry_is_sane` validates every entry.

## Code

Before you open a PR:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings   # CI treats warnings as errors
cargo test --workspace
cargo build --release -p tokenstash && scripts/leak-test.sh target/release/tokenstash
```

Formatting is by hand (`rustfmt.toml` disables rustfmt): match the surrounding code. A PR needs the
`test` check green on Linux and macOS; the release workflow runs the same gate before it publishes.

The rule that matters: **no code path may emit a secret value.** Not stdout, not stderr, not the
SQLite index, not the audit log, not an MCP tool result, not an error message. `scripts/leak-test.sh`
drives the real binary with a canary and fails the build if it ever appears. If you add an output
surface, add it to that script.

Other invariants (see README): we never create accounts for users, never proxy an API, never read
other tools' credential stores.
