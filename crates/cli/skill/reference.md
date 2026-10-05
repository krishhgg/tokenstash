# tokenstash CLI reference

Every command, flag and exit code, as of this version. `tokenstash <command> --help` prints the same flags.

Three kinds of command. **Agent** commands are yours to run. **Card** commands act for the user: run by you, each files a card and changes nothing until the user confirms it from their own inbox link. **Person** commands are the user's alone: run by you, each stops with `... is for a person at a terminal, not an agent` and changes nothing. tokenstash decides by looking for an agent's environment variables (`CLAUDECODE`, `CODEX_SANDBOX`, `CURSOR_AGENT`, `GEMINI_CLI`, ...) and for a terminal on both standard input and output. Do not work around that check; tell the user what the command does and what to run instead.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done: every key is in the env file, or the card was answered |
| 10 | Pending: at least one card waits on the user |
| 20 | Denied: the user declined (remembered for `task_ttl_hours`, 24 by default) |
| 30 | Expired: the card was not answered in time |
| 1 | Error: the message on stderr says what went wrong |

## Commands for agents

### `tokenstash need NAME... [flags]`

Writes each key to the project's env file, or files a card for it. The project is the git root of the current directory (or the directory itself outside a repository).

| Flag | Meaning |
|---|---|
| `--why TEXT` | Why the code needs it; shown on the card |
| `--url URL` | Where to get the key; for a key tokenstash knows, its own signup page wins |
| `--step TEXT` | One instruction on the card; repeat for several |
| `--pattern REGEX` | Format the pasted value must match; for a known key, the registry's pattern wins |
| `--identity ID` | Which copy of the key (`default` unless the project is bound to another) |
| `--blocking` | Wait for the user instead of returning at once |
| `--timeout SECONDS` | With `--blocking`, how long to wait (default 600) |
| `--agent NAME` | Your name on the card and in the audit log (detected otherwise) |
| `--force` | Ask again after the user declined. Once per key and project until the "no" expires; the card says it is a second ask |
| `--json` | One JSON object instead of lines |

Generated secrets (`AUTH_SECRET`, `JWT_SECRET`, `SESSION_SECRET`, `NEXTAUTH_SECRET`, `ENCRYPTION_KEY`) are never asked for: tokenstash generates one per project, or keeps the value the env file already holds.

Text output, one block per key:

```
✓ OPENAI_API_KEY injected → .env.local
  next: OPENAI_API_KEY is in /path/to/project/.env.local. Load it with your runtime ...
⏳ RESEND_API_KEY pending (card t_1a2b3c)
  next: RESEND_API_KEY is not in the stash; the user has been asked to add it (t_1a2b3c). Show the user this link: http://127.0.0.1:7433/p/... ...
```

`--json`:

```json
{
  "project": "/path/to/project",
  "env_file": ".env.local",
  "inbox": "http://127.0.0.1:7433/",
  "results": [
    { "status": "injected", "name": "OPENAI_API_KEY", "identity": "default", "written_to": "/path/to/project/.env.local", "generated": false, "unverified": false, "next": "..." },
    { "status": "pending", "name": "RESEND_API_KEY", "identity": "default", "task_id": "t_1a2b3c", "title": "...", "url": "https://resend.com/api-keys", "inbox": "http://127.0.0.1:7433/p/t_1a2b3c?t=...", "next": "..." },
    { "status": "denied", "name": "...", "task_id": "...", "next": "..." },
    { "status": "expired", "name": "...", "task_id": "...", "next": "..." }
  ],
  "next": "..."
}
```

`unverified: true` means the key was delivered without the usual re-check with its provider (provider unreachable or rate-limited). `url` is where the key is created; `inbox` is the card.

### `tokenstash ask TITLE [flags]`

Files a card for something only the user can do: a DNS record, a dashboard setting, an OAuth consent screen. Asking with the same title again returns the same card.

| Flag | Meaning |
|---|---|
| `--why TEXT`, `--url URL`, `--step TEXT` | As for `need` |
| `--expects confirm\|text` | `confirm` (default): the user marks it done. `text`: the user types an answer, returned to you word for word |
| `--blocking`, `--timeout SECONDS`, `--agent NAME`, `--json` | As for `need` |

`--json` prints `{ "task": {...}, "inbox": "<card link>" }`. The answer to a `text` card is the task's `note`.

### `tokenstash tasks [--history] [--json]`

This project's open cards. `--history` adds answered, denied and expired ones. `--json` prints an array of tasks:

```json
{ "id": "t_1a2b3c", "kind": "secret|approval|human", "project": "...", "agent": "...", "name": "RESEND_API_KEY", "identity": "default", "title": "...", "why": null, "url": "...", "steps": [], "expects": "secret|replace|pairing|sensitive|once|confirm|text", "pattern": null, "names": [], "status": "pending|answered|denied|expired", "created": "...", "deadline": "...", "answered_at": null, "note": null }
```

`expects` tells the card apart: `secret` (paste a missing key), `replace` (paste a replacement for a rejected key), `pairing` and `sensitive` (approve stored keys for this folder; `names` lists them as `NAME@identity`), `once` (approve one `run` request), `confirm` and `text` (a step from `ask`). `--all` (every project's cards) is person only.

### `tokenstash report-bad NAME [--status CODE] [--identity ID]`

Tells tokenstash a provider rejected a key it delivered. tokenstash re-checks the key itself where the provider allows it; a dead key becomes a Replace card on the next `need`. Always prints the same line, whatever it found. `--message` is accepted and discarded (provider error text can echo a key).

### `tokenstash run [--retries N] [--timeout SECONDS] -- COMMAND...`

Runs COMMAND with the env file loaded into its environment. Its output reaches you with every value tokenstash loaded, and inherited variables that look like secrets, masked. If it exits non-zero and its output names a key tokenstash knows that is not set, files an approval card for it, waits up to `--timeout` seconds (default 900), writes the key and runs COMMAND again, up to `--retries` times (default 3). Exits with COMMAND's exit code.

### `tokenstash doctor`

Checks the setup, one line each: config file, stash backend (and how long keys last in it), database, provider registry, inbox, agent mode, the skill and any MCP registration per agent, this directory (refused, paired, or not yet), and the binary path. Exit 0 when nothing is wrong, 1 otherwise. Safe to run at any time.

### `tokenstash remote [tailscale [--login LOGIN] | off]`

Whether the inbox can be reached from the user's other computers. With no argument, prints the setting. `tailscale`: the inbox also listens on this machine's Tailscale address, every link and notification uses that address, and a request from another device signed in to the owner's Tailscale account (`--login`, or the account this machine is signed in with) counts as the user, so it can approve. Nothing else on the tailnet gets an answer. A running inbox picks the change up within a second; links printed before still point at 127.0.0.1. `off`: back to 127.0.0.1 only. You may run it when the user is on another computer; it needs `tailscale` connected here. `--login` is for a tagged node, which has no owner; on a machine signed in to Tailscale, naming another login is the user's to do at a terminal.

### `tokenstash registry`

Lists the providers tokenstash knows: env var name, provider, signup URL, and `[sensitive]` for keys that ask in every folder.

### `tokenstash init [--no-agents] [--print-skill]`

Sets up the stash and installs this skill for the agents it finds (Claude Code, Codex and Gemini CLI, Cursor), in the mode the user chose before (automatic unless they chose explicit). You may run it, for example to install tokenstash when the user asks. `--no-agents` only sets up the stash. `--print-skill` prints the skill text and changes nothing. Choosing the mode, the MCP server and undoing are card commands (below).

### `tokenstash list [--json]`

The keys this directory received or was granted: name, identity, provider, and flags (`sensitive`, `STALE`, `no-verify`). Never values. Run by the user, every stored key.

### `tokenstash audit [--limit N] [--json]`

Recent events for this directory: which key was stored, delivered, reported or approved, when, and by which agent. `--json` prints `ts`, `project`, `agent`, `action`, `name`, `identity`, `detail`, `grant_source`. Run by the user, every directory.

### `tokenstash check [NAME...] [--stale-only] [--json]`

Re-checks keys with their providers (the same free request tokenstash makes before a delivery) and marks a rejected one stale, so its next `need` is a Replace card. Covers the keys this directory received or was granted (or the NAMEs given, among those). Prints one line per key: `ok`, `REJECTED (HTTP 401) → stale`, `unknown (...)` or `no check`. Run by the user, every stored key.

## Card commands

Run these only when the user asks for what they do. Each prints the card like a pending key (a status line and a `next:` line with the link) and exits 10. Asking again returns the same open card. `--why TEXT` puts the user's reason on the card.

| Command | What confirming does |
|---|---|
| `tokenstash rotate NAME [--identity ID] [--why TEXT]` | A Replace card: the user pastes the new key, and every folder that had the old one gets it. The old key keeps working until then. Only for a key this directory received or was granted |
| `tokenstash forget NAME [--identity ID] [--why TEXT]` | Deletes the stored key. Folders keep the copy in their env file; the next request for it is a paste card |
| `tokenstash bind NAME --identity ID [--why TEXT]` | This project receives the ID copy of NAME from then on. The project must have asked for a key before |
| `tokenstash init --mode auto\|explicit` | Whether agents load this skill by themselves or only when the user invokes it |
| `tokenstash init --mcp`, `tokenstash init --no-mcp` | Registers tokenstash as an MCP server with every agent, or takes it out. Not in explicit mode |
| `tokenstash init --undo` | Puts every agent config file back as `init` found it and removes the skill. Stored keys stay |

## Person commands

The user never needs these: everything they decide happens on a card in the browser. They remain for a person who prefers a terminal. Run by you, each stops without changing anything.

| Command | What it does |
|---|---|
| `tokenstash open` | Opens the inbox in the browser with the full session, which can approve cards |
| `tokenstash answer [ID] [--allow\|--allow-broad\|--deny] [--note TEXT]` | Answers a card from the terminal. Run by you it can only fill or decline this project's own cards and never approve or confirm, and the rules in `SKILL.md` say not to do even that |
| `tokenstash tasks --all` | Every project's cards |
| `tokenstash workspaces [list\|revoke DIR\|forget DIR]` | Which folders may receive which keys; take a folder's approvals away |
| `tokenstash export [-o FILE]`, `tokenstash import FILE` | Move the stash to another machine in a passphrase-encrypted bundle |
| `tokenstash export --from-env DIR` | Import keys found in a tree of existing env files |

`tokenstash mcp` (the MCP server, only after `init --mcp`) and `tokenstash inbox` (the local web inbox, started on its own when a card is filed) are started by other programs.

## Settings

`config.toml` in the tokenstash home. Edited by the user; `doctor` shows the path.

| Setting | Default | Meaning |
|---|---|---|
| `env_file` | `.env.local` | File written in each project, relative to the project root |
| `inbox_port` | `7433` | Port of the local inbox |
| `task_ttl_hours` | `24` | How long a card stays open, and how long a "no" is remembered |
| `notifications` | `true` | Desktop notifications for new cards |
| `verify_every` | `24h` | How often a key is re-checked with its provider before delivery: `<n>h`, `<n>m`, `always`, `never` |
| `stash_backend` | chosen by `init` | `keyring` (OS keychain or Secret Service), `keyutils` (Linux kernel keyring), `insecure-file` (tests only) |
| `agent_mode` | `auto` | `auto`: the skill loads by itself. `explicit`: only when the user invokes it |
| `mcp` | `false` | Whether `init` registers the MCP server |
| `remote` | off | `tailscale` once `tokenstash remote tailscale` ran; with `remote_host`, `remote_ip`, `remote_login` |

## Files and environment

| Path | What |
|---|---|
| `~/.config/tokenstash/` (Linux), `~/Library/Application Support/tokenstash/` (macOS) | The tokenstash home: `config.toml`, `tokenstash.db` (names, cards, approvals, audit; never values), inbox credentials |
| `TOKENSTASH_HOME` | Another home. Every command must see the same one, or it sees a different stash |
| `TOKENSTASH_STASH` | Overrides `stash_backend` for one command |
| `TOKENSTASH_AGENT` | Your name on cards, instead of the detected one |
| `<project>/.env.local` | Where keys are written: mode 0600, added to `.gitignore`, refused if git tracks it |
| `~/.claude/skills/tokenstash/`, `~/.agents/skills/tokenstash/`, `~/.cursor/skills/tokenstash/` | This skill, as `init` installed it (Claude Code; Codex and Gemini CLI; Cursor) |

Values live in the OS keychain (macOS Keychain, Linux Secret Service), or in the Linux kernel keyring when no Secret Service runs, which keeps them until the next reboot.
