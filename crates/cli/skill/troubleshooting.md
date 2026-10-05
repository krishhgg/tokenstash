# Troubleshooting tokenstash

Start with `tokenstash doctor`. Each section below starts from what you see. Whatever the fix, the rules in `SKILL.md` still hold: no pasted secrets, no reading the env file, no stand-in values.

## `tokenstash: command not found`

tokenstash is not installed, or not on this shell's `PATH`. The user installs it once with one of `brew install krishhgg/tokenstash/tokenstash`, `npm install -g tokenstash` or `uv tool install tokenstash`, then `tokenstash init`. If they ask you to install it, you may run those commands. Until it is installed, name the variable the code needs, say what it is for, and continue with what does not need it.

## `... is for a person at a terminal, not an agent`

A few commands are the user's alone: they approve, show every directory, or move the whole stash. Do not work around the check. What to do instead:

| You wanted to | Do instead |
|---|---|
| Approve or confirm a card | Only the user does, from their own inbox link. Give them the card link; the card can send that link to their desktop |
| Open the inbox (`open`) | Give the user the card link from `need`, or tell them to click the tokenstash desktop notification |
| See every project's cards (`tasks --all`) | `tokenstash tasks` shows this project's |
| Take a folder's approvals away (`workspaces`) | Tell the user; they can run `tokenstash workspaces revoke DIR` |
| Move keys to another machine (`export`, `import`) | Tell the user; they run `tokenstash export` on the old machine and `tokenstash import FILE` on the new one |

`rotate`, `forget`, `bind`, `need --force` and `init --mode/--mcp/--no-mcp/--undo` do not refuse: they file a card for the user to confirm (see `reference.md`). `list`, `audit` and `check` show you this directory's part.

## The user cannot open the link

Unless remote access is on, the inbox listens on `127.0.0.1` of the machine tokenstash runs on, so a link only opens in a browser on that machine.

- The user is on another computer and both machines are on Tailscale: run `tokenstash remote tailscale`, then run the same `tokenstash need` again for a link with this machine's Tailscale name. On any device signed in to the same Tailscale account, that link opens as the user and can approve; nothing else on the tailnet gets in. `tokenstash remote` shows the setting, `tokenstash remote off` turns it off. On a tagged Tailscale node, the user names their login: `tokenstash remote tailscale --login them@example.com`.
- Remote access is on but `need` still gives a `127.0.0.1` link: the inbox has not proved it answers on the Tailscale address. The remote access line of `tokenstash doctor` says why: another process holds that address and port, the inbox runs but does not answer there, or this machine's Tailscale address changed. Fix that, then run `tokenstash remote tailscale` again.
- No Tailscale: they can forward the port with `ssh -L 7433:127.0.0.1:7433 <this-machine>` and open the link on their computer. Port `7433` is the default `inbox_port`. Over the forwarded port the inbox cannot tell them from this machine, so an approval still needs their own link (the card's "Send the link to my desktop" button needs a desktop on this machine); `tokenstash remote tailscale` avoids that.
- `next` says "The inbox is unavailable": the inbox could not start, or another process holds the port. `tokenstash doctor` shows which. Another tokenstash under a different `TOKENSTASH_HOME` is the usual culprit; the user can stop it or set another `inbox_port`.
- The page says the link is old or invalid: the inbox restarted, which retires earlier full-session links. Card links from `need` keep working, and a card's "Send the link to my desktop" button sends a fresh full link.

## A key stays pending

- `tokenstash tasks --history --json` shows the card's `status`. `answered` means the user answered: run `tokenstash need NAME` again and it is written. `pending` means it still waits; remind the user once, with the link.
- An approval or confirm card cannot be answered from your link. The user answers from the link in the desktop notification; the card's "Send the link to my desktop" button sends it again.
- Desktop notifications do not show on a machine without a desktop session (a server, an SSH login, a container), and they are off when `notifications = false`. Give the user the link yourself.

## The program says the key is missing, but `need` said it was written

- The program does not read the env file. Frameworks that read `.env.local` do so at start: restart the dev server. Anything else: load it with the runtime's dotenv support, or start the program with `tokenstash run -- <command>`.
- The env file is at the project root, which is the git repository's root. An app in a subfolder of a monorepo that only reads its own folder's `.env.local` does not see it: load the root file explicitly (most dotenv libraries take a path), or start the app with `tokenstash run --` from the root.
- The program reads a different name (`OPENAI_KEY` instead of `OPENAI_API_KEY`). Request the name the code reads.
- Do not open the env file to check. `need` writing it with exit 0 is the check.

## The provider rejects a key with 401

Follow "When a provider rejects a key" in `SKILL.md`: `tokenstash report-bad NAME --status 401`, then `tokenstash need NAME`. If the second `need` writes the key again, the provider accepted it on re-check: compare your request with the provider's documentation (auth header name and format, base URL, project or organization header).

If the user pasted a new key and the old, rejected one keeps coming back, run `tokenstash doctor` and look at the stash backend line. With `keyutils` (the Linux kernel keyring, used when no Secret Service runs), versions before 0.4 kept a separate copy per login session, so a key pasted from one session could be shadowed in another; `doctor`'s last line shows which binary runs. Tell the user what you found.

## `need` exits 1

Read the message. The common ones:

| Message contains | Cause | Fix |
|---|---|---|
| `tokenstash does not deliver keys there` | You ran it from the home directory, `/`, a shared temp directory or a tool directory (`~/.claude`, `~/.ssh`, ...) | Run it from the project |
| `is tracked by git` | The env file is committed, so `.gitignore` cannot protect it | It is the user's repository: tell them, and suggest `git rm --cached .env.local` (keeps the file, stops tracking it) |
| `.gitignore` ... `symlink` or `still does not ignore` | tokenstash could not make git ignore the env file | Tell the user which rule is in the way; nothing was written |
| `is not an environment variable name` | Letters, digits and underscores only, not starting with a digit | Fix the name |
| `no usable Linux keyring` | No Secret Service and no kernel keyring (some containers) | Tell the user; tokenstash cannot store keys here |
| `no home directory to keep state in` | No `HOME` (a bare container or service) | Set `TOKENSTASH_HOME` to a private directory, the same one for every command |
| `is answered but ... is not in the stash` | The value was lost between the paste and now (the kernel keyring after a reboot, or another `TOKENSTASH_HOME`) | Run `tokenstash need NAME` again; it files a new card |

## The user declined, or the card expired

Exit 20: do not ask again; make the feature optional or say what is blocked. If the user changes their mind and tells you so, run `tokenstash need NAME --force`: that files one more card, marked as a second ask. A second "no" stands until the first expires, after `task_ttl_hours` (24 by default).

Exit 30: the card timed out. Run `tokenstash need NAME` again when the work needs it; that files a new card.

## Different results in different shells

Every command must see the same `TOKENSTASH_HOME`. A home set in one shell and not in another is a different stash, a different set of approvals and a different inbox. `tokenstash doctor` prints the config path in use.
