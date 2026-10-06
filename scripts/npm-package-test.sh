#!/usr/bin/env bash
# Runs scripts/npm-package.sh with NPM_PUBLISH=1 against a mock registry (a local HTTP server
# for the `?write=true` documents and tarballs) and a fake `npm` on PATH (real `npm pack`;
# `publish` and `view` recorded against the mock), and checks the two things the 0.2.0
# incident was about:
#   1. the launcher is published only after every platform package is SERVED. Here each
#      platform package becomes visible a few seconds after `npm publish` returns;
#   2. a platform package the registry serves with different contents stops the release
#      before the launcher is published.
# Needs bash, python3, tar, curl and a real npm (for `npm pack`). No network.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
real_npm="$(command -v npm)" || { echo "npm is required (for npm pack)" >&2; exit 2; }
work="$(mktemp -d)"
# Everything started here, meaning the mock server and the fake npm's visibility jobs, which
# outlive the npm process that started them and are recorded in $reg/jobs, is stopped
# before the fixtures go, so nothing writes into a directory being removed.
cleanup() {
  local p
  for p in $(cat "$reg/jobs" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
  kill "${server:-}" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
reg="$work/registry"; mkdir -p "$reg" "$work/bin" "$work/src"
# Four fake platform tarballs, each holding one executable named tokenstash.
for n in linux-x64 linux-arm64 darwin-arm64 darwin-x64; do
  d="$work/src/$n"; mkdir -p "$d"; printf '#!/bin/sh\necho %s\n' "$n" > "$d/tokenstash"; chmod +x "$d/tokenstash"
  tar -czf "$work/src/tokenstash-$n.tar.gz" -C "$d" tokenstash
done
# The mock registry: GET /<name>?write=true → the packument if <name>/<version> is visible,
# else 404; GET /tarballs/<name>/<version>.tgz → the file.
cat > "$work/registry.py" <<'PY'
import http.server, json, os, sys, urllib.parse
REG, PORT = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); path = urllib.parse.unquote(u.path)
        if path.startswith("/tarballs/"):
            f = os.path.join(REG, path[len("/tarballs/"):])
            if os.path.isfile(f):
                data = open(f, "rb").read(); self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data); return
            self.send_response(404); self.end_headers(); return
        name = path.strip("/"); d = os.path.join(REG, name)
        versions = {}
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "visible")):
            for f in os.listdir(d):
                if f.endswith(".tgz"):
                    v = f[:-4]; versions[v] = {"dist": {"tarball": f"http://127.0.0.1:{PORT}/tarballs/{name}/{f}"}}
        if not versions:
            self.send_response(404); self.end_headers(); return
        body = json.dumps({"name": name, "versions": versions}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 "$work/registry.py" "$reg" "$port" & server=$!
ready=0
for _ in $(seq 1 50); do curl -s -m 2 -o /dev/null "http://127.0.0.1:$port/nothing" 2>/dev/null && { ready=1; break; }; sleep 0.1; done
[ "$ready" = 1 ] || { echo "the mock registry did not come up on port $port" >&2; exit 2; }
# The fake npm. `publish` packs the directory into the registry and makes it visible after
# FAKE_DELAY seconds (platform packages) or at once (the launcher); `view` answers from the
# registry's visible state, like the real one answers from what it serves.
cat > "$work/bin/npm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
now() { python3 -c 'import time; print(f"{time.time():.3f}")'; }
case "$1" in
  pack) exec "$REAL_NPM" "$@" ;;
  publish)
    name=$(python3 -c 'import json; print(json.load(open("package.json"))["name"])')
    ver=$(python3 -c 'import json; print(json.load(open("package.json"))["version"])')
    # Timestamped on entry, before packing: the ordering check must see when the script
    # decided to publish, not when the pack finished.
    echo "publish $name $(now)" >> "$FAKE_REG/log"
    mkdir -p "$FAKE_REG/$name"
    "$REAL_NPM" pack --silent --pack-destination "$FAKE_REG/$name" >/dev/null
    mv "$FAKE_REG/$name"/*.tgz "$FAKE_REG/$name/$ver.tgz"
    delay=0; case "$name" in tokenstash-*) delay="${FAKE_DELAY:-0}" ;; esac
    ( sleep "$delay"; touch "$FAKE_REG/$name/visible"; echo "visible $name $(now)" >> "$FAKE_REG/log" ) &
    # This npm process exits at once; the job outlives it, so the harness gets its pid to
    # stop on cleanup.
    echo $! >> "$FAKE_REG/jobs"
    ;;
  view)
    spec="$2"; name="${spec%@*}"; ver="${spec##*@}"; field="${3:-}"
    if [ "$field" = dist-tags ]; then echo '{"latest":"mock"}'; exit 0; fi
    [ -f "$FAKE_REG/$name/visible" ] && [ -f "$FAKE_REG/$name/$ver.tgz" ] || exit 1
    case "$field" in version) echo "$ver" ;; dist.tarball) echo "http://127.0.0.1:$FAKE_PORT/tarballs/$name/$ver.tgz" ;; esac
    ;;
  *) echo "fake npm: unexpected: $*" >&2; exit 1 ;;
esac
SH
chmod +x "$work/bin/npm"
run() { # <FAKE_DELAY> → runs the script; stdout/stderr to $work/run.log; returns its status
  rm -rf "$reg"/* "$work/out"
  PATH="$work/bin:$PATH" REAL_NPM="$real_npm" FAKE_REG="$reg" FAKE_PORT="$port" FAKE_DELAY="$1" \
    NPM_PUBLISH=1 NPM_REGISTRY_URL="http://127.0.0.1:$port" NPM_SETTLE_ATTEMPTS=20 NPM_SETTLE_PAUSE=1 \
    "$here/scripts/npm-package.sh" 0.0.0-test.1 "$work/src" "$work/out" >"$work/run.log" 2>&1
}
fail() {
  set +e
  echo "FAIL: $*" >&2; echo "--- script output:" >&2; cat "$work/run.log" >&2
  echo "--- registry log:" >&2; cat "$reg/log" 2>/dev/null >&2; echo "--- registry dir:" >&2; ls -laR "$reg" >&2
  exit 1
}

# 1. Delayed visibility: the launcher goes out only after all four are served.
run 3 || fail "the release should succeed once every platform package is visible"
launcher=$(awk '$1=="publish" && $2=="tokenstash" {print $3}' "$reg/log")
[ -n "$launcher" ] || fail "the launcher was never published"
for n in linux-x64 linux-arm64 darwin-arm64 darwin-x64; do
  seen=$(awk -v p="tokenstash-$n" '$1=="visible" && $2==p {print $3}' "$reg/log")
  [ -n "$seen" ] || fail "tokenstash-$n never became visible"
  python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) > float(sys.argv[2]) else 1)' "$launcher" "$seen" \
    || fail "the launcher was published at $launcher, before tokenstash-$n was served at $seen"
done
grep -q '"tokenstash-linux-x64": "0.0.0-test.1"' "$work/out/tokenstash/package.json" || fail "the launcher does not pin the platform packages"
echo "ok: launcher published after every platform package was served"

# 2. A platform package the registry serves with other contents: no launcher, non-zero exit.
rm -rf "$reg"/* "$work/out"
tampered="$work/tampered"; mkdir -p "$tampered"
cat > "$work/bin/npm-tamper" <<SH
#!/usr/bin/env bash
# After the fake publish of linux-x64, replace its served tarball with something else,
# before returning, so the release script can never observe the original.
"$work/bin/npm.real" "\$@"; status=\$?
if [ "\$1" = publish ] && grep -q '"name": "tokenstash-linux-x64"' package.json; then
  d="$reg/tokenstash-linux-x64"; mkdir -p "$tampered/pkg"
  printf '{"name":"tokenstash-linux-x64","version":"0.0.0-test.1","description":"not ours"}\n' > "$tampered/pkg/package.json"
  tar -czf "\$d/0.0.0-test.1.tgz" -C "$tampered" pkg
fi
exit \$status
SH
mv "$work/bin/npm" "$work/bin/npm.real"; mv "$work/bin/npm-tamper" "$work/bin/npm"; chmod +x "$work/bin/npm"
if run 0; then fail "the release must stop when a served platform package is not ours"; fi
grep -q 'does not match what we built' "$work/run.log" || fail "the failure should name the mismatch"
if awk '$1=="publish" && $2=="tokenstash" {found=1} END {exit !found}' "$reg/log"; then fail "the launcher was published despite a tampered platform package"; fi
echo "ok: a tampered platform package stops the release before the launcher"
