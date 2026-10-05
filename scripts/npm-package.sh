#!/usr/bin/env bash
# Assemble the npm packages for one release from the release tarballs, then (optionally)
# publish them. Layout: one binary package per platform (tokenstash-<os>-<arch>, no scripts,
# `os`/`cpu` pinned so package managers pick exactly one) plus the `tokenstash` launcher
# package that lists them as optionalDependencies at the same exact version.
#
#   scripts/npm-package.sh <version> <dir-with-tokenstash-*.tar.gz> <out-dir>
#   NPM_PUBLISH=1 scripts/npm-package.sh ...   # also `npm publish --access public --provenance` each one
#
# A pre-release publishes under the `next` dist-tag, and only a pre-release: npm refuses to
# publish a prerelease under the default tag at all, and an explicit `--tag latest` on a
# final would switch off npm's own guard against moving `latest` backwards (a 0.2.1 backport
# published after 0.3.0 would silently become what everyone installs).
# What `--tag next` does NOT buy: the registry assigns `latest` itself on a package's FIRST
# publish, whatever --tag says. So the first release candidate of a brand-new name is what a
# bare `npm install tokenstash` (and bun / pnpm / npx) resolves to until the final version
# moves `latest`. Keep that window short; a dry run on an established name is free.
#
# Platform packages are published first and each must be VISIBLE on the registry before the
# launcher is published, so a launcher that pins them never resolves to a package the
# registry has accepted but does not serve yet. (0.2.0: npm took ~11 minutes to serve one
# platform package it had accepted; the launcher was already live, so `npm install` on
# that platform failed for those minutes.)
set -euo pipefail
version="${1:?version}"; src="${2:?tarball dir}"; out="${3:?out dir}"
tagopt=(); case "$version" in *-*) tagopt=(--tag next) ;; esac
# Overridable for scripts/npm-package-test.sh, which runs this against a mock registry.
registry="${NPM_REGISTRY_URL:-https://registry.npmjs.org}"
settle_attempts="${NPM_SETTLE_ATTEMPTS:-60}"; settle_pause="${NPM_SETTLE_PAUSE:-15}"
here="$(cd "$(dirname "$0")/.." && pwd)"
# Skip a package already on the registry at this version so a re-run after a partial
# failure finishes the set instead of dying on E403 — but only if what is there is OURS:
# the published tarball, fully extracted, must be identical to what `npm pack` produces
# from our directory (every file, package.json included — so no foreign scripts or
# dependencies can hide behind a familiar binary). Anything else stops the release.
# Never unpublish: npm forbids re-using name@version forever and the launcher pins exact
# versions — ship a patch release instead.
# The tarball URL for name@version, from the registry's own document with the CDN cache
# bypassed (`?write=true`): `npm view` reads through the CDN, which can serve a packument
# up to five minutes stale. A version the registry does not serve yet is a miss.
# Every request is bounded: a registry that accepts the connection and then says nothing
# must not hold the settle loop past its own budget.
tarball_url() { # <name>
  curl -fsSL --connect-timeout 10 --max-time 60 "$registry/$1?write=true" 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["versions"][sys.argv[1]]["dist"]["tarball"])' "$version" 2>/dev/null
}
same_package() { # <pkg dir>
  local dir="$1" url tmp ok=1
  url=$(tarball_url "$name") && [ -n "$url" ] || return 1
  tmp=$(mktemp -d); mkdir -p "$tmp/theirs" "$tmp/ours" "$tmp/pack"
  if curl -fsSL --connect-timeout 10 --max-time 300 "$url" -o "$tmp/theirs.tgz" && tar -xzf "$tmp/theirs.tgz" -C "$tmp/theirs" \
     && (cd "$dir" && npm pack --silent --pack-destination "$tmp/pack" >/dev/null) \
     && tar -xzf "$tmp"/pack/*.tgz -C "$tmp/ours" && diff -r "$tmp/theirs" "$tmp/ours" >/dev/null; then ok=0; fi
  rm -rf "$tmp"; return $ok
}
# The registry can answer a version it accepted with a 404 for a while — writes and reads
# take different paths, and 0.2.0 saw eleven minutes — so a package gets 60 attempts, 15 s
# apart (about fifteen minutes plus the lookups themselves), before it is judged. A package
# that is there and differs still fails; it just fails after the wait.
settled() { # <pkg dir>
  local i url
  for i in $(seq 1 "$settle_attempts"); do
    same_package "$1" && return 0
    if [ "$i" -lt "$settle_attempts" ]; then sleep "$settle_pause"; fi
  done
  # Two different failures read the same from here; say which one this was.
  if url=$(tarball_url "$name") && [ -n "$url" ]; then
    echo "$name@$version is on the registry ($url) but does not match what we built, or could not be compared" >&2
  else
    echo "$name@$version did not appear on the registry after $settle_attempts attempts, $settle_pause s apart" >&2
  fi
  return 1
}
publish() { # <pkg dir>
  [ "${NPM_PUBLISH:-}" = 1 ] || return 0
  local name; name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$1/package.json")
  if npm view "$name@$version" version >/dev/null 2>&1; then
    if same_package "$1"; then echo "$name@$version already published, identical; skipping"; return 0; fi
    echo "$name@$version exists on the registry and DIFFERS from what we would publish — not ours; refusing to continue" >&2; exit 1
  fi
  # --provenance on both paths: the OIDC path gets it automatically, the bootstrap token
  # path does not, and a first release nobody can verify is the one that matters most.
  (cd "$1" && npm publish --access public --provenance ${tagopt[@]+"${tagopt[@]}"})
}
rm -rf "$out"; mkdir -p "$out"
for name in linux-x64 linux-arm64 darwin-arm64 darwin-x64; do
  os="${name%-*}"; cpu="${name#*-}"   # already npm's os/cpu vocabulary (darwin|linux, x64|arm64)
  tar="$src/tokenstash-$name.tar.gz"; [ -f "$tar" ] || { echo "missing $tar" >&2; exit 1; }
  pkg="$out/tokenstash-$name"; mkdir -p "$pkg/bin"
  tar -xzf "$tar" -C "$pkg/bin" tokenstash
  chmod 755 "$pkg/bin/tokenstash"
  cp "$here/LICENSE" "$pkg/"
  cat > "$pkg/package.json" <<JSON
{
  "name": "tokenstash-$name",
  "version": "$version",
  "description": "tokenstash binary for $os/$cpu. Install \`tokenstash\` instead.",
  "license": "MIT",
  "repository": { "type": "git", "url": "git+https://github.com/krishhgg/tokenstash.git" },
  "os": ["$os"],
  "cpu": ["$cpu"],
  "files": ["bin", "LICENSE"],
  "preferUnplugged": true
}
JSON
  printf '# tokenstash-%s\n\nPrebuilt `tokenstash` binary for this platform. Install the `tokenstash` package instead; it selects this one automatically.\n' "$name" > "$pkg/README.md"
  publish "$pkg"
done
# Every platform package must be served before the launcher that pins them is published.
if [ "${NPM_PUBLISH:-}" = 1 ]; then
  for name in linux-x64 linux-arm64 darwin-arm64 darwin-x64; do
    name="tokenstash-$name"; settled "$out/$name" || { echo "$name@$version is missing or not ours; the launcher is not published" >&2; exit 1; }
  done
fi
main="$out/tokenstash"; mkdir -p "$main"
cp -r "$here/npm/tokenstash/bin" "$main/"
cp "$here/LICENSE" "$main/"
# npmjs.com does not resolve relative links either: the same rewrite PyPI gets.
python3 "$here/scripts/absolute-links.py" "$here/README.md" "$main/README.md"
python3 - "$here/npm/tokenstash/package.json" "$main/package.json" "$version" <<'PY'
import json, sys
p = json.load(open(sys.argv[1])); v = sys.argv[3]
p["version"] = v
p["optionalDependencies"] = {k: v for k in p["optionalDependencies"]}
json.dump(p, open(sys.argv[2], "w"), indent=2); open(sys.argv[2], "a").write("\n")
PY
publish "$main"
if [ "${NPM_PUBLISH:-}" = 1 ]; then
  # Final check: the launcher resolves AND is exactly ours (the platform packages were
  # checked before it was published).
  name=tokenstash; settled "$main" || { echo "tokenstash@$version is missing or not ours" >&2; exit 1; }
  # What the registry actually did with the tags, in the job log: the only place the
  # "first publish takes latest" behaviour above is observable rather than assumed. Never
  # fatal — every package is published and verified by this point, and a rate-limited
  # diagnostic must not be what leaves the release sitting as a draft.
  npm view tokenstash dist-tags --json || echo "dist-tag lookup failed; packages are published"
fi
echo "assembled in $out"; ls "$out"
