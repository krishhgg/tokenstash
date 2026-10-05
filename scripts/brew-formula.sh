#!/usr/bin/env bash
# Print a Homebrew formula for a release, with per-platform sha256 taken from the *.sha256
# sidecars (never recomputed locally). In the release workflow SUMS_DIR points at the build
# artifacts of the same run — release assets are mutable, so a formula digested from them
# could bless a clobbered tarball. Without SUMS_DIR (a manual run) the release's assets are
# downloaded. Usage: scripts/brew-formula.sh v0.1.0
set -euo pipefail
tag="${1:?usage: brew-formula.sh vX.Y.Z}"
repo="${REPO:-${GITHUB_REPOSITORY:-krishhgg/tokenstash}}"
version="${tag#v}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
if [ -n "${SUMS_DIR:-}" ]; then
  cp "$SUMS_DIR"/tokenstash-*.tar.gz.sha256 "$tmp"/
else
  gh release download "$tag" --repo "$repo" --pattern '*.sha256' --dir "$tmp" >/dev/null
fi
sum() { awk '{print $1}' "$tmp/tokenstash-$1.tar.gz.sha256"; }
base="https://github.com/$repo/releases/download/$tag"
cat <<RUBY
class Tokenstash < Formula
  desc "Credential broker for coding agents: paste a key once, approve each directory, keep secrets out of status output"
  homepage "https://github.com/$repo"
  version "$version"
  license "MIT"

  on_macos do
    on_arm do
      url "$base/tokenstash-darwin-arm64.tar.gz"
      sha256 "$(sum darwin-arm64)"
    end
    on_intel do
      url "$base/tokenstash-darwin-x64.tar.gz"
      sha256 "$(sum darwin-x64)"
    end
  end

  on_linux do
    on_arm do
      url "$base/tokenstash-linux-arm64.tar.gz"
      sha256 "$(sum linux-arm64)"
    end
    on_intel do
      url "$base/tokenstash-linux-x64.tar.gz"
      sha256 "$(sum linux-x64)"
    end
  end

  def install
    bin.install "tokenstash"
  end

  test do
    assert_match "tokenstash", shell_output("#{bin}/tokenstash --help")
  end
end
RUBY
