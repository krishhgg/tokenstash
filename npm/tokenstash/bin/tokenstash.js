#!/usr/bin/env node
// Thin launcher. The binary ships in a per-platform package selected by npm/bun/pnpm/yarn
// through `optionalDependencies` + `os`/`cpu`, with no lifecycle scripts, so package managers
// that refuse dependency postinstalls (bun, pnpm ≥ 10, `npm ci --ignore-scripts`) still
// get a working install. TOKENSTASH_BINARY overrides (brew/cargo installs, tests).
const path = require("path");
const platform = { darwin: "darwin", linux: "linux" }[process.platform];
const arch = { x64: "x64", arm64: "arm64" }[process.arch];
let bin = process.env.TOKENSTASH_BINARY;
if (!bin) {
  if (!platform || !arch) {
    console.error(`tokenstash: no prebuilt binary for ${process.platform}/${process.arch} (Windows is not supported). From source: cargo install --git https://github.com/krishhgg/tokenstash tokenstash`);
    process.exit(1);
  }
  const pkg = `tokenstash-${platform}-${arch}`;
  try {
    bin = require.resolve(`${pkg}/bin/tokenstash`);
  } catch {
    console.error(`tokenstash: the platform package ${pkg} is not installed.\n  Optional dependencies were skipped (\`--no-optional\`, \`omit=optional\`, or an unsupported platform).\n  Reinstall with optional dependencies enabled, or from source: cargo install --git https://github.com/krishhgg/tokenstash tokenstash`);
    process.exit(1);
  }
}
// Signals: every one the launcher receives is forwarded to the child, whether it came from
// the terminal (Ctrl-C reaches the whole foreground group, so the child also gets it directly;
// a second SIGINT is harmless to it) or from a supervisor that signals this PID only. The
// launcher never exits before the child; when the child dies by a signal it is re-raised so
// callers see an interrupt, not exit 1.
const { spawn } = require("child_process");
const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
for (const s of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(s, () => child.kill(s));
child.on("error", (e) => { console.error(`tokenstash: cannot run ${bin}: ${e.message}`); process.exit(1); });
child.on("exit", (code, signal) => {
  if (signal) { process.removeAllListeners(signal); process.kill(process.pid, signal); }
  process.exit(code ?? 1);
});
