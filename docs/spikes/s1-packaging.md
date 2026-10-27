# Spike S1: packaging and native addons

Status: **done**. Code: `spikes/s1-packaging/` (throwaway). CI: `.github/workflows/spike-s1.yml`.

Green run (all 3 OSes, plain node and SEA binary, real keyring on every runner):
https://github.com/MagnetonIO/agent-vault/actions/runs/40436061038

## Decisions

| # | Question | Decision |
|---|----------|----------|
| 1 | SQLite driver | **`node:sqlite`.** Passes on macOS, Linux, Windows, in plain node and inside the SEA binary, with no `ExperimentalWarning` on Node 24.21/24.22. One fewer native addon. `better-sqlite3` also passes everywhere and is the fallback if `node:sqlite` ever regresses |
| 2 | Addon layout | **`.node` files in `addons/` beside the binary, loaded with `process.dlopen`.** No `node_modules` shipped. JS is bundled by esbuild into the SEA blob |
| 3 | Linux CI keyring | `dbus-run-session` + `gnome-keyring-daemon --unlock --components=secrets` with a **non-empty** password on stdin (exact incantation below) |

## Results (CI run above, Node 24)

| Check | macOS (arm64, node 24.22.1) | Linux (x64 glibc, node 24.21.0) | Windows (x64, node 24.22.1) |
|-------|------|------|------|
| `node:sqlite` write+read, plain node | ok | ok | ok |
| `node:sqlite` write+read, SEA | ok | ok | ok |
| `better-sqlite3` write+read, plain node | ok | ok | ok |
| `better-sqlite3` write+read, SEA | ok | ok | ok |
| `@napi-rs/keyring` set/get/delete, plain node | ok | ok | ok |
| `@napi-rs/keyring` set/get/delete, SEA | ok | ok | ok |
| `ExperimentalWarning` printed | no | no | no |
| Binary prints `OK` | yes | yes | yes |
| Linux pin, locked keyring (bus exists, keyring not unlocked) | n/a | pinned Entry **throws**: `Couldn't access platform storage: Secret Service: unlock prompt was dismissed` | n/a |
| Linux pin, no bus (`DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent`) | n/a | pinned Entry **throws**: `Platform failure: DBus error: Failed to connect to socket /nonexistent: No such file or directory` | n/a |
| Linux control, no bus, **unpinned** (`SPIKE_NO_PIN=1`) | n/a | **succeeds** (set/get/delete ok, prints `OK`): silent fallback observed. Only the kernel keyutils store is reachable without a bus, so that is the store it used | n/a |

Local Mac (Node 24.22.0, arm64) ran the SEA binary with `SPIKE_SKIP_KEYRING=1`: both SQLite drivers ok, keyring `.node` loads (`Entry` exported), no `Entry` constructed, so the real Keychain was never touched. Removing `dist/addons/` makes the binary fail with a `dlopen` error, which proves the addons really load from beside it.

## Exact CI keyring setup

Linux (`ubuntu-latest`):

```bash
sudo apt-get update
sudo apt-get install -y gnome-keyring dbus-x11
dbus-run-session -- sh -c '
  echo -n "ci-keyring-pass" | gnome-keyring-daemon --unlock --components=secrets
  ./dist/s1-spike        # or: node dist/main.cjs
'
```

- The password **must be non-empty.** With `echo -n ""` the daemon starts but no usable default collection exists, and every call fails with `Secret Service: no result found`. Tried and failed: `--unlock` alone, `--unlock --components=secrets`, `--daemonize --login --components=secrets`, and a `secret-tool store` primer, all with an empty password. A non-empty password worked first time.
- Everything that touches the keyring must run **inside** the same `dbus-run-session` shell.
- macOS and Windows need no setup: the runner's login Keychain and Credential Manager work as is.
- Code side: `new Entry(service, account, { linux: { store: 'secret-service' } })`. Without the pin, an unreachable Secret Service silently falls back to the kernel keyutils keyring (control observed on the runner). With the pin it throws instead. Two distinct errors, handle both (Task 7):
  - Locked keyring (a bus exists, keyring not unlocked): `Couldn't access platform storage: Secret Service: unlock prompt was dismissed`. Seen on the plain runner, where libdbus autolaunches a bus because `dbus-x11` is installed.
  - No bus: `Platform failure: DBus error: Failed to connect to socket /nonexistent: No such file or directory`. Unsetting `DBUS_SESSION_BUS_ADDRESS` is **not** enough to get here (autolaunch), so the CI step points it at a nonexistent socket.
  - Empty-password keyring (see above): `Secret Service: no result found`.
  - The fallback is observed, not just per upstream docs. The control only proves the unpinned call succeeds with no Secret Service; that it landed in keyutils is inferred (no other store was reachable), not read back from `/proc/keys`.

Windows step needs `shell: bash` (set as a default in the workflow) so the same `./dist/s1-spike | tee` line works; Git Bash resolves `s1-spike` to `s1-spike.exe`.

## Addon layout

```
dist/
  s1-spike[.exe]        SEA binary (node + injected blob)
  addons/
    better_sqlite3.node     only if better-sqlite3 is used
    keyring.node            platform file from @napi-rs/keyring-<triple>
  main.cjs              plain-node run of the same bundle (spike only)
```

- Resolve the directory with `node:sea`: `sea.isSea() ? path.dirname(process.execPath) : __dirname`.
- Load: `const m = { exports: {} }; process.dlopen(m, path.join(dir, 'addons', 'keyring.node')); const { Entry } = m.exports;`
- The `.node` files are renamed to fixed names at build time, so runtime code never has to know the platform triple.
- `@napi-rs/keyring`'s own `index.js` is **not** bundled: it is a loader with a `require()` per platform triple. Going straight to the `.node` via `dlopen` skips it. Its exports are the plain napi classes (`Entry`, `findCredentials`, ...).
- `better-sqlite3` 13 accepts an addon object: `new Database(file, { nativeBinding: addonObject })`. That is what makes bundling its JS work.
- If `node:sqlite` is chosen, only `keyring.node` ships.

## Build recipe (what `build.mjs` does)

1. `esbuild` bundle, `platform: node`, `format: cjs`, `target: node24`. Native packages are not required by name; builtins (`node:*`) stay external.
2. Copy the `.node` files into `addons/`.
3. `node --experimental-sea-config sea-config.json` with `disableExperimentalSEAWarning: true`.
4. Copy `process.execPath` to the output name.
5. macOS only: `codesign --remove-signature` before injecting.
6. `postject` API `inject(exe, 'NODE_SEA_BLOB', blob, { sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2', machoSegmentName: 'NODE_SEA' })`; `machoSegmentName` on macOS only.
7. macOS only: `codesign --sign - <exe>` (ad hoc).

Windows needed no `signtool` step: injecting into the stock signed `node.exe` ran fine on the runner.

## Pitfalls hit or confirmed

- **Empty keyring password** (see above). This cost the only failed CI run.
- **SEA `require` only loads builtins.** `better-sqlite3`'s `nativeBinding: '<path>'` string form calls `require(path)` and would fail inside the blob. Pass an addon object from `process.dlopen` instead.
- **No install scripts were needed.** `better-sqlite3` 13 ships all 8 prebuilds in its tarball, so no `allowBuilds` entry is required (checked with a clean install that lists only `esbuild: false`). `@napi-rs/keyring` delivers its `.node` through an optional platform package. Later tasks that add a dependency with a real install script still need an `allowBuilds` entry.
- **pnpm installs only the optional keyring package for the current platform**, so build and pick up the addon on each target OS (as the CI matrix does). Cross-building would need `supportedArchitectures`.
- **Spike has its own `pnpm-workspace.yaml`**, so it stays out of the root lockfile and the root `pnpm i --frozen-lockfile` is unaffected. Root `biome check .` does lint `spikes/`.

## Not verified

- Linux arm64, Linux musl, macOS x64, Windows arm64 (CI covered one arch per OS).
- A developer Mac: the CI runner has no Keychain prompts. A user's first Keychain access from an ad-hoc-signed or unsigned binary may prompt, and an ACL tied to the binary signature may break across upgrades. Design already says "signed binary for a stable ACL"; a Developer ID signed build is a Phase-1 packaging task.
- Windows SmartScreen / AV behaviour on an injected `node.exe`.
- Distro keyrings other than `gnome-keyring` (KWallet exposes Secret Service too, untested).
- `node:sqlite` is still a young API. No warning on 24.21/24.22 does not guarantee API stability across Node minors, so pin the Node version in releases.
