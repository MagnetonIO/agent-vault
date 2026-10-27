# agent-vault — Build & Development Plan (Phase 0 spikes + Phase 1 MVP)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. On approval, copy this file to `docs/superpowers/plans/2026-10-26-agent-vault-mvp.md` and commit it as the first commit.

**Goal:** Ship agent-vault as the default keystore for Claude Code, Codex, and OpenCode. Every paste, `.env` value, and harness-config value ends up in the vault, and agents use keys without seeing them.

**Architecture:**
- A pnpm TypeScript monorepo. One daemon, `vaultd`, owns all secret values. The CLI, MCP server, and harness hooks talk to it over local JSON-RPC.
- Values flow **into** vaultd: capture, `set`, `import`, and hooks. Values never flow **out** to callers. The only exceptions are `run` (the child process gets the env, and its output is redacted) and `helper` (a harness's own model key).
- Phase 0 spikes run first and lock three decisions that the later tasks consume.

**Tech Stack:**

| Area | Choice |
|------|--------|
| Runtime, package manager | Node 24 LTS, pnpm workspaces, TypeScript (strict, ESM) |
| Tests, lint, bundling | vitest, Biome, esbuild |
| Crypto | `@noble/ciphers` (XChaCha20-Poly1305), `@noble/hashes` (HMAC-SHA-256, HKDF, Argon2id), `@scure/bip39` |
| Keyring, storage | `@napi-rs/keyring`; `better-sqlite3` or `node:sqlite` (Spike S1 decides) |
| CLI, MCP, I/O | `commander`, `@modelcontextprotocol/sdk`, `clipboardy`, `jsonc-parser`, `smol-toml` |

**Spec:** `docs/design.md` (read it alongside this plan).

---

## Context

`docs/design.md` defines the product, and the repo has no code yet. This plan covers the build system, the development workflow, and every task from an empty repo to an installable MVP:
- Paste capture: paths A, B, and C.
- Harness install for Claude Code, Codex, and OpenCode.
- An MCP server.
- `run` with output redaction.
- A hash-chained audit log.

Phase 2 and later (proxy, human-presence gate, sync, cloud) get separate plans.

## Development workflow

| Command | What it does |
|---------|--------------|
| `pnpm i` | Install the workspace |
| `pnpm build` | `tsc -b` across all packages |
| `pnpm test` | `vitest run` (unit + e2e) |
| `pnpm lint` | `biome check .` |
| `pnpm dev` | Runs `tsx watch packages/cli/src/main.ts daemon run` against a sandbox |
| `pnpm dist` | Builds release binaries (Task 20) |

**The sandbox rule:** dev and test runs **never touch your real keychain or harness configs.**
- Every test sets `HOME` / `USERPROFILE` / `CODEX_HOME` / `AGENT_VAULT_HOME` to a temp dir.
- Every test uses an injected `MemoryKeyStore`, or the keyfile store with `AGENT_VAULT_KEYFILE_PASSPHRASE`.

**Commit after every task**, and keep CI green on all three OSes.

## Global Constraints

- Node `>=24`. CI matrix: `macos-latest`, `ubuntu-latest`, `windows-latest`.
- Crypto:
  - XChaCha20-Poly1305 with a random 192-bit nonce.
  - AAD = `vault_id‖table‖record_id‖field‖version`, with each part length-prefixed (u32 BE) and the version as u64 BE.
- Metadata that is readable while locked is MAC'd with HMAC-SHA-256 under a vault MAC key.
- Key hierarchy:
  - Device root key in the OS keyring.
  - The vault data key is wrapped twice: by the root key and by the recovery key.
  - The recovery key is shown **once** at `init`, as 24 BIP39 words.
- Linux keyring: always `{ linux: { store: 'secret-service' } }`. If that is unavailable, the fallback is an Argon2id passphrase keyfile, logged as weaker. **Never silently use keyutils.**
- Never accept a secret through argv or env vars. `set` reads only from a TTY. **No `get`/`reveal` in the MVP.**
- Never print or log a secret value. The display form is `name · type · length`. Fingerprints are `ruleId len=N sha256:XXXXXXXX`.
- Audit records never contain values, request/response bodies, or Authorization headers.
- All filesystem locations go through `packages/platform` `getPaths()`. Never hardcode `/tmp`, and never write `~/.local` outside the XDG default.
- Harness integration:
  - Use **documented extension points only**.
  - Back up every file before editing it.
  - `uninstall` restores the backup.
  - Agents get references (`vault://name`), never values.
- Secret names match `^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`, with a maximum length of 128.

## Review Focus

| # | Situation | Expected behavior | Pinned in |
|---|-----------|-------------------|-----------|
| 1 | A web page POSTs to the capture page, or a DNS-rebinding request arrives | Rejected unless `Host` is `127.0.0.1:<port>`. Nonces are single-use with a 10-minute TTL; an expired nonce gets **410** | Task 11 |
| 2 | A prompt contains several keys (in a code block, quoted, or followed by punctuation) | All are detected and stored, and the prompt is blocked once. If storing fails, the hook **still blocks** (fail-closed) | Tasks 6, 17 |
| 3 | The harness appends to a JSONL file while the scrubber runs | The file stays valid JSONL, appended lines are kept and also scrubbed, and no secret remains | Task 13 |
| 4 | Headless Linux with no Secret Service | A clear message offers the keyfile fallback. The vault never lands in an in-memory keyring | Task 7 |
| 5 | A secret is split across two stdout chunks in `run` | Still redacted | Task 6 |

---

# Phase 0 — Spikes (≈1 week)

### Task 1: Repo scaffold + CI

**Files:**
- Create: `package.json`, `pnpm-workspace.yaml`, `tsconfig.base.json`, `biome.json`, `vitest.config.ts`, `.gitignore`, `.github/workflows/ci.yml`
- Create: `packages/{crypto,detect,platform,core,daemon,cli,mcp,adapters}/package.json` + `tsconfig.json` + `src/index.ts`
- Modify: `AGENTS.md`. Fill in **Current state** with the commands from Development workflow, and add the sandbox rule under **Conventions**.

**Interfaces:**
- Produces: package names `@agent-vault/<pkg>`, all ESM. `packages/cli` exposes `bin: { "agent-vault": "dist/main.js" }`.

- [ ] **Step 1:** Write `packages/crypto/src/smoke.test.ts` → `expect(1 + 1).toBe(2)`.
- [ ] **Step 2:** `pnpm i && pnpm build && pnpm test && pnpm lint` → all pass locally.
- [ ] **Step 3:** CI workflow:
  - Matrix of the 3 OSes × Node 24.
  - Steps: `pnpm i --frozen-lockfile`, build, lint, test.
  - Push a branch and confirm 3 green jobs.
- [ ] **Step 4:** Commit: `chore: scaffold pnpm monorepo and CI matrix`.

### Task 2: Spike S1 — packaging + native addons

**Files:** Create `spikes/s1-packaging/` (throwaway) and `docs/spikes/s1-packaging.md` (decision record).

- [ ] **Step 1:** Build a script that does three things:
  - Opens a SQLite file and runs a write + read: once with `better-sqlite3`, once with `node:sqlite`.
  - Does `@napi-rs/keyring` set/get/delete, pinned to `secret-service` on Linux.
  - Prints `OK`.
- [ ] **Step 2:** Package it as a Node SEA (esbuild bundle → `node --experimental-sea-config` → `postject`), with the `.node` addons shipped beside the binary.
- [ ] **Step 3:** CI job: build and run the binary on all 3 OSes. Linux runs under `dbus-run-session` with `gnome-keyring-daemon --unlock`. Expected output: `OK` on each.
- [ ] **Step 4:** Record the decisions:
  - SQLite driver: prefer `node:sqlite` if it passes on all 3 OSes, since that means one fewer native addon.
  - Addon layout.
  - The exact CI keyring setup.
- [ ] **Step 5:** Commit: `spike: S1 packaging + native addons`.

### Task 3: Spike S2 — Windows IPC

**Files:** Create `spikes/s2-ipc/` and `docs/spikes/s2-ipc.md`.

- [ ] **Step 1:** On Windows CI, start a Node `net` server on `\\.\pipe\agent-vault-<user-sid-hash>`. Inspect its DACL with PowerShell `Get-Acl` (on the pipe path) and record whether `Everyone` has read.
- [ ] **Step 2:** If Node can't restrict the DACL, prototype the fallback:
  - Loopback TCP on `127.0.0.1:0`.
  - A 32-byte token in a file under `%LOCALAPPDATA%\agent-vault\run\` (user-only ACL via `icacls`).
  - The client must send the token as its first frame.
- [ ] **Step 3:** Record the decision as `ipcEndpoint()` return kinds: `unix` on macOS/Linux, plus `pipe` or `tcp` on Windows.
- [ ] **Step 4:** Commit: `spike: S2 windows ipc`.

### Task 4: Spike S3 — harness hook behavior (manual, real machine)

**Files:** Create `spikes/s3-hooks/` (hook scripts) and `docs/spikes/s3-harness-hooks.md`.

Use the canary string `AVCANARY_<uuid4>`, never a real key.

- [ ] **Step 1:** Claude Code. Add a temporary `UserPromptSubmit` hook to a **sandboxed `CLAUDE_CONFIG_DIR`** that blocks prompts containing `AVCANARY_` with `suppressOriginalPrompt: true`. Submit the canary.
  - Then `grep -rl AVCANARY_` across the config dir to record every file that contains it (transcript, `history.jsonl`).
  - Record the exact hook stdin and stdout JSON.
- [ ] **Step 2:** Codex. Repeat with `CODEX_HOME` pointing at a temp dir and `features.hooks` enabled. Record:
  - The hook config file format (`hooks.json` vs. inline `[hooks]`).
  - Which files contain the canary.
  - Whether `codex mcp add` exists.
- [ ] **Step 3:** OpenCode. Write a plugin that logs every `message.*` event, and check whether any handler can mutate the user's text before it is sent. Record yes or no, plus the data dir path.
- [ ] **Step 4:** Claude Code `apiKeyHelper`. Set a helper that prints `AVCANARY_…`, then run `env | grep -c AVCANARY_` in the Bash tool. Record whether the key is exported to tool subprocesses.
- [ ] **Step 5:** Scrub safety test:
  - With the harness **stopped**, rewrite each canary-containing file (temp file + rename).
  - Restart, then `--resume` / `codex resume` the session.
  - Record whether the resume still works.
- [ ] **Step 6:** Update `docs/design.md`:
  - The adapter table (replace each "verify" with the result).
  - The Interfaces of Tasks 17–19 in this plan.
- [ ] **Step 7:** Commit: `spike: S3 harness hook behavior`.

**Gate:** apply the S1–S3 decisions to `docs/design.md` and to Tasks 7, 8, 10, and 17–20 before Phase 1 starts.

---

# Phase 1 — MVP

### Task 5: `@agent-vault/crypto`

**Files:** Create `packages/crypto/src/{aead.ts,keys.ts,recovery.ts,index.ts}` and `packages/crypto/test/crypto.test.ts`.

**Interfaces — Produces:**
- `randomKey(): Uint8Array` (32 bytes)
- `deriveSubkey(key: Uint8Array, info: 'enc' | 'mac' | 'audit'): Uint8Array` (HKDF-SHA-256)
- `encodeAad(p: { vaultId: string; table: string; recordId: string; field: string; version: number }): Uint8Array`
- `seal(key, plaintext, aad): Uint8Array` returns `nonce(24) ‖ ciphertext ‖ tag`
- `open(key, sealed, aad): Uint8Array`, which throws `DecryptError`
- `mac(key, data): Uint8Array` (HMAC-SHA-256) and `macEqual(a, b): boolean` (constant-time)
- `recoveryWords(key): string[]` (24 words) and `keyFromRecoveryWords(words: string[]): Uint8Array`
- `deriveKeyfileKey(passphrase: string, salt: Uint8Array): Uint8Array` (Argon2id, m=65536 KiB, t=3, p=1)

- [ ] **Step 1:** Failing tests:
  - `roundtrip`: `open(k, seal(k, pt, aad), aad)` equals `pt`.
  - `aad mismatch throws`: open with `version: 2` after sealing with `version: 1` → `DecryptError`.
  - `row swap throws`: open with a different `recordId` → `DecryptError`.
  - `nonce unique`: 1000 seals → 1000 distinct 24-byte prefixes.
  - `encodeAad unambiguous`: `{table:'ab', recordId:'c'}` ≠ `{table:'a', recordId:'bc'}`.
  - `recovery roundtrip`: words for a key → `keyFromRecoveryWords` returns the same key, and `length === 24`.
  - `bad checksum`: a mutated word → throws.
- [ ] **Step 2:** `pnpm vitest run packages/crypto` → FAIL.
- [ ] **Step 3:** Implement the functions with `@noble/ciphers/chacha` `xchacha20poly1305`, `@noble/hashes` (`hmac`, `hkdf`, `argon2id`, `sha256`), and `@scure/bip39` with the English wordlist.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(crypto): AEAD with AAD, HMAC, HKDF, recovery words`.

### Task 6: `@agent-vault/detect`

**Files:** Create `packages/detect/src/{rules.ts,detect.ts,redact.ts,fingerprint.ts,index.ts}`, `packages/detect/test/{detect,redact}.test.ts`, and `packages/detect/test/fixtures/fake-keys.ts`. The fixtures are generated fakes, never real keys.

**Interfaces — Produces:**
- `type Detection = { ruleId: string; value: string; start: number; end: number; suggestedName: string }`
- `detectSecrets(text: string): Detection[]`. Results are de-duplicated by value and sorted by `start`.
- `createRedactor(secrets: { name: string; value: string }[]): { push(chunk: string): string; flush(): string }`. Each match is replaced with `[redacted vault://<name>]`.
- `fingerprint(d: Detection | { ruleId: string; value: string }): string`

**Rules** (ruleId → suggestedName prefix):

| ruleId | Matches | Name prefix |
|--------|---------|-------------|
| `anthropic` | `sk-ant-[A-Za-z0-9_-]{20,}` | `anthropic/api-key` |
| `openai` | `sk-(proj-)?[A-Za-z0-9_-]{20,}` (not `sk-ant-`) | `openai/api-key` |
| `github` | `gh[pousr]_[A-Za-z0-9]{36}` or `github_pat_[A-Za-z0-9_]{50,}` | `github/pat` |
| `slack` | `xox[baprs]-[A-Za-z0-9-]{10,}` | `slack/token` |
| `aws-akid` | `AKIA[0-9A-Z]{16}` | `aws/access-key-id` |
| `apify` | `apify_api_[A-Za-z0-9]{20,}` | `apify/api-token` |
| `jwt` | `eyJ…\.eyJ…\.[A-Za-z0-9_-]+` | `jwt/token` |
| `pem` | `-----BEGIN [A-Z ]*PRIVATE KEY-----` … `END` | `pem/private-key` |
| `generic-high-entropy` | `[A-Za-z0-9_\-+/=]{32,}` with Shannon entropy > 4.3 bits/char (excludes hex SHAs) | `secret/unnamed` |

`suggestedName` = `<prefix>-<yyyymmdd>`, plus a `-2`, `-3`… suffix when the name is taken (the caller supplies a taken-check).

- [ ] **Step 1:** Failing tests:
  - Each rule detects its fixture.
  - Multiple keys: a prompt containing a GitHub PAT in backticks, a quoted `sk-ant-…`, and `AKIA…` followed by a comma → **3** detections with correct `start`/`end`.
  - No false positive on a 40-char git SHA, a UUID, or `npm install`.
  - Redactor:
    - `push('abc' + secret.slice(0, 5))` + `push(secret.slice(5) + 'xyz')` + `flush()` equals `'abc[redacted vault://gh]xyz'` **(Review Focus 5)**.
    - The base64, base64url, and URL-encoded forms are also redacted.
  - `fingerprint` never contains the value.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. The redactor holds back `maxVariantLength - 1` chars between pushes.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(detect): secret rules, streaming redactor, fingerprints`.

### Task 7: `@agent-vault/platform`

**Files:** Create `packages/platform/src/{paths.ts,keystore.ts,ipc-endpoint.ts,index.ts}` and `packages/platform/test/*.test.ts`.

**Interfaces — Produces:**
- `type VaultPaths = { dataDir: string; runtimeDir: string; backupsDir: string; dbFile: string }`
- `getPaths(env = process.env, platform = process.platform): VaultPaths`. `AGENT_VAULT_HOME` overrides `dataDir`.
  - darwin: `~/Library/Application Support/agent-vault`
  - linux: `$XDG_DATA_HOME/agent-vault`, falling back to the XDG default. `runtimeDir` = `$XDG_RUNTIME_DIR/agent-vault`, else `dataDir/run`.
  - win32: `%LOCALAPPDATA%\agent-vault`
- `interface RootKeyStore { readonly kind: 'os-keyring' | 'keyfile' | 'memory'; load(): Promise<Uint8Array | null>; save(k: Uint8Array): Promise<void>; remove(): Promise<void> }`
- `openOsKeyring(): RootKeyStore` uses `new Entry('agent-vault', 'device-root-key', { linux: { store: 'secret-service' } })` with a base64 payload. It throws `KeyringUnavailableError` with the message `"No Secret Service found. Run: agent-vault init --keystore keyfile"`.
- `openKeyfileStore(file: string, passphrase: string): RootKeyStore` (Argon2id + `seal`)
- `class MemoryKeyStore implements RootKeyStore` (tests only)
- `ipcEndpoint(paths, platform): { kind: 'unix'; path } | { kind: 'pipe'; name } | { kind: 'tcp'; tokenFile }`, per Spike S2
- `ensurePrivateDir(dir): void` creates the directory with mode `0700` (POSIX) and verifies the owner equals the current uid.

- [ ] **Step 1:** Failing tests:
  - `getPaths` table test for the 3 platforms using injected env, and the `AGENT_VAULT_HOME` override.
  - The keyfile store round-trips, and a wrong passphrase throws.
  - `openOsKeyring` on Linux with `DBUS_SESSION_BUS_ADDRESS` unset → `KeyringUnavailableError` **(Review Focus 4)**.
  - `ensurePrivateDir` sets mode `0o700` (skipped on win32).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS. CI also runs the real-keyring test on all 3 OSes using the S1 keyring setup.
- [ ] **Step 5:** Commit: `feat(platform): paths, pinned keyring, keyfile fallback, ipc endpoint`.

### Task 8: `@agent-vault/core` — vault

**Files:** Create `packages/core/src/{db.ts,migrations.ts,vault.ts,errors.ts,index.ts}` and `packages/core/test/vault.test.ts`.

**Interfaces:**
- Consumes: Tasks 5 and 7.
- Produces:
  - `openDb(file: string): Db`, where `Db = { exec(sql): void; prepare(sql): { run(...a): unknown; get(...a): any; all(...a): any[] } }` (driver per S1)
  - Schema v1:
    - `meta(vault_id, schema_version, wrapped_dk_device, wrapped_dk_recovery)`
    - `secrets(id, name UNIQUE, type, ciphertext, length, version, tags_json, created_at, updated_at, meta_mac)`
    - `bundles(id, name UNIQUE, meta_mac)`, `bundle_env(bundle_id, env_name, secret_name)`, `bundle_exes(bundle_id, exe_path)`
    - `audit_log(seq, ts, event_json, prev_hmac, hmac)`, `scrub_queue(id, harness, file, secret_name, created_at)`
  - `initVault({ paths, store }): Promise<{ vault: Vault; recoveryWords: string[] }>`, which throws `VaultExistsError`
  - `openVault({ paths, store }): Promise<Vault>`, which throws `VaultNotInitializedError` or `RootKeyMissingError`
  - `recoverVault({ paths, store, words }): Promise<Vault>` re-wraps the data key under a new root key.
  - `type SecretMeta = { name: string; type: string; length: number; tags: string[]; createdAt: string; updatedAt: string }`
  - `class Vault`:
    - `vaultId: string`
    - `putSecret(name, value: Uint8Array, opts?: { type?: string; tags?: string[] }): SecretMeta`. Overwrites bump `version`.
    - `list(): SecretMeta[]`
    - `has(name): boolean`
    - `remove(name): boolean`
    - `addTag(name, tag): void`
    - `readValue(name): Uint8Array`. **Internal: called only by the runner, helper, and scrubber inside vaultd.**
    - `close(): void`

- [ ] **Step 1:** Failing tests:
  - `init → put → close → open → readValue` round-trips.
  - `list` never includes values.
  - Tamper: flip one byte of `ciphertext` → `readValue` throws.
  - Row swap: swap the `ciphertext` of two rows → both throw.
  - Metadata tamper: edit `tags_json` in SQL → `list` throws `MetadataTamperError`.
  - Recovery: init with store A, then `recoverVault` with store B and the words → the secret is readable.
  - Invalid names (`../x`, `A`, 129 chars) → `InvalidNameError`.
  - `init` twice → `VaultExistsError`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. AAD uses `table='secrets'`, `field='value'`, with `recordId` = row id. Metadata MAC uses `deriveSubkey(dk, 'mac')`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(core): encrypted vault, metadata MAC, recovery`.

### Task 9: `@agent-vault/core` — bundles, references, audit

**Files:** Create `packages/core/src/{bundles.ts,refs.ts,audit.ts}` and `packages/core/test/{bundles,refs,audit}.test.ts`.

**Interfaces — Produces:**
- Bundles:
  - `createBundle(v: Vault, name): void`
  - `grant(v, bundle, { env: string; secret: string }): void`
  - `allowExe(v, bundle, absPath: string): void`
  - `resolveBundle(v, name): { env: Record<string, string>; exes: string[] }` (env name → secret name)
- References:
  - `parseRef(s: string): string | null` (`vault://<name>` → name)
  - `parseEnvFile(text): { key: string; ref?: string; literal?: string; line: number }[]`
- Audit:
  - `type AuditEvent = { ts: string; deviceId: string; harness?: 'claude-code' | 'codex' | 'opencode' | 'cli' | 'mcp'; actor: string; secretName?: string; bundle?: string; operation: string; outcome: 'captured' | 'brokered' | 'blocked' | 'error'; requestId: string }`
  - `appendAudit(v, e: Omit<AuditEvent, 'ts' | 'requestId'>): AuditEvent`
  - `verifyAudit(v): { ok: true } | { ok: false; brokenAtSeq: number }`
  - `queryAudit(v, f: { secretName?: string; since?: string; limit?: number }): AuditEvent[]`

- [ ] **Step 1:** Failing tests:
  - `resolveBundle` returns the granted env map.
  - `parseEnvFile` handles quotes, `export` prefixes, comments, and `vault://` refs.
  - Audit chain: 3 appends → `verifyAudit` ok. Deleting the middle row → `{ ok: false, brokenAtSeq: 2 }`.
  - An `AuditEvent` with an unknown key (for example `value`) is rejected at runtime.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. Each row's `hmac` = `mac(deriveSubkey(dk, 'audit'), prev_hmac ‖ event_json)`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(core): bundles, vault:// references, hash-chained audit`.

### Task 10: `@agent-vault/daemon` — RPC server, client, autostart

**Files:** Create `packages/daemon/src/{server.ts,rpc.ts,client.ts,autostart.ts,methods/*.ts,index.ts}` and `packages/daemon/test/rpc.test.ts`.

**Interfaces:**
- Consumes: Tasks 7–9.
- Produces:
  - `startDaemon({ paths, store }): Promise<{ endpoint; close(): Promise<void> }>`
  - `connect(endpoint): Promise<IpcClient>`, where `IpcClient = { call<T>(method: string, params?: unknown): Promise<T>; onNotification(fn: (method: string, params: unknown) => void): void; close(): void }`
  - `ensureDaemon(paths): Promise<IpcClient>` connects, or spawns `agent-vault daemon run` detached and retries for ≤3 s.
  - Wire protocol: newline-delimited JSON-RPC 2.0.
  - Methods:
    - `status` → `{ initialized, keystore, version }`
    - `vault.init` `{ keystore }` → `{ recoveryWords }`
    - `secret.list`
    - `secret.put` `{ name?, valueB64, type?, tags?, harness? }` → `SecretMeta`. A missing name means detect + `suggestedName`.
    - `secret.remove`
    - `bundle.create` / `bundle.grant` / `bundle.allowExe` / `bundle.list`
    - `audit.query` / `audit.verify`
  - Tasks 11–13 add `capture.begin`, `run.start`, `helper.get`, `scrub.queue`, and `scrub.run`.

- [ ] **Step 1:** Failing tests:
  - Start the daemon on a temp `AGENT_VAULT_HOME` with `MemoryKeyStore`.
  - `secret.put` then `secret.list` → 1 entry with no value field anywhere in the JSON.
  - An unknown method → JSON-RPC error `-32601`.
  - **No RPC method returns secret bytes** except `helper.get`. This is asserted by a method-registry test.
  - The socket file mode is `0600` inside a `0700` dir (POSIX).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. Every mutating method writes an audit event.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(daemon): JSON-RPC server, client, autostart`.

### Task 11: Capture page (Path A, browser)

**Files:** Create `packages/daemon/src/capture-page.ts` and `packages/daemon/test/capture-page.test.ts`.

**Interfaces — Produces:** RPC `capture.begin` `{ name? }` → `{ url: string; elicitationId: string; expiresAt: string }`. The URL looks like `http://127.0.0.1:<port>/capture/<nonce>`, where the nonce is 32 random bytes in base64url.

- [ ] **Step 1:** Failing tests **(Review Focus 1)**:
  - GET returns a form page with `Cache-Control: no-store` and `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'`.
  - POST stores the secret, and the response shows `name · type · length` only.
  - A second POST with the same nonce → 410.
  - A POST after 10 minutes (fake timers) → 410.
  - `Host: evil.com` → 421.
  - `Origin` ≠ self → 403.
  - The audit log gets an event with outcome `captured`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement with `node:http` bound to `127.0.0.1:0`, and open the page with the platform opener (`open` / `xdg-open` / `start`).
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(daemon): one-time loopback capture page`.

### Task 12: Runner + helper

**Files:** Create `packages/daemon/src/{runner.ts,helper.ts}` and `packages/daemon/test/runner.test.ts`.

**Interfaces — Produces:**
- `run.start`:
  - Params: `{ argv: string[]; cwd: string; bundle?: string; envFile?: string; env?: Record<string, string /* vault://ref */> }`.
  - Streams `run.output { stream: 'stdout' | 'stderr'; data: string }` notifications and resolves to `{ exitCode: number }`.
  - When the bundle has exes, `realpath(which(argv[0]))` must be among them, or the call fails with `ExeNotAllowedError`.
- `helper.get` `{ secret }` → `{ value: string }`. It only works for secrets tagged `helper` and writes an audit event with outcome `brokered`.

- [ ] **Step 1:** Failing tests:
  - `run.start` with `env: { TOKEN: 'vault://t' }` running `node -e "console.log(process.env.TOKEN)"` → output equals `[redacted vault://t]\n`, and `exitCode` is 0.
  - The base64 form is printed redacted too.
  - A bundle with exes `[/usr/bin/true]` running `node` → `ExeNotAllowedError`.
  - `helper.get` on an untagged secret → error.
  - Windows: a `.cmd` shim runs with escaped args (`cross-spawn`).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement with `cross-spawn` and a `createRedactor` per stream. stdin is piped through.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(daemon): run with redacted output, credential helper`.

### Task 13: Scrubber

**Files:** Create `packages/daemon/src/scrubber.ts` and `packages/daemon/test/scrubber.test.ts`.

**Interfaces — Produces:**
- `scrubFiles(files: string[], replacements: { value: string; ref: string }[]): Promise<{ filesChanged: number; replacements: number }>`
  - Replaces raw values and their JSON-escaped forms with `vault://<name>`.
  - Writes through a temp file + rename. Before the rename, it re-reads any bytes appended since the start and scrubs them too.
- RPC `scrub.queue { harness; files; secretNames }` and `scrub.run { harness }`. The pending rows live in `scrub_queue`.

- [ ] **Step 1:** Failing tests:
  - A JSONL file with the secret on 2 lines → 0 occurrences after scrubbing, every line still parses as JSON, and `replacements === 2`.
  - A PEM key with `\n` escapes inside JSON is scrubbed.
  - **Concurrent append (Review Focus 3):** a writer appends 50 lines during the scrub → all 50 lines are present, none contains the secret, and the file is valid JSONL.
  - A missing file is skipped without error.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. On Windows, retry the rename up to 5× with 100 ms backoff, then leave the row queued.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(daemon): append-safe transcript scrubber`.

### Task 14: CLI core commands

**Files:** Create `packages/cli/src/{main.ts,tty.ts,commands/{init,status,set,grab,list,rm,run,bundle,audit,helper,daemon}.ts}` and `packages/cli/test/cli.e2e.test.ts`.

**Interfaces:**
- Consumes: Tasks 10–12.
- Produces:
  - `readSecretFromTty(prompt: string): Promise<Uint8Array>`. When `!process.stdin.isTTY` it exits with code 2 and the message `"Run this in a terminal, or use: agent-vault grab <name>"`.
  - Commands:
    - `init [--keystore os|keyfile]` prints the recovery words once, with a "write these down" line.
    - `grab <name>` reads the clipboard via `clipboardy`, stores the value, clears the clipboard, and prints `stored <name> · <type> · <len> chars`.
    - `set <name>`
    - `list`
    - `rm <name>`
    - `run [--bundle b] [--env-file f] [--env K=vault://x]... -- <cmd>`
    - `bundle create|grant|allow-exe|list`
    - `audit [--verify]`
    - `helper <secret>`
    - `daemon run|install|uninstall`

- [ ] **Step 1:** Failing e2e tests (spawn the built CLI with sandbox env + keyfile store):
  - `init` → 24 words.
  - `grab` with a mocked clipboard → `list` shows the name with no value, and the clipboard is empty afterwards.
  - `set` with piped stdin → exit 2.
  - `run --env T=vault://x -- node -e "console.log(process.env.T)"` → redacted output.
  - The `audit --verify` exit code is 0.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement with `commander`. Every command goes through `ensureDaemon`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(cli): init, grab, set, list, rm, run, bundle, audit, helper`.

### Task 15: Import, migrate, scan (Path C + backfill)

**Files:** Create `packages/adapters/src/{migrate.ts,sources.ts,backup.ts}`, `packages/cli/src/commands/{import,migrate,scan}.ts`, and `packages/adapters/test/migrate.test.ts` (+ fixtures).

**Interfaces — Produces:**
- `type Finding = { file: string; kind: 'dotenv' | 'claude-mcp' | 'codex-mcp' | 'opencode-mcp' | 'opencode-remote-header'; locator: string; envName: string; detection: Detection }`
- `findPlaintextSecrets(sources: { home: string; cwd: string }): Promise<Finding[]>` scans:
  - `.env*` in the cwd
  - `.mcp.json`
  - `~/.claude.json` `mcpServers.*.env`
  - `$CODEX_HOME/config.toml` `mcp_servers.*.env`
  - `opencode.json` `mcp.*.environment` / `.headers`
  - A value counts when it matches `detectSecrets` **or** its key matches `/KEY|TOKEN|SECRET|PASSWORD/i` and it isn't already a `vault://` ref.
- `applyMigration(findings, client): Promise<{ migrated: number; listedForPhase2: number; backups: string[] }>`
  - Each value is stored first.
  - `.env` values are rewritten to `vault://<name>`.
  - Stdio MCP servers are rewritten to `agent-vault run --bundle mcp-<server> -- <original argv>`: the env is removed and the bundle is created.
  - Remote headers are listed under `listedForPhase2`.
  - JSON/JSONC is edited with `jsonc-parser` `modify` (formatting preserved). TOML is edited with `smol-toml` (comments are not kept, which is why the backup and diff come first).
- `backupFile(file, backupsDir): string`
- `scanHistory(harnessFiles: string[]): Promise<{ file: string; fingerprints: string[] }[]>`

- [ ] **Step 1:** Failing tests on fixtures:
  - `migrate` (dry run) reports 5 findings across the 5 source kinds and **writes nothing**.
  - `migrate --apply`:
    - The `.env` now has `GITHUB_TOKEN=vault://github/pat-…`.
    - The `~/.claude.json` server `command` is `agent-vault`, and its env no longer contains the value.
    - The backups exist.
  - A second `migrate` reports 0 findings (idempotent).
  - The `opencode.json` comments are preserved.
  - `scan` output contains fingerprints only, never values.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. The CLI prints the counts table and requires `--apply` to write.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat: import, migrate, scan`.

### Task 16: `@agent-vault/mcp`

**Files:** Create `packages/mcp/src/{server.ts,tools.ts}`, `packages/cli/src/commands/mcp.ts`, and `packages/mcp/test/mcp.test.ts`.

**Interfaces — Produces:** `agent-vault mcp` (stdio server) with these tools:

| Tool | Behavior |
|------|----------|
| `vault_list` | Returns `SecretMeta[]` |
| `vault_status` | Returns daemon status |
| `vault_capture { name? }` | If the client declared `elicitation.url`, sends `elicitation/create` `{ mode: 'url', url, elicitationId, message }`. Otherwise returns the text `Open <url> to add the key`. Returns the stored name |
| `vault_run { bundle; argv }` | Requires a bundle with ≥1 allowed exe. Returns redacted stdout/stderr + exit code |

The tool descriptions tell the agent: "Never ask the user to paste keys; call vault_capture."

- [ ] **Step 1:** Failing tests with the SDK in-memory client:
  - `vault_list` → names only.
  - A client with URL-mode capability receives `mode: 'url'`, and the URL contains no secret.
  - A client without it gets the URL as text.
  - `vault_run` with no bundle → error.
  - The serialized JSON of every tool result has 0 secret bytes.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement with `@modelcontextprotocol/sdk` + `IpcClient`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(mcp): metadata tools, URL-mode capture, vault_run`.

### Task 17: Claude Code adapter (Path B)

**Files:** Create `packages/adapters/src/{adapter.ts,claude-code.ts,hook.ts}`, `packages/cli/src/commands/{install,uninstall,doctor,hook}.ts`, and `packages/adapters/test/claude-code.test.ts`.

**Interfaces — Produces:**
- `interface HarnessAdapter { id: 'claude-code' | 'codex' | 'opencode'; detect(home): Promise<boolean>; install(opts: { home: string; modelKey?: boolean }): Promise<InstallReport>; uninstall(home): Promise<void>; doctor(home): Promise<DoctorReport>; handleHook(event: string, input: unknown): Promise<HookOutput>; historyFiles(home, input?): string[] }`
- `agent-vault hook <harness> <event>` reads JSON from stdin, writes the hook JSON to stdout, and exits 0.
- `install` does four things:
  - Merges hooks into `~/.claude/settings.json` (`UserPromptSubmit` → `agent-vault hook claude-code prompt-submit`; `SessionEnd` + `SessionStart` → `agent-vault hook claude-code scrub`).
  - Registers MCP with `claude mcp add --scope user agent-vault -- agent-vault mcp`.
  - Adds `apiKeyHelper` only with `--model-key`, and only if S3 confirmed no env export.
  - Backs up every file first.
- **The prompt-submit hook logic:**
  1. `detectSecrets(prompt)`.
  2. If there are none: emit `{}` (allow).
  3. Otherwise, `secret.put` each detection (`tags: ['exposed-locally']`, `harness: 'claude-code'`).
  4. `scrub.queue` for `transcript_path` + `~/.claude/history.jsonl`.
  5. Emit `{ decision: 'block', reason: 'Stored as <names>. Re-send using vault://<name>.', hookSpecificOutput: { hookEventName: 'UserPromptSubmit', suppressOriginalPrompt: true } }`. The exact shape comes from S3.
- **Failure rules:**
  - Storage failure **still blocks**, with the reason `Key held back from the model. Run: agent-vault init, then paste again.`
  - Any crash before detection exits 0 with no output (allow).

- [ ] **Step 1:** Failing tests:
  - A prompt with 2 keys → block JSON naming 2 refs, and `secret.list` has 2 entries tagged `exposed-locally` **(Review Focus 2)**.
  - A prompt with 0 keys → `{}`.
  - With the daemon unreachable and a key present → block JSON (fail-closed).
  - Install into a sandbox home: `settings.json` has the 3 hooks, existing keys are preserved, and a backup exists.
  - `uninstall` restores the file byte-for-byte.
  - `doctor` reports all checks green.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(adapters): claude code install, prompt capture, scrub`.

### Task 18: Codex adapter

**Files:** Create `packages/adapters/src/codex.ts` and `packages/adapters/test/codex.test.ts`.

**Interfaces:**
- Consumes: `HarnessAdapter` and the hook logic from Task 17 (shared in `hook.ts`).
- Produces:
  - `install` sets `features.hooks = true` in `$CODEX_HOME/config.toml` and adds `UserPromptSubmit` / `SessionEnd` / `SessionStart` hooks, in the format S3 recorded.
  - MCP is registered via `codex mcp add agent-vault -- agent-vault mcp` (per S3), or else a `[mcp_servers.agent-vault]` table.
  - `--model-key` sets `model_providers.<id>.auth.command = ["agent-vault", "helper", "<secret>"]`.
  - Scrub targets: `$CODEX_HOME/history.jsonl` + `$CODEX_HOME/sessions/**`.

- [ ] **Step 1:** Failing tests:
  - Install into a sandbox `CODEX_HOME` → the TOML parses and contains `features.hooks = true` + the hook entries.
  - Hook block output matches the S3 Codex format.
  - The `uninstall` restore is byte-identical.
- [ ] **Step 2–4:** Run → FAIL, implement, run → PASS.
- [ ] **Step 5:** Commit: `feat(adapters): codex install, prompt capture, scrub`.

### Task 19: OpenCode adapter

**Files:** Create `packages/adapters/src/opencode.ts` and `packages/adapters/test/opencode.test.ts`.

**Interfaces — Produces:**
- `install` adds `mcp["agent-vault"] = { type: "local", command: ["agent-vault", "mcp"], enabled: true }` to `opencode.json` via `jsonc-parser`.
- Prompt capture: wired only if S3 found a mutating message hook. Otherwise `doctor` shows `prompt capture: use agent-vault grab (no OpenCode prompt hook yet)`.

- [ ] **Step 1:** Failing tests:
  - Install keeps comments and adds the MCP entry.
  - `doctor` output matches the S3 outcome.
  - The `uninstall` restore is byte-identical.
- [ ] **Step 2–4:** Run → FAIL, implement, run → PASS.
- [ ] **Step 5:** Commit: `feat(adapters): opencode install`.

### Task 20: Distribution

**Files:** Create `scripts/build-sea.mjs`, `packages/daemon/src/service/{launchd,systemd,schtasks}.ts`, `.github/workflows/release.yml`, and `packages/daemon/test/service.test.ts`.

**Interfaces — Produces:**
- `agent-vault daemon install|uninstall` writes, per OS:
  - macOS: `~/Library/LaunchAgents/com.agent-vault.daemon.plist`
  - Linux: `~/.config/systemd/user/agent-vault.service` (lazy start)
  - Windows: a Task Scheduler logon task (no admin).
- `pnpm dist` builds SEA binaries for darwin-arm64, darwin-x64, linux-x64, linux-arm64, and win32-x64, with the native addons laid out per S1.
- The npm package `agent-vault` is the primary install path in the MVP (`npm i -g agent-vault`). This depends on the name decision (design open question 1).

- [ ] **Step 1:** Failing tests: each generated unit file matches a snapshot, and the paths come from `getPaths`.
- [ ] **Step 2–4:** Run → FAIL, implement, run → PASS.
- [ ] **Step 5:** The release workflow runs on a tag. The built binary runs `agent-vault status` on all 3 OSes in CI.
- [ ] **Step 6:** Commit: `build: SEA binaries, service units, release workflow`.

### Task 21: End-to-end acceptance (design success criteria 1–4)

**Files:** Create `test/e2e/acceptance.test.ts` and `test/e2e/fixtures/home/` (fake harness configs + `.env` with generated fake keys).

- [ ] **Step 1:** Write the tests:

| Criterion | Assertion |
|-----------|-----------|
| 1 | `install claude-code`, `install codex`, and `install opencode` in a sandbox home → each `doctor` exits 0 |
| 2 | `migrate` reports N > 0 before `--apply`, and 0 after |
| 3 | 20 fixture prompts with keys fed to `hook claude-code prompt-submit` and `hook codex prompt-submit` → **20/20 blocked** on each |
| 4 | Every MCP tool result and every `run` output over the fixture corpus contains **0** secret bytes. Grep the captured output for each fixture value |

- [ ] **Step 2:** `pnpm test test/e2e` → PASS on all 3 OSes in CI.
- [ ] **Step 3:** Commit: `test: MVP acceptance suite`.

---

## Verification (end-to-end, by hand, after Task 21)

1. On your machine:
   - `npm i -g ./packages/cli`
   - `agent-vault init`: write down the 24 words.
   - `agent-vault install claude-code`
2. In Claude Code, paste a **freshly created, throwaway** GitHub token into the prompt.
   - Expected: the prompt is blocked, and the message shows `Stored as github/pat-…`.
3. Exit Claude Code, then search for the token: `grep -rc '<token>' ~/.claude/history.jsonl ~/.claude/projects` → **0** after the `SessionEnd` scrub.
4. Run `agent-vault run --env GH_TOKEN=vault://github/pat-… -- gh api user` → your profile JSON appears.
5. Ask the agent to "list my vault": it calls `vault_list` and shows names only.
6. Run `agent-vault audit --verify` → exit 0.
7. Revoke the throwaway token.

## Next plans (out of scope here)

| Phase | What it adds |
|-------|--------------|
| Phase 2 | Base-URL proxy, then forward proxy, plus the human-presence gate and `reveal` |
| Phase 3 | Sync |
| Phase 4 | Cloud runners |

Each phase gets its own plan when it is reached.
