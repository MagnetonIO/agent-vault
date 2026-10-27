# agent-vault — High-Level Design

**Goal: the default keystore for every agent harness**: Claude Code, Codex, OpenCode, and anything that runs a shell, speaks MCP, or honors `HTTPS_PROXY`. When you paste a key, it goes into the vault. It doesn't go into `.env`, the prompt, or the transcript. Agents use keys without ever seeing them.

**Cross-platform: macOS, Linux, Windows.** Same feature set and CLI on all three. The credential store is **one library** (`@napi-rs/keyring`). Only IPC, paths, and the service manager are platform seams.

Inspired by **Infisical Agent Vault** (network-boundary injection, access bundles, session logs) and **HashiCorp Vault** (seal/unseal, leases, dynamic secrets, audit devices).

**Positioning:** Infisical Agent Vault (in preview) already guides Claude Code, Codex, OpenCode, Hermes, and OpenClaw through `HTTPS_PROXY`, and it requires Infisical. Our wedge:
1. **Local-first, no account.** Your machine is the source of truth. Cloud is optional.
2. **Paste capture.** A key pasted anywhere ends up in the vault (see §Capture).
3. **Config migration.** One command moves plaintext keys out of `.env` and harness configs.

---

## Problem

| Leak path | Where the key ends up |
|-----------|-----------------------|
| Paste key into the prompt | Model API, session transcript, prompt history (`~/.claude/history.jsonl`, `~/.codex/history.jsonl`) |
| `.env` files | Disk, git, backups, agent `Read` tool |
| Harness configs | Plaintext tokens in `.mcp.json`, `~/.claude.json`, `~/.codex/config.toml`, `opencode.json` |
| Agent shell env | Any `printenv`, `env`, `/proc/<pid>/environ` |

Agents need real credentials to be useful, and they can't be trusted to hold them.

## Success criteria (measurable)

| # | Criterion | Measure |
|---|-----------|---------|
| 1 | One-command setup per harness | `agent-vault install claude\|codex\|opencode` → `doctor` passes |
| 2 | No plaintext keys in harness configs or `.env` | `agent-vault migrate` count before → 0 after |
| 3 | Pasted keys never reach the model API | 100% of detector-matched keys blocked in hook tests (Claude Code, Codex) |
| 4 | Agent never receives a value | 0 secret bytes in MCP/tool output across redaction test corpus |

---

## Threat model

| Tier | Adversary | Defended in |
|------|-----------|-------------|
| **T1** | Accidental exposure: paste, `.env` commit, plaintext config, transcript/log | **Phase 1 (MVP)** |
| **T2** | Prompt-injected or misbehaving agent running as **your OS user** with a shell | Phase 2 (proxy + human-presence gate), partial |
| **T3** | Malware with same-user code execution | Out of scope (can read keyring, keylog) |
| **T4** | Lost/stolen disk | Phase 1 (keys wrapped by OS credential store) |
| **T5** | Compromised cloud | Phase 3/4 (end-to-end encryption, SAS-verified enrollment) |

**MVP covers T1 + T4, which is every paste, `.env`, and config leak. Phase 2 adds T2** through the proxy and a human-presence gate. Why T2 needs Phase 2: the agent runs as the same user, so
- It can call vaultd's IPC socket directly, the same way the CLI does.
- It can read the device root key from the OS store:
  - Linux Secret Service has no per-app ACL.
  - Windows Credential Manager is readable by any process the user runs.
  - On macOS, the ACL is bound to the creating binary, so if that binary is a generic `node`, any `node -e` can read the key. **Ship a signed binary.**
- In `run` mode the agent picks the command. `run -- printenv` prints the secret.

Prompt-injection resistance ships in Phase 2.

---

## Core principles

1. **Value never enters the agent.** The agent sees names, permissions, and status, never secrets. This holds against T1 in Phase 1 and against T2 from Phase 2.
2. **Capture beats discipline.** The safe path must be shorter than pasting.
3. **Local-first.** Encrypted SQLite on-device. Device root key in the OS credential store.
4. **Established AEAD only.** XChaCha20-Poly1305 (libsodium / `@noble/ciphers`) with AAD binding. Never design crypto.
5. **Record-level sync.** Never copy a live WAL SQLite file (Dropbox/Git/iCloud are the wrong tools).
6. **Network-boundary injection** is the preferred path. Process-env injection is the fallback.
7. **Audit without values.** Record who, which secret, what operation, and when, never the secret.
8. **Cross-platform by default.** One CLI/daemon/MCP surface. Only IPC, paths, and the service manager are per-OS.
9. **Harness-agnostic.** Integrate only through each harness's documented extension points (hooks, MCP, credential helpers, proxy env). Never patch harness binaries.
10. **Agents get session tokens, not secrets.** Adapters put proxy settings and session tokens into the agent environment, never raw keys.

---

## Architecture

```
  Harnesses: Claude Code · Codex · OpenCode · any shell/MCP/proxy client
     │ prompt hook          │ MCP (stdio)          │ helpers · proxy env · run
┌────▼──────────────────────▼──────────────────────▼─────────────────┐
│  Local device (source of truth)                                    │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────────────┐   │
│  │ CLI +        │──▶│ vaultd        │──▶│ SQLite: encrypted    │   │
│  │ harness      │   │ IPC · proxy · │   │ records, MAC'd       │   │
│  │ adapters     │   │ capture page  │   │ metadata, audit      │   │
│  └──────────────┘   └───────┬───────┘   └──────────▲───────────┘   │
│                             │           ┌──────────┴───────────┐   │
│                             │           │ OS credential store  │   │
│                             │           │ (device root key)    │   │
│                             │           └──────────────────────┘   │
└─────────────────────────────┼──────────────────────────────────────┘
                              │ record-level encrypted sync (phase 3)
                      ┌───────▼────────┐
                      │ Cloud (opt-in) │  Cloudflare Workers
                      │ Durable Objects│  + R2 encrypted blobs
                      └───────┬────────┘
                              │ scoped enrollment (phase 4)
                      ┌───────▼────────┐
                      │ Remote runner  │  own device key + bundle key
                      └────────────────┘
```

---

## Primitives (borrowed from Infisical Agent Vault)

| Primitive | What it is | Local equivalent |
|-----------|------------|------------------|
| **Secret** | Named credential record | Encrypted row in SQLite |
| **Reference** | Pointer that replaces a value in files/configs: `vault://github/pat` | Resolved by `run` / adapters |
| **Service** | One external API + how auth is attached (header/basic/query) | `services` table |
| **Access bundle** | Named set of services granted as a unit, per job (`code-review`: GitHub, Slack) | `bundles` + `bundle_services` |
| **Policy** | Host allowlist, HTTP methods, path prefixes, request-count caps | `policies` on bundle×service |
| **Session** | Time-bound grant on a bundle; TTL; revocable | `sessions` (local + synced) |
| **Device** | Enrolled machine with its own key + scoped grants | `devices` (sync identity) |
| **Audit event** | Who used which secret for what, when, with no value | Hash-chained `audit_log` |

---

## Capture: paste → vault (MVP core)

Three paths, strongest first:

| Path | How | Does the key touch the harness? | Status |
|------|-----|---------------------------------|--------|
| **A. Out-of-band (primary)** | `agent-vault grab <name>` reads the clipboard, stores the key, clears the clipboard, and prints `stored github/pat (ghp_, 40 chars)`. Inside a harness: `! agent-vault grab github/pat` (the command line holds no secret). Or MCP `vault_capture` → **URL-mode elicitation** → vaultd's one-time page `http://127.0.0.1:<port>/capture/<nonce>` | **No** | Buildable now |
| **B. Prompt safety net** | `UserPromptSubmit` hook detects a key → stores it → **blocks** the prompt → tells the user the reference name | **Yes:** it reaches local disk but not the model | Claude Code ✅ · Codex ⚠️ **fail-open until the hook is trusted** (`/hooks` → `t`; an untrusted hook is silently skipped and the prompt goes to the model; re-check with `doctor` after every Codex upgrade) · OpenCode ⚠️ (no block; can redact or reject via `session.context`/`session.title`, but text stays in `opencode.db`). Measured in S3 |
| **C. Files** | `agent-vault import .env` and `agent-vault migrate` move values into the vault and rewrite them to references | Already on disk → rewritten | Buildable now |

**How Path B works (checked against harness docs 2026-10-26):**
1. Block with `suppressOriginalPrompt: true`. **The key never reaches the model.** Codex exception: the hook must be **trusted** first. Install cannot forge the trust hash; the user runs `/hooks` and presses `t`. Until then the hook is skipped silently (fail-open) and the prompt is sent. `doctor` proves the hook fires with a probe canary and repeats the check after each Codex upgrade.
2. Store the key in the vault.
3. Scrub what the harness left on disk (measured in S3, `docs/spikes/s3-harness-hooks.md`). Hooks can't rewrite prompts. Residue differs: Claude `-p` writes one `queue-operation` transcript line (**after** the hook returns, so scrub on `SessionEnd` (measured working in `-p`: transcript stays valid JSONL, `--resume` OK; long-lived TUI untested) and sweep at the next `SessionStart` as the fallback; `Stop` doesn't fire after a block); Claude's TUI and `codex exec` leave nothing; Codex's TUI leaves a `history.jsonl` line unless `history.persistence = "none"`; OpenCode keeps the message in `opencode.db`. The Codex transcript format "isn't a stable interface", so the scrubber must tolerate format changes, be binary-safe (sqlite files need a same-length rewrite) and re-validate JSONL afterwards.
4. Tag the secret `exposed-locally` and suggest rotation.
5. **Route to 100% off-disk:** Path A today, plus an upstream prompt-rewrite hook in each harness (Open question 3).

**Detector:** gitleaks-compatible rules (provider prefixes such as `sk-ant-`, `sk-proj-`, `ghp_`, `github_pat_`, `xoxb-`, `AKIA`, `apify_api_`, plus JWTs and PEM blocks) plus an entropy check. False negatives are expected. That is why Path A is primary and B is only a net.

**Clipboard caveat:** clipboard managers (Raycast, Paste, Windows clipboard history) may retain the copy. The capture page avoids this.

**References in files:** `GITHUB_TOKEN=vault://github/pat` is safe to commit. `agent-vault run --env-file .env -- <cmd>` resolves it.

**Backfill:** `agent-vault scan` finds keys already leaked into harness history and transcripts, offers to vault them, and lists which to rotate.

---

## Harness adapters

`agent-vault install <harness>` backs up and edits configs using only documented extension points. `doctor` verifies the result. `uninstall` restores the backup.

| Concern | Claude Code | Codex | OpenCode | Any other |
|---------|-------------|-------|----------|-----------|
| Prompt capture (B) | `UserPromptSubmit`: block + `suppressOriginalPrompt: true` (**required**; otherwise `Original prompt:` is written to the transcript). Measured: `-p` leaves 1 transcript line, TUI leaves nothing | `UserPromptSubmit` in `hooks.json`: `{"decision":"block"}`. Hooks are on by default, but **must be trusted** (`/hooks` → `t`, stored as `[hooks.state.*] trusted_hash`); an untrusted hook is skipped and the prompt goes to the model | No prompt hook in 2.x. `session.context` + `session.title` (v2 plugin, `export default {id, setup}`) can redact or reject the outbound turn; stored text stays in `opencode.db` | — |
| Tool guard | `PreToolUse` (`updatedInput` can rewrite) | `PreToolUse` | `tool.execute.before` (docs name; in 2.1.4 the `tool.hook("execute.before")` name exists, not exercised) | — |
| Harness's own model key | `apiKeyHelper` → `agent-vault helper anthropic`. **Measured: the helper output is not exported to Bash tool or hook env** (a key in `ANTHROPIC_API_KEY` is) | `model_providers.<id>.auth.command` | Phase 2 base-URL proxy; MVP `run -- opencode` (T1 only) | `run --` |
| MCP server secrets | Wrap stdio servers: `command: agent-vault`, `args: [run, --bundle, x, --, <server>]` | Same; HTTP servers: `http_headers_helper` / `bearer_token_env_var` | Wrap local `command`; remote `headers` | Wrap |
| Shell env hygiene | Never put raw keys in harness env (`ANTHROPIC_API_KEY` reaches Bash and hooks) | `shell_environment_policy` | `shell.env` is **not in 2.1.4**; v2 `shell.hook` name unverified. Inject via `run --` for now | — |
| CLI to add an MCP server (S3, `--help` only) | `claude mcp add [-s user] [-t stdio\|sse\|http] [-e K=V] [-H "K: V"] <name> <cmdOrUrl> [args]` | `codex mcp add <name> (--url U [--bearer-token-env-var V] \| [--env K=V] -- <cmd>...)` | `opencode mcp add [--url U] [--header k=v] [--env k=v] [--global] <name> [-- <cmd>...]` | — |
| Proxy mode (phase 2) | `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS` | same | same | same |
| History scrub | transcript `projects/<proj>/<session>.jsonl` (`queue-operation.content`); `history.jsonl` is TUI-only and held nothing for a blocked prompt. Resume after scrub: OK | `history.persistence = "none"` removes the TUI residue entirely; otherwise `history.jsonl`, rollout, `state_5.sqlite`, `thread_history_1.sqlite` (+`-wal`). Resume after scrub: OK | `~/.local/share/opencode/opencode.db` (`session_message.data`) + `log/opencode.log` (argv). Resume after scrub: OK | — |

---

## Component design

### 1. Vault core (local)

- **Storage:** SQLite. Tables: `secrets`, `services`, `bundles`, `bundle_services`, `policies`, `sessions`, `audit_log`, `sync_state`, `devices`.
- **Crypto:** per-record XChaCha20-Poly1305, random 192-bit nonce.
  - **AAD** = `vault_id‖table‖record_id‖field‖version`. This stops row-swap and cross-record replay, which the tag alone does not.
- **Metadata needed while locked** (names, services, policies) stays plaintext but is **MAC'd** (HMAC-SHA-256 under a vault MAC key). Tampered rows are rejected.
- **Key hierarchy:**
  - **Device root key:** random 256-bit, stored via `@napi-rs/keyring`. Never written next to the DB.
  - **Vault data key:** generated at init, wrapped by the device root key.
  - **Recovery key:** 256-bit, shown once at `init` as words, and also wraps the vault data key. Without it, losing the keychain entry (OS reinstall, keyring reset) loses the vault.
  - **Per-bundle data keys:** **required before Phase 3**. Runners and scoped devices must not receive the whole vault key.
- **Unlock/lock:** the OS keyring unlocks at login, which keeps MVP friction at zero. Phase 2 adds a human-presence gate for admin ops so a same-user agent can't drive them.
- **Memory:** Node/V8 cannot guarantee zeroing because strings are immutable and the GC copies them.
  - Keep keys in `Buffer`s, `.fill(0)` on lock, and never stringify keys.
  - Secret values inevitably become strings in headers/env. Accept and document this.
  - A Rust core removes the caveat.

**Credential store, one library:**

| Library | Backends | Notes |
|---------|----------|-------|
| **`@napi-rs/keyring`** | macOS Keychain · Linux Secret Service · Windows Credential Manager | Active (v2.1.2, Oct 2026). API: `new Entry(service, account)` → `setPassword` / `getPassword` / `deletePassword`. Prebuilt for darwin/linux (gnu+musl)/win32 × x64/arm64 |
| ~~`keytar`~~ | — | **Archived** (repo archived Dec 2022). Do not use |
| Rust `keyring` crate | same three | If the core is ported to Rust |

**Linux setup:**
- `@napi-rs/keyring` **silently falls back to the kernel keyutils keyring** when Secret Service is absent. That keyring "will not persist across reboots", so the vault would be lost on reboot.
- **Always pin `{ linux: { store: 'secret-service' } }`.** If that throws, use the explicit headless fallback: an Argon2id passphrase-wrapped keyfile, logged as weaker.

### 2. Daemon (`vaultd`)

- **IPC:** JSON-RPC over:
  - Unix domain socket (macOS/Linux) in a `0700` per-user directory (`$XDG_RUNTIME_DIR` on Linux). Verify the peer uid.
  - Named pipe (Windows):
    - The default pipe DACL grants Everyone read, so **set an explicit DACL** for the user SID.
    - Use a per-user pipe name and `FILE_FLAG_FIRST_PIPE_INSTANCE` so another process cannot squat the name and impersonate vaultd.
    - Node `net` can't set a pipe DACL. That needs a native helper or the loopback-TCP+token fallback. **Spike.**
- **Responsibilities:** unlock lifecycle, policy enforcement, audit writes, capture page, sync engine, session issuance.
- **Service manager (one per OS, no admin):**

| Platform | Manager | Unit |
|----------|---------|------|
| macOS | launchd | `~/Library/LaunchAgents/com.agent-vault.daemon.plist` |
| Linux | systemd --user | `agent-vault.service`; start lazily, because Secret Service needs the login keyring unlocked |
| Windows | Task Scheduler at logon | **Not a Windows Service:** it needs admin and runs outside the user session, so it has no access to the user's Credential Manager |

Path handling goes through one `paths` module: XDG on Linux, `%LOCALAPPDATA%` on Windows, `~/Library/Application Support` on macOS. Never hardcode `/tmp` or `~/.local`.

### 3. CLI (`agent-vault`)

| Command | Notes |
|---------|-------|
| `init` | Create DB, generate keys, store root key in OS store, **print recovery key once** |
| `grab <name>` | Clipboard → vault → clear clipboard. Prints name + type + length only |
| `set <name>` | Reads from TTY (`/dev/tty` / `CONIN$`) or opens the capture page. **Never argv/env**. Refuses without a TTY |
| `list` / `rm` | Names + status, never values |
| ~~`get`~~ → `reveal` | **Not in MVP.** Phase 2: human-presence gate, TTY-only output |
| `import <.env>` / `migrate` | Move plaintext values → vault and rewrite them to `vault://` references (`.env`, `.mcp.json`, `~/.claude.json`, `~/.codex/config.toml`, `opencode.json`) |
| `scan` | Find keys already leaked into harness history/transcripts |
| `install` / `uninstall` / `doctor <harness>` | Harness adapters (see table above). `doctor codex` must prove the `UserPromptSubmit` hook is **trusted and fires** (probe canary blocked), not just present in `hooks.json`; rerun after Codex upgrades. Untrusted = silently skipped = fail-open |
| `run [--bundle] [--env-file] -- <cmd>` | Process injection with output redaction |
| `helper <service>` | Credential-helper output for harness model keys (`apiKeyHelper`, `auth.command`) |
| `service add` / `bundle create` / `grant` / `session create` | Admin ops; human-presence gate in Phase 2 |
| `audit` | Query logs (no values) |
| `sync` / `enroll` | Phase 3 / 4 |

### 4. MCP server

Tools the agent sees (metadata only):

| Tool | Returns |
|------|---------|
| `vault_list` | Names, bundle, permitted ops, configured/locked status |
| `vault_capture` | Starts a URL-mode elicitation to the capture page; returns the stored **name** only |
| `vault_status` | Locked/unlocked, session TTL, sync state |
| `vault_run` | Runs an **allowlisted** command bound to a bundle; returns redacted stdout/stderr |
| `vault_request` | (Phase 2) Vault makes an approved HTTP call on the agent's behalf |

**MCP spec constraint (2025-11-25):**
- Servers "MUST NOT use form mode elicitation to request sensitive information" and "MUST use URL mode" for it.
- If a client lacks URL mode, `vault_capture` returns the capture URL as text. The URL carries only a one-time nonce, never a secret.

### 5. Execution / injection

**A. Process injection (MVP, T1 only)**
`agent-vault run --bundle <b> -- <command>` spawns the process with the secret in a named env var.
- **Lock-down:** the agent chooses the command (for example `run -- printenv`), so:
  - Bundles bind to allowlisted executables (resolved absolute paths).
  - The vault **redacts known secret values** (raw, base64, URL-encoded) from child stdout/stderr.
- **Windows:** npm-installed CLIs are `.cmd` shims, and Node refuses to spawn those without a shell (CVE-2024-27980 fix). Use `cross-spawn`-style escaping. Never interpolate secrets into the command line.

**B. Network-boundary proxy (phase 2, gold standard)**
- **B1 base-URL mode first (no CA, no MITM):**
  - The vault serves plain HTTP on loopback per service (`GITHUB_API_URL`, `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` → `http://127.0.0.1:<port>/<service>`) and makes the TLS call upstream.
  - This also means the **harness never holds its own model key**.
- **B2 forward proxy** (`HTTPS_PROXY`) with TLS interception, for tools without a base-URL override:
  - **Trust the CA per process only** (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`), **never in the system store**. A stolen CA key would MITM all of the user's HTTPS.
  - Name-constrain the CA to allowlisted hosts. Keep the CA private key inside the vault.
  - Node's built-in `fetch` ignores `HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1` (Node 24+).
  - Clients that pin certificates fail, so pass them through.
- **Placeholders** (`__GITHUB_PAT__`) are substituted **only into the service template's auth slot** (header/basic/query param), **never into bodies**. Otherwise the agent could post `__GITHUB_PAT__` in an issue comment and the proxy would publish the real token.
- **Response scrubbing:** redact the secret value from responses and errors, since some endpoints echo headers.
- Enforce host/method/path policy **before** the request leaves.
- The session token travels in plaintext on loopback. That's fine locally, but a remote proxy needs TLS.

B makes credential exfiltration by prompt injection useless **only together with** the Phase 2 human-presence gate. Without the gate, the agent can drive vaultd's admin IPC itself.

### 6. Sync (phase 3)

- **Record-level sync only.** Each device has its own SQLite. Never sync the DB file.
- Payload: encrypted records + HLC version + tombstones + device signatures.
- **Ordering:** hybrid logical clock with a `device_id` tiebreak. A single integer `version` cannot order concurrent edits.
- **Security-state conflicts:** revocations, tombstones, and narrowing **win over widening**. Plain LWW could silently undo a revoke.
- **Enrollment:**
  - A new device's public key must be approved **on an existing unlocked device** with a short verification code (SAS).
  - The vault/bundle keys are then sent as an X25519 sealed box.
  - Without SAS, a malicious cloud can inject its own device key.
- **Rollback protection:** devices reject version regressions.
- **Cloud default: Cloudflare.** Durable Objects coordinate the device registry and sync; R2 holds encrypted blobs. Ciphertext is never decrypted in transit or inside CF.
- Each device keeps its own device root key. **A locked or logged-out machine cannot serve unattended cloud jobs** (see §7).

### 7. Cloud & remote runners (phase 4)

- **Enrollment:** the runner generates a keypair and registers it via the SAS flow above. It gets a device ID + scoped grants.
- **Remote runner:**
  - Holds its **own** wrapped keys and **only the per-bundle keys** it is granted (e.g. only `contract-search/apify`).
  - The cloud ships it bundle-scoped records only. It is not a mirror of the laptop vault.
- **Cloudflare:** Worker API (sync + session brokerage) + Durable Objects (per-vault coordination, lease/revocation state).
- **Revocation:** the DO pushes, or runners poll (default 60s, configurable 10–300s).

### 8. Audit

Append-only, **hash-chained** log: each entry carries an HMAC of the previous entry. That makes it tamper-evident, not tamper-proof, since a same-user process can still truncate it. Local first, then optionally synced as ciphertext:

```
{ ts, device_id, harness, actor, secret_name, bundle, operation, target_host,
  outcome: captured|brokered|blocked|error, request_id, prev_hmac }
```

**Never:** secret values, request/response bodies, Authorization headers.

---

## Security model

| Concern | Approach | Tier |
|---------|----------|------|
| Confidentiality at rest | AEAD per record; root key in OS credential store | T4 |
| Tampering / row swap | AEAD tag + AAD binding; HMAC on plaintext metadata | T4 |
| Key pasted into prompt | Capture Path A (primary); hook block (B) keeps it from the model, disk scrub best-effort | T1 |
| Plaintext in `.env` / harness configs | `import` / `migrate` → `vault://` references | T1 |
| Secrets in conversation | MCP returns names/status only; `run` output redacted | T1 |
| Secrets in process argv | Never: TTY/capture page for `set`; env injection only for the child | T1 |
| Agent drives vaultd IPC / CLI | Human-presence gate on admin ops + no `reveal` path for agents | T2, phase 2 |
| Agent reads child env (`run -- printenv`) | Allowlisted executables + output redaction; real fix is proxy mode | T1 now, T2 phase 2 |
| Prompt-injection exfil | Proxy mode: no credential in agent; policy limits blast radius | T2, phase 2 |
| Placeholder reflected into a body | Substitute only in the template auth slot | T2 |
| Upstream echoes credential | Response scrubbing | T2 |
| Local CA key theft | Per-process trust, name-constrained CA, key in vault | T2/T3 |
| IPC impersonation (pipe squatting) | Per-user `0700` socket dir; Windows DACL + first-instance flag | T3-lite |
| Audit tampering | Hash chain (evident, not proof) | T2 |
| Stolen session token | TTL + revocable + host/method/path scope | T2 |
| Live DB sync (WAL) | Forbidden: record-level sync | — |
| Lost keychain entry | Recovery key at `init` | — |
| Lost/stolen device | Remote revoke; other devices hold separate keys | T4 |
| Malicious cloud adds a device | SAS-verified enrollment on an existing device | T5 |
| Locked laptop + cloud job | Not supported by design: runners enroll with their own keys | — |

**Out of scope (matching Infisical's stated limits):** this is not a sandbox. Pair it with one if the agent must not touch other local resources. Same-user malware (T3) is out of scope.

---

## Concrete scenarios

**Paste (Claude Code, MVP):**
1. You paste `ghp_…` into the prompt.
2. The `UserPromptSubmit` hook detects it, stores it as `github/pat`, and **blocks** the prompt. The key never reaches the model.
3. The hook replies: "Stored as `github/pat`. Re-send using `vault://github/pat`."
4. On `Stop`, the scrubber removes the key from the transcript and `~/.claude/history.jsonl`. Audit records `captured`.
5. The secret is tagged `exposed-locally`. `agent-vault list` suggests rotation.

**Apify collector:**
1. `agent-vault grab contract-search/apify` (copied from the Apify console, never typed into chat).
2. Agent sees: `contract-search/apify` exists, bundle `collector`, permission `api.apify.com`, **configured**.
3. You grant `collector` → `apify` with limits: POST `/acts/...` only, request-count cap.
   - **Spend caps live at the provider:** a scoped Apify token or account limits. A generic proxy can't price requests.
4. The agent runs. The vault injects or proxies the token. The agent gets job results + redacted errors.
5. Audit: `agent X (claude-code) used contract-search/apify for POST api.apify.com at T`.

**Prefer provider-scoped tokens** (fine-grained GitHub PATs, scoped API keys). Least privilege at the source beats proxy policy.

---

## Phased roadmap

| Phase | Deliverable | Why this order |
|-------|-------------|----------------|
| **0. Spikes (1 wk)** | 1) Node SEA + native addons on all 3 OSes. 2) Windows pipe DACL from Node. 3) Per harness: what a blocked prompt leaves on disk, and is scrub safe? | De-risk before building |
| **1. MVP** | Vault core + recovery key + capture (A, B for Claude Code & Codex, C) + `install`/`migrate`/`scan` for Claude Code, Codex, OpenCode + MCP + `run` with redaction + hash-chained audit | Kills paste/.env leaks (T1). Usable as the default keystore on day one |
| **2. Proxy + gate** | Base-URL proxy → forward proxy; sessions; host/method/path policy; human-presence gate on admin ops; `reveal` | T2 resistance without any cloud |
| **3. Sync** | Per-bundle keys, record-level encrypted sync, SAS enrollment, revocation | Laptop ↔ desktop |
| **4. Cloud** | Cloudflare Workers + Durable Objects + enrolled runners with scoped bundles | Unattended jobs without unlocking your laptop |
| **5. Hardening** | Dynamic secrets / leases (Vault-style), cert auth for devices, SIEM export | Production-grade |

---

## Stack recommendation

| Layer | Choice | Tradeoff |
|-------|--------|----------|
| Runtime | **Node 24 LTS** (Node 20 reached EOL 2026-04-30) | MCP + Cloudflare are TS-native. **Alt:** Rust core for real memory zeroing and no native-addon packaging pain; slower MVP |
| Crypto | `libsodium-wrappers` or `@noble/ciphers` (XChaCha20-Poly1305), behind a thin `packages/crypto` | Swap-able for a Rust port |
| SQLite | `better-sqlite3` (native addon); evaluate built-in `node:sqlite` in the spike to drop one addon | Native addons complicate SEA |
| OS credential store | **`@napi-rs/keyring`** (pin Linux store) | One API → Keychain / Secret Service / Cred Manager |
| Secret detection | gitleaks-compatible rule set + entropy | Shared by hook, `scan`, `migrate`, redaction |
| MCP | `@modelcontextprotocol/sdk`, URL-mode elicitation | Needs spec 2025-11-25 clients for in-harness capture |
| Proxy | Custom loopback reverse proxy (B1); CONNECT + per-process CA (B2) | B2 needs TLS interception |
| Cloud | **Cloudflare Workers + Durable Objects + R2** | DOs fit lease/revocation state |
| Monorepo | pnpm workspaces: `core`, `crypto`, `daemon`, `cli`, `mcp`, `proxy`, `detect`, `adapters` (claude-code, codex, opencode), `cloud`, `platform` | `platform` = paths/IPC/service only |
| Packaging | **Node SEA** binaries + Homebrew tap, deb/rpm, winget/MSI. ~~`pkg`~~ (archived Jan 2024), ~~`nexe`~~ (still beta) | **SEA can't embed native addons directly.** Ship `.node` files beside the binary or extract at runtime. Spike first |

---

## Cross-platform matrix

| Concern | macOS | Linux | Windows |
|---------|-------|-------|---------|
| Credential store | `@napi-rs/keyring` (signed binary for a stable ACL) | same, **pinned to `secret-service`**; Argon2id keyfile if absent | same |
| Daemon IPC | Unix socket in `0700` dir | Unix socket in `$XDG_RUNTIME_DIR` | Named pipe, explicit DACL, per-user name, first-instance |
| Paths | `~/Library/Application Support/agent-vault` | `$XDG_DATA_HOME/agent-vault` | `%LOCALAPPDATA%\agent-vault` |
| Service manager | launchd LaunchAgent | systemd `--user` (lazy start) | Task Scheduler at logon |
| Env injection | child env | child env | child env; `.cmd` shims need careful escaping |
| Proxy CA trust | **Per-process env only** | **Per-process env only** | **Per-process env only** |
| Tests | CI matrix: `macos-latest`, `ubuntu-latest`, `windows-latest` | same | same |

**Rules that keep this honest:**
1. The credential store is **one dependency**. Never fork it. `packages/platform` isolates **paths, IPC, and service install** only.
2. Never assume `/tmp`, `~/.local`, or `:` path separators.
3. CI runs the full suite on all three OSes before merge.
4. Secrets in a child env are acceptable for T1. Never write them to disk or argv.
5. Never install a CA into a system trust store.

---

## What we deliberately copy vs. invent

| From Infisical | From HashiCorp Vault | Our own |
|----------------|----------------------|---------|
| Access bundles, sessions, service auth templates | Seal/unseal (cred-store lib, not Shamir for v1) | Local-first SQLite as SoT |
| Forward proxy + placeholder substitution | Leases + revocation (TTL) | Paste capture (out-of-band + prompt hook) |
| Session logs without values (brokered/blocked/error) | Audit devices (append-only) | Harness config migration (`migrate`, `install`) |
| Machine identity for unattended agents | Dynamic secrets (phase 5) | Record-level encrypted sync + CF Durable Objects |
| Traffic policy ("access bundle hosts only") | Transit / EaaS (later) | Base-URL proxy mode (no CA needed) |

---

## Open questions

1. **Name collision:** "agent-vault" vs. Infisical's "Agent Vault" product. Rename before any public release?
2. **OpenCode prompt capture:** no documented prompt hook. Research plugin `message.*` events, or upstream a PR.
3. **Upstream asks (the only airtight fix for Path B):** a prompt-rewrite/redaction hook in Claude Code, Codex, and OpenCode. File feature requests once the MVP proves demand.
4. **Human-presence mechanism:**
   - OS biometrics (Touch ID / Windows Hello / polkit) means per-OS code.
   - A local approval page has no per-OS code, but an agent with browser automation can click it.
   - Pick per platform in Phase 2.
5. **Single-user vs. team:** v1 is single-user multi-device. Team/org is Infisical's job. Don't compete yet.
6. **Dynamic secrets:** out of MVP; Vault-style lease/issue is phase 5.

---

## References

- Infisical Agent Vault — https://infisical.com/platform/agent-vault (primitives, supported harnesses, `NODE_USE_ENV_PROXY`, limits)
- Infisical security / key hierarchy — https://infisical.com/docs/internals/security
- Claude Code hooks (`UserPromptSubmit`, `suppressOriginalPrompt`, "What a blocked prompt leaves behind") — https://code.claude.com/docs/en/hooks
- Codex config reference (`shell_environment_policy`, `auth.command`, `http_headers_helper`, `history.persistence`) — https://learn.chatgpt.com/docs/config-file/config-reference
- Codex hooks — https://learn.chatgpt.com/docs/hooks
- OpenCode config / MCP / plugins (`{env:}`, `{file:}`, `shell.env`, `tool.execute.before`) — https://opencode.ai/docs/config/ · https://opencode.ai/docs/mcp-servers/ · https://opencode.ai/docs/plugins/
- MCP elicitation, URL mode (spec 2025-11-25) — https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation
- `@napi-rs/keyring` (Linux backend selection) — https://github.com/Brooooooklyn/keyring-node
- HashiCorp Vault — https://www.vaultproject.io/
- SQLite WAL — https://sqlite.org/wal.html
- Libsodium AEAD — https://doc.libsodium.org/secret-key_cryptography/aead
