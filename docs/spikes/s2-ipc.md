# Spike S2: local IPC access control

Status: **done**. Code: `spikes/s2-ipc/` (throwaway). CI: `.github/workflows/spike-s2.yml`.

Run with every number below (macOS, Linux, Windows all green):
https://github.com/MagnetonIO/agent-vault/actions/runs/40439676232
(The pipe sections come from the same harness; the first full run, 40438281968, shows identical pipe results.)

## Decision

| OS | `ipcEndpoint()` kind | Access control |
|----|----------------------|----------------|
| macOS | `unix` | Socket in a `0700` dir owned by the user. The dir is the access control |
| Linux | `unix` | Same. Dir under `$XDG_RUNTIME_DIR`, see "Socket location" |
| Windows | **`tcp`** | `127.0.0.1:<random port>`, **mutual** HMAC handshake on a per-start token, token+port in an `icacls`-locked file |

`pipe` stays in the `IpcEndpoint` type but **no OS returns it**. Reserved for a future native helper that can set a DACL and use `FILE_FLAG_FIRST_PIPE_INSTANCE`.

Why not a Windows pipe (measured, not assumed):

1. A plain Node `net` pipe gets the default DACL: SYSTEM, Administrators and the creator get full control, **Everyone and ANONYMOUS LOGON get read**. `net` has no option to change it.
2. Another user cannot send commands (InOut and Out connects were denied), but **can open it read-only** (In connect succeeded). It can hold instances open, and would see anything the server writes unprompted.
3. **A client cannot tell who owns the pipe.** With vaultd not running, a second user created the pipe name with an Everyone-full DACL, and this user's client connected to the impostor and got the impostor's reply. Node's `listen()` fails closed against a squatter (see Q2), but the CLI is the one that sends secrets.
4. TCP with a **mutual** handshake closes 3. The token never crosses the wire, the client sends nothing but a nonce until the server proves it knows the token. The port is visible to every local user in `netstat -ano`, so its secrecy is not relied on. Measured: a squatter holding the stale port saw 65 bytes (the nonce line) and no payload.
5. A random pipe name plus the same mutual handshake was still rejected: the pipe's DACL grants Everyone and ANONYMOUS LOGON read and Node cannot change it, so any user can still open the pipe and hold instances, and the CLI demonstrably reached the impostor. TCP gives the same identity proof with a smaller exposure (a handshake-gated port) and an OS-level file ACL for the secret.

Doc correction: `docs/design.md` says "Verify the peer uid". **Pure Node cannot do that** (Q4). On POSIX the `0700` dir is the control. On Windows the token is.

## Evidence (CI run above)

| Question | macOS (arm64, node 24.22.1) | Linux (x64, node 24.21.0) | Windows (x64, node 24.22.1) |
|----------|------|------|------|
| Q1 pipe DACL (plain Node pipe) | n/a | n/a | SDDL `O:LAG:...D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)(A;;FR;;;WD)(A;;FR;;;AN)`. **Everyone: read. ANONYMOUS LOGON: read.** Neither has write or create-instance |
| Q1 second user vs that pipe | n/a | n/a | InOut **denied**, Out **denied**, In (read-only) **connected** |
| Q1 `Get-Acl` on the pipe path | n/a | n/a | **Fails**: `Method failed with unexpected error code 87`. Two other methods worked (see Commands) |
| Q2 Node 2nd `listen()` on a live name | `EADDRINUSE` | `EADDRINUSE` | `EADDRINUSE` |
| Q2 order A: vaultd first, same-user squatter | n/a | n/a | .NET `NamedPipeServerStream` **created** an instance (same user is trusted) |
| Q2 order A: vaultd first, other-user squatter | n/a | n/a | **Create failed**: `Access to the path is denied` |
| Q2 order B: squatter first, same user, then vaultd `listen()` | n/a | n/a | `EADDRINUSE` |
| Q2 order B: squatter first, other user, Everyone-full DACL, then vaultd `listen()` | n/a | n/a | `EADDRINUSE`. vaultd never shares instances |
| Q2 order B: same squatter, CLI connects with vaultd down | n/a | n/a | **Reached the impostor** (`SQUAT`) |
| Q2 AF_UNIX path via Node on Windows | n/a | n/a | `listen(C:\...\x.sock)` -> `EACCES`. Not usable |
| Q2 POSIX second `listen()` on a live socket | `EADDRINUSE` | `EADDRINUSE` | n/a |
| Q2 POSIX stale socket file after `SIGKILL` | file stays, `listen` -> `EADDRINUSE`, `connect` -> `ECONNREFUSED`, unlink then `listen` ok | same | n/a |
| Q3 TCP bind | n/a | n/a | `127.0.0.1:0` ok (e.g. port 52242) |
| Q3 `icacls` on the token dir, step 1 only (`/inheritance:r /grant:r`) | n/a | n/a | principals still `SYSTEM`, `Administrators`, user (they are explicit ACEs, no `(I)` in the listing before the command) |
| Q3 `icacls` on the token dir after all three commands | n/a | n/a | only `runneradmin:(OI)(CI)(F)` |
| Q3 `icacls` on the token file | n/a | n/a | only `runneradmin:(F)` |
| Q3 mutual handshake, right token | n/a | n/a | server mac verified, payload echoed |
| Q3 client holding a wrong token | n/a | n/a | `vaultd identity check failed`, **0 payload bytes sent** |
| Q3 attacker without token: bogus client mac / server mac reflected back | n/a | n/a | server closes, 0 bytes (both) |
| Q3 JSON-RPC as first line / 63-char nonce | n/a | n/a | closed, 0 bytes |
| Q3 silent client / 4096 bytes, no newline | n/a | n/a | closed by the 1500 ms timer / at the 128-byte cap |
| Q3 second user reads control file (default ACL) | n/a | n/a | `READ OK` (proves the test can fail) |
| Q3 second user reads `icacls`-locked file | n/a | n/a | **`DENIED`** |
| Q3 second user sees and connects to the port | n/a | n/a | `netstat -ano` as that user lists `127.0.0.1:52242 LISTENING`; connect works; wrong first line gets 0 bytes and a close |
| Q3 order A: vaultd listening, same-user Node `listen()` on the same `127.0.0.1:port` | n/a | n/a | `EADDRINUSE` |
| Q3 order A: same-user .NET listener with `SO_REUSEADDR` | n/a | n/a | bind **refused**: `forbidden by its access permissions` (the socket is effectively exclusive) |
| Q3 order A: other user, plain / with `SO_REUSEADDR` | n/a | n/a | `Only one usage of each socket address` / `forbidden by its access permissions`. Port cannot be shared or hijacked while vaultd listens |
| Q3 order B: vaultd gone, stale `endpoint.json`, Node squatter replies `ok\n` | n/a | n/a | CLI: `vaultd identity check failed`, 0 payload bytes. Squatter received **65 bytes** (nonce + newline) |
| Q3 order B: same, squatter replies with a plausible fake mac+nonce line | n/a | n/a | same: refused, 0 payload bytes, 65 bytes received |
| Q3 order B: squatter is another user (`avspike2`) | n/a | n/a | same: refused, squatter log `first=65 after=0` |
| Q4 dir after `mkdir(mode 0700)` | `0700` | `0700` | n/a |
| Q4 socket mode after `listen()`, umask 022 / 077 / 000 | `0755` / `0700` / `0777` | `0755` / `0700` / `0777` | n/a |
| Q4 `chmod(sock, 0600)` | `0755` -> `0600`, owner still connects | same | n/a |
| Q4 `listen({readableAll, writableAll})` | socket `0666` | `0666` | n/a |
| Q4 other user (`sudo -u nobody`), socket `0777` inside `0700` dir | **refused** (`nc -U` exit 1) | **`EACCES`** | n/a |
| Q4 same, dir widened to `0755` (control) | `CONNECTED` | `CONNECTED` | n/a |
| Q4 dir pre-created by another user (mode `0777`) | check `uid==me && mode&077==0` says unsafe | same | n/a |
| Q4 max socket path accepted by `listen()` | **104** bytes (105 -> `EINVAL`) | **108** bytes (109 -> `EINVAL`) | n/a |
| Q4 path with 93 chars but 113 UTF-8 bytes | `EINVAL` (limit is bytes) | `EINVAL` | n/a |
| Q4 dir resolution: Linux with `XDG_RUNTIME_DIR` set / unset, macOS-style home | listen ok in all three, dir `0700`, owned by me | same | n/a |
| Q4 over-length path -> hashed fallback `<tmpdir>/av-<uid>/<hash>.sock` | listen ok, dir `0700`, 77 bytes (macOS `$TMPDIR` is long) | listen ok, dir `0700`, 34 bytes | n/a |
| Q4 fallback dir pre-created by `nobody` with mode `0777` | **refused** (`unsafe ipc dir`, owner uid 4294967294) | **refused** (owner uid 65534) | n/a |
| Q4 peer-credential API | none | none | n/a |

Peer credentials (Q4): a scan of 181-183 property names across `net`, `Server`, `Socket` and its `_handle` finds no uid/gid/pid/cred accessor. The only hit is the private `_getpeername()`, which returns `{}` for a unix socket. The scan is supporting evidence only; the conclusion also rests on Node's public docs, which list no `SO_PEERCRED`/`getpeereid` binding. Real peer-uid verification needs a native addon.

## Mutual handshake (Windows TCP)

Required, not optional (ruling after review). The token is 32 random bytes, hex-encoded (64 lowercase hex chars), **regenerated at every daemon start** and never sent on the wire. All lines are ASCII ending in `\n`. `HMAC` is HMAC-SHA256 keyed with the 32 raw token bytes; the message is the ASCII label followed by the ASCII hex nonce.

| Step | Direction | Bytes |
|------|-----------|-------|
| 1 | client -> server | `nonce_c\n`, 32 random bytes as 64 hex |
| 2 | server -> client | `HMAC("srv" + nonce_c)` as 64 hex, a space, `nonce_s` (32 random bytes, 64 hex), `\n` |
| 3 | client | verifies the mac with `timingSafeEqual`. **Sends nothing else until it matches.** On mismatch, a malformed line, or no line within 2500 ms: close the socket and fail with `"vaultd identity check failed"` |
| 4 | client -> server | `HMAC("cli" + nonce_s)` as 64 hex, `\n`. JSON-RPC lines may follow immediately |
| 5 | server | verifies with `timingSafeEqual`. On mismatch: close, no reply, nothing served |

Server limits: each line at most 128 bytes, each step must complete within 1500 ms, else `socket.destroy()` with no reply. The `srv` and `cli` labels stop a server mac being replayed as a client mac (tested: reflected mac is rejected).

Daemon lifecycle:

1. Generate a fresh token. `listen({ host: '127.0.0.1', port: 0 })`. Read the port from `server.address()`.
2. Lock the dir, then write `{"host":"127.0.0.1","port":<n>,"token":"<hex>"}\n` to `endpoint.json` (temp file + rename), only after `listen()` resolved.
3. Delete `endpoint.json` on clean exit.

Client lifecycle: read `endpoint.json` (missing means the daemon is not running), connect, run the handshake, then send requests. A crash leaves a stale file; the next daemon start overwrites it with a new port and token.

Reference implementation: `createMutualServer`, `mutualConnect` (client) and `attack` (token-less attacker) in `spikes/s2-ipc/lib.mjs`.

What this does and does not give: any process that can read `endpoint.json` is the user (or an admin) and can talk to vaultd. A process that cannot read it can neither authenticate nor impersonate vaultd, even if it sits on the right port. It does not hide the port, does not stop a local user from opening connections that are then dropped after the timeouts, and does not authenticate individual requests after the handshake.

## Socket location (macOS, Linux)

All through `getPaths()` `runtimeDir`. Prototype: `spikes/s2-ipc/paths.mjs` (`dirsFor`, `ensurePrivateDir`, `resolveSocket`).

| OS | `runtimeDir` | Socket |
|----|--------------|--------|
| Linux | `$XDG_RUNTIME_DIR/agent-vault`; when `XDG_RUNTIME_DIR` is unset: `$dataDir/run` (`$XDG_DATA_HOME/agent-vault/run`, default `~/.local/share/agent-vault/run`) | `<runtimeDir>/vaultd.sock` |
| macOS | `~/Library/Application Support/agent-vault/run` | `<runtimeDir>/vaultd.sock` |

`AGENT_VAULT_HOME` overrides `dataDir`, so it moves `runtimeDir` too (except the Linux `XDG_RUNTIME_DIR` branch). Create with `ensurePrivateDir()` (mode `0700`, then `lstat`: real directory, owned by this uid, no group/other bits; otherwise throw).

**Length rule: the UTF-8 byte length of the socket path must be at most 103 on macOS and at most 107 on Linux** (`sizeof(sun_path)` minus the NUL; measured hard limits are 104 and 108, one byte more). It is bytes, not characters: a 93-character path that is 113 bytes gets `EINVAL`.

- A default macOS path is `/Users/<name>/Library/Application Support/agent-vault/run/vaultd.sock` = 63 bytes + the username. On the macOS runner (`/Users/runner`) that is 69 bytes. The longest username that fits is 40 bytes.
- Over the limit: fall back to `<os.tmpdir()>/av-<uid>/<first 16 hex of sha256(runtimeDir)>.sock`. `os.tmpdir()` is `$TMPDIR` on macOS (user-private, about 49 chars, giving 77 bytes measured) and `/tmp` on Linux (34 bytes measured). The `av-<uid>` dir goes through the same `ensurePrivateDir()` check. Its name is predictable, so if another user pre-created it, `ensurePrivateDir()` throws and the daemon does not start (fail closed). Measured with a `0777` dir owned by `nobody`. If even the fallback is too long, error out naming both paths.
- The client must use the same `resolveSocket()` call so both sides compute the same path.
- Linux with `XDG_RUNTIME_DIR` unset is exercised in CI by passing `env: {}` and a temporary `HOME`, then really listening there. `XDG_RUNTIME_DIR` itself is not unset in the runner process.

## Commands later tasks must reuse

Windows token dir and file. Run in this order, dir first, so the file is created inside an already locked dir. These are exactly the commands CI ran (`lockDir` and `lockFile` in `spikes/s2-ipc/win-tcp.mjs`):

```bat
icacls "%LOCALAPPDATA%\agent-vault\run" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"
icacls "%LOCALAPPDATA%\agent-vault\run" /remove *S-1-5-18
icacls "%LOCALAPPDATA%\agent-vault\run" /remove *S-1-5-32-544
:: then, after writing endpoint.json:
icacls "%LOCALAPPDATA%\agent-vault\run\endpoint.json" /inheritance:r /grant:r "%USERNAME%:F"
```

- `*S-1-5-18` is SYSTEM and `*S-1-5-32-544` is Administrators. Use the SIDs, not names: the names are localized.
- **Why the two `/remove` lines exist.** On the new dir, the `SYSTEM` and `Administrators` ACEs are *explicit*, not inherited: the listing before any change shows them with no `(I)` flag, while inherited ACEs elsewhere in the same run do show `(I)`. `/inheritance:r` only removes inherited ACEs, so after step 1 CI printed `["NT AUTHORITY\\SYSTEM","BUILTIN\\Administrators","runnervmdaln5\\runneradmin"]` (`icacls-localappdata-after-step1`). After the two removes it printed only the user (`icacls-localappdata-after-step3`). The file needed only its own `/inheritance:r /grant:r`.
- Verify by parsing `icacls <path>` output and assert the only principal is the current user. `win-tcp.mjs` does this and fails the job otherwise.
- A bare `%USERNAME%` worked on the runner's local account. **Domain or Entra-joined accounts are untested**; use the `whoami /user` SID form (`*S-1-5-21-...`) if that matters.
- Administrators and SYSTEM can still take ownership. Removing their ACEs is hygiene, not a boundary.

POSIX:

```js
const { path: sockPath, dir } = resolveSocket();   // see "Socket location"
ensurePrivateDir(dir);                              // mkdir 0700, then lstat: dir, my uid, mode&077==0
// stale socket: probe first, unlink only if connect() gets ECONNREFUSED
server.listen(sockPath);
fs.chmodSync(sockPath, 0o600); // belt and braces; the dir is the control
```

Pipe ACL inspection (only needed if `pipe` is ever revived). `Get-Acl` fails with error 87. These worked, from Windows PowerShell 5.1 (`scripts/acl-dump.ps1`):

- P/Invoke `CreateFileW(pipe, READ_CONTROL=0x20000, share=7, OPEN_EXISTING=3)` then `GetSecurityInfo(handle, SE_KERNEL_OBJECT=6, 7, ...)` then `ConvertSecurityDescriptorToStringSecurityDescriptor`.
- `NamedPipeClientStream('.', name, [PipeAccessRights]'ReadData,ReadPermissions', ...)` then `.GetAccessControl()`. `ReadPermissions` alone throws "pipe direction" (the ctor derives direction from the rights).

CI recipe for a second local user (Windows): `net user avspike2 <password up to 14 chars> /add`, then `Start-Process -Credential` (`scripts/as-other.ps1`). A longer password makes `net user` stop on a Y/N prompt and silently not create the user. This cost one CI run.

## Pitfalls

1. **Same-user processes are inside the boundary.** Any process running as the user can read the socket dir or `endpoint.json`. That is why the design needs the human-presence gate for agents that run as the user.
2. **Admin and SYSTEM are inside the boundary too.** They had full control on every ACL here.
3. **The port is not secret.** `netstat -ano` as another user lists the listening port (measured). Security rests on the mutual handshake and the unreadable token, not on hiding the port. Nothing is sent to a peer until it proves it knows the token.
4. **Write the endpoint file only after `listen()` resolves.** A stale file from a crash points at a dead port. Treat `ECONNREFUSED` as "not running" and overwrite.
5. **Bind `127.0.0.1`, not `localhost`.** Avoids `::1` and resolver surprises.
6. **The loopback port is open to every local user, and to browsers.** The handshake is the only gate. A JSON-RPC line as the first line is closed with no reply (tested; not tested with a real browser).
7. **Per Node's docs, `fs` modes do not set Windows ACLs.** Do not rely on `writeFile({ mode })` or `chmod` there. Not re-tested here.
8. **The Windows runner is atypical.** Its user is the built-in Administrator with an elevated token, so the creator ACE showed as `LA`. For a standard user the creator ACE should be that user. Not measured.
9. **Remote pipe access is unresolved.** A same-user connect through `\\localhost\pipe\...` succeeded, but that may be a local shortcut, so it does not show whether remote SMB clients are rejected.
10. **POSIX socket path limit** is in UTF-8 bytes: rule and fallback in "Socket location".
11. **POSIX socket mode follows the umask** (`0777 & ~umask`; default `0755`), and there is a short window before any `chmod`. The `0700` dir covers it. Never pass `readableAll` or `writableAll`.
12. **Do not unlink a live socket.** `listen()` on an existing path gives `EADDRINUSE` even when stale. Probe with `connect()` first.
13. **Do not put the POSIX dir in a shared parent without the `lstat` ownership check.** `mkdir({ recursive: true })` does not complain about an existing dir (Node semantics, not re-tested), so a dir pre-created by another user would be accepted. The check above catches it (tested with a `0777` dir owned by `nobody`).
14. **Linux and macOS other-user tests used `sudo -u nobody`.** macOS's hosted node lives in a user-only dir, so that leg used `/usr/bin/nc -U`. Both had a passing control (dir widened to `0755` -> connects).
