# Spike S2: local IPC access control

Status: **done**. Code: `spikes/s2-ipc/` (throwaway). CI: `.github/workflows/spike-s2.yml`.

Run with every number below (macOS, Linux, Windows all green):
https://github.com/MagnetonIO/agent-vault/actions/runs/40438281968

## Decision

| OS | `ipcEndpoint()` kind | Access control |
|----|----------------------|----------------|
| macOS | `unix` | Socket in a `0700` dir owned by the user. The dir is the access control |
| Linux | `unix` | Same. Dir under `$XDG_RUNTIME_DIR` |
| Windows | **`tcp`** | `127.0.0.1:<random port>`, first-line token, token+port in an `icacls`-locked file |

`pipe` stays in the `IpcEndpoint` type but **no OS returns it**. Reserved for a future native helper that can set a DACL and use `FILE_FLAG_FIRST_PIPE_INSTANCE`.

Why not a Windows pipe (measured, not assumed):

1. A plain Node `net` pipe gets the default DACL: SYSTEM, Administrators and the creator get full control, **Everyone and ANONYMOUS LOGON get read**. `net` has no option to change it.
2. Another user cannot send commands (InOut and Out connects were denied), but **can open it read-only** (In connect succeeded). It can hold instances open, and would see anything the server writes unprompted.
3. **A client cannot tell who owns the pipe.** With vaultd not running, a second user created the pipe name with an Everyone-full DACL, and this user's client connected to the impostor and got the impostor's reply. Node's `listen()` fails closed against a squatter (see Q2), but the CLI is the one that sends secrets.
4. TCP+token closes 3: the port is only discoverable from a file the other user cannot read.

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
| Q3 TCP bind | n/a | n/a | `127.0.0.1:0` ok (e.g. port 50027) |
| Q3 `icacls` on token file | n/a | n/a | only `runneradmin:(F)` remains. Dir needed one extra step (see Commands) |
| Q3 right token | n/a | n/a | `ok\n`, then JSON-RPC echoed |
| Q3 wrong token / 63-char token / JSON-RPC as first line | n/a | n/a | closed, 0 bytes back (all three) |
| Q3 silent client | n/a | n/a | closed by the 1500 ms timer |
| Q3 4096 bytes, no newline | n/a | n/a | closed at the 128-byte cap |
| Q3 second user reads control file (default ACL) | n/a | n/a | `READ OK` (proves the test can fail) |
| Q3 second user reads `icacls`-locked file | n/a | n/a | **`DENIED`** |
| Q3 second user connects to the TCP port | n/a | n/a | connects, wrong token, server closes (port is open to all local users, so the token is the only gate) |
| Q4 dir after `mkdir(mode 0700)` | `0700` | `0700` | n/a |
| Q4 socket mode after `listen()`, umask 022 / 077 / 000 | `0755` / `0700` / `0777` | `0755` / `0700` / `0777` | n/a |
| Q4 `chmod(sock, 0600)` | `0755` -> `0600`, owner still connects | same | n/a |
| Q4 `listen({readableAll, writableAll})` | socket `0666` | `0666` | n/a |
| Q4 other user (`sudo -u nobody`), socket `0777` inside `0700` dir | **refused** (`nc -U` exit 1) | **`EACCES`** | n/a |
| Q4 same, dir widened to `0755` (control) | `CONNECTED` | `CONNECTED` | n/a |
| Q4 dir pre-created by another user (mode `0777`) | check `uid==me && mode&077==0` says unsafe | same | n/a |
| Q4 max socket path accepted by `listen()` | **104** chars (105 -> `EINVAL`) | **108** chars (109 -> `EINVAL`) | n/a |
| Q4 peer-credential API | none | none | n/a |

Peer credentials (Q4): a scan of 181-183 property names across `net`, `Server`, `Socket` and its `_handle` finds no uid/gid/pid/cred accessor. The only hit is the private `_getpeername()`, which returns `{}` for a unix socket. The scan is supporting evidence only; the conclusion also rests on Node's public docs, which list no `SO_PEERCRED`/`getpeereid` binding. Real peer-uid verification needs a native addon.

## Token handshake (Windows TCP)

Server:

1. Generate `token = randomBytes(32).toString('hex')` (64 lowercase hex chars) at every daemon start.
2. `listen({ host: '127.0.0.1', port: 0 })`. Read the port from `server.address()`.
3. Write `{"host":"127.0.0.1","port":<n>,"token":"<hex>"}\n` to `endpoint.json` (temp file + rename), after the dir is locked down.
4. On each connection, buffer bytes until the first `\n`:
   - Match: `timingSafeEqual(line, token)` with equal length -> write `ok\n`, then JSON-RPC lines flow.
   - Mismatch, wrong length, no newline within **128 bytes**, or no line within **1500 ms** -> `socket.destroy()`. **No reply of any kind.**
5. Delete `endpoint.json` on clean exit.

Client:

1. Read `endpoint.json`. Missing file means the daemon is not running.
2. Connect to `host:port`. First write is exactly `<token>\n`.
3. Expect `ok\n`. Anything else, or a close, is a failure.
4. Then send JSON-RPC lines.

Reference implementation: `createTokenServer` and `exchange` in `spikes/s2-ipc/lib.mjs`.

## Commands later tasks must reuse

Windows token dir and file (run in this order; the dir first, so the file inherits only the user):

```bat
icacls "%LOCALAPPDATA%\agent-vault\run" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"
icacls "%LOCALAPPDATA%\agent-vault\run\endpoint.json" /inheritance:r /grant:r "%USERNAME%:F"
```

- **On the dir, those two flags were not enough.** `icacls` still listed `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` on the dir afterwards (cause not determined; they showed as explicit ACEs even before). `win-tcp.mjs` therefore re-lists with `icacls <dir>` and runs `icacls <dir> /remove "<principal>"` for every principal that is not the user. After that, only the user remained, on both dir and file.
- The file ended up user-only straight from `/inheritance:r /grant:r`.
- Verify by parsing `icacls <path>` output. A bare `%USERNAME%` worked on the runner's local account. **Domain or Entra-joined accounts are untested**; use `whoami /user` SID form (`*S-1-5-21-...`) if that matters.

POSIX:

```js
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
const st = fs.lstatSync(dir);
if (!st.isDirectory() || st.uid !== process.getuid() || (st.mode & 0o077) !== 0) throw new Error('unsafe ipc dir');
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
3. **The handshake is one-way.** The server never proves it knows the token. A process that bound a stale port could reply `ok`. The attacker would have to guess the port, since the file is unreadable to them. If this matters, add an HMAC challenge (server sends nonce, client answers `HMAC(token, nonce)`). Not built or tested here.
4. **Write the endpoint file only after `listen()` resolves.** A stale file from a crash points at a dead port. Treat `ECONNREFUSED` as "not running" and overwrite.
5. **Bind `127.0.0.1`, not `localhost`.** Avoids `::1` and resolver surprises.
6. **The loopback port is open to every local user, and to browsers.** The token line is the only gate. A JSON-RPC line or an HTTP request as the first line is closed with no reply (tested with a JSON-RPC line, not with a real browser).
7. **Per Node's docs, `fs` modes do not set Windows ACLs.** Do not rely on `writeFile({ mode })` or `chmod` there. Not re-tested here.
8. **The Windows runner is atypical.** Its user is the built-in Administrator with an elevated token, so the creator ACE showed as `LA`. For a standard user the creator ACE should be that user. Not measured.
9. **Remote pipe access is unresolved.** A same-user connect through `\\localhost\pipe\...` succeeded, but that may be a local shortcut, so it does not show whether remote SMB clients are rejected.
10. **POSIX socket path limit:** 104 chars on macOS, 108 on Linux (measured). A long home path on macOS can exceed it. Check length at startup and fail with a clear message.
11. **POSIX socket mode follows the umask** (`0777 & ~umask`; default `0755`), and there is a short window before any `chmod`. The `0700` dir covers it. Never pass `readableAll` or `writableAll`.
12. **Do not unlink a live socket.** `listen()` on an existing path gives `EADDRINUSE` even when stale. Probe with `connect()` first.
13. **Do not put the POSIX dir in a shared parent without the `lstat` ownership check.** `mkdir({ recursive: true })` does not complain about an existing dir (Node semantics, not re-tested), so a dir pre-created by another user would be accepted. The check above catches it (tested with a `0777` dir owned by `nobody`).
14. **Linux and macOS other-user tests used `sudo -u nobody`.** macOS's hosted node lives in a user-only dir, so that leg used `/usr/bin/nc -U`. Both had a passing control (dir widened to `0755` -> connects).
