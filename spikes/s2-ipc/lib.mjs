// Shared helpers for the S2 spike scripts. Throwaway: no deps, plain Node 24.
import { spawn } from "node:child_process";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const here = path.dirname(fileURLToPath(import.meta.url));
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** One greppable evidence line per fact: `EVIDENCE <id>: <text>`. */
export const ev = (id, text) => console.log(`EVIDENCE ${id}: ${text}`);
export const section = (title) => console.log(`\n===== ${title} =====`);

/** Per-user pipe name. The hash only separates users; it is not a secret. */
export function pipeName(suffix = "") {
  const h = createHash("sha256").update(os.userInfo().username).digest("hex").slice(0, 16);
  return `\\\\.\\pipe\\agent-vault-${h}${suffix}`;
}

export function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { windowsHide: true, ...opts });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => {
      stdout += d;
    });
    child.stderr?.on("data", (d) => {
      stderr += d;
    });
    child.on("error", (e) => resolve({ code: -1, stdout, stderr: `${stderr}${e.message}` }));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

/** Resolves with `{ ok: true }` or `{ ok: false, code, message }`. Never throws. */
export function tryListen(server, ...args) {
  return new Promise((resolve) => {
    const onError = (e) => resolve({ ok: false, code: e.code, message: e.message });
    server.once("error", onError);
    server.listen(...args, () => {
      server.off("error", onError);
      resolve({ ok: true });
    });
  });
}

// ---- mutual token handshake (the exact protocol the real daemon will use over TCP) ----------
// All lines are `\n`-terminated ASCII. `token` is 32 random bytes (64 lowercase hex chars),
// regenerated at every daemon start, never sent on the wire. HMAC key = the 32 raw token bytes;
// HMAC message = the ASCII label followed by the ASCII hex nonce.
//   1. client -> `nonce_c`                      (32 random bytes, 64 hex)
//   2. server -> `HMAC(token,"srv"+nonce_c) nonce_s`   (mac hex, space, 32 random bytes hex)
//   3. client verifies the mac with timingSafeEqual and sends NOTHING else until it matches.
//      Mismatch, malformed line or no reply in 2500 ms: close, error "vaultd identity check failed".
//   4. client -> `HMAC(token,"cli"+nonce_s)`, then JSON-RPC lines may follow immediately.
//   5. server verifies; on mismatch it closes without a reply and serves nothing.
// Server limits: every line max 128 bytes, each step must complete within 1500 ms.
export const LINE_MAX = 128;
export const STEP_TIMEOUT_MS = 1500;
export const CLIENT_TIMEOUT_MS = 2500;
export const IDENTITY_ERROR = "vaultd identity check failed";
const HEX64 = /^[0-9a-f]{64}$/;

export const newNonce = () => randomBytes(32).toString("hex");
export const newToken = () => randomBytes(32).toString("hex");
export const mac = (token, label, nonceHex) =>
  createHmac("sha256", Buffer.from(token, "hex")).update(`${label}${nonceHex}`).digest("hex");
const sameHex = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** Line reader over a socket that keeps bytes after the newline for the next call. */
export function lineReader(socket) {
  let buf = Buffer.alloc(0);
  let wake = null;
  const onData = (c) => {
    buf = Buffer.concat([buf, c]);
    wake?.();
  };
  const onEnd = () => wake?.();
  socket.on("data", onData);
  socket.on("close", onEnd);
  socket.on("error", onEnd);
  return {
    async line(max, timeoutMs) {
      const end = Date.now() + timeoutMs;
      for (;;) {
        const nl = buf.indexOf(0x0a);
        if (nl >= 0) {
          const l = buf.subarray(0, nl).toString("latin1");
          buf = buf.subarray(nl + 1);
          return l;
        }
        if (buf.length > max) throw new Error("line too long");
        if (socket.destroyed) throw new Error("closed");
        const left = end - Date.now();
        if (left <= 0) throw new Error("timeout");
        await new Promise((r) => {
          const t = setTimeout(r, left);
          wake = () => {
            clearTimeout(t);
            r();
          };
        });
        wake = null;
      }
    },
    /** Stop reading; return whatever was already buffered. */
    detach() {
      socket.off("data", onData);
      socket.off("close", onEnd);
      socket.off("error", onEnd);
      const b = buf;
      buf = Buffer.alloc(0);
      return b;
    },
  };
}

/** `onAuthed(socket, leftover)` runs only after the client proved it knows the token. */
export function createMutualServer(token, onAuthed) {
  return net.createServer(async (socket) => {
    socket.on("error", () => {});
    const rd = lineReader(socket);
    try {
      const nonceC = await rd.line(LINE_MAX, STEP_TIMEOUT_MS);
      if (!HEX64.test(nonceC)) throw new Error("bad nonce");
      const nonceS = newNonce();
      socket.write(`${mac(token, "srv", nonceC)} ${nonceS}\n`);
      const cli = await rd.line(LINE_MAX, STEP_TIMEOUT_MS);
      if (!sameHex(cli, mac(token, "cli", nonceS))) throw new Error("bad client mac");
      onAuthed(socket, rd.detach());
    } catch {
      socket.destroy();
    }
  });
}

/** Echo server body for authed sockets: every JSON-RPC line comes back as a result. */
export function echoLines(socket, leftover) {
  let pending = leftover.toString("utf8");
  const flush = () => {
    let i = pending.indexOf("\n");
    while (i !== -1) {
      const line = pending.slice(0, i);
      pending = pending.slice(i + 1);
      socket.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { echo: line } })}\n`);
      i = pending.indexOf("\n");
    }
  };
  socket.on("data", (d) => {
    pending += d.toString("utf8");
    flush();
  });
  flush();
}

/**
 * The real client. Sends the nonce, verifies the server's mac, and only then sends the client
 * mac and `payload`. `payloadBytesSent` is 0 whenever the identity check fails.
 */
export async function mutualConnect(connectOpts, token, { payload = "", waitMs = 1200 } = {}) {
  const socket = net.connect(connectOpts);
  socket.on("error", () => {});
  const out = { ok: false, error: null, payloadBytesSent: 0, data: "" };
  try {
    await new Promise((res, rej) => {
      socket.once("connect", res);
      socket.once("error", rej);
    });
    const rd = lineReader(socket);
    const nonceC = newNonce();
    socket.write(`${nonceC}\n`);
    let reply;
    try {
      reply = await rd.line(LINE_MAX, CLIENT_TIMEOUT_MS);
    } catch {
      out.error = `${IDENTITY_ERROR} (no usable reply)`;
      return out;
    }
    const m = /^([0-9a-f]{64}) ([0-9a-f]{64})$/.exec(reply);
    if (!m || !sameHex(m[1], mac(token, "srv", nonceC))) {
      out.error = IDENTITY_ERROR;
      return out;
    }
    socket.write(`${mac(token, "cli", m[2])}\n`);
    if (payload) {
      socket.write(payload);
      out.payloadBytesSent = Buffer.byteLength(payload);
    }
    const pre = rd.detach();
    out.data = pre.toString("utf8");
    socket.on("data", (d) => {
      out.data += d.toString("utf8");
    });
    await sleep(waitMs);
    out.ok = true;
    return out;
  } catch (e) {
    out.error = `connect failed: ${e.code ?? e.message}`;
    return out;
  } finally {
    socket.destroy();
  }
}

/**
 * Attacker that does NOT know the token. Sends a valid nonce, reads the server's reply, then
 * answers per `mode` ("bogus" = 64 f's, "reflect" = replays the server's own mac) and tries a
 * JSON-RPC request. Reports what the server returned after the reply line.
 */
export function attack(connectOpts, mode) {
  return new Promise((resolve) => {
    const out = { afterReply: "", serverClosed: false };
    const socket = net.connect(connectOpts);
    let first = true;
    let buf = "";
    socket.on("error", () => {});
    socket.on("connect", () => socket.write(`${newNonce()}\n`));
    socket.on("data", (d) => {
      buf += d.toString("utf8");
      if (first) {
        const nl = buf.indexOf("\n");
        if (nl < 0) return;
        first = false;
        const serverMac = buf.slice(0, nl).split(" ")[0];
        buf = buf.slice(nl + 1);
        const fake = mode === "reflect" ? serverMac : "f".repeat(64);
        socket.write(`${fake}\n{"jsonrpc":"2.0","id":9,"method":"list"}\n`);
      }
    });
    const done = () => {
      out.afterReply = buf;
      socket.destroy();
      resolve(out);
    };
    const timer = setTimeout(done, 2500);
    socket.on("close", () => {
      out.serverClosed = true;
      clearTimeout(timer);
      done();
    });
  });
}

/**
 * Connect, write each string in `lines` (spaced 100 ms apart), then wait up to `waitMs`.
 * Reports what came back and whether the server closed the connection.
 */
export function exchange(connectOpts, lines, waitMs = 2500) {
  return new Promise((resolve) => {
    const out = { data: "", serverClosed: false, error: null };
    const socket = net.connect(connectOpts);
    const done = () => {
      socket.destroy();
      resolve(out);
    };
    const timer = setTimeout(done, waitMs);
    socket.on("connect", async () => {
      for (const l of lines) {
        if (socket.destroyed) break;
        socket.write(l);
        await sleep(100);
      }
    });
    socket.on("data", (d) => {
      out.data += d.toString("utf8");
    });
    socket.on("error", (e) => {
      out.error = e.code ?? e.message;
    });
    socket.on("close", () => {
      out.serverClosed = true;
      clearTimeout(timer);
      done();
    });
  });
}

// ---- Windows: second local user + helper scripts --------------------------------------------
export const PS = "powershell.exe"; // Windows PowerShell 5.1 (has the System.IO.Pipes ACL APIs)
export const PUBLIC = "C:\\Users\\Public\\av-spike";
const psArgs = (...rest) => ["-NoProfile", "-ExecutionPolicy", "Bypass", ...rest];

export const hasOtherUser = () =>
  Boolean(process.env.SPIKE_OTHER_USER && process.env.SPIKE_OTHER_PASS);

/** Copy the .ps1 helpers to a folder the second user can read, and open it up for output files. */
export async function preparePublic() {
  fs.mkdirSync(PUBLIC, { recursive: true });
  await run("icacls", [PUBLIC, "/grant", "Everyone:(OI)(CI)M"]);
  for (const f of fs.readdirSync(path.join(here, "scripts"))) {
    fs.copyFileSync(path.join(here, "scripts", f), path.join(PUBLIC, f));
  }
}

/** Run `scripts/<script>` as the current user; resolves with its output. */
export const runScript = (script, args = []) =>
  run(PS, psArgs("-File", path.join(here, "scripts", script), ...args));

/**
 * Launch `PUBLIC/<script>` as the second user via Start-Process -Credential, stdout/stderr
 * redirected to `outFile`. With `wait` the call returns when the child exits.
 */
export async function runAsOther(script, args, outFile, { wait = true } = {}) {
  fs.rmSync(outFile, { force: true });
  const r = await run(
    PS,
    psArgs(
      "-File",
      path.join(here, "scripts", "as-other.ps1"),
      "-Script",
      path.join(PUBLIC, script),
      "-ScriptArgs",
      args.join(" "),
      "-Out",
      outFile,
      ...(wait ? ["-Wait"] : []),
    ),
  );
  console.log(`  as-other(${script}): ${(r.stdout + r.stderr).trim().replaceAll("\n", " | ")}`);
  return r;
}

export async function waitForLine(file, re, timeoutMs = 15000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try {
      const t = fs.readFileSync(file, "utf8");
      if (re.test(t)) return t;
    } catch {}
    await sleep(250);
  }
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

export const readOr = (file, dflt = "") => {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return dflt;
  }
};

export const indent = (s) =>
  s
    .trim()
    .split(/\r?\n/)
    .map((l) => `    ${l}`)
    .join("\n");
