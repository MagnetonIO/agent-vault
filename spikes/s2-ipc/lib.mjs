// Shared helpers for the S2 spike scripts. Throwaway: no deps, plain Node 24.
import { spawn } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
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

// ---- token handshake (the exact protocol the real daemon will use over TCP) ----------------
// Client -> server, first line: `<64 lowercase hex chars>\n` (32 random bytes).
// Server: match (timingSafeEqual) -> writes `ok\n`, then JSON-RPC lines flow.
//         mismatch, over 128 bytes with no newline, or no line within 1500 ms -> destroy the
//         socket with no reply.
export const FIRST_LINE_MAX = 128;
export const FIRST_LINE_TIMEOUT_MS = 1500;

/** `onAuthed(socket, leftover)` runs after the token line has matched. */
export function createTokenServer(token, onAuthed) {
  const want = Buffer.from(token, "utf8");
  return net.createServer((socket) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => socket.destroy(), FIRST_LINE_TIMEOUT_MS);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const nl = buf.indexOf(0x0a);
      if (nl === -1) {
        if (buf.length > FIRST_LINE_MAX) {
          clearTimeout(timer);
          socket.destroy();
        }
        return;
      }
      socket.off("data", onData);
      clearTimeout(timer);
      const line = buf.subarray(0, nl);
      const ok = line.length === want.length && timingSafeEqual(line, want);
      if (!ok) {
        socket.destroy();
        return;
      }
      socket.write("ok\n");
      onAuthed(socket, buf.subarray(nl + 1));
    };
    socket.on("data", onData);
    socket.on("error", () => {});
    socket.on("close", () => clearTimeout(timer));
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
