import { execFile } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { appendAudit, VaultClosedError } from "@agent-vault/core";
import { deviceId, type Harness } from "./device.js";
import { isValidName } from "./methods/params.js";
import { storeSecret } from "./methods/secret.js";
import type { DaemonState } from "./methods/types.js";

/** How long a capture link stays valid. */
export const CAPTURE_TTL_MS = 10 * 60_000;
/** Largest POST body the page accepts. */
export const MAX_BODY_BYTES = 64 * 1024;
const HEADERS_TIMEOUT_MS = 10_000;
const REQUEST_TIMEOUT_MS = 30_000;

/** The brief's three directives first, then the clickjacking and base-tag ones. */
const CSP =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

export type CaptureOptions = {
  /** The clock, in epoch ms. Tests advance it to cross the TTL. */
  now?: (() => number) | undefined;
  ttlMs?: number | undefined;
  /** Replaces the storage path; tests use it to make a store fail. */
  store?: typeof storeSecret | undefined;
};

export type CaptureBegin = { url: string; elicitationId: string; expiresAt: string };

/**
 * `expired` also covers "not stored within `timeoutMs`", and a capture whose store failed: in
 * both cases there is nothing to find under that elicitation id.
 */
export type CaptureWait =
  | { status: "stored"; name: string; type: string; length: number }
  | { status: "expired" };

export type CaptureService = {
  /** Start the loopback server if it is not running and open a one-time link. */
  begin(input: { name?: string | undefined; harness: Harness }): Promise<CaptureBegin>;
  /** Resolve when that link's form is submitted and stored, or when it can no longer be. */
  wait(elicitationId: string, timeoutMs: number): Promise<CaptureWait>;
  /** Stop the server and release every waiter. */
  close(): Promise<void>;
};

type Stored = Extract<CaptureWait, { status: "stored" }>;

type Waiter = { resolve: (r: CaptureWait) => void; timer: NodeJS.Timeout };

type Entry = {
  nonce: string;
  elicitationId: string;
  name: string | undefined;
  harness: Harness;
  expiresAt: number;
  state: "open" | "used";
  /** Set when `used`: what was stored, or null if the store failed. */
  result: Stored | null;
  waiters: Set<Waiter>;
};

export function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const STYLE = `body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}
label{display:block;margin:1rem 0 .25rem;font-weight:600}
input{width:100%;box-sizing:border-box;font:inherit;padding:.5rem}
button{margin-top:1.25rem;font:inherit;padding:.5rem 1.25rem}
.err{color:#b00020}.note{color:#555}`;

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title><style>${STYLE}</style></head>
<body>${body}</body></html>
`;
}

function formPage(nonce: string, name: string, error?: string): string {
  return page(
    "agent-vault: add a key",
    `<h1>Add a key</h1>
<p class="note">Stored in agent-vault. The agent only ever sees the name.</p>
${error === undefined ? "" : `<p class="err" role="alert">${escapeHtml(error)}</p>`}
<form method="post" action="/capture/${escapeHtml(nonce)}">
<label>Name (optional, blank to auto-detect)
<input type="text" name="name" value="${escapeHtml(name)}" maxlength="128" autocomplete="off" spellcheck="false"></label>
<label>Key
<input type="password" name="value" autocomplete="off" required></label>
<button type="submit">Store</button>
</form>`,
  );
}

const messagePage = (title: string, message: string, isError = false): string =>
  page(
    `agent-vault: ${title}`,
    `<h1>${escapeHtml(title)}</h1><p${isError ? ' class="err"' : ""}>${escapeHtml(message)}</p>`,
  );

const hexVal = (c: number): number =>
  c >= 0x30 && c <= 0x39
    ? c - 0x30
    : c >= 0x41 && c <= 0x46
      ? c - 0x41 + 10
      : c >= 0x61 && c <= 0x66
        ? c - 0x61 + 10
        : -1;

/** application/x-www-form-urlencoded decoding on bytes, so the value never becomes a string here. */
function percentDecode(src: Buffer): Buffer {
  const out = Buffer.alloc(src.length);
  let n = 0;
  for (let i = 0; i < src.length; i++) {
    const c = src[i] as number;
    if (c === 0x2b) {
      out[n++] = 0x20;
    } else if (
      c === 0x25 &&
      i + 2 < src.length &&
      hexVal(src[i + 1] as number) >= 0 &&
      hexVal(src[i + 2] as number) >= 0
    ) {
      out[n++] = (hexVal(src[i + 1] as number) << 4) | hexVal(src[i + 2] as number);
      i += 2;
    } else {
      out[n++] = c;
    }
  }
  return out.subarray(0, n);
}

/**
 * The first `name` and the first `value` field of a urlencoded body. The caller zeroes `value`.
 * Other fields are skipped without being decoded.
 */
function parseForm(body: Buffer): { name: string | undefined; value: Buffer | undefined } {
  let name: string | undefined;
  let value: Buffer | undefined;
  let start = 0;
  while (start <= body.length) {
    let end = body.indexOf(0x26, start);
    if (end < 0) end = body.length;
    const pair = body.subarray(start, end);
    const eq = pair.indexOf(0x3d);
    const key = (eq < 0 ? pair : pair.subarray(0, eq)).toString("latin1");
    if (key === "name" && name === undefined) {
      name = percentDecode(pair.subarray(eq < 0 ? pair.length : eq + 1)).toString("utf8");
    } else if (key === "value" && value === undefined) {
      value = percentDecode(pair.subarray(eq < 0 ? pair.length : eq + 1));
    }
    start = end + 1;
  }
  return { name, value };
}

/** The body, or null if it is over `max`; the rest of an oversized body is read and dropped. */
function readBody(req: http.IncomingMessage, max: number): Promise<Buffer | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let over = false;
    const wipe = () => {
      for (const c of chunks) c.fill(0);
      chunks.length = 0;
    };
    req.on("data", (chunk: Buffer) => {
      if (over) return;
      size += chunk.length;
      if (size > max) {
        over = true;
        wipe();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (over) return;
      const body = Buffer.concat(chunks);
      wipe();
      resolve(body);
    });
    req.on("error", (err) => {
      wipe();
      reject(err);
    });
    req.on("close", () => {
      if (!req.complete) {
        wipe();
        reject(new Error("request aborted"));
      }
    });
  });
}

function reply(
  res: http.ServerResponse,
  status: number,
  body: string,
  extra: http.OutgoingHttpHeaders = {},
): void {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": CSP,
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    ...extra,
  });
  res.end(body);
}

const gone = (res: http.ServerResponse) =>
  reply(
    res,
    410,
    messagePage(
      "Link expired",
      "This capture link was already used or has expired. Ask the agent for a new one.",
      true,
    ),
  );

const FORM_TYPE = /^application\/x-www-form-urlencoded\s*(;|$)/i;

export function createCaptureService(
  state: Pick<DaemonState, "vault" | "closed">,
  opts: CaptureOptions = {},
): CaptureService {
  const now = opts.now ?? Date.now;
  const ttlMs = opts.ttlMs ?? CAPTURE_TTL_MS;
  const store = opts.store ?? storeSecret;
  const byNonce = new Map<string, Entry>();
  const byId = new Map<string, Entry>();
  const server = http.createServer(
    { headersTimeout: HEADERS_TIMEOUT_MS, requestTimeout: REQUEST_TIMEOUT_MS },
    (req, res) => {
      handle(req, res).catch(() => {
        if (!res.headersSent) {
          reply(
            res,
            500,
            messagePage("Error", "Something went wrong. Start again from your agent.", true),
          );
        } else {
          res.destroy();
        }
      });
    },
  );
  let listening: Promise<number> | undefined;
  let closed = false;

  const settle = (entry: Entry, result: CaptureWait) => {
    for (const w of entry.waiters) {
      clearTimeout(w.timer);
      w.resolve(result);
    }
    entry.waiters.clear();
  };

  const isLive = (e: Entry) => e.expiresAt > now();

  /** Drop expired entries and release whoever waits on them. */
  function purge(): void {
    for (const e of byNonce.values()) {
      if (isLive(e)) continue;
      byNonce.delete(e.nonce);
      byId.delete(e.elicitationId);
      settle(e, { status: "expired" });
    }
  }

  function start(): Promise<number> {
    listening ??= new Promise<number>((resolve, reject) => {
      const onError = (err: Error) => {
        listening = undefined;
        reject(err);
      };
      server.once("error", onError);
      server.listen({ host: "127.0.0.1", port: 0 }, () => {
        server.off("error", onError);
        resolve((server.address() as AddressInfo).port);
      });
    });
    return listening;
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const port = (server.address() as AddressInfo).port;
    // Exactly our own host and port: a rebinding page reaches us under its own name.
    if (req.headers.host !== `127.0.0.1:${port}`) {
      reply(res, 421, messagePage("Misdirected request", "Wrong host.", true));
      return;
    }
    const raw = req.url ?? "";
    const q = raw.indexOf("?");
    const route = /^\/capture\/([^/]+)$/.exec(q < 0 ? raw : raw.slice(0, q));
    if (!route) {
      reply(res, 404, messagePage("Not found", "Nothing here.", true));
      return;
    }
    if (req.method !== "GET" && req.method !== "POST") {
      reply(res, 405, messagePage("Method not allowed", "Use GET or POST.", true), {
        Allow: "GET, POST",
      });
      return;
    }
    purge();
    const entry = byNonce.get(route[1] as string);
    if (entry?.state !== "open") {
      gone(res);
      return;
    }
    if (req.method === "GET") {
      reply(res, 200, formPage(entry.nonce, entry.name ?? ""));
      return;
    }

    if (req.headers.origin !== `http://127.0.0.1:${port}`) {
      reply(res, 403, messagePage("Forbidden", "Cross-origin request refused.", true));
      return;
    }
    const site = req.headers["sec-fetch-site"];
    if (site !== undefined && site !== "same-origin") {
      reply(res, 403, messagePage("Forbidden", "Cross-origin request refused.", true));
      return;
    }
    if (!FORM_TYPE.test(req.headers["content-type"] ?? "")) {
      reply(res, 415, messagePage("Unsupported media type", "Submit the form on the page.", true));
      return;
    }
    const declared = Number(req.headers["content-length"] ?? 0);
    const body = declared > MAX_BODY_BYTES ? null : await readBody(req, MAX_BODY_BYTES);
    if (body === null) {
      reply(res, 413, messagePage("Too large", "That request is too large.", true), {
        Connection: "close",
      });
      req.resume();
      return;
    }
    await submit(entry, body, res);
  }

  async function submit(entry: Entry, body: Buffer, res: http.ServerResponse): Promise<void> {
    const form = parseForm(body);
    body.fill(0);
    const value = form.value;
    const typed = form.name?.trim();
    const name = typed === undefined || typed === "" ? undefined : typed;
    // Mistakes the user can fix on the same link: nothing is consumed.
    const retry = (message: string) => {
      value?.fill(0);
      reply(res, 400, formPage(entry.nonce, typed ?? entry.name ?? "", message));
    };
    if (name !== undefined && !isValidName(name)) {
      retry("That name is not valid. Use lowercase letters, digits, . _ - and / between parts.");
      return;
    }
    if (value === undefined || value.length === 0) {
      retry("Enter the key.");
      return;
    }

    // Consumed before storing: a failed store still needs a fresh link.
    entry.state = "used";
    let meta: { name: string; type: string; length: number } | undefined;
    try {
      const vault = state.vault;
      if (!vault || state.closed) throw new VaultClosedError();
      meta = store(vault, { name, value });
    } catch {
      meta = undefined;
    } finally {
      value.fill(0);
    }

    const audit = (outcome: "captured" | "error", secretName: string | undefined) => {
      const vault = state.vault;
      if (!vault) throw new VaultClosedError();
      appendAudit(vault, {
        deviceId,
        harness: entry.harness,
        actor: "capture",
        ...(secretName !== undefined && { secretName }),
        operation: "capture",
        outcome,
      });
    };

    if (meta === undefined) {
      entry.result = null;
      settle(entry, { status: "expired" });
      try {
        audit("error", name);
      } catch {
        // The user is told the store failed; a failed audit append must not hide that.
      }
      reply(
        res,
        500,
        messagePage(
          "Not stored",
          "The key could not be stored and nothing was saved. Start again from your agent.",
          true,
        ),
      );
      return;
    }

    const stored: Stored = {
      status: "stored",
      name: meta.name,
      type: meta.type,
      length: meta.length,
    };
    entry.result = stored;
    settle(entry, stored);
    try {
      audit("captured", meta.name);
    } catch {
      reply(
        res,
        500,
        messagePage(
          "Stored, not logged",
          `Stored as ${meta.name} · ${meta.type} · ${meta.length} chars, but the audit log could not be written.`,
          true,
        ),
      );
      return;
    }
    reply(
      res,
      200,
      messagePage("Stored", `Stored as ${meta.name} · ${meta.type} · ${meta.length} chars`),
    );
  }

  return {
    async begin({ name, harness }) {
      if (closed || state.closed) throw new VaultClosedError();
      const port = await start();
      purge();
      const entry: Entry = {
        nonce: randomBytes(32).toString("base64url"),
        elicitationId: randomUUID(),
        name,
        harness,
        expiresAt: now() + ttlMs,
        state: "open",
        result: null,
        waiters: new Set(),
      };
      byNonce.set(entry.nonce, entry);
      byId.set(entry.elicitationId, entry);
      return {
        url: `http://127.0.0.1:${port}/capture/${entry.nonce}`,
        elicitationId: entry.elicitationId,
        expiresAt: new Date(entry.expiresAt).toISOString(),
      };
    },

    wait(elicitationId, timeoutMs) {
      purge();
      const entry = byId.get(elicitationId);
      if (!entry) return Promise.resolve({ status: "expired" });
      if (entry.state === "used") {
        return Promise.resolve(entry.result ?? { status: "expired" });
      }
      return new Promise<CaptureWait>((resolve) => {
        const waiter: Waiter = {
          resolve,
          timer: setTimeout(
            () => {
              entry.waiters.delete(waiter);
              resolve({ status: "expired" });
            },
            Math.max(0, Math.min(timeoutMs, entry.expiresAt - now())),
          ),
        };
        waiter.timer.unref();
        entry.waiters.add(waiter);
      });
    },

    async close() {
      closed = true;
      for (const e of byNonce.values()) settle(e, { status: "expired" });
      byNonce.clear();
      byId.clear();
      if (!listening) return;
      const stopped = new Promise<void>((resolve) => server.close(() => resolve()));
      server.closeAllConnections();
      await stopped;
    },
  };
}

/** The platform's URL opener, run without a shell. Only http(s) URLs are accepted. */
export function openCommand(
  url: string,
  platform: NodeJS.Platform = process.platform,
): { file: string; args: string[] } {
  let href: string;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error();
    href = parsed.href;
  } catch {
    throw new Error("openUrl needs an http(s) URL");
  }
  if (platform === "darwin") return { file: "/usr/bin/open", args: [href] };
  if (platform === "win32") {
    return { file: "rundll32.exe", args: ["url.dll,FileProtocolHandler", href] };
  }
  return { file: "xdg-open", args: [href] };
}

/** Open `url` in the user's default browser. The daemon never calls this: it is headless. */
export function openUrl(url: string): Promise<void> {
  return new Promise((resolve, reject) => {
    let command: { file: string; args: string[] };
    try {
      command = openCommand(url);
    } catch (err) {
      reject(err);
      return;
    }
    const child = execFile(command.file, command.args, { windowsHide: true }, (err) => {
      if (err) reject(err);
    });
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
    child.once("error", reject);
  });
}
