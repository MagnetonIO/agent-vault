import { type ChildProcess, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CLI, makeSandbox, type Result, type Sandbox } from "../../packages/cli/test/harness.js";
import { ALNUM, B64, body } from "../../packages/detect/test/fixtures/fake-keys.js";

const here = path.dirname(fileURLToPath(import.meta.url));

/** Harness config skeletons: no key-shaped literal lives in the repo, so the tests add keys. */
export const SKELETON = path.join(here, "fixtures", "home");

export const read = (file: string): string => fs.readFileSync(file, "utf8");

export const put = (file: string, text: string): string => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
};

// ---------------------------------------------------------------------------------------------
// The sandbox: a temp HOME holding a copy of the skeleton, and an environment that points every
// harness at it (AGENTS.md sandbox rule).

export type Home = {
  sb: Sandbox;
  /** HOME, USERPROFILE and the project's parent. */
  dir: string;
  proj: string;
  claudeSettings: string;
  claudeJson: string;
  codexHome: string;
  codexConfig: string;
  codexHooks: string;
  opencodeConfig: string;
  /** The environment of every CLI call: PATH holds nothing, so no real harness binary can run. */
  env: NodeJS.ProcessEnv;
  /** Run the built CLI in the sandbox. */
  cli(
    args: string[],
    opts?: { stdin?: string; cwd?: string; env?: NodeJS.ProcessEnv },
  ): Promise<Result>;
};

/** A sandbox whose HOME holds a fresh copy of `fixtures/home`. */
export function makeHome(): Home {
  const sb = makeSandbox("keyfile");
  fs.cpSync(SKELETON, sb.dir, { recursive: true });
  const empty = path.join(sb.dir, "empty-path");
  fs.mkdirSync(empty, { recursive: true });
  const codexHome = path.join(sb.dir, ".codex");
  const env: NodeJS.ProcessEnv = {
    PATH: empty,
    Path: empty,
    CODEX_HOME: codexHome,
    // Empty means "the default": <HOME>/.claude and <HOME>/.claude.json, and HOME is the sandbox.
    CLAUDE_CONFIG_DIR: "",
    XDG_CONFIG_HOME: path.join(sb.dir, ".config"),
    XDG_STATE_HOME: path.join(sb.dir, ".local", "state"),
    XDG_CACHE_HOME: path.join(sb.dir, ".cache"),
    TMPDIR: path.join(sb.dir, "tmp"),
  };
  fs.mkdirSync(env.TMPDIR as string, { recursive: true });
  return {
    sb,
    dir: sb.dir,
    proj: path.join(sb.dir, "proj"),
    claudeSettings: path.join(sb.dir, ".claude", "settings.json"),
    claudeJson: path.join(sb.dir, ".claude.json"),
    codexHome,
    codexConfig: path.join(codexHome, "config.toml"),
    codexHooks: path.join(codexHome, "hooks.json"),
    opencodeConfig: path.join(sb.dir, ".config", "opencode", "opencode.json"),
    env,
    cli: (args, opts = {}) =>
      sb.cli(args, { ...opts, env: { ...env, ...opts.env }, cwd: opts.cwd ?? sb.dir }),
  };
}

/** Every file under `root` as relative path -> text. */
export function snapshot(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (dir: string) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile()) out[path.relative(root, full).replaceAll("\\", "/")] = read(full);
    }
  };
  walk(root);
  return out;
}

// ---------------------------------------------------------------------------------------------
// Fake keys, built at runtime with a seed (the fake-keys.ts pattern: no literal key-shaped string).

const URLSAFE = `${ALNUM}_-`;
const UPPER_DIGITS = `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`;
const b64url = (s: string) => Buffer.from(s, "utf8").toString("base64url");

/** Distinct keys per `seed`, so two harnesses can each store their own 20. */
export function keys(seed: number) {
  const s = (n: number) => seed + n;
  const jwt = (payload: string, n: number) =>
    [b64url('{"alg":"HS256","typ":"JWT"}'), b64url(payload), body(URLSAFE, 43, s(n))].join(".");
  const pemBody = (n: number) => [
    body(B64, 64, s(n)),
    body(B64, 64, s(n + 1)),
    body(B64, 24, s(n + 2)),
  ];
  return {
    anthropic: `sk-${"ant"}-${body(URLSAFE, 48, s(1))}`,
    anthropic2: `sk-${"ant"}-${body(URLSAFE, 48, s(2))}`,
    openai: `sk-${body(ALNUM, 48, s(3))}`,
    openaiProj: `sk-${"proj"}-${body(URLSAFE, 60, s(4))}`,
    githubPat: `gh${"p"}_${body(ALNUM, 36, s(5))}`,
    githubFine: `github${"_pat"}_${body(`${ALNUM}_`, 70, s(6))}`,
    slack: `xo${"xb"}-${body(`${ALNUM}-`, 40, s(7))}`,
    slack2: `xo${"xp"}-${body(`${ALNUM}-`, 40, s(8))}`,
    aws: `AK${"IA"}${body(UPPER_DIGITS, 16, s(9))}`,
    aws2: `AK${"IA"}${body(UPPER_DIGITS, 16, s(10))}`,
    apify: `apify${"_api"}_${body(ALNUM, 30, s(11))}`,
    apify2: `apify${"_api"}_${body(ALNUM, 30, s(12))}`,
    jwt: jwt('{"sub":"fake-subject","name":"Fake User","iat":1700000000}', 13),
    jwt2: jwt('{"sub":"other-subject","name":"Other User","iat":1700000001}', 14),
    pemBody: pemBody(15),
    pem2Body: pemBody(20),
    pem3Body: pemBody(25),
    generic: body(B64, 40, s(30)),
    generic2: body(B64, 40, s(31)),
  };
}

const pemOf = (lines: string[], closed = true): string =>
  [
    `-----BEGIN ${"RSA "}PRIVATE KEY-----`,
    ...lines,
    ...(closed ? [`-----END ${"RSA "}PRIVATE KEY-----`] : []),
  ].join("\n");

/** One thing the user pastes, and every string in it that must never come back out. */
export type Prompt = {
  id: string;
  rule: string;
  text: string;
  /** Strings from the prompt that are secret (checked in every form). */
  secrets: string[];
};

const SENTENCE = "the quick brown fox jumps over the lazy dog while the build runs\n";

/** About `bytes` of ordinary prose, line by line, so no run of key-like characters forms. */
const filler = (bytes: number): string => SENTENCE.repeat(Math.ceil(bytes / SENTENCE.length));

/**
 * The 20 prompts of criterion 3. Every rule gets 2, PEM gets its 3 shapes and generic its 2; the
 * contexts the design worries about (code fence, quotes, trailing punctuation, a Basic-auth line,
 * a ~7 MiB prompt with the key at the end) ride on those, so the total is exactly 20.
 */
export function corpus(seed: number): Prompt[] {
  const k = keys(seed);
  const pem = pemOf(k.pemBody);
  const pemTruncated = pemOf(k.pem2Body.slice(0, 2), false);
  const pemJson = pemOf(k.pem3Body);
  const basicBlob = Buffer.from(`deploy:${k.githubPat}`).toString("base64");
  const p = (id: string, rule: string, text: string, ...secrets: string[]): Prompt => ({
    id,
    rule,
    text,
    secrets,
  });
  const pemSecrets = (full: string, lines: string[]) => [full, ...lines];
  return [
    p(
      "anthropic: 7 MiB, key at the end",
      "anthropic",
      `${filler(7 * 1024 * 1024)}\nmy key is ${k.anthropic}`,
      k.anthropic,
    ),
    p(
      "anthropic: code fence",
      "anthropic",
      `run it like this\n\`\`\`sh\nANTHROPIC_API_KEY=${k.anthropic2} node app.js\n\`\`\`\n`,
      k.anthropic2,
    ),
    p("openai: plain", "openai", `use ${k.openai} for the client`, k.openai),
    p("openai: quoted project key", "openai", `OPENAI="${k.openaiProj}"`, k.openaiProj),
    p("github: trailing period", "github", `my token is ${k.githubPat}.`, k.githubPat),
    p("github: fine-grained", "github", `token: ${k.githubFine}`, k.githubFine),
    p("slack: plain", "slack", `bot token ${k.slack} please`, k.slack),
    p("slack: single quotes", "slack", `tokens = ['${k.slack2}', 'b']`, k.slack2),
    p("aws-akid: env assignment", "aws-akid", `AWS_ACCESS_KEY_ID=${k.aws}`, k.aws),
    p("aws-akid: trailing comma", "aws-akid", `use ${k.aws2}, the region is us-east-1`, k.aws2),
    p("apify: plain", "apify", `apify token ${k.apify}`, k.apify),
    p("apify: code fence", "apify", `\`\`\`\nAPIFY_TOKEN=${k.apify2}\n\`\`\``, k.apify2),
    p("jwt: plain", "jwt", `session ${k.jwt} expired`, k.jwt),
    p(
      "jwt: bearer header",
      "jwt",
      `curl -H "Authorization: Bearer ${k.jwt2}" https://api.example.test/v1`,
      k.jwt2,
    ),
    p("pem: closed", "pem", `here is the key:\n${pem}\nthanks`, ...pemSecrets(pem, k.pemBody)),
    p(
      "pem: truncated (no END line)",
      "pem",
      `half of it:\n${pemTruncated}\n\nthe rest got cut off`,
      ...pemSecrets(pemTruncated, k.pem2Body.slice(0, 2)),
    ),
    p(
      "pem: JSON-escaped",
      "pem",
      JSON.stringify({ type: "service_account", private_key: pemJson }),
      ...pemSecrets(pemJson, k.pem3Body),
    ),
    p("generic: plain", "generic", `the value is ${k.generic} thanks`, k.generic),
    p("generic: assignment", "generic", `SERVICE_SECRET=${k.generic2}`, k.generic2),
    p(
      "basic auth: user:KEY in base64",
      "generic",
      `curl -H 'Authorization: Basic ${basicBlob}' https://api.example.test`,
      basicBlob,
      k.githubPat,
    ),
  ];
}

// ---------------------------------------------------------------------------------------------
// Looking for a secret in output: every form the design names.

const FILLER_BYTE = 0x78;
const MIN_FORM_CHARS = 12;

/**
 * The base64 / base64url text that a buffer holding `value` at byte offset `k` (mod 3) always
 * contains: only the characters made of the value's own bits (the edge characters that also hold
 * a neighbour's bits are dropped). Written from the encoding, not copied from the redactor.
 */
function offsetForm(value: string, k: number, encoding: "base64" | "base64url"): string | null {
  const bytes = Buffer.from(value, "utf8");
  const first = Math.ceil((8 * k) / 6);
  const end = Math.floor((8 * (k + bytes.length)) / 6);
  if (end - first < MIN_FORM_CHARS) return null;
  const buf = Buffer.concat([Buffer.alloc(k, FILLER_BYTE), bytes, Buffer.alloc(2, FILLER_BYTE)]);
  return buf.toString(encoding).slice(first, end);
}

/**
 * The names of the forms of `value` found in `text`. Line breaks are ignored for the encoded
 * forms, so a wrapped base64 copy (any column) counts. Hex is checked only when `hex` is set:
 * the redactor does not treat hex as a variant (a child that hex-encodes a secret has chosen to
 * transform it), so run output is the one place the suite does not look for it.
 */
export function leaksOf(text: string, value: string, opts: { hex: boolean }): string[] {
  const found: string[] = [];
  const flat = text.replace(/\r?\n/g, "");
  const has = (needle: string | null, haystack = text) =>
    needle !== null && needle.length > 0 && haystack.includes(needle);
  if (has(value)) found.push("raw");
  if (has(JSON.stringify(value).slice(1, -1))) found.push("json");
  if (has(encodeURIComponent(value))) found.push("urlencoded");
  if (has(Buffer.from(value).toString("base64"), flat)) found.push("base64");
  if (has(Buffer.from(value).toString("base64url"), flat)) found.push("base64url");
  for (const encoding of ["base64", "base64url"] as const) {
    for (let k = 0; k < 3; k++) {
      if (has(offsetForm(value, k, encoding), flat)) found.push(`${encoding}@${k}`);
    }
  }
  if (opts.hex) {
    const hex = Buffer.from(value).toString("hex");
    if (has(hex, flat.toLowerCase())) found.push("hex");
  }
  return [...new Set(found)];
}

/**
 * Throws, naming the surface, the form and a fingerprint (never the value), if any of `secrets`
 * is in `text`. `hex: false` is for run output only (see `leaksOf`).
 */
export function expectNoLeak(
  surface: string,
  text: string,
  secrets: Iterable<string>,
  opts: { hex?: boolean } = {},
): number {
  let checked = 0;
  for (const value of secrets) {
    checked++;
    const found = leaksOf(text, value, { hex: opts.hex ?? true });
    if (found.length > 0) {
      throw new Error(
        `${surface} holds a secret (len=${value.length} head=${value.slice(0, 3)}…): ${found.join(", ")}`,
      );
    }
  }
  return checked;
}

/** The child both `run` and `vault_run` start: it prints every `AV_S_*` variable in every form. */
export const PRINT_FORMS_SCRIPT = `
const names = Object.keys(process.env).filter((k) => k.startsWith("AV_S_")).sort();
const out = [];
const err = [];
for (const k of names) {
  const v = process.env[k];
  const b = Buffer.from(v, "utf8");
  out.push("raw " + k + " " + v);
  out.push("json " + k + " " + JSON.stringify(v));
  err.push("raw " + k + " " + v);
  for (let off = 0; off < 3; off++) {
    const buf = Buffer.concat([Buffer.alloc(off, 0x78), b, Buffer.alloc(2, 0x78)]);
    out.push("b64@" + off + " " + k + " " + buf.toString("base64"));
    out.push("b64u@" + off + " " + k + " " + buf.toString("base64url"));
    err.push("b64@" + off + " " + k + " " + buf.toString("base64"));
  }
  const whole = b.toString("base64");
  for (const cols of [64, 76]) out.push("wrap" + cols + " " + k + "\\n" + whole.replace(new RegExp("(.{" + cols + "})", "g"), "$1\\n"));
}
console.log(out.join("\\n"));
console.error(err.join("\\n"));
`;

// ---------------------------------------------------------------------------------------------
// A stdio MCP client: JSON-RPC lines over a child's stdin and stdout (the SDK is not a root
// dependency, and the wire is the thing under test).

type Pending = { resolve(v: unknown): void; reject(e: Error): void };

export type ToolResult = { isError: boolean; text: string };

export class McpStdio {
  readonly child: ChildProcess;
  /** Every byte the server wrote to stdout and stderr, for leak checks. */
  stdout = "";
  stderr = "";
  /** What the server asked of the client (URL-mode elicitation). */
  onRequest: (method: string, params: Record<string, unknown>) => Promise<unknown> = async () => ({
    action: "decline",
  });
  readonly #pending = new Map<number, Pending>();
  #next = 1;
  #buf = "";
  readonly #exited: Promise<number | null>;

  constructor(home: Home) {
    this.child = spawn(process.execPath, [CLI, "mcp"], {
      env: { ...home.sb.env, ...home.env },
      cwd: home.dir,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.child.stdout?.setEncoding("utf8").on("data", (c: string) => this.#data(c));
    this.child.stderr?.setEncoding("utf8").on("data", (c: string) => (this.stderr += c));
    this.child.stdin?.on("error", () => {});
    this.#exited = new Promise((resolve) => this.child.once("close", resolve));
  }

  #data(chunk: string): void {
    this.stdout += chunk;
    this.#buf += chunk;
    for (let nl = this.#buf.indexOf("\n"); nl !== -1; nl = this.#buf.indexOf("\n")) {
      const line = this.#buf.slice(0, nl).trim();
      this.#buf = this.#buf.slice(nl + 1);
      if (line !== "") this.#frame(JSON.parse(line) as Record<string, unknown>);
    }
  }

  #frame(msg: Record<string, unknown>): void {
    const { id, method } = msg as { id?: number; method?: string };
    if (method !== undefined && id !== undefined) {
      void this.onRequest(method, (msg.params ?? {}) as Record<string, unknown>).then((result) =>
        this.#send({ jsonrpc: "2.0", id, result }),
      );
      return;
    }
    if (id === undefined) return;
    const pending = this.#pending.get(id);
    if (!pending) return;
    this.#pending.delete(id);
    if (msg.error) pending.reject(new Error(JSON.stringify(msg.error)));
    else pending.resolve(msg.result);
  }

  #send(msg: Record<string, unknown>): void {
    this.child.stdin?.write(`${JSON.stringify(msg)}\n`);
  }

  request(method: string, params: Record<string, unknown> = {}, ms = 120_000): Promise<unknown> {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`${method} timed out after ${ms} ms`)), ms);
      this.#pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.#send({ jsonrpc: "2.0", id, method, params });
    });
  }

  /** `initialize` as a client that can take URL-mode elicitation (so the server never opens a browser). */
  async initialize(): Promise<void> {
    await this.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: { elicitation: { url: {} } },
      clientInfo: { name: "agent-vault-e2e", version: "1.0.0" },
    });
    this.#send({ jsonrpc: "2.0", method: "notifications/initialized" });
  }

  async tools(): Promise<string[]> {
    const res = (await this.request("tools/list")) as { tools: { name: string }[] };
    return res.tools.map((t) => t.name).sort();
  }

  async call(name: string, args: Record<string, unknown> = {}, ms = 120_000): Promise<ToolResult> {
    const res = (await this.request("tools/call", { name, arguments: args }, ms)) as {
      isError?: boolean;
      content: { type: string; text?: string }[];
    };
    return {
      isError: res.isError === true,
      text: res.content.map((c) => c.text ?? "").join("\n"),
    };
  }

  /** Close stdin, wait for the server to go; kill it if it does not. */
  async close(): Promise<void> {
    this.child.stdin?.end();
    const timer = setTimeout(() => this.child.kill("SIGKILL"), 10_000);
    await this.#exited;
    clearTimeout(timer);
  }
}

/** The user filling in the capture page in a browser: a form POST. Returns status and body. */
export function submitCapture(
  url: string,
  fields: Record<string, string>,
): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  const form = new URLSearchParams(fields).toString();
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: u.port,
        path: u.pathname,
        method: "POST",
        agent: false,
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": String(Buffer.byteLength(form)),
          origin: u.origin,
          "sec-fetch-site": "same-origin",
        },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8").on("data", (c: string) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text }));
      },
    );
    req.on("error", reject);
    req.end(form);
  });
}

/** Run `fn` over `items`, at most `width` at a time. */
export async function inBatches<T>(
  items: T[],
  width: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  for (let i = 0; i < items.length; i += width) {
    await Promise.all(items.slice(i, i + width).map(fn));
  }
}
