import { type ChildProcess, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connect, type DaemonHandle, type IpcClient, startDaemon } from "@agent-vault/daemon";
import { getPaths, ipcEndpoint, MemoryKeyStore, type VaultPaths } from "@agent-vault/platform";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createMcpServer, harnessFor, type McpServerOptions } from "../src/server.js";

vi.setConfig({ testTimeout: 30_000 });

const SECRET = "ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jK5";
const NODE = process.execPath;
const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, "../../cli/dist/main.js");

type Result = { isError?: boolean; content: { type: string; text?: string }[] };
type Elicit = { mode?: string; url?: string; elicitationId?: string; message?: string };

/** Everything a test needs: a sandboxed in-process daemon and MCP clients wired to a server. */
type Env = {
  dir: string;
  paths: VaultPaths;
  daemon: DaemonHandle;
  admin: IpcClient;
  /** Every daemon connection the MCP server made, so none outlives the test. */
  opened: IpcClient[];
  /** A client connected to a fresh MCP server. */
  mcp(opts?: {
    clientName?: string;
    elicitation?: boolean;
    onElicit?: (params: Elicit) => Promise<{ action: "accept" | "decline" | "cancel" }>;
    server?: McpServerOptions;
  }): Promise<Client>;
};

const texts = (r: Result): string => r.content.map((c) => c.text ?? "").join("\n");

/** The user filling in the capture page in a browser. */
function submitCapture(url: string, fields: Record<string, string>): Promise<number> {
  const u = new URL(url);
  const body = new URLSearchParams(fields).toString();
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
          "content-length": String(Buffer.byteLength(body)),
          origin: u.origin,
          "sec-fetch-site": "same-origin",
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

function useEnv(opts: { capture?: { ttlMs?: number } } = {}): Env {
  const env = {} as Env;
  const clients: Client[] = [];
  beforeEach(async () => {
    env.dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "avm-")));
    env.paths = getPaths({ AGENT_VAULT_HOME: env.dir }, process.platform);
    env.opened = [];
    env.daemon = await startDaemon({
      paths: env.paths,
      store: new MemoryKeyStore(),
      endpoint: ipcEndpoint(env.paths),
      capture: opts.capture,
    });
    env.admin = await connect(ipcEndpoint(env.paths));
    await env.admin.call("vault.init", { keystore: "memory" });
    env.mcp = async (o = {}) => {
      const server = createMcpServer({
        connectDaemon: async () => {
          const c = await connect(ipcEndpoint(env.paths));
          env.opened.push(c);
          return c;
        },
        openUrl: async () => {},
        ...o.server,
      });
      const client = new Client(
        { name: o.clientName ?? "test-client", version: "1.0.0" },
        { capabilities: o.elicitation ? { elicitation: { url: {} } } : {} },
      );
      if (o.elicitation) {
        client.setRequestHandler(ElicitRequestSchema, async (req) => {
          const reply = (await o.onElicit?.(req.params as Elicit)) ?? { action: "accept" };
          return reply;
        });
      }
      const [a, b] = InMemoryTransport.createLinkedPair();
      await Promise.all([server.connect(a), client.connect(b)]);
      clients.push(client);
      return client;
    };
  });
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.close();
    for (const c of env.opened) c.close();
    env.admin.close();
    await env.daemon.close();
    fs.rmSync(env.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });
  return env;
}

const call = async (c: Client, name: string, args: Record<string, unknown> = {}) =>
  (await c.callTool({ name, arguments: args })) as Result;

/** Every way a test can spot the secret in text: raw, base64, hex. */
function expectNoSecret(value: unknown, secret = SECRET): void {
  const json = JSON.stringify(value);
  const raw = Buffer.from(secret);
  expect(json).not.toContain(secret);
  expect(json).not.toContain(raw.toString("base64"));
  expect(json).not.toContain(raw.toString("hex"));
}

async function putSecret(env: Env, name: string, value = SECRET): Promise<void> {
  await env.admin.call("secret.put", {
    name,
    valueB64: Buffer.from(value).toString("base64"),
  });
}

/** A bundle that grants `TOKEN` and allows `node`, made straight in the vault. */
async function makeBundle(env: Env, name: string, opts: { exe?: boolean } = {}): Promise<void> {
  await env.admin.call("bundle.create", { name });
  if (opts.exe !== false) await env.admin.call("bundle.allowExe", { bundle: name, path: NODE });
  await env.admin.call("bundle.grant", { bundle: name, env: "TOKEN", secret: "api/token" });
}

describe("harnessFor", () => {
  test.each([
    ["claude-code", "claude-code"],
    ["Claude Desktop", "claude-code"],
    ["codex-mcp-client", "codex"],
    ["opencode", "opencode"],
    ["cursor", "mcp"],
    [undefined, "mcp"],
  ])("%s -> %s", (name, expected) => {
    expect(harnessFor(name)).toBe(expected);
  });
});

describe("tool list", () => {
  const env = useEnv();

  test("the four tools, each telling the agent never to ask for keys", async () => {
    const c = await env.mcp();
    const { tools } = await c.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      "vault_capture",
      "vault_list",
      "vault_run",
      "vault_status",
    ]);
    for (const t of tools) {
      expect(t.description).toContain("Never ask the user to paste keys; call vault_capture.");
    }
  });

  test("vault_run takes only bundle and argv", async () => {
    const c = await env.mcp();
    const { tools } = await c.listTools();
    const run = tools.find((t) => t.name === "vault_run");
    expect(Object.keys(run?.inputSchema.properties ?? {}).sort()).toEqual(["argv", "bundle"]);
  });
});

describe("vault_list and vault_status", () => {
  const env = useEnv();

  test("vault_list returns names and metadata, never values", async () => {
    await putSecret(env, "api/token");
    await putSecret(env, "db/password", "hunter2-hunter2");
    const c = await env.mcp();
    const r = await call(c, "vault_list");
    expect(r.isError).toBeFalsy();
    const list = JSON.parse(texts(r)) as { name: string; type: string; length: number }[];
    expect(list.map((s) => s.name)).toEqual(["api/token", "db/password"]);
    expect(list[0]).toMatchObject({ length: SECRET.length });
    expectNoSecret(r);
    expectNoSecret(r, "hunter2-hunter2");
  });

  test("vault_status returns the daemon status", async () => {
    const c = await env.mcp();
    const r = await call(c, "vault_status");
    expect(JSON.parse(texts(r))).toMatchObject({ initialized: true, keystore: "memory" });
  });
});

describe("vault_capture with URL-mode elicitation", () => {
  const env = useEnv();

  test("sends mode url with a secret-free url, then reports the stored name", async () => {
    let seen: Elicit | undefined;
    const c = await env.mcp({
      elicitation: true,
      clientName: "claude-code",
      onElicit: async (params) => {
        seen = params;
        // The user, in the browser, while the elicitation request is open.
        expect(await submitCapture(params.url ?? "", { name: "api/captured", value: SECRET })).toBe(
          200,
        );
        return { action: "accept" };
      },
    });
    const r = await call(c, "vault_capture", { name: "api/captured" });
    expect(r.isError).toBeFalsy();
    expect(seen?.mode).toBe("url");
    expect(seen?.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/capture\/[A-Za-z0-9_-]+$/);
    expect(seen?.elicitationId).toMatch(/^[0-9a-f-]{36}$/);
    expect(seen?.message).toBe("Add the key in your browser. The agent only sees its name.");
    expect(texts(r)).toBe(`Stored as api/captured · generic · ${SECRET.length} bytes`);
    expectNoSecret(seen);
    expectNoSecret(r);
    // The audit trail names the harness the MCP client mapped to.
    const audit = await env.admin.call<{ harness: string; operation: string }[]>("audit.query", {});
    expect(audit.some((e) => e.harness === "claude-code")).toBe(true);
  });

  test("a decline stops the wait and says nothing was stored", async () => {
    const c = await env.mcp({
      elicitation: true,
      onElicit: async () => ({ action: "decline" }),
    });
    const r = await call(c, "vault_capture", {});
    expect(texts(r)).toMatch(/declined/i);
    expect(texts(r)).toMatch(/nothing was stored/i);
  });

  test("a cancel stops the wait", async () => {
    const c = await env.mcp({
      elicitation: true,
      onElicit: async () => ({ action: "cancel" }),
    });
    const r = await call(c, "vault_capture", {});
    expect(texts(r)).toMatch(/cancel/i);
    expect(texts(r)).toMatch(/nothing was stored/i);
  });
});

describe("vault_capture without URL-mode elicitation", () => {
  const env = useEnv();

  test("opens the url best effort and returns it as text with the stored name", async () => {
    const opened: string[] = [];
    const c = await env.mcp({
      server: {
        openUrl: async (url) => {
          opened.push(url);
          // The browser opens; the user submits.
          void submitCapture(url, { name: "api/text", value: SECRET });
        },
      },
    });
    const r = await call(c, "vault_capture", { name: "api/text" });
    expect(opened).toHaveLength(1);
    expect(texts(r)).toContain(`Open ${opened[0]} to add the key`);
    expect(texts(r)).toContain(`Stored as api/text · generic · ${SECRET.length} bytes`);
    expectNoSecret(r);
  });

  test("a failing openUrl still returns the url", async () => {
    let url = "";
    const c = await env.mcp({
      server: {
        openUrl: async (u) => {
          url = u;
          void submitCapture(u, { name: "api/headless", value: SECRET });
          throw new Error("no browser here");
        },
      },
    });
    const r = await call(c, "vault_capture", { name: "api/headless" });
    expect(r.isError).toBeFalsy();
    expect(texts(r)).toContain(`Open ${url} to add the key`);
    expect(texts(r)).toContain("Stored as api/headless");
  });

  test("a client with only form elicitation takes this path too", async () => {
    const server = createMcpServer({
      connectDaemon: async () => {
        const c = await connect(ipcEndpoint(env.paths));
        env.opened.push(c);
        return c;
      },
      openUrl: async (u) => void submitCapture(u, { name: "api/form", value: SECRET }),
    });
    const client = new Client({ name: "form-only", version: "1" }, { capabilities: {} });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    const r = await call(client, "vault_capture", { name: "api/form" });
    expect(texts(r)).toContain("Stored as api/form");
    await client.close();
  });
});

describe("vault_capture expiry", () => {
  const env = useEnv({ capture: { ttlMs: 150 } });

  test("an unused link ends with the call-again message", async () => {
    const c = await env.mcp({ elicitation: true, onElicit: async () => ({ action: "accept" }) });
    const r = await call(c, "vault_capture", {});
    expect(texts(r)).toBe("Capture expired; call vault_capture again");
  });

  test("the text path says the same, after the url", async () => {
    const c = await env.mcp();
    const r = await call(c, "vault_capture", {});
    expect(texts(r)).toMatch(/^Open http:\/\/127\.0\.0\.1:\d+\/capture\/\S+ to add the key\n/);
    expect(texts(r)).toContain("Capture expired; call vault_capture again");
  });
});

describe("vault_capture deadline", () => {
  const env = useEnv();

  test("the overall deadline ends the wait", async () => {
    const c = await env.mcp({
      server: { limits: { captureDeadlineMs: 300, waitMs: 100 } },
    });
    const r = await call(c, "vault_capture", {});
    expect(texts(r)).toContain("Capture expired; call vault_capture again");
  });
});

describe("vault_run", () => {
  const env = useEnv();

  beforeEach(async () => {
    await putSecret(env, "api/token");
  });

  test("with no bundle argument it is an error", async () => {
    const c = await env.mcp();
    const r = await c.callTool({ name: "vault_run", arguments: { argv: [NODE, "-v"] } }).then(
      (x) => ({ failed: (x as Result).isError === true, text: texts(x as Result) }),
      (e: Error) => ({ failed: true, text: e.message }),
    );
    expect(r.failed).toBe(true);
  });

  test("an unknown bundle is an error", async () => {
    const c = await env.mcp();
    const r = await call(c, "vault_run", { bundle: "nope", argv: [NODE, "-v"] });
    expect(r.isError).toBe(true);
    expect(texts(r)).toContain("vault_run requires a bundle with at least one allowed executable");
  });

  test("a bundle with no allowed exe is an error", async () => {
    await makeBundle(env, "noexe", { exe: false });
    const c = await env.mcp();
    const r = await call(c, "vault_run", { bundle: "noexe", argv: [NODE, "-v"] });
    expect(r.isError).toBe(true);
    expect(texts(r)).toContain("vault_run requires a bundle with at least one allowed executable");
  });

  test("runs the command with the secret injected and returns exit code and output", async () => {
    await makeBundle(env, "ci");
    const c = await env.mcp({ clientName: "codex-cli" });
    const r = await call(c, "vault_run", {
      bundle: "ci",
      argv: [
        NODE,
        "-e",
        "console.log('has token', process.env.TOKEN !== undefined); console.error('to stderr'); process.exit(3)",
      ],
    });
    expect(r.isError).toBeFalsy();
    const text = texts(r);
    expect(text).toMatch(/^exit 3/);
    expect(text).toContain("has token true");
    expect(text).toContain("to stderr");
    // Run under the harness the client name maps to.
    const audit = await env.admin.call<{ harness: string; operation: string }[]>("audit.query", {});
    expect(audit.some((e) => e.operation === "run" && e.harness === "codex")).toBe(true);
  });

  test("a secret the child prints is redacted in the result", async () => {
    await makeBundle(env, "leaky");
    const c = await env.mcp();
    const r = await call(c, "vault_run", {
      bundle: "leaky",
      argv: [
        NODE,
        "-e",
        "console.log('token=' + process.env.TOKEN); console.error('err=' + process.env.TOKEN)",
      ],
    });
    expect(texts(r)).toMatch(/^exit 0/);
    expectNoSecret(r);
    expect(texts(r)).toContain("api/token");
  });

  test("a command outside the bundle's allowed executables is an error", async () => {
    await env.admin.call("bundle.create", { name: "other" });
    await env.admin.call("bundle.allowExe", {
      bundle: "other",
      path: path.join(env.dir, "not-node"),
    });
    await env.admin.call("bundle.grant", { bundle: "other", env: "TOKEN", secret: "api/token" });
    const c = await env.mcp();
    const r = await call(c, "vault_run", { bundle: "other", argv: [NODE, "-v"] });
    expect(r.isError).toBe(true);
  });

  test("output over the cap is cut with a truncation note", async () => {
    await makeBundle(env, "loud");
    const c = await env.mcp({ server: { limits: { outputCapBytes: 1000 } } });
    const r = await call(c, "vault_run", {
      bundle: "loud",
      argv: [NODE, "-e", "process.stdout.write('x'.repeat(5000))"],
    });
    const text = texts(r);
    const note = /…\[truncated (\d+) bytes\]/.exec(text);
    expect(note).not.toBeNull();
    expect(Number(note?.[1])).toBe(4000);
    expect(/x{10,}/.exec(text)?.[0]).toHaveLength(1000);
  });

  test("a run past the overall timeout is signalled", async () => {
    await makeBundle(env, "slow");
    const c = await env.mcp({ server: { limits: { runTimeoutMs: 500 } } });
    const r = await call(c, "vault_run", {
      bundle: "slow",
      argv: [NODE, "-e", "setInterval(() => {}, 1000)"],
    });
    expect(texts(r)).toMatch(/timed out/i);
    expect(texts(r)).not.toMatch(/^exit 0/);
  });
});

describe("daemon unreachable", () => {
  const env = useEnv();

  test("every tool answers with an error and the server stays alive", async () => {
    const c = await env.mcp({
      server: {
        connectDaemon: async () => {
          throw new Error("connect ENOENT /nowhere");
        },
      },
    });
    for (const [name, args] of [
      ["vault_list", {}],
      ["vault_status", {}],
      ["vault_capture", {}],
      ["vault_run", { bundle: "ci", argv: ["x"] }],
    ] as const) {
      const r = await call(c, name, args);
      expect(r.isError, name).toBe(true);
      expect(texts(r), name).toMatch(/could not reach the agent-vault daemon/);
    }
    // Still answering protocol requests afterwards.
    expect((await c.listTools()).tools).toHaveLength(4);
  });
});

describe("no tool result carries secret bytes", () => {
  const env = useEnv();

  // The daemon redacts the forms the detect redactor knows (raw, base64, url, json); a child that
  // hex-encodes its own secret is outside that contract, so the run here prints only those.
  test("raw, base64 and hex are all absent from every tool's result", async () => {
    await putSecret(env, "api/token");
    await makeBundle(env, "sweep");
    const c = await env.mcp({
      elicitation: true,
      onElicit: async (p) => {
        await submitCapture(p.url ?? "", { name: "api/sweep", value: SECRET });
        return { action: "accept" };
      },
    });
    const results = [
      await call(c, "vault_list"),
      await call(c, "vault_status"),
      await call(c, "vault_capture", { name: "api/sweep" }),
      await call(c, "vault_run", {
        bundle: "sweep",
        argv: [
          NODE,
          "-e",
          [
            "const t = process.env.TOKEN",
            "console.log(t)",
            "console.log(Buffer.from(t).toString('base64'))",
          ].join(";"),
        ],
      }),
    ];
    for (const r of results) expectNoSecret(r);
  });
});

describe("agent-vault mcp over stdio", () => {
  let dir = "";
  let child: ChildProcess | undefined;
  beforeEach(() => {
    dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "avs-")));
  });
  afterEach(() => {
    child?.kill();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  test("stdout carries only JSON-RPC frames through initialize and tools/list", async () => {
    expect(fs.existsSync(CLI), `${CLI} is missing: run pnpm build first`).toBe(true);
    const home = path.join(dir, "vault");
    fs.mkdirSync(home, { recursive: true });
    child = spawn(NODE, [CLI, "mcp"], {
      env: {
        ...process.env,
        HOME: dir,
        USERPROFILE: dir,
        CODEX_HOME: dir,
        AGENT_VAULT_HOME: home,
        XDG_DATA_HOME: path.join(dir, "xdg-data"),
        XDG_RUNTIME_DIR: path.join(dir, "xdg-run"),
      },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const proc = child;
    let out = "";
    let err = "";
    proc.stdout?.setEncoding("utf8").on("data", (c: string) => (out += c));
    proc.stderr?.setEncoding("utf8").on("data", (c: string) => (err += c));
    const send = (msg: object) => proc.stdin?.write(`${JSON.stringify(msg)}\n`);
    const until = async (pred: () => boolean) => {
      const end = Date.now() + 20_000;
      while (!pred()) {
        if (Date.now() > end) throw new Error(`timed out; stdout=${out} stderr=${err}`);
        await new Promise((r) => setTimeout(r, 25));
      }
    };
    send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "purity-test", version: "1" },
      },
    });
    await until(() => out.includes('"id":1'));
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    await until(() => out.includes('"id":2'));

    const lines = out.split("\n").filter((l) => l.length > 0);
    expect(lines.length).toBeGreaterThanOrEqual(2);
    for (const line of lines) {
      const msg = JSON.parse(line) as { jsonrpc?: string };
      expect(msg.jsonrpc).toBe("2.0");
    }
    const list = JSON.parse(lines.find((l) => l.includes('"id":2')) ?? "{}") as {
      result: { tools: { name: string }[] };
    };
    expect(list.result.tools.map((t) => t.name).sort()).toEqual([
      "vault_capture",
      "vault_list",
      "vault_run",
      "vault_status",
    ]);

    // Closing stdin ends the server; no daemon was ever needed.
    const exited = new Promise<number | null>((resolve) => proc.once("close", resolve));
    proc.stdin?.end();
    expect(await exited).toBe(0);
  });
});
