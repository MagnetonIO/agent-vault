import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { MemoryKeyStore } from "@agent-vault/platform";
import { describe, expect, test, vi } from "vitest";
import { connect } from "../src/client.js";
import { DaemonAlreadyRunningError } from "../src/errors.js";
import type { Registry } from "../src/methods/index.js";
import { registry } from "../src/methods/index.js";
import { MAX_LINE_BYTES } from "../src/rpc.js";
import { startDaemon } from "../src/server.js";
import { endpointFor, MODES, RawPeer, useDaemon, useTmp } from "./helpers.js";

const bigCalls = { count: 0 };
const hangCalls = { count: 0 };
const pressureMethods: Registry = {
  ...registry,
  "test.big": {
    mutates: false,
    returnsSecret: false,
    handler: () => {
      bigCalls.count++;
      return "x".repeat(20 * 1024);
    },
  },
  "test.hang": {
    mutates: false,
    returnsSecret: false,
    handler: () => {
      hangCalls.count++;
      return new Promise(() => {});
    },
  },
};

const posix = process.platform === "win32" ? describe.skip : describe;

describe.each(MODES)("transport over %s", (mode) => {
  const env = useDaemon(mode, { init: true });

  test("a second startDaemon on the same endpoint is DaemonAlreadyRunningError", async () => {
    await expect(
      startDaemon({ paths: env.paths, store: env.store, endpoint: env.endpoint }),
    ).rejects.toBeInstanceOf(DaemonAlreadyRunningError);
    // The first daemon is untouched.
    expect(await env.client.call("secret.list")).toEqual([]);
    expect(await (await env.connect()).call("secret.list")).toEqual([]);
  });

  test("close() removes the endpoint files and refuses new connections", async () => {
    const files =
      env.endpoint.kind === "unix"
        ? [env.endpoint.path]
        : [env.endpoint.endpointFile, env.endpoint.tokenFile];
    for (const f of files) expect(fs.existsSync(f)).toBe(true);
    await env.daemon.close();
    await env.daemon.close(); // idempotent
    for (const f of files) expect(fs.existsSync(f)).toBe(false);
    await expect(connect(env.endpoint)).rejects.toThrow();
  });

  test("close() ends open connections and lets the vault be opened again", async () => {
    const pending = env.client.call("status");
    await pending;
    await env.daemon.close();
    await expect(env.client.call("status")).rejects.toThrow();
    const again = await startDaemon({
      paths: env.paths,
      store: env.store,
      endpoint: env.endpoint,
    });
    try {
      const c = await connect(env.endpoint);
      expect(await c.call("secret.list")).toEqual([]);
      c.close();
    } finally {
      await again.close();
    }
  });

  test("a request line over 1 MiB is -32600 and the connection is closed", async () => {
    const peer = await RawPeer.open(env.endpoint);
    try {
      peer.send(`${"x".repeat(MAX_LINE_BYTES + 1)}\n`);
      const reply = JSON.parse((await peer.line()) as string);
      expect(reply).toMatchObject({ id: null, error: { code: -32600 } });
      expect(await peer.waitClosed()).toBe(true);
    } finally {
      peer.destroy();
    }
    // Without a newline it is cut off as soon as the buffer passes the limit.
    const endless = await RawPeer.open(env.endpoint);
    try {
      endless.send("y".repeat(MAX_LINE_BYTES + 100));
      expect(JSON.parse((await endless.line()) as string)).toMatchObject({
        error: { code: -32600 },
      });
      expect(await endless.waitClosed()).toBe(true);
    } finally {
      endless.destroy();
    }
    expect(await env.client.call("secret.list")).toEqual([]);
  });

  test("a line of exactly 1 MiB is still read", async () => {
    const peer = await RawPeer.open(env.endpoint);
    try {
      const head = '{"jsonrpc":"2.0","id":1,"method":"status","params":{"pad":"';
      const tail = '"}}';
      const fill = "z".repeat(MAX_LINE_BYTES - head.length - tail.length);
      peer.send(`${head}${fill}${tail}\n`);
      // Parsed and dispatched (the unknown "pad" key is -32602), not rejected as too large.
      expect(JSON.parse((await peer.line()) as string)).toMatchObject({
        id: 1,
        error: { code: -32602 },
      });
    } finally {
      peer.destroy();
    }
  });

  test("the client refuses to send a request over 1 MiB", async () => {
    await expect(
      env.client.call("secret.put", { name: "big/one", valueB64: "A".repeat(MAX_LINE_BYTES) }),
    ).rejects.toThrow(/too large/);
    expect(await env.client.call("status")).toBeTruthy();
  });

  test("the 65th authenticated connection is closed, and a slot frees up when one leaves", async () => {
    const open: RawPeer[] = [];
    try {
      // env.client is one of them; 63 more fill the daemon.
      for (let i = 0; i < 63; i++) open.push(await RawPeer.open(env.endpoint));
      const extra = await RawPeer.open(env.endpoint);
      open.push(extra);
      expect(await extra.waitClosed(1000)).toBe(true);
      // A counted one is still open.
      expect(open[0]?.closed).toBe(false);

      open[0]?.destroy();
      await new Promise((r) => setTimeout(r, 200));
      const next = await RawPeer.open(env.endpoint);
      open.push(next);
      await new Promise((r) => setTimeout(r, 200));
      expect(next.closed).toBe(false);
    } finally {
      for (const p of open) p.destroy();
    }
  });

  describe("backpressure", () => {
    const hold = useDaemon(mode, { init: true, methods: pressureMethods });

    test("2000 pipelined requests from a client that never reads stay bounded", async () => {
      const peer = await RawPeer.open(hold.endpoint);
      try {
        peer.socket.pause(); // never reads a byte of the 2000 x 20 KB of answers
        const before = process.memoryUsage().rss;
        const line = (id: number) => `{"jsonrpc":"2.0","id":${id},"method":"test.big"}\n`;
        let batch = "";
        for (let i = 1; i <= 2000; i++) batch += line(i);
        peer.send(batch);
        await new Promise((r) => setTimeout(r, 1000));
        const grown = process.memoryUsage().rss - before;
        expect(grown).toBeLessThan(20 * 1024 * 1024);
        expect(bigCalls.count).toBeLessThan(2000);
        // Other clients are served meanwhile.
        const other = await hold.connect();
        expect(await other.call("secret.list")).toEqual([]);
      } finally {
        peer.destroy();
      }
    });

    test("at most 64 requests are in flight on one connection", async () => {
      hangCalls.count = 0;
      const peer = await RawPeer.open(hold.endpoint);
      try {
        let batch = "";
        for (let i = 1; i <= 200; i++) {
          batch += `{"jsonrpc":"2.0","id":${i},"method":"test.hang"}\n`;
        }
        peer.send(batch);
        await new Promise((r) => setTimeout(r, 300));
        expect(hangCalls.count).toBe(64);
      } finally {
        peer.destroy();
      }
    });
  });
});

describe("tcp connection caps", () => {
  const env = useDaemon("tcp", { init: true });
  const port = () =>
    (
      JSON.parse(
        fs.readFileSync((env.endpoint as { endpointFile: string }).endpointFile, "utf8"),
      ) as {
        port: number;
      }
    ).port;

  test("a flood of silent connections cannot lock out a real client: the oldest is evicted", async () => {
    const silent: RawPeer[] = [];
    try {
      for (let i = 0; i < 16; i++) silent.push(await RawPeer.plain(port()));
      await new Promise((r) => setTimeout(r, 100)); // let the daemon accept all 16
      const real = await env.connect();
      expect(await real.call("secret.list")).toEqual([]);
      // The oldest silent connection made room; the newer ones were left alone.
      expect(await silent[0]?.waitClosed(1000)).toBe(true);
      expect(silent[15]?.closed).toBe(false);
      // The authenticated client was never touched.
      expect(await env.client.call("secret.list")).toEqual([]);
    } finally {
      for (const p of silent) p.destroy();
    }
  });

  test("a stream of newcomers evicts silent connections one at a time, never authenticated ones", async () => {
    const silent: RawPeer[] = [];
    try {
      for (let i = 0; i < 16; i++) silent.push(await RawPeer.plain(port()));
      await new Promise((r) => setTimeout(r, 100));
      const later: RawPeer[] = [];
      for (let i = 0; i < 4; i++) later.push(await RawPeer.plain(port()));
      silent.push(...later);
      await new Promise((r) => setTimeout(r, 100));
      expect(silent.slice(0, 4).every((p) => p.closed)).toBe(true);
      expect(silent.slice(4).every((p) => !p.closed)).toBe(true);
      expect(await env.client.call("status")).toBeTruthy();
    } finally {
      for (const p of silent) p.destroy();
    }
  });

  test("silent connections do not use up authenticated slots, nor the reverse", async () => {
    const authed: RawPeer[] = [];
    const silent: RawPeer[] = [];
    try {
      for (let i = 0; i < 63; i++) authed.push(await RawPeer.open(env.endpoint)); // + env.client = 64
      for (let i = 0; i < 16; i++) silent.push(await RawPeer.plain(port()));
      await new Promise((r) => setTimeout(r, 200));
      expect(silent.every((p) => !p.closed)).toBe(true);
      expect(authed.every((p) => !p.closed)).toBe(true);
    } finally {
      for (const p of [...authed, ...silent]) p.destroy();
    }
  });
});

describe("tcp endpoint files", () => {
  const tmp = useTmp();

  test("a fresh 32-byte token and the port are written on every start", async () => {
    const endpoint = endpointFor("tcp", tmp.paths);
    if (endpoint.kind !== "tcp") throw new Error("unreachable");
    const tokens: string[] = [];
    for (let i = 0; i < 2; i++) {
      const d = await startDaemon({ paths: tmp.paths, store: new MemoryKeyStore(), endpoint });
      try {
        const token = fs.readFileSync(endpoint.tokenFile, "utf8");
        expect(token).toMatch(/^[0-9a-f]{64}$/);
        tokens.push(token);
        const info = JSON.parse(fs.readFileSync(endpoint.endpointFile, "utf8"));
        expect(info).toEqual({ port: expect.any(Number), pid: process.pid });
        const stray = fs
          .readdirSync(path.dirname(endpoint.tokenFile))
          .filter((f) => f.endsWith(".tmp"));
        expect(stray).toEqual([]);
      } finally {
        await d.close();
      }
    }
    expect(tokens[0]).not.toBe(tokens[1]);
  });

  test("the port is published before the token", async () => {
    const endpoint = endpointFor("tcp", tmp.paths);
    if (endpoint.kind !== "tcp") throw new Error("unreachable");
    const order: string[] = [];
    const realRename = fs.renameSync;
    const spy = vi.spyOn(fs, "renameSync").mockImplementation((from, to) => {
      order.push(path.basename(String(to)));
      realRename(from, to);
    });
    try {
      const d = await startDaemon({ paths: tmp.paths, store: new MemoryKeyStore(), endpoint });
      await d.close();
    } finally {
      spy.mockRestore();
    }
    expect(order).toEqual(["endpoint.json", "token"]);
  });

  test("a stale endpoint file from a dead daemon is replaced", async () => {
    const endpoint = endpointFor("tcp", tmp.paths);
    if (endpoint.kind !== "tcp") throw new Error("unreachable");
    fs.mkdirSync(path.dirname(endpoint.endpointFile), { recursive: true });
    // A port nothing listens on.
    const probe = net.createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    const dead = (probe.address() as net.AddressInfo).port;
    await new Promise((r) => probe.close(r));
    fs.writeFileSync(endpoint.endpointFile, JSON.stringify({ port: dead, pid: 1 }));
    fs.writeFileSync(endpoint.tokenFile, "00".repeat(32));

    const d = await startDaemon({ paths: tmp.paths, store: new MemoryKeyStore(), endpoint });
    try {
      const c = await connect(endpoint);
      expect((await c.call<{ initialized: boolean }>("status")).initialized).toBe(false);
      c.close();
    } finally {
      await d.close();
    }
  });
});

posix("unix socket", () => {
  const tmp = useTmp();

  test("the socket is mode 0600 in a 0700 dir", async () => {
    const d = await startDaemon({ paths: tmp.paths, store: new MemoryKeyStore() });
    try {
      if (d.endpoint.kind !== "unix") throw new Error("expected a unix endpoint");
      expect(fs.statSync(d.endpoint.path).mode & 0o777).toBe(0o600);
      expect(fs.statSync(path.dirname(d.endpoint.path)).mode & 0o777).toBe(0o700);
    } finally {
      await d.close();
    }
  });

  test("a socket dir that is too open is tightened to 0700", async () => {
    fs.mkdirSync(tmp.paths.runtimeDir, { recursive: true, mode: 0o755 });
    fs.chmodSync(tmp.paths.runtimeDir, 0o755);
    const d = await startDaemon({ paths: tmp.paths, store: new MemoryKeyStore() });
    try {
      expect(fs.statSync(tmp.paths.runtimeDir).mode & 0o777).toBe(0o700);
    } finally {
      await d.close();
    }
  });

  /** Bind a socket in a child process and SIGKILL it: the file stays, nothing listens. */
  async function leaveStaleSocket(file: string): Promise<void> {
    const child = spawn(
      process.execPath,
      [
        "-e",
        "require('node:net').createServer().listen(process.argv[1], () => console.log('ready'))",
        file,
      ],
      { stdio: ["ignore", "pipe", "ignore"] },
    );
    await new Promise<void>((resolve, reject) => {
      child.once("error", reject);
      child.stdout.once("data", () => resolve());
    });
    const exited = new Promise((r) => child.once("exit", r));
    child.kill("SIGKILL");
    await exited;
  }

  test("a stale socket file from a dead daemon is recovered", async () => {
    const { ipcEndpoint } = await import("@agent-vault/platform");
    const endpoint = ipcEndpoint(tmp.paths);
    if (endpoint.kind !== "unix") throw new Error("expected a unix endpoint");
    fs.mkdirSync(path.dirname(endpoint.path), { recursive: true, mode: 0o700 });
    await leaveStaleSocket(endpoint.path);
    expect(fs.lstatSync(endpoint.path).isSocket()).toBe(true);
    await expect(connect(endpoint)).rejects.toThrow();

    const d = await startDaemon({ paths: tmp.paths, store: new MemoryKeyStore() });
    try {
      const c = await connect(endpoint);
      expect((await c.call<{ keystore: string }>("status")).keystore).toBe("memory");
      c.close();
    } finally {
      await d.close();
    }
  });

  test("a regular file at the socket path is refused, not deleted", async () => {
    const { ipcEndpoint } = await import("@agent-vault/platform");
    const endpoint = ipcEndpoint(tmp.paths);
    if (endpoint.kind !== "unix") throw new Error("expected a unix endpoint");
    fs.mkdirSync(path.dirname(endpoint.path), { recursive: true, mode: 0o700 });
    fs.writeFileSync(endpoint.path, "precious");
    await expect(startDaemon({ paths: tmp.paths, store: new MemoryKeyStore() })).rejects.toThrow(
      /not a socket/,
    );
    expect(fs.readFileSync(endpoint.path, "utf8")).toBe("precious");
  });
});
