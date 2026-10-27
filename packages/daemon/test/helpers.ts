import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import {
  getPaths,
  type IpcEndpoint,
  ipcEndpoint,
  MemoryKeyStore,
  type VaultPaths,
} from "@agent-vault/platform";
import { afterEach, beforeEach } from "vitest";
import { connect, type IpcClient, openChannel } from "../src/client.js";
import type { Registry } from "../src/methods/index.js";
import { LineSplitter } from "../src/rpc.js";
import { type DaemonHandle, startDaemon } from "../src/server.js";

/** `unix` is the POSIX default; `tcp` is forced on every OS so the handshake runs everywhere. */
export type Mode = "unix" | "tcp";
export const MODES: Mode[] = process.platform === "win32" ? ["tcp"] : ["unix", "tcp"];

export function endpointFor(mode: Mode, paths: VaultPaths): IpcEndpoint {
  if (mode === "unix") return ipcEndpoint(paths);
  return {
    kind: "tcp",
    endpointFile: path.join(paths.runtimeDir, "endpoint.json"),
    tokenFile: path.join(paths.runtimeDir, "token"),
  };
}

/** A fresh sandbox dir (never the real home), removed after the test. */
export function useTmp(): { dir: string; paths: VaultPaths } {
  const box = {} as { dir: string; paths: VaultPaths };
  beforeEach(() => {
    box.dir = fs.mkdtempSync(path.join(os.tmpdir(), "avd-"));
    box.paths = getPaths({ AGENT_VAULT_HOME: box.dir }, process.platform);
  });
  afterEach(() => {
    fs.rmSync(box.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });
  return box;
}

export type DaemonEnv = {
  dir: string;
  paths: VaultPaths;
  store: MemoryKeyStore;
  endpoint: IpcEndpoint;
  daemon: DaemonHandle;
  /** An open client, already connected. Closed after the test. */
  client: IpcClient;
  /** Another client; closed after the test. */
  connect(): Promise<IpcClient>;
};

/** A sandboxed daemon (temp AGENT_VAULT_HOME, MemoryKeyStore) with one client. */
export function useDaemon(
  mode: Mode,
  opts: { init?: boolean; methods?: Registry } = {},
): DaemonEnv {
  const env = {} as DaemonEnv;
  const clients: IpcClient[] = [];
  beforeEach(async () => {
    env.dir = fs.mkdtempSync(path.join(os.tmpdir(), "avd-"));
    env.paths = getPaths({ AGENT_VAULT_HOME: env.dir }, process.platform);
    env.store = new MemoryKeyStore();
    env.endpoint = endpointFor(mode, env.paths);
    env.daemon = await startDaemon({
      paths: env.paths,
      store: env.store,
      endpoint: env.endpoint,
      methods: opts.methods,
    });
    env.connect = async () => {
      const c = await connect(env.endpoint);
      clients.push(c);
      return c;
    };
    env.client = await env.connect();
    if (opts.init) await env.client.call("vault.init", { keystore: "memory" });
  });
  afterEach(async () => {
    for (const c of clients.splice(0)) c.close();
    await env.daemon.close();
    fs.rmSync(env.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });
  return env;
}

export const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

/** A socket read line by line, to see exactly what the daemon sends and when it hangs up. */
export class RawPeer {
  readonly socket: net.Socket;
  readonly splitter = new LineSplitter(32 * 1024 * 1024);
  closed = false;
  #wake: (() => void) | null = null;

  constructor(socket: net.Socket, leftover?: LineSplitter) {
    this.socket = socket;
    if (leftover) this.splitter = leftover;
    socket.on("error", () => {});
    socket.on("data", (chunk: Buffer) => {
      this.splitter.push(chunk);
      this.#wake?.();
    });
    socket.on("close", () => {
      this.closed = true;
      this.#wake?.();
    });
    socket.resume();
  }

  /** Connect to the endpoint, doing the real handshake for tcp. */
  static async open(endpoint: IpcEndpoint): Promise<RawPeer> {
    const { socket, splitter } = await openChannel(endpoint, 2000);
    return new RawPeer(socket, splitter);
  }

  /** Connect without any handshake, to a unix path or a tcp port. */
  static async plain(target: string | number): Promise<RawPeer> {
    const socket =
      typeof target === "number" ? net.connect(target, "127.0.0.1") : net.connect(target);
    await new Promise<void>((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    });
    return new RawPeer(socket);
  }

  send(data: string | Buffer): void {
    this.socket.write(data);
  }

  /** The next line, or null if the socket closes or `ms` pass first. */
  async line(ms = 2000): Promise<string | null> {
    const end = Date.now() + ms;
    for (;;) {
      const l = this.splitter.next();
      if (l) return l.toString("utf8");
      if (this.closed) return null;
      const left = end - Date.now();
      if (left <= 0) return null;
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, left);
        this.#wake = () => {
          clearTimeout(t);
          resolve();
        };
      });
      this.#wake = null;
    }
  }

  /** Send one request and parse the reply. */
  async rpc(method: string, params?: unknown, id: number | string = 1): Promise<Reply> {
    this.send(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    const line = await this.line();
    if (line === null) throw new Error("no reply");
    return JSON.parse(line) as Reply;
  }

  async waitClosed(ms = 3000): Promise<boolean> {
    const end = Date.now() + ms;
    while (!this.closed && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
    return this.closed;
  }

  destroy(): void {
    this.socket.destroy();
  }
}

export type Reply = {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};
