import { randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { openVault, RootKeyMissingError, VaultNotInitializedError } from "@agent-vault/core";
import {
  ensurePrivateDir,
  type IpcEndpoint,
  ipcEndpoint,
  type RootKeyStore,
  type VaultPaths,
} from "@agent-vault/platform";
import { type CaptureOptions, createCaptureService } from "./capture-page.js";
import { connect } from "./client.js";
import { Connection } from "./connection.js";
import { createDispatcher, type Dispatcher } from "./dispatch.js";
import { DaemonAlreadyRunningError } from "./errors.js";
import {
  HANDSHAKE_LINE_MAX,
  HANDSHAKE_STEP_TIMEOUT_MS,
  HEX64,
  handshakeMac,
  macMatches,
  newNonce,
} from "./handshake.js";
import { acquireLock } from "./lock.js";
import { type DaemonState, registry as defaultRegistry, type Registry } from "./methods/index.js";
import { ERR, encodeLine, LineSplitter, MAX_LINE_BYTES, parseRequestLine } from "./rpc.js";
import { createRunnerService } from "./runner.js";

/** Authenticated connections (on unix, where there is no handshake, all connections). */
export const MAX_CONNECTIONS = 64;
/** tcp connections that have not finished the handshake yet; the oldest is evicted beyond this. */
export const MAX_PENDING_CONNECTIONS = 16;
/** Requests being handled at once on one connection; reading pauses beyond this. */
export const MAX_IN_FLIGHT = 64;
const PROBE_TIMEOUT_MS = 500;
/** How long a connection we are closing may keep sending before it is cut off. */
const CLOSE_GRACE_MS = 1000;

export type StartDaemonOptions = {
  paths: VaultPaths;
  store: RootKeyStore;
  /** Where to listen. Defaults to `ipcEndpoint(paths)`; tests force `tcp` on every OS. */
  endpoint?: IpcEndpoint | undefined;
  /** Replaces the built-in method registry; tests add test-only methods. */
  methods?: Registry | undefined;
  /** The capture page's clock, TTL and storage; tests replace them. */
  capture?: CaptureOptions | undefined;
};

export type DaemonHandle = {
  endpoint: IpcEndpoint;
  close(): Promise<void>;
  /** Resolves once the daemon has closed, whether `close()` or a `daemon.stop` call did it. */
  closed: Promise<void>;
};

/** True if something answers `status` on `endpoint` (after the handshake, for tcp). */
async function isLive(endpoint: IpcEndpoint): Promise<boolean> {
  try {
    const client = await connect(endpoint, {
      timeoutMs: PROBE_TIMEOUT_MS,
      requestTimeoutMs: PROBE_TIMEOUT_MS,
    });
    try {
      await client.call("status");
      return true;
    } finally {
      client.close();
    }
  } catch {
    return false;
  }
}

/** Write `data` to `file` through a temp file in the same dir, so readers never see a partial. */
function writeAtomic(file: string, data: string): void {
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

function listen(server: net.Server, options: net.ListenOptions): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    server.once("error", onError);
    server.listen(options, () => {
      server.off("error", onError);
      resolve();
    });
  });
}

/**
 * POSIX: make the socket's dir private, recover a stale socket file, listen, chmod 0600.
 * A live daemon on the path is DaemonAlreadyRunningError; the 0700 dir is the access control.
 */
async function listenUnix(server: net.Server, socketPath: string): Promise<() => void> {
  ensurePrivateDir(path.dirname(socketPath));
  const st = fs.lstatSync(socketPath, { throwIfNoEntry: false });
  if (st) {
    if (!st.isSocket())
      throw new Error(`${socketPath} exists and is not a socket, refusing to remove it`);
    if (await isLive({ kind: "unix", path: socketPath })) throw new DaemonAlreadyRunningError();
    fs.unlinkSync(socketPath);
  }
  try {
    await listen(server, { path: socketPath });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EADDRINUSE") throw new DaemonAlreadyRunningError();
    throw err;
  }
  const remove = () => fs.rmSync(socketPath, { force: true });
  try {
    fs.chmodSync(socketPath, 0o600);
  } catch (err) {
    server.close();
    remove();
    throw err;
  }
  return remove;
}

/**
 * tcp: listen on loopback, then publish the port and a fresh token, each through temp + rename in
 * the private runtime dir.
 */
async function listenTcp(
  server: net.Server,
  endpoint: Extract<IpcEndpoint, { kind: "tcp" }>,
  token: Buffer,
): Promise<() => void> {
  for (const dir of new Set(
    [endpoint.endpointFile, endpoint.tokenFile].map((f) => path.dirname(f)),
  )) {
    ensurePrivateDir(dir);
  }
  if (fs.existsSync(endpoint.endpointFile) && (await isLive(endpoint))) {
    throw new DaemonAlreadyRunningError();
  }
  await listen(server, { host: "127.0.0.1", port: 0 });
  const remove = () => {
    fs.rmSync(endpoint.endpointFile, { force: true });
    fs.rmSync(endpoint.tokenFile, { force: true });
  };
  try {
    const { port } = server.address() as net.AddressInfo;
    // The port first and the token last, so a client never pairs a new token with a stale port.
    writeAtomic(endpoint.endpointFile, JSON.stringify({ port, pid: process.pid }));
    writeAtomic(endpoint.tokenFile, token.toString("hex"));
  } catch (err) {
    remove();
    throw err;
  }
  return remove;
}

/**
 * Connection accounting. Unauthenticated tcp connections are kept in their own set, capped apart
 * from authenticated ones; when it is full the OLDEST one is evicted for the newcomer, so a flood
 * of silent connections can never lock real clients out. Authenticated connections are never
 * evicted.
 */
class Limits {
  readonly #pending = new Set<net.Socket>();
  #authed = 0;
  readonly #handshake: boolean;

  constructor(handshake: boolean) {
    this.#handshake = handshake;
  }

  /** Count a new connection. False if it is over the cap (unix, or tcp only via `promote`). */
  admit(socket: net.Socket): boolean {
    if (this.#handshake) {
      if (this.#pending.size >= MAX_PENDING_CONNECTIONS) {
        const oldest = this.#pending.values().next().value as net.Socket;
        this.#pending.delete(oldest);
        oldest.destroy();
      }
      this.#pending.add(socket);
      return true;
    }
    if (this.#authed >= MAX_CONNECTIONS) return false;
    this.#authed++;
    return true;
  }

  /** A tcp connection passed the handshake. False if the authenticated cap is full. */
  promote(socket: net.Socket): boolean {
    this.#pending.delete(socket);
    if (this.#authed >= MAX_CONNECTIONS) return false;
    this.#authed++;
    return true;
  }

  /** The connection is gone; `authenticated` says whether it had been counted as one. */
  release(socket: net.Socket, authenticated: boolean): void {
    if (authenticated) this.#authed--;
    else this.#pending.delete(socket);
  }
}

type Conn = {
  socket: net.Socket;
  token: Buffer | null;
  dispatch: Dispatcher;
  limits: Limits;
};

/** One accepted connection: the handshake (tcp only), then newline-delimited JSON-RPC. */
function serveConnection({ socket, token, dispatch, limits }: Conn): void {
  type Phase = "nonce" | "mac" | "rpc" | "closing";
  let phase: Phase = token ? "nonce" : "rpc";
  let nonceC = "";
  let nonceS = "";
  let inFlight = 0;
  const splitter = new LineSplitter(token ? HANDSHAKE_LINE_MAX : MAX_LINE_BYTES);
  let timer: NodeJS.Timeout | undefined;

  if (!limits.admit(socket)) {
    socket.destroy();
    return;
  }
  // Runs started on this connection end with it.
  const connection = new Connection({
    blocked: () => socket.writableNeedDrain,
    onDrain: (fn) => void socket.once("drain", fn),
  });
  socket.once("close", () => connection.close());
  // Where this connection is counted: pending until the handshake passes (unix: never pending).
  let authenticated = token === null;
  socket.once("close", () => limits.release(socket, authenticated));

  const armStepTimer = () => {
    clearTimeout(timer);
    timer = setTimeout(() => socket.destroy(), HANDSHAKE_STEP_TIMEOUT_MS);
  };
  const send = (msg: object) => {
    if (socket.writable) socket.write(encodeLine(msg));
  };
  const notify = (method: string, params: unknown) => send({ jsonrpc: "2.0", method, params });

  socket.on("error", () => {});
  socket.once("close", () => clearTimeout(timer));
  if (token) armStepTimer();

  /** Answer, stop reading, and cut the connection off if the peer keeps sending. */
  const rejectAndClose = (error: { code: number; message: string }) => {
    phase = "closing";
    clearTimeout(timer);
    socket.end(encodeLine({ jsonrpc: "2.0", id: null, error }));
    timer = setTimeout(() => socket.destroy(), CLOSE_GRACE_MS);
  };

  /** Stop reading while the peer is not reading our answers or too many requests are open. */
  const blocked = () => socket.writableNeedDrain || inFlight >= MAX_IN_FLIGHT;

  const handleRpcLine = async (line: Buffer) => {
    const req = parseRequestLine(line.toString("utf8"));
    if (req.kind === "ignore") return;
    if (req.kind === "error") {
      send({ jsonrpc: "2.0", id: req.id, error: req.error });
      return;
    }
    inFlight++;
    try {
      const outcome = await dispatch(req.method, req.params, notify, connection);
      try {
        send(
          outcome.ok
            ? { jsonrpc: "2.0", id: req.id, result: outcome.result ?? null }
            : { jsonrpc: "2.0", id: req.id, error: outcome.error },
        );
      } catch {
        // A result that cannot be serialized (a handler bug) must not crash the daemon.
        send({
          jsonrpc: "2.0",
          id: req.id,
          error: { code: ERR.INTERNAL, message: "internal error" },
        });
      }
    } finally {
      inFlight--;
      pump();
    }
  };

  const drain = () => {
    while (phase !== "closing" && !blocked()) {
      let line: Buffer | null;
      try {
        line = splitter.next();
      } catch {
        if (phase === "rpc") {
          rejectAndClose({ code: ERR.INVALID_REQUEST, message: "request too large" });
        } else {
          socket.destroy();
        }
        return;
      }
      if (line === null) return;

      if (phase === "nonce" && token) {
        nonceC = line.toString("latin1");
        if (!HEX64.test(nonceC)) {
          socket.destroy();
          return;
        }
        nonceS = newNonce();
        socket.write(
          `${handshakeMac(token, "srv", socket.localPort ?? 0, nonceC, nonceS)} ${nonceS}\n`,
        );
        phase = "mac";
        armStepTimer();
      } else if (phase === "mac" && token) {
        const expected = handshakeMac(token, "cli", socket.localPort ?? 0, nonceS, nonceC);
        if (!macMatches(line.toString("latin1"), expected)) {
          socket.destroy();
          return;
        }
        if (!limits.promote(socket)) {
          socket.destroy(); // authenticated, but the daemon is full
          return;
        }
        authenticated = true;
        phase = "rpc";
        clearTimeout(timer);
        splitter.max = MAX_LINE_BYTES;
      } else {
        handleRpcLine(line).catch(() => socket.destroy());
      }
    }
  };

  /** Read again if nothing holds us back, and work through what is already buffered. */
  const pump = () => {
    if (phase === "closing" || socket.destroyed) return;
    if (blocked()) {
      socket.pause();
      return;
    }
    socket.resume();
    drain();
    if (blocked()) socket.pause();
  };

  socket.on("drain", pump);
  socket.on("data", (chunk: Buffer) => {
    if (phase === "closing") return;
    splitter.push(chunk);
    pump();
  });
}

/**
 * Start vaultd: open the vault (or run without one until `vault.init` or `vault.recover`: there
 * is none yet, or this device's root key is gone), claim the endpoint and serve JSON-RPC. `close()` stops listening, ends connections, zeroes the vault's keys and removes
 * the socket or endpoint files.
 */
export async function startDaemon(opts: StartDaemonOptions): Promise<DaemonHandle> {
  const { paths, store } = opts;
  const endpoint = opts.endpoint ?? ipcEndpoint(paths);
  const state: DaemonState = { vault: null, initializing: false, closed: false };
  // First and synchronous: of several daemons started at once, exactly one gets past this line.
  const releaseLock = acquireLock(paths.runtimeDir);

  const capture = createCaptureService(state, opts.capture);
  const runner = createRunnerService();
  const token = endpoint.kind === "tcp" ? randomBytes(32) : null;
  const sockets = new Set<net.Socket>();
  let removeEndpoint: () => void;
  let server: net.Server;
  try {
    try {
      state.vault = await openVault({ paths, store });
    } catch (err) {
      if (!(err instanceof VaultNotInitializedError || err instanceof RootKeyMissingError)) {
        throw err;
      }
    }
    const dispatch = createDispatcher({
      registry: opts.methods ?? defaultRegistry,
      state,
      paths,
      store,
      capture,
      runner,
      requestStop: () => void setImmediate(() => void stopGracefully()),
    });
    const limits = new Limits(token !== null);
    server = net.createServer((socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      serveConnection({ socket, token, dispatch, limits });
    });
    removeEndpoint =
      endpoint.kind === "unix"
        ? await listenUnix(server, endpoint.path)
        : await listenTcp(server, endpoint, token as Buffer);
  } catch (err) {
    await runner.close();
    await capture.close();
    state.vault?.close();
    token?.fill(0);
    releaseLock();
    throw err;
  }

  let closing: Promise<void> | undefined;
  let markClosed!: () => void;
  const closed = new Promise<void>((resolve) => {
    markClosed = resolve;
  });
  const close = (): Promise<void> => {
    closing ??= (async () => {
      state.closed = true;
      const stopped = new Promise<void>((resolve) => server.close(() => resolve()));
      for (const socket of sockets) socket.destroy();
      await stopped;
      await runner.close();
      await capture.close();
      state.vault?.close();
      state.vault = null;
      token?.fill(0);
      removeEndpoint();
      releaseLock();
      markClosed();
    })();
    return closing;
  };
  /** A `daemon.stop`: let the connections finish writing their replies, then close. */
  async function stopGracefully(): Promise<void> {
    const ended = [...sockets].map(
      (socket) =>
        new Promise<void>((resolve) => {
          socket.once("close", () => resolve());
          socket.end();
        }),
    );
    await Promise.race([Promise.all(ended), sleep(CLOSE_GRACE_MS)]);
    await close();
  }
  return { endpoint, close, closed };
}
