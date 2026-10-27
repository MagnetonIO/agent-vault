import { randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { openVault, VaultNotInitializedError } from "@agent-vault/core";
import {
  ensurePrivateDir,
  type IpcEndpoint,
  ipcEndpoint,
  type RootKeyStore,
  type VaultPaths,
} from "@agent-vault/platform";
import { connect } from "./client.js";
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
import { type DaemonState, registry as defaultRegistry, type Registry } from "./methods/index.js";
import { ERR, encodeLine, LineSplitter, MAX_LINE_BYTES, parseRequestLine } from "./rpc.js";

export const MAX_CONNECTIONS = 64;
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
};

export type DaemonHandle = {
  endpoint: IpcEndpoint;
  close(): Promise<void>;
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
 * tcp: listen on loopback, then publish a fresh token and the port, each through temp + rename in
 * the private runtime dir. The token is written first so a client that finds the port finds it.
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
    writeAtomic(endpoint.tokenFile, token.toString("hex"));
    writeAtomic(endpoint.endpointFile, JSON.stringify({ port, pid: process.pid }));
  } catch (err) {
    remove();
    throw err;
  }
  return remove;
}

type Conn = {
  socket: net.Socket;
  token: Buffer | null;
  dispatch: Dispatcher;
};

/** One accepted connection: the handshake (tcp only), then newline-delimited JSON-RPC. */
function serveConnection({ socket, token, dispatch }: Conn): void {
  type Phase = "nonce" | "mac" | "rpc" | "closing";
  let phase: Phase = token ? "nonce" : "rpc";
  let nonceC = "";
  let nonceS = "";
  const splitter = new LineSplitter(token ? HANDSHAKE_LINE_MAX : MAX_LINE_BYTES);
  let timer: NodeJS.Timeout | undefined;

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

  const handleRpcLine = async (line: Buffer) => {
    const req = parseRequestLine(line.toString("utf8"));
    if (req.kind === "ignore") return;
    if (req.kind === "error") {
      send({ jsonrpc: "2.0", id: req.id, error: req.error });
      return;
    }
    const outcome = await dispatch(req.method, req.params, notify);
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
  };

  const drain = () => {
    while (phase !== "closing") {
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
        socket.write(`${handshakeMac(token, "srv", nonceC, nonceS)} ${nonceS}\n`);
        phase = "mac";
        armStepTimer();
      } else if (phase === "mac" && token) {
        const expected = handshakeMac(token, "cli", nonceS, nonceC);
        if (!macMatches(line.toString("latin1"), expected)) {
          socket.destroy();
          return;
        }
        phase = "rpc";
        clearTimeout(timer);
        splitter.max = MAX_LINE_BYTES;
      } else {
        handleRpcLine(line).catch(() => socket.destroy());
      }
    }
  };

  socket.on("data", (chunk: Buffer) => {
    if (phase === "closing") return;
    splitter.push(chunk);
    drain();
  });
}

/**
 * Start vaultd: open the vault (or run uninitialized until `vault.init`), claim the endpoint and
 * serve JSON-RPC. `close()` stops listening, ends connections, zeroes the vault's keys and removes
 * the socket or endpoint files.
 */
export async function startDaemon(opts: StartDaemonOptions): Promise<DaemonHandle> {
  const { paths, store } = opts;
  const endpoint = opts.endpoint ?? ipcEndpoint(paths);
  const state: DaemonState = { vault: null, initializing: false, closed: false };
  try {
    state.vault = await openVault({ paths, store });
  } catch (err) {
    if (!(err instanceof VaultNotInitializedError)) throw err;
  }

  const dispatch = createDispatcher({
    registry: opts.methods ?? defaultRegistry,
    state,
    paths,
    store,
  });
  const token = endpoint.kind === "tcp" ? randomBytes(32) : null;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    serveConnection({ socket, token, dispatch });
  });
  server.maxConnections = MAX_CONNECTIONS;

  let removeEndpoint: () => void;
  try {
    removeEndpoint =
      endpoint.kind === "unix"
        ? await listenUnix(server, endpoint.path)
        : await listenTcp(server, endpoint, token as Buffer);
  } catch (err) {
    state.vault?.close();
    throw err;
  }

  let closing: Promise<void> | undefined;
  const close = (): Promise<void> => {
    closing ??= (async () => {
      state.closed = true;
      const stopped = new Promise<void>((resolve) => server.close(() => resolve()));
      for (const socket of sockets) socket.destroy();
      await stopped;
      state.vault?.close();
      state.vault = null;
      token?.fill(0);
      removeEndpoint();
    })();
    return closing;
  };
  return { endpoint, close };
}
