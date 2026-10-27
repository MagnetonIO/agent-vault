import fs from "node:fs";
import net from "node:net";
import type { IpcEndpoint } from "@agent-vault/platform";
import { DaemonIdentityError, RpcError } from "./errors.js";
import {
  HANDSHAKE_LINE_MAX,
  handshakeMac,
  macMatches,
  newNonce,
  parseToken,
  SERVER_REPLY,
} from "./handshake.js";
import { encodeLine, LineSplitter, MAX_LINE_BYTES } from "./rpc.js";

const DEFAULT_CONNECT_TIMEOUT_MS = 2000;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
/** Responses are not bounded by the request limit (`audit.query` can return a lot). */
const MAX_RESPONSE_LINE_BYTES = 16 * 1024 * 1024;

export type IpcClient = {
  call<T = unknown>(method: string, params?: unknown): Promise<T>;
  onNotification(fn: (method: string, params: unknown) => void): void;
  close(): void;
};

export type ConnectOptions = {
  /** Socket connect plus handshake. Default 2000. */
  timeoutMs?: number | undefined;
  /** Per request. Default 30000. */
  requestTimeoutMs?: number | undefined;
};

/** A connected, authenticated socket. Bytes the peer sent after the handshake are in `splitter`. */
export type Channel = { socket: net.Socket; splitter: LineSplitter };

function readTcpEndpoint(file: string, tokenFile: string): { port: number; token: Buffer } {
  try {
    const info = JSON.parse(fs.readFileSync(file, "utf8")) as { port?: unknown };
    const token = parseToken(fs.readFileSync(tokenFile, "utf8"));
    if (!token) throw new Error("token file is not a 32-byte hex token");
    const port = info.port;
    if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error("endpoint file has no valid port");
    }
    return { port, token };
  } catch (cause) {
    throw new Error("could not read the vaultd endpoint (is it running?)", { cause });
  }
}

/**
 * Connect and, for tcp, authenticate the daemon before sending anything but a nonce. Fails with
 * DaemonIdentityError if the peer cannot prove it knows the token; nothing else is ever sent to it.
 */
export function openChannel(endpoint: IpcEndpoint, timeoutMs: number): Promise<Channel> {
  return new Promise<Channel>((resolve, reject) => {
    let token: Buffer | null = null;
    let dialed = 0;
    let socket: net.Socket;
    if (endpoint.kind === "tcp") {
      let port: number;
      try {
        ({ port, token } = readTcpEndpoint(endpoint.endpointFile, endpoint.tokenFile));
        dialed = port;
      } catch (err) {
        reject(err);
        return;
      }
      socket = net.connect({ host: "127.0.0.1", port });
    } else {
      socket = net.connect(endpoint.path);
    }

    type Phase = "connecting" | "awaiting-server" | "done";
    let phase: Phase = "connecting";
    const splitter = new LineSplitter(HANDSHAKE_LINE_MAX);
    const nonceC = newNonce();

    const fail = (err: Error) => {
      if (phase === "done") return;
      phase = "done";
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    };
    const succeed = () => {
      phase = "done";
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("connect", onConnect);
      socket.off("error", onError);
      socket.off("close", onClose);
      // Never leave the socket without an error listener between here and the Client taking over.
      socket.on("error", () => {});
      socket.pause();
      splitter.max = MAX_RESPONSE_LINE_BYTES;
      resolve({ socket, splitter });
    };
    const timer = setTimeout(
      () =>
        fail(
          phase === "awaiting-server"
            ? new DaemonIdentityError()
            : new Error("timed out connecting to vaultd"),
        ),
      timeoutMs,
    );

    const onConnect = () => {
      if (!token) {
        succeed();
        return;
      }
      phase = "awaiting-server";
      socket.write(`${nonceC}\n`);
    };
    const onData = (chunk: Buffer) => {
      splitter.push(chunk);
      let line: Buffer | null;
      try {
        line = splitter.next();
      } catch {
        fail(new DaemonIdentityError());
        return;
      }
      if (line === null || !token) return;
      const m = SERVER_REPLY.exec(line.toString("latin1"));
      const nonceS = m?.[2];
      const serverMac = m?.[1];
      if (
        serverMac === undefined ||
        nonceS === undefined ||
        !macMatches(serverMac, handshakeMac(token, "srv", dialed, nonceC, nonceS))
      ) {
        fail(new DaemonIdentityError());
        return;
      }
      socket.write(`${handshakeMac(token, "cli", dialed, nonceS, nonceC)}\n`);
      succeed();
    };
    const onError = (err: Error) => fail(err);
    const onClose = () => fail(new Error("vaultd closed the connection during the handshake"));

    socket.on("connect", onConnect);
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

type Pending = {
  resolve: (value: never) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
};

class Client implements IpcClient {
  readonly #socket: net.Socket;
  readonly #splitter: LineSplitter;
  readonly #requestTimeoutMs: number;
  readonly #pending = new Map<number, Pending>();
  readonly #listeners: ((method: string, params: unknown) => void)[] = [];
  #nextId = 1;
  #closed = false;

  constructor({ socket, splitter }: Channel, requestTimeoutMs: number) {
    this.#socket = socket;
    this.#splitter = splitter;
    this.#requestTimeoutMs = requestTimeoutMs;
    socket.on("error", () => {});
    socket.on("close", () => this.#shutdown(new Error("connection to vaultd closed")));
    socket.on("data", (chunk: Buffer) => {
      splitter.push(chunk);
      this.#drain();
    });
    socket.resume();
    this.#drain();
  }

  call<T = unknown>(method: string, params?: unknown): Promise<T> {
    if (this.#closed) return Promise.reject(new Error("connection to vaultd closed"));
    const id = this.#nextId++;
    let line: string;
    try {
      line = encodeLine({ jsonrpc: "2.0", id, method, ...(params !== undefined && { params }) });
    } catch (err) {
      return Promise.reject(err);
    }
    if (Buffer.byteLength(line) - 1 > MAX_LINE_BYTES) {
      return Promise.reject(new Error("request too large"));
    }
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`request timed out: ${method}`));
      }, this.#requestTimeoutMs);
      this.#pending.set(id, { resolve: resolve as (value: never) => void, reject, timer });
      this.#socket.write(line);
    });
  }

  onNotification(fn: (method: string, params: unknown) => void): void {
    this.#listeners.push(fn);
  }

  close(): void {
    this.#shutdown(new Error("connection to vaultd closed"));
  }

  #shutdown(reason: Error): void {
    if (!this.#closed) {
      this.#closed = true;
      this.#socket.destroy();
    }
    for (const [id, p] of this.#pending) {
      clearTimeout(p.timer);
      this.#pending.delete(id);
      p.reject(reason);
    }
  }

  #drain(): void {
    for (;;) {
      let line: Buffer | null;
      try {
        line = this.#splitter.next();
      } catch {
        this.#shutdown(new Error("vaultd sent an oversized line"));
        return;
      }
      if (line === null) return;
      this.#handle(line.toString("utf8"));
    }
  }

  #handle(text: string): void {
    let msg: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(text);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return;
      msg = parsed as Record<string, unknown>;
    } catch {
      return;
    }
    if (typeof msg.id === "number") {
      const p = this.#pending.get(msg.id);
      if (!p) return;
      this.#pending.delete(msg.id);
      clearTimeout(p.timer);
      const err = msg.error as { code?: unknown; message?: unknown; data?: unknown } | undefined;
      if (err && typeof err === "object") {
        p.reject(
          new RpcError(
            typeof err.code === "number" ? err.code : -32603,
            typeof err.message === "string" ? err.message : "error",
            err.data,
          ),
        );
      } else {
        p.resolve(msg.result as never);
      }
    } else if (typeof msg.method === "string") {
      for (const fn of this.#listeners) {
        try {
          fn(msg.method, msg.params);
        } catch {
          // A faulty listener must not take the connection down.
        }
      }
    }
  }
}

/** Connect to vaultd. tcp endpoints are authenticated; see `openChannel`. */
export async function connect(
  endpoint: IpcEndpoint,
  opts: ConnectOptions = {},
): Promise<IpcClient> {
  const channel = await openChannel(endpoint, opts.timeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS);
  return new Client(channel, opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);
}
