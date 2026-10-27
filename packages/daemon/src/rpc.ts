/** Newline-delimited JSON-RPC 2.0: error codes, line framing and request parsing. */

export const ERR = {
  PARSE: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL: -32603,
  APP: -32000,
} as const;

/** Longest request line the server accepts, not counting the newline. */
export const MAX_LINE_BYTES = 1024 * 1024;

export type JsonRpcId = string | number;
export type JsonRpcErrorObject = { code: number; message: string; data?: unknown };

export const encodeLine = (msg: object): string => `${JSON.stringify(msg)}\n`;

export class LineTooLongError extends Error {
  constructor() {
    super("line too long");
    this.name = "LineTooLongError";
  }
}

/** Splits a byte stream into `\n`-terminated lines, refusing any line longer than `max` bytes. */
export class LineSplitter {
  max: number;
  #buf: Buffer = Buffer.alloc(0);
  #scanned = 0;

  constructor(max: number) {
    this.max = max;
  }

  push(chunk: Buffer): void {
    this.#buf = this.#buf.length === 0 ? chunk : Buffer.concat([this.#buf, chunk]);
  }

  /** The next complete line without its newline, or null. Throws LineTooLongError. */
  next(): Buffer | null {
    const nl = this.#buf.indexOf(0x0a, this.#scanned);
    if (nl === -1) {
      if (this.#buf.length > this.max) throw new LineTooLongError();
      this.#scanned = this.#buf.length;
      return null;
    }
    if (nl > this.max) throw new LineTooLongError();
    const line = this.#buf.subarray(0, nl);
    this.#buf = this.#buf.subarray(nl + 1);
    this.#scanned = 0;
    return line;
  }
}

export type ParsedRequest =
  | { kind: "ignore" }
  | { kind: "error"; id: JsonRpcId | null; error: JsonRpcErrorObject }
  | { kind: "request"; id: JsonRpcId; method: string; params: unknown };

const invalidRequest = (id: JsonRpcId | null): ParsedRequest => ({
  kind: "error",
  id,
  error: { code: ERR.INVALID_REQUEST, message: "invalid request" },
});

/** Turn one line into a request, an error to send back, or nothing (a notification). */
export function parseRequestLine(text: string): ParsedRequest {
  let msg: unknown;
  try {
    msg = JSON.parse(text);
  } catch {
    return { kind: "error", id: null, error: { code: ERR.PARSE, message: "parse error" } };
  }
  if (typeof msg !== "object" || msg === null || Array.isArray(msg)) return invalidRequest(null);
  const obj = msg as Record<string, unknown>;
  // Notifications get no reply, valid or not.
  if (!("id" in obj)) return { kind: "ignore" };
  const id = obj.id;
  if (typeof id !== "string" && !(typeof id === "number" && Number.isFinite(id))) {
    return invalidRequest(null);
  }
  if (obj.jsonrpc !== "2.0" || typeof obj.method !== "string") return invalidRequest(id);
  const params = obj.params;
  if (params !== undefined && (typeof params !== "object" || params === null)) {
    return invalidRequest(id);
  }
  return { kind: "request", id, method: obj.method, params };
}
