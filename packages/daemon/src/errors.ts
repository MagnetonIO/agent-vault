/** Another vaultd already answers on this endpoint. */
export class DaemonAlreadyRunningError extends Error {
  constructor() {
    super("vaultd is already running");
    this.name = "DaemonAlreadyRunningError";
  }
}

/**
 * The peer did not prove it knows the daemon's token (or sent nothing usable). The message is
 * fixed: it never carries the token, a nonce or a MAC.
 */
export class DaemonIdentityError extends Error {
  constructor() {
    super("vaultd identity check failed");
    this.name = "DaemonIdentityError";
  }
}

/** A JSON-RPC error object, as thrown by the daemon's handlers and as rejected by `IpcClient.call`. */
export class RpcError extends Error {
  readonly code: number;
  readonly data: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "RpcError";
    this.code = code;
    this.data = data;
  }
}
