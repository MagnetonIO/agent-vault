/**
 * Another vaultd already answers on this endpoint, or holds the single-instance lock. With a
 * `lockFile` the message names it, so a user whose lock is stale can delete it.
 */
export class DaemonAlreadyRunningError extends Error {
  constructor(lockFile?: string) {
    super(
      lockFile === undefined
        ? "vaultd is already running"
        : `vaultd is already running (lock held: ${lockFile}; if no daemon is running, delete that file)`,
    );
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
