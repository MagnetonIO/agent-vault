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

/**
 * `run.start` refused: the bundle lists executables and the resolved `argv[0]` is not one of them.
 * The message names the resolved path, which is not a secret.
 */
export class ExeNotAllowedError extends Error {
  constructor(resolved: string) {
    super(`executable is not allowed by the bundle: ${resolved}`);
    this.name = "ExeNotAllowedError";
  }
}

/** `helper.get` refused: the secret is not tagged `helper`. Names the secret only. */
export class HelperNotAllowedError extends Error {
  constructor(secret: string) {
    super(`secret ${secret} is not available to credential helpers (it lacks the helper tag)`);
    this.name = "HelperNotAllowedError";
  }
}

/** A secret that cannot be handed over as text (not valid UTF-8). Names the secret only. */
export class SecretNotTextError extends Error {
  constructor(secret: string) {
    super(`secret ${secret} is not valid UTF-8 text`);
    this.name = "SecretNotTextError";
  }
}

/**
 * A `run.*` call that cannot proceed (unknown run, too-short secret, command not found, …).
 * Messages are built from names and fixed text only, never from secret values.
 */
export class RunError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RunError";
  }
}

/**
 * The daemon this call started exited before it answered. `exitCode` is its exit code
 * (null: it was killed by a signal), so a caller can tell a wrong passphrase from a crash.
 */
export class DaemonExitedError extends Error {
  readonly exitCode: number | null;

  constructor(message: string, exitCode: number | null) {
    super(message);
    this.name = "DaemonExitedError";
    this.exitCode = exitCode;
  }
}

/** The vault exists but this device's root key is gone: only `vault.recover` can open it. */
export class VaultLockedError extends Error {
  constructor() {
    super("vault is locked; run: agent-vault recover");
    this.name = "VaultLockedError";
  }
}
