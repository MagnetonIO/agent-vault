import fs from "node:fs";
import {
  connect,
  DaemonExitedError,
  ensureDaemon,
  type IpcClient,
  RpcError,
  recoveryInProgress,
} from "@agent-vault/daemon";
import { getPaths, ipcEndpoint, type VaultPaths } from "@agent-vault/platform";
import {
  EXIT_WRONG_PASSPHRASE,
  keyfilePath,
  PASSPHRASE_ENV,
  readConfig,
  WRONG_PASSPHRASE_MESSAGE,
} from "./config.js";
import { CliError } from "./errors.js";
import { isTty, promptPassphrase } from "./tty.js";

export const LOCKED_MESSAGE = `keyfile store is locked: set ${PASSPHRASE_ENV} or run 'agent-vault daemon run' in a terminal`;

export type DaemonOptions = {
  /** The keyfile passphrase, when the caller already has it (`recover`). */
  passphrase?: string | undefined;
  /** What to spawn instead of this CLI's `daemon run --passphrase-stdin` (tests). */
  spawnArgv?: string[] | undefined;
  /** This is `recover`, which owns the recovery lock: start a daemon despite it (`--recovering`). */
  recovering?: boolean | undefined;
  /** Told the pid of the daemon this call spawned, if it spawned one. */
  onSpawn?: ((pid: number | undefined) => void) | undefined;
  /** `false` when stdin belongs to another protocol (`mcp`): never prompt for the passphrase. */
  interactive?: boolean | undefined;
};

export const RECOVERY_IN_PROGRESS = "vault recovery in progress";

/** This process's environment without the passphrase: a spawned daemon must never inherit it. */
function spawnEnv(): NodeJS.ProcessEnv {
  const { [PASSPHRASE_ENV]: _passphrase, ...rest } = process.env;
  return rest;
}

/**
 * A connection to vaultd, starting the daemon first if none runs. A keyfile daemon needs its
 * passphrase to start. It is taken from `opts`, else from the environment of this CLI, else asked
 * for on the terminal (twice while the keyfile does not exist yet), and goes to the daemon over
 * its stdin. It is never put in the daemon's environment: that block stays readable to every
 * process of the same user for as long as the daemon lives.
 */
export async function daemonClient(
  paths: VaultPaths = getPaths(),
  opts: DaemonOptions = {},
): Promise<IpcClient> {
  const running = await connect(ipcEndpoint(paths)).catch(() => null);
  if (running) return running;
  // While `recover` replaces the root key, no other daemon may come up under another passphrase.
  if (!opts.recovering && recoveryInProgress(paths.runtimeDir)) {
    throw new CliError(RECOVERY_IN_PROGRESS);
  }
  let stdinPayload: Buffer | undefined;
  if (readConfig(paths) === "keyfile") {
    let passphrase = opts.passphrase ?? process.env[PASSPHRASE_ENV];
    if (!passphrase) {
      if (opts.interactive === false || !isTty()) throw new CliError(LOCKED_MESSAGE, 2);
      passphrase = await promptPassphrase(!fs.existsSync(keyfilePath(paths)));
    }
    if (/[\r\n]/.test(passphrase)) throw new CliError("the passphrase must be a single line");
    stdinPayload = Buffer.from(passphrase, "utf8");
  }
  try {
    return await ensureDaemon(paths, {
      env: spawnEnv(),
      ...(stdinPayload !== undefined && { stdinPayload }),
      ...(opts.spawnArgv !== undefined && { spawnArgv: opts.spawnArgv }),
      ...(opts.recovering && { extraArgs: ["--recovering"] }),
      ...(opts.onSpawn !== undefined && { onSpawn: opts.onSpawn }),
    });
  } catch (err) {
    // The daemon we spawned may have been refused by a recover that began a moment ago.
    if (!opts.recovering && recoveryInProgress(paths.runtimeDir)) {
      throw new CliError(RECOVERY_IN_PROGRESS);
    }
    throw err;
  }
}

/** Run `fn` with a daemon connection and close it afterwards. */
export async function withDaemon<T>(fn: (client: IpcClient, paths: VaultPaths) => Promise<T>) {
  const paths = getPaths();
  const client = await daemonClient(paths);
  try {
    return await fn(client, paths);
  } finally {
    client.close();
  }
}

/** The text for stderr: the message, plus a way forward for the failures people hit. */
export function describeError(err: unknown): string {
  if (err instanceof RpcError) {
    const name = (err.data as { name?: unknown } | undefined)?.name;
    if (name === "VaultNotInitializedError") return `${err.message} (run: agent-vault init)`;
    return err.message;
  }
  if (err instanceof DaemonExitedError && err.exitCode === EXIT_WRONG_PASSPHRASE) {
    return WRONG_PASSPHRASE_MESSAGE;
  }
  const message = err instanceof Error ? err.message : String(err);
  if (/^vaultd (exited|did not start)/.test(message)) {
    return `${message}; run 'agent-vault daemon run' in a terminal to see why`;
  }
  return message;
}
