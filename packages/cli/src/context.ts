import fs from "node:fs";
import {
  connect,
  DaemonExitedError,
  ensureDaemon,
  type IpcClient,
  RpcError,
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
};

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
  let stdinPayload: Buffer | undefined;
  if (readConfig(paths) === "keyfile") {
    let passphrase = opts.passphrase ?? process.env[PASSPHRASE_ENV];
    if (!passphrase) {
      if (!isTty()) throw new CliError(LOCKED_MESSAGE, 2);
      passphrase = await promptPassphrase(!fs.existsSync(keyfilePath(paths)));
    }
    if (/[\r\n]/.test(passphrase)) throw new CliError("the passphrase must be a single line");
    stdinPayload = Buffer.from(passphrase, "utf8");
  }
  return ensureDaemon(paths, {
    env: spawnEnv(),
    ...(stdinPayload !== undefined && { stdinPayload }),
    ...(opts.spawnArgv !== undefined && { spawnArgv: opts.spawnArgv }),
  });
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
