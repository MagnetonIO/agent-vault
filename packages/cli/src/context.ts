import fs from "node:fs";
import { connect, ensureDaemon, type IpcClient, RpcError } from "@agent-vault/daemon";
import { getPaths, ipcEndpoint, type VaultPaths } from "@agent-vault/platform";
import { type KeystoreChoice, keyfilePath, PASSPHRASE_ENV, readConfig } from "./config.js";
import { CliError } from "./errors.js";
import { isTty, promptPassphrase } from "./tty.js";

export const LOCKED_MESSAGE = `keyfile store is locked: set ${PASSPHRASE_ENV} or run 'agent-vault daemon run' in a terminal`;

/**
 * A connection to vaultd, starting the daemon first if none runs. A keyfile daemon needs its
 * passphrase to start: from the environment it is inherited by the spawned daemon, otherwise it is
 * asked for here (twice while the keyfile does not exist yet) and handed on the same way. With
 * `interactive: false` (stdin is someone else's protocol) it is never asked for.
 */
export async function daemonClient(
  paths: VaultPaths = getPaths(),
  opts: { interactive?: boolean } = {},
): Promise<IpcClient> {
  const running = await connect(ipcEndpoint(paths)).catch(() => null);
  if (running) return running;
  const keystore: KeystoreChoice = readConfig(paths);
  if (keystore === "keyfile" && !process.env[PASSPHRASE_ENV]) {
    if (opts.interactive === false || !isTty()) throw new CliError(LOCKED_MESSAGE, 2);
    process.env[PASSPHRASE_ENV] = await promptPassphrase(!fs.existsSync(keyfilePath(paths)));
  }
  return ensureDaemon(paths);
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
    if (name === "VaultNotInitializedError") {
      return `${err.message} (run: agent-vault init; if this device lost its key: agent-vault recover)`;
    }
    return err.message;
  }
  const message = err instanceof Error ? err.message : String(err);
  if (/^vaultd (exited|did not start)/.test(message)) {
    return `${message}; run 'agent-vault daemon run' in a terminal to see why`;
  }
  return message;
}
