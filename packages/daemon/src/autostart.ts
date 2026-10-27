import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { ipcEndpoint, type VaultPaths } from "@agent-vault/platform";
import { connect, type IpcClient } from "./client.js";
import { DaemonIdentityError } from "./errors.js";

const RETRY_INTERVAL_MS = 100;
const DEFAULT_TIMEOUT_MS = 3000;

export type EnsureDaemonOptions = {
  /** Command that runs the daemon. Default: the running CLI's `daemon run`. */
  spawnArgv?: string[] | undefined;
  /** How long to wait for a spawned daemon. Default 3000. */
  timeoutMs?: number | undefined;
};

/** The CLI that is running now, asked to run the daemon (Task 14 provides `daemon run`). */
function defaultArgv(): string[] {
  const entry = process.argv[1];
  if (!entry) throw new Error("cannot tell which CLI to spawn: process.argv[1] is empty");
  return [process.execPath, entry, "daemon", "run"];
}

/**
 * Connect to vaultd, starting it first if nobody answers: spawn it detached, then retry every
 * 100 ms for up to `timeoutMs`.
 */
export async function ensureDaemon(
  paths: VaultPaths,
  opts: EnsureDaemonOptions = {},
): Promise<IpcClient> {
  const endpoint = ipcEndpoint(paths);
  try {
    return await connect(endpoint);
  } catch {
    // Not running (or not answering): start one below.
  }

  const [cmd, ...args] = opts.spawnArgv ?? defaultArgv();
  if (!cmd) throw new Error("spawnArgv is empty");
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const child = spawn(cmd, args, { detached: true, stdio: "ignore", windowsHide: true });
  let spawnError: Error | undefined;
  child.on("error", (err) => {
    spawnError = err;
  });
  child.unref();

  const deadline = Date.now() + timeoutMs;
  let last: unknown;
  while (Date.now() < deadline) {
    await sleep(RETRY_INTERVAL_MS);
    if (spawnError) throw new Error("could not start vaultd", { cause: spawnError });
    try {
      return await connect(endpoint, { timeoutMs: Math.max(1, deadline - Date.now()) });
    } catch (err) {
      last = err;
    }
  }
  if (last instanceof DaemonIdentityError) throw last;
  throw new Error(`vaultd did not start within ${timeoutMs} ms`, { cause: last });
}
