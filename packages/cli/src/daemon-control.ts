import { setTimeout as sleep } from "node:timers/promises";
import { connect } from "@agent-vault/daemon";
import { ipcEndpoint, type VaultPaths } from "@agent-vault/platform";
import { CliError } from "./errors.js";
import { say } from "./output.js";

const STOP_WAIT_MS = 10_000;

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
};

/**
 * Stop vaultd and wait for its process to be gone. Never starts one to stop it: with none running
 * this says so and returns.
 */
export async function stopDaemon(paths: VaultPaths, quiet = false): Promise<void> {
  const client = await connect(ipcEndpoint(paths)).catch(() => null);
  if (!client) {
    if (!quiet) say("vaultd is not running");
    return;
  }
  try {
    const { pid } = await client.call<{ pid: number }>("status");
    await client.call("daemon.stop");
    const deadline = Date.now() + STOP_WAIT_MS;
    while (alive(pid)) {
      if (Date.now() > deadline) throw new CliError(`vaultd (pid ${pid}) did not stop within 10 s`);
      await sleep(50);
    }
  } finally {
    client.close();
  }
  if (!quiet) say("vaultd stopped");
}
