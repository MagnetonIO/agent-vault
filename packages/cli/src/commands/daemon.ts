import fs from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { connect, DaemonAlreadyRunningError, startDaemon } from "@agent-vault/daemon";
import {
  getPaths,
  ipcEndpoint,
  openKeyfileStore,
  openOsKeyring,
  type RootKeyStore,
  type VaultPaths,
} from "@agent-vault/platform";
import type { Command } from "commander";
import { keyfilePath, PASSPHRASE_ENV, readConfig } from "../config.js";
import { LOCKED_MESSAGE } from "../context.js";
import { CliError, exitWith } from "../errors.js";
import { say } from "../output.js";
import { isTty, promptPassphrase } from "../tty.js";

const STOP_WAIT_MS = 5000;

/** The key store the config names. A keyfile needs its passphrase: from env, else the terminal. */
async function openConfiguredStore(paths: VaultPaths): Promise<RootKeyStore> {
  if (readConfig(paths) === "os") return openOsKeyring();
  let passphrase = process.env[PASSPHRASE_ENV];
  // Do not leave it in the environment of this long-lived process.
  delete process.env[PASSPHRASE_ENV];
  if (!passphrase) {
    if (!isTty()) throw new CliError(LOCKED_MESSAGE);
    passphrase = await promptPassphrase(!fs.existsSync(keyfilePath(paths)));
  }
  return openKeyfileStore(keyfilePath(paths), passphrase);
}

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
};

async function runDaemon(): Promise<void> {
  const paths = getPaths();
  const store = await openConfiguredStore(paths);
  let handle: Awaited<ReturnType<typeof startDaemon>>;
  try {
    handle = await startDaemon({ paths, store });
  } catch (err) {
    // Losing the race to another daemon is how a second start ends.
    if (err instanceof DaemonAlreadyRunningError) await exitWith(0);
    throw err;
  }
  const shutdown = () => void handle.close();
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  await handle.closed;
  await exitWith(0);
}

async function stopDaemon(): Promise<void> {
  // Never start a daemon just to stop it.
  const client = await connect(ipcEndpoint(getPaths())).catch(() => null);
  if (!client) {
    say("vaultd is not running");
    return;
  }
  try {
    const { pid } = await client.call<{ pid: number }>("status");
    await client.call("daemon.stop");
    const deadline = Date.now() + STOP_WAIT_MS;
    while (alive(pid)) {
      if (Date.now() > deadline) throw new CliError(`vaultd (pid ${pid}) did not stop within 5 s`);
      await sleep(50);
    }
  } finally {
    client.close();
  }
  say("vaultd stopped");
}

export function daemonCommand(program: Command): void {
  const daemon = program
    .command("daemon")
    .description("the background process that holds the vault");
  daemon.command("run").description("run vaultd in the foreground").action(runDaemon);
  daemon.command("stop").description("stop vaultd").action(stopDaemon);
}
