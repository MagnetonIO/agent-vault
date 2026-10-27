import fs from "node:fs";
import path from "node:path";
import { acquireRecoverLock, RecoveryInProgressError } from "@agent-vault/daemon";
import { getPaths, type VaultPaths } from "@agent-vault/platform";
import type { Command } from "commander";
import { keyfilePath, readConfig } from "../config.js";
import { type DaemonOptions, daemonClient, RECOVERY_IN_PROGRESS } from "../context.js";
import { stopDaemon } from "../daemon-control.js";
import { CliError } from "../errors.js";
import { say } from "../output.js";
import { isTty, promptPassphrase, readLineFromTty } from "../tty.js";

const WORD_COUNT = 24;

/** Words from what was typed: any spacing or commas, numbering like `1.` ignored. */
export function parseWords(line: string): string[] {
  return line
    .toLowerCase()
    .split(/[\s,]+/)
    .filter((token) => token !== "" && !/^\d+[.)]?$/.test(token));
}

export type RecoverIo = {
  /** The 24 recovery words. */
  words(): Promise<string[]>;
  /** A NEW keyfile passphrase (asked twice). Only called for a keyfile store. */
  passphrase(): Promise<string>;
};

/** Test seams: called after each step of a keyfile recover, to act at that moment. */
export type RecoverStep = "locked" | "stopped" | "renamed" | "started";
export type RecoverOptions = Pick<DaemonOptions, "spawnArgv"> & {
  after?: ((step: RecoverStep) => void | Promise<void>) | undefined;
};

const INTERRUPTED = 130;

/**
 * Get this device back into the vault with the recovery words.
 *
 * OS keyring: ask the (locked or open) daemon. Keyfile: the old passphrase may be the very thing
 * that is lost, so a daemon that needs it cannot start. Instead the keyfile is set aside, a daemon
 * is started on a NEW passphrase (it comes up locked, with no root key), and `vault.recover` makes
 * a fresh root key and writes it to a new keyfile under that passphrase. The old keyfile is
 * deleted on success and put back on failure.
 *
 * For that to mean what the user typed, this must be the only daemon: `recover.lock` keeps every
 * other start out for the duration (a missing keyfile accepts any passphrase, so a daemon some
 * hook started under the old one would win), and the daemon that answers must be the one spawned
 * here. SIGINT and SIGTERM roll everything back at the next step boundary; one that arrives while
 * `vault.recover` itself runs lets it finish, because a half-way root key is worse than a late exit.
 */
export async function recover(
  paths: VaultPaths,
  io: RecoverIo,
  opts: RecoverOptions = {},
): Promise<void> {
  const words = await io.words();
  if (words.length !== WORD_COUNT) {
    throw new CliError(`expected ${WORD_COUNT} words, got ${words.length}`);
  }
  if (readConfig(paths) !== "keyfile") {
    const client = await daemonClient(paths, opts);
    try {
      await client.call("vault.recover", { words });
    } finally {
      client.close();
    }
    return;
  }

  const passphrase = await io.passphrase();
  let release: () => void;
  try {
    release = acquireRecoverLock(paths.runtimeDir);
  } catch (err) {
    if (err instanceof RecoveryInProgressError) throw new CliError(RECOVERY_IN_PROGRESS);
    throw err;
  }
  let interrupted = false;
  const onSignal = () => {
    interrupted = true;
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  const checkpoint = () => {
    if (interrupted) throw new CliError("interrupted; the old keyfile is back", INTERRUPTED);
  };

  const keyfile = keyfilePath(paths);
  let backup: string | null = null;
  let client: Awaited<ReturnType<typeof daemonClient>> | undefined;
  try {
    await opts.after?.("locked");
    // A running daemon has the old key store; it must not answer this.
    await stopDaemon(paths, true);
    await opts.after?.("stopped");
    checkpoint();
    if (fs.existsSync(keyfile)) {
      backup = path.join(paths.dataDir, `keyfile.bak-${Date.now()}`);
      fs.renameSync(keyfile, backup);
      fs.chmodSync(backup, 0o600);
    }
    await opts.after?.("renamed");
    checkpoint();

    let spawned: number | undefined;
    client = await daemonClient(paths, {
      ...opts,
      passphrase,
      recovering: true,
      onSpawn: (pid) => {
        spawned = pid;
      },
    });
    await opts.after?.("started");
    const { pid } = await client.call<{ pid: number }>("status");
    if (spawned === undefined || pid !== spawned) {
      throw new CliError(
        "another vaultd answered instead of the one recover started; nothing was changed",
      );
    }
    checkpoint();
    await client.call("vault.recover", { words });
  } catch (err) {
    client?.close();
    await stopDaemon(paths, true).catch(() => {});
    // Whatever the failed attempt wrote goes; the old keyfile comes back.
    if (backup) fs.renameSync(backup, keyfile);
    else fs.rmSync(keyfile, { force: true });
    throw err;
  } finally {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
    release();
  }
  client.close();
  if (backup) fs.rmSync(backup, { force: true });
}

export function recoverCommand(program: Command): void {
  program
    .command("recover")
    .description("get this device back into the vault with the 24 recovery words")
    .action(async () => {
      if (!isTty()) {
        process.stderr.write("Run this in a terminal.\n");
        throw new CliError("recover reads the words from a terminal", 2);
      }
      await recover(getPaths(), {
        words: async () => parseWords(await readLineFromTty(`Recovery words (${WORD_COUNT}): `)),
        passphrase: () => promptPassphrase(true, "New keyfile passphrase"),
      });
      say("recovered: this device has a new key, and the same recovery words still work");
    });
}
