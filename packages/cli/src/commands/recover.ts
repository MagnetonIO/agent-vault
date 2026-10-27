import fs from "node:fs";
import path from "node:path";
import type { VaultPaths } from "@agent-vault/platform";
import { getPaths } from "@agent-vault/platform";
import type { Command } from "commander";
import { keyfilePath, readConfig } from "../config.js";
import { type DaemonOptions, daemonClient } from "../context.js";
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

/**
 * Get this device back into the vault with the recovery words.
 *
 * OS keyring: ask the (locked or open) daemon. Keyfile: the old passphrase may be the very thing
 * that is lost, so a daemon that needs it cannot start. Instead the keyfile is set aside, a daemon
 * is started on a NEW passphrase (it comes up locked, with no root key), and `vault.recover` makes
 * a fresh root key and writes it to a new keyfile under that passphrase. The old keyfile is
 * deleted on success and put back on failure.
 */
export async function recover(
  paths: VaultPaths,
  io: RecoverIo,
  daemon: Pick<DaemonOptions, "spawnArgv"> = {},
): Promise<void> {
  const words = await io.words();
  if (words.length !== WORD_COUNT) {
    throw new CliError(`expected ${WORD_COUNT} words, got ${words.length}`);
  }
  if (readConfig(paths) !== "keyfile") {
    const client = await daemonClient(paths, daemon);
    try {
      await client.call("vault.recover", { words });
    } finally {
      client.close();
    }
    return;
  }

  const passphrase = await io.passphrase();
  // A running daemon has the old key store; it must not answer this.
  await stopDaemon(paths, true);
  const keyfile = keyfilePath(paths);
  const backup = fs.existsSync(keyfile)
    ? path.join(paths.dataDir, `keyfile.bak-${Date.now()}`)
    : null;
  if (backup) {
    fs.renameSync(keyfile, backup);
    fs.chmodSync(backup, 0o600);
  }
  let client: Awaited<ReturnType<typeof daemonClient>> | undefined;
  try {
    client = await daemonClient(paths, { ...daemon, passphrase });
    await client.call("vault.recover", { words });
  } catch (err) {
    client?.close();
    await stopDaemon(paths, true).catch(() => {});
    // Whatever the failed attempt wrote goes; the old keyfile comes back.
    if (backup) fs.renameSync(backup, keyfile);
    else fs.rmSync(keyfile, { force: true });
    throw err;
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
