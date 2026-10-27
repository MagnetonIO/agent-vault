import { connect, type IpcClient } from "@agent-vault/daemon";
import { getPaths, ipcEndpoint } from "@agent-vault/platform";
import type { Command } from "commander";
import {
  KEYSTORE_CHOICES,
  type KeystoreChoice,
  PASSPHRASE_ENV,
  readConfig,
  restoreConfig,
  STORE_KIND,
  snapshotConfig,
  writeConfig,
} from "../config.js";
import { daemonClient } from "../context.js";
import { CliError } from "../errors.js";
import { say, warn } from "../output.js";
import { isTty, promptPassphrase } from "../tty.js";

const WORDS_PER_LINE = 4;

/** The recovery words, numbered, four to a line. This is the first thing `init` prints. */
export function formatWords(words: string[]): string[] {
  const lines: string[] = [];
  for (let i = 0; i < words.length; i += WORDS_PER_LINE) {
    lines.push(
      words
        .slice(i, i + WORDS_PER_LINE)
        .map((word, j) => `${String(i + j + 1).padStart(2)}. ${word}`.padEnd(16))
        .join("")
        .trimEnd(),
    );
  }
  return lines;
}

async function isRunning(): Promise<boolean> {
  const client = await connect(ipcEndpoint(getPaths())).catch(() => null);
  client?.close();
  return client !== null;
}

export function initCommand(program: Command): void {
  program
    .command("init")
    .description("create the vault and show its recovery words (once)")
    .option("--keystore <kind>", "where the device key lives: os (default) or keyfile")
    .action(async (opts: { keystore?: string }) => {
      const paths = getPaths();
      const requested = opts.keystore ?? readConfig(paths);
      if (!(KEYSTORE_CHOICES as readonly string[]).includes(requested)) {
        throw new CliError(`--keystore must be one of: ${KEYSTORE_CHOICES.join(", ")}`, 2);
      }
      const keystore = requested as KeystoreChoice;

      // The keyfile passphrase has to be settled before a daemon is started: it is inherited.
      if (keystore === "keyfile" && !process.env[PASSPHRASE_ENV] && !(await isRunning())) {
        if (!isTty()) {
          throw new CliError(
            `keyfile store needs a passphrase: set ${PASSPHRASE_ENV} or run this in a terminal`,
            2,
          );
        }
        process.env[PASSPHRASE_ENV] = await promptPassphrase(true);
      }

      // The daemon reads the config when it starts. If init does not complete, the old config goes
      // back: a vault made under one key store must never be pointed at another.
      const before = snapshotConfig(paths);
      writeConfig(paths, keystore);
      let client: IpcClient | undefined;
      try {
        client = await daemonClient(paths);
        const status = await client.call<{ keystore: string }>("status");
        if (status.keystore !== STORE_KIND[keystore]) {
          throw new CliError("stop the running daemon first: agent-vault daemon stop");
        }
        const { recoveryWords } = await client.call<{ recoveryWords: string[] }>("vault.init", {
          keystore: STORE_KIND[keystore],
        });
        for (const line of formatWords(recoveryWords)) say(line);
        say();
        say("Write these down. They are shown once and are the only way to recover this vault.");
      } catch (err) {
        restoreConfig(paths, before);
        throw err;
      } finally {
        client?.close();
      }
      say(`vault ready · key store: ${keystore}`);
      if (keystore === "keyfile") {
        warn("the keyfile store is weaker than the OS keyring: keep the passphrase safe");
      }
    });
}
