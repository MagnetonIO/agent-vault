import type { Command } from "commander";
import { withDaemon } from "../context.js";
import { CliError } from "../errors.js";
import { say } from "../output.js";
import { isTty, readLineFromTty } from "../tty.js";

const WORD_COUNT = 24;

/** Words from what was typed: any spacing or commas, numbering like `1.` ignored. */
export function parseWords(line: string): string[] {
  return line
    .toLowerCase()
    .split(/[\s,]+/)
    .filter((token) => token !== "" && !/^\d+[.)]?$/.test(token));
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
      const words = parseWords(await readLineFromTty(`Recovery words (${WORD_COUNT}): `));
      if (words.length !== WORD_COUNT) {
        throw new CliError(`expected ${WORD_COUNT} words, got ${words.length}`);
      }
      await withDaemon((client) => client.call("vault.recover", { words }));
      say("recovered: this device has a new key, and the same recovery words still work");
    });
}
