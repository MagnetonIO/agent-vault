import type { Command } from "commander";
import { withDaemon } from "../context.js";
import { CliError } from "../errors.js";
import { say, storedLine } from "../output.js";
import { readSecretFromTty } from "../tty.js";

export const collect = (value: string, previous: string[]): string[] => [...previous, value];

export type PutResult = { name: string; type: string; length: number };

export function setCommand(program: Command): void {
  program
    .command("set")
    .argument("<name>", "secret name, e.g. github/pat")
    .description("store a value typed at the terminal (echo off)")
    .option("--type <type>", "secret type")
    .option("--tag <tag>", "tag (repeatable)", collect, [] as string[])
    .action(async (name: string, opts: { type?: string; tag: string[] }) => {
      // The terminal first: with no terminal this exits 2 before a daemon is started.
      const value = await readSecretFromTty(`Value for ${name} (hidden): `);
      try {
        if (value.length === 0) throw new CliError("no value entered");
        const valueB64 = Buffer.from(value).toString("base64");
        const meta = await withDaemon((client) =>
          client.call<PutResult>("secret.put", {
            name,
            valueB64,
            ...(opts.type !== undefined && { type: opts.type }),
            ...(opts.tag.length > 0 && { tags: opts.tag }),
          }),
        );
        say(storedLine(meta));
      } finally {
        value.fill(0);
      }
    });
}
