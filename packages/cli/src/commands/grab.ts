import type { Command } from "commander";
import { clearClipboard, readClipboard } from "../clipboard.js";
import { withDaemon } from "../context.js";
import { CliError } from "../errors.js";
import { say, storedLine, warn } from "../output.js";
import { collect, type PutResult } from "./set.js";

export function grabCommand(program: Command): void {
  program
    .command("grab")
    .argument("[name]", "secret name; omit to detect the type and pick one")
    .description("store the clipboard's contents, then clear the clipboard")
    .option("--type <type>", "secret type")
    .option("--tag <tag>", "tag (repeatable)", collect, [] as string[])
    .action(async (name: string | undefined, opts: { type?: string; tag: string[] }) => {
      // A copied value usually ends in a newline that is not part of it.
      const value = (await readClipboard()).replace(/[\r\n]+$/, "");
      if (value === "") throw new CliError("clipboard is empty");
      const bytes = Buffer.from(value, "utf8");
      let meta: PutResult;
      try {
        meta = await withDaemon((client) =>
          client.call<PutResult>("secret.put", {
            ...(name !== undefined && { name }),
            valueB64: bytes.toString("base64"),
            ...(opts.type !== undefined && { type: opts.type }),
            ...(opts.tag.length > 0 && { tags: opts.tag }),
          }),
        );
      } finally {
        bytes.fill(0);
      }
      say(storedLine(meta));
      // Only after the value is safely stored: a failed grab leaves the clipboard alone.
      try {
        await clearClipboard();
      } catch {
        warn("warning: the value is stored, but the clipboard could not be cleared");
      }
    });
}
