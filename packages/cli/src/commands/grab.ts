import type { Command } from "commander";
import { clearClipboard, readClipboard } from "../clipboard.js";
import { withDaemon } from "../context.js";
import { CliError } from "../errors.js";
import { say, storedLine, warn } from "../output.js";
import { collect, type PutResult } from "./set.js";

/**
 * What to store for clipboard text. A single line loses the whitespace a copy picks up at either
 * end. Several lines (a PEM) are kept exactly, final newline included. Text that is empty, or that
 * did not decode as UTF-8 (U+FFFD), is refused.
 */
export function clipboardValue(text: string): string {
  const trimmed = text.replace(/^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g, "");
  if (trimmed === "") throw new CliError("clipboard is empty");
  if (text.includes("\uFFFD")) throw new CliError("clipboard is not text");
  return trimmed.includes("\n") ? text : trimmed;
}

export function grabCommand(program: Command): void {
  program
    .command("grab")
    .argument("[name]", "secret name; omit to detect the type and pick one")
    .description("store the clipboard's contents, then clear the clipboard")
    .option("--type <type>", "secret type")
    .option("--tag <tag>", "tag (repeatable)", collect, [] as string[])
    .action(async (name: string | undefined, opts: { type?: string; tag: string[] }) => {
      const value = clipboardValue(await readClipboard());
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
