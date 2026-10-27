import { type Command, Option } from "commander";
import { adapterFor } from "../harness.js";
import { warn } from "../output.js";

/** A prompt larger than this is let through unread: nobody pastes a key into 8 MiB. */
export const STDIN_CAP_BYTES = 8 * 1024 * 1024;

/** All of `stream` as text, or null if it holds more than `cap` bytes. */
export async function readCapped(
  stream: AsyncIterable<Buffer | string>,
  cap = STDIN_CAP_BYTES,
): Promise<string | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    size += buf.length;
    if (size > cap) return null;
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * One hook event: the harness's JSON on stdin, its answer on stdout, exit 0. Nothing but that
 * JSON goes to stdout, and nothing here throws: a hook that fails must let the prompt through.
 * (A prompt that holds a key is blocked inside the adapter, which fails closed on its own.)
 */
export async function runHook(
  harness: string,
  event: string,
  opts: { probe?: boolean | undefined },
  stdin: AsyncIterable<Buffer | string> & { isTTY?: boolean },
): Promise<void> {
  try {
    if (stdin.isTTY) return;
    const raw = await readCapped(stdin);
    if (raw === null || raw.trim() === "") return;
    let input: unknown;
    try {
      input = JSON.parse(raw);
    } catch {
      return;
    }
    const out = await adapterFor(harness).handleHook(event, input, { probe: opts.probe === true });
    if (out !== null) process.stdout.write(`${JSON.stringify(out)}\n`);
  } catch (err) {
    warn(`agent-vault hook: ${err instanceof Error ? err.message : String(err)}`);
  }
}

export function hookCommand(program: Command): void {
  program
    .command("hook")
    .argument("<harness>", "claude-code | codex")
    .argument("<event>", "prompt-submit | scrub")
    .addOption(
      new Option("--probe", "detect only: block a prompt with a key, store nothing").hideHelp(),
    )
    .description(
      "handle one harness hook event: JSON on stdin, JSON on stdout (run by the harness)",
    )
    .action(async (harness: string, event: string, opts: { probe?: boolean }) => {
      await runHook(harness, event, opts, process.stdin);
    });
}
