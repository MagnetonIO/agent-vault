import { type HookOutput, OVERSIZE_REASON } from "@agent-vault/adapters";
import { type Command, Option } from "commander";
import { adapterFor } from "../harness.js";
import { readHookInput } from "../hook-input.js";
import { warn } from "../output.js";

/**
 * One hook event: the harness's JSON on stdin, its answer on stdout, exit 0. Nothing but that
 * JSON goes to stdout, and nothing here throws: a hook that fails must let the prompt through.
 * (A prompt that holds a key is blocked inside the adapter, which fails closed on its own. A
 * prompt too large to read cannot be checked, so it is blocked here too.)
 */
export async function runHook(
  harness: string,
  event: string,
  opts: { probe?: boolean | undefined },
  stdin: Parameters<typeof readHookInput>[0],
): Promise<void> {
  try {
    if (stdin.isTTY) return;
    const input = await readHookInput(stdin);
    const adapter = adapterFor(harness);
    if (input.oversize) {
      if (event === "prompt-submit") print(adapter.blockOutput(OVERSIZE_REASON));
      return;
    }
    if (input.raw.trim() === "") return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(input.raw);
    } catch {
      return;
    }
    print(await adapter.handleHook(event, parsed, { probe: opts.probe === true }));
  } catch (err) {
    warn(`agent-vault hook: ${err instanceof Error ? err.message : String(err)}`);
  }
}

const print = (out: HookOutput): void => {
  if (out !== null) process.stdout.write(`${JSON.stringify(out)}\n`);
};

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
