import fs from "node:fs";
import { isSea } from "node:sea";
import {
  createClaudeCodeAdapter,
  createCodexAdapter,
  createOpenCodeAdapter,
  type HarnessAdapter,
} from "@agent-vault/adapters";
import { daemonClient } from "./context.js";
import { CliError } from "./errors.js";
import { warn } from "./output.js";

/** The harnesses `install`, `uninstall`, `doctor` and `hook` know. */
export const HARNESS_IDS = ["claude-code", "codex", "opencode"] as const;

/**
 * How this process was started, as absolute words a hook can run later without PATH: the
 * single-file binary, or node plus the built entry script. Anything else (tsx on a `.ts` file)
 * comes back as the bare name, which `install` refuses.
 */
export function selfCommand(): string[] {
  if (isSea()) return [fs.realpathSync(process.execPath)];
  const entry = process.argv[1];
  if (!entry || !/\.[cm]?js$/.test(entry) || !fs.existsSync(entry)) return ["agent-vault"];
  return [process.execPath, fs.realpathSync(entry)];
}

/** The adapter for `id`, or an error that lists the ones that exist. */
export function adapterFor(id: string): HarnessAdapter {
  switch (id) {
    case "claude-code":
      return createClaudeCodeAdapter({
        command: selfCommand(),
        // stdin and stdout belong to the harness: never ask for a passphrase.
        client: () => daemonClient(undefined, { interactive: false }),
        log: warn,
      });
    case "codex":
      return createCodexAdapter({
        command: selfCommand(),
        client: () => daemonClient(undefined, { interactive: false }),
        log: warn,
      });
    case "opencode":
      return createOpenCodeAdapter({
        command: selfCommand(),
        client: () => daemonClient(undefined, { interactive: false }),
        log: warn,
      });
    default:
      throw new CliError(`unknown harness "${id}"; one of: ${HARNESS_IDS.join(", ")}`);
  }
}
