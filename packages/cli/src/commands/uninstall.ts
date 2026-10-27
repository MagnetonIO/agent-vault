import os from "node:os";
import { AdapterError } from "@agent-vault/adapters";
import type { Command } from "commander";
import { CliError } from "../errors.js";
import { adapterFor } from "../harness.js";
import { say } from "../output.js";

export function uninstallCommand(program: Command): void {
  program
    .command("uninstall")
    .argument("<harness>", "claude-code | codex")
    .description("remove what `install` added; the harness's other settings stay")
    .action(async (harness: string) => {
      await adapterFor(harness)
        .uninstall(os.homedir())
        .catch((err: unknown) => {
          if (err instanceof AdapterError) throw new CliError(err.message);
          throw err;
        });
      say(`removed the agent-vault entries for ${harness}`);
    });
}
