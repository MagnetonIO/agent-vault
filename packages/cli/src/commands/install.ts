import os from "node:os";
import { AdapterError } from "@agent-vault/adapters";
import type { Command } from "commander";
import { CliError } from "../errors.js";
import { adapterFor } from "../harness.js";
import { say, warn } from "../output.js";

export function installCommand(program: Command): void {
  program
    .command("install")
    .argument("<harness>", "claude-code")
    .option("--model-key <secret>", "use this `helper`-tagged secret as the harness's model key")
    .description("hook a harness up to the vault: prompt capture, scrubbing and MCP")
    .action(async (harness: string, opts: { modelKey?: string }) => {
      const adapter = adapterFor(harness);
      const report = await adapter
        .install({
          home: os.homedir(),
          ...(opts.modelKey !== undefined && { modelKey: opts.modelKey }),
        })
        .catch((err: unknown) => {
          if (err instanceof AdapterError) throw new CliError(err.message);
          throw err;
        });
      for (const w of report.warnings ?? []) warn(`WARNING: ${w}`);
      for (const note of report.notes) say(note);
      for (const file of report.backups) say(`backed up to ${file}`);
      say(`installed for ${harness}. Check it with: agent-vault doctor ${harness}`);
    });
}
