import os from "node:os";
import { AdapterError } from "@agent-vault/adapters";
import type { Command } from "commander";
import { CliError } from "../errors.js";
import { adapterFor } from "../harness.js";
import { box, say, warn } from "../output.js";

type InstallFlags = {
  modelKey?: string;
  provider?: string;
  /** `--no-history` makes this false. */
  history?: boolean;
};

export function installCommand(program: Command): void {
  program
    .command("install")
    .argument("<harness>", "claude-code | codex | opencode")
    .option("--model-key <secret>", "use this `helper`-tagged secret as the harness's model key")
    .option("--provider <id>", "codex: the model provider --model-key is for (default openai)")
    .option("--no-history", "codex: turn off all of Codex's own prompt history")
    .description("hook a harness up to the vault: prompt capture, scrubbing and MCP")
    .action(async (harness: string, opts: InstallFlags) => {
      const adapter = adapterFor(harness);
      const noHistory = opts.history === false;
      if (harness !== "codex" && (opts.provider !== undefined || noHistory)) {
        throw new CliError("--provider and --no-history only apply to codex");
      }
      const report = await adapter
        .install({
          home: os.homedir(),
          ...(opts.modelKey !== undefined && { modelKey: opts.modelKey }),
          ...(opts.provider !== undefined && { provider: opts.provider }),
          ...(noHistory && { noHistory }),
        })
        .catch((err: unknown) => {
          if (err instanceof AdapterError) throw new CliError(err.message);
          throw err;
        });
      for (const w of report.warnings ?? []) warn(`WARNING: ${w}`);
      for (const note of report.notes) say(note);
      for (const file of report.backups) say(`backed up to ${file}`);
      say(`installed for ${harness}. Check it with: agent-vault doctor ${harness}`);
      if (report.action) {
        say();
        for (const line of box(report.action)) say(line);
      }
    });
}
