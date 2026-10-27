import type { Command } from "commander";
import { withDaemon } from "../context.js";
import { CliError } from "../errors.js";
import { say } from "../output.js";

export function rmCommand(program: Command): void {
  program
    .command("rm")
    .argument("<name>", "secret name")
    .description("delete a secret")
    .action(async (name: string) => {
      const { removed } = await withDaemon((client) =>
        client.call<{ removed: boolean }>("secret.remove", { name }),
      );
      if (!removed) throw new CliError(`no such secret: ${name}`);
      say(`removed ${name}`);
    });
}
