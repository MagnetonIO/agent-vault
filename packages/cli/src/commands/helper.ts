import type { Command } from "commander";
import { withDaemon } from "../context.js";

export function helperCommand(program: Command): void {
  program
    .command("helper")
    .argument("<secret>", "a secret tagged `helper`")
    .description("print a helper-tagged secret for a harness's apiKeyHelper")
    .action(async (secret: string) => {
      const { value } = await withDaemon((client) =>
        client.call<{ value: string }>("helper.get", { secret }),
      );
      // The one place a value is printed: this is the command's whole purpose.
      process.stdout.write(`${value}\n`);
    });
}
