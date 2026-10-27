import type { SecretMeta } from "@agent-vault/core";
import type { Command } from "commander";
import { withDaemon } from "../context.js";
import { say, table } from "../output.js";

export function listCommand(program: Command): void {
  program
    .command("list")
    .description("show stored secrets (names and types, never values)")
    .option("--json", "print SecretMeta[] as JSON")
    .action(async (opts: { json?: boolean }) => {
      const secrets = await withDaemon((client) => client.call<SecretMeta[]>("secret.list"));
      if (opts.json) {
        say(JSON.stringify(secrets, null, 2));
        return;
      }
      if (secrets.length === 0) {
        say("no secrets stored");
        return;
      }
      const rows = [
        ["NAME", "TYPE", "LENGTH", "TAGS"],
        ...secrets.map((s) => [s.name, s.type, String(s.length), s.tags.join(",")]),
      ];
      for (const line of table(rows)) say(line);
    });
}
