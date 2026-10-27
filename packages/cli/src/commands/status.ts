import type { Command } from "commander";
import { withDaemon } from "../context.js";
import { say, table } from "../output.js";

type Status = { initialized: boolean; keystore: string; version: string; pid: number };

export function statusCommand(program: Command): void {
  program
    .command("status")
    .description("show the daemon and the vault")
    .action(async () => {
      const s = await withDaemon((client) => client.call<Status>("status"));
      const rows = [
        ["initialized", s.initialized ? "yes" : "no"],
        ["key store", s.keystore],
        ["version", s.version],
        ["daemon pid", String(s.pid)],
      ];
      for (const line of table(rows)) say(line);
    });
}
