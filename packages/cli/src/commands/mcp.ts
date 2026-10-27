import { runStdio } from "@agent-vault/mcp";
import type { Command } from "commander";
import { daemonClient } from "../context.js";

export function mcpCommand(program: Command): void {
  program
    .command("mcp")
    .description("serve the vault to an agent over MCP on stdio (metadata, key capture, vault_run)")
    .action(async () => {
      // stdout is the protocol; stdin is the client's, so a locked keyfile store is an error here.
      await runStdio({ connectDaemon: () => daemonClient(undefined, { interactive: false }) });
    });
}
