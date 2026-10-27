import os from "node:os";
import { historyFiles, scanHistory } from "@agent-vault/adapters";
import type { Command } from "commander";
import { exitWith } from "../errors.js";
import { say, warn } from "../output.js";

export function scanCommand(program: Command): void {
  program
    .command("scan")
    .description("look for secrets in agent transcripts and history (fingerprints only)")
    .option("--json", "print the hits as JSON")
    .action(async (opts: { json?: boolean }) => {
      const files = historyFiles({
        home: os.homedir(),
        ...(process.env.CODEX_HOME && { codexHome: process.env.CODEX_HOME }),
        ...(process.env.CLAUDE_CONFIG_DIR && { claudeConfigDir: process.env.CLAUDE_CONFIG_DIR }),
        ...(process.env.XDG_DATA_HOME && { xdgDataHome: process.env.XDG_DATA_HOME }),
      });
      const hits = await scanHistory(files, { warn });
      if (opts.json) {
        say(JSON.stringify({ scanned: files.length, hits }, null, 2));
      } else if (hits.length === 0) {
        say(`no secrets found in ${files.length} files`);
      } else {
        for (const hit of hits) {
          say(`${hit.file}  ${hit.fingerprints.length} secret(s)`);
          for (const fp of hit.fingerprints) say(`  ${fp}`);
        }
        say();
        say(`${hits.length} of ${files.length} files hold secrets; values are not shown`);
      }
      if (hits.length > 0) await exitWith(1);
    });
}
