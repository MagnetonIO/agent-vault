import os from "node:os";
import type { Command } from "commander";
import { exitWith } from "../errors.js";
import { adapterFor } from "../harness.js";
import { say } from "../output.js";

export function doctorCommand(program: Command): void {
  program
    .command("doctor")
    .argument("<harness>", "claude-code")
    .description("check that a harness is wired up: hooks, daemon, vault, MCP, and a live probe")
    .action(async (harness: string) => {
      const report = await adapterFor(harness).doctor(os.homedir());
      const width = Math.max(...report.checks.map((c) => c.name.length));
      for (const c of report.checks) {
        say(`${c.ok ? "ok  " : "FAIL"}  ${c.name.padEnd(width)}  ${c.detail}`);
        if (!c.ok && c.fix) say(`      fix: ${c.fix}`);
      }
      const bad = report.checks.filter((c) => !c.ok).length;
      say(
        bad === 0
          ? `all ${report.checks.length} checks passed`
          : `${bad} of ${report.checks.length} checks failed`,
      );
      if (!report.ok) await exitWith(1);
    });
}
