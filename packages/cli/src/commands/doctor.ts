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
      const tests = report.checks.filter((c) => !c.info);
      const width = Math.max(...tests.map((c) => c.name.length));
      for (const c of tests) {
        say(`${c.ok ? "ok  " : "FAIL"}  ${c.name.padEnd(width)}  ${c.detail}`);
        if (!c.ok && c.fix) say(`      fix: ${c.fix}`);
      }
      const bad = tests.filter((c) => !c.ok).length;
      say(
        bad === 0 ? `all ${tests.length} checks passed` : `${bad} of ${tests.length} checks failed`,
      );
      for (const c of report.checks.filter((c) => c.info)) say(`info  ${c.name}: ${c.detail}`);
      if (!report.ok) await exitWith(1);
    });
}
