import os from "node:os";
import type { Command } from "commander";
import { exitWith } from "../errors.js";
import { adapterFor } from "../harness.js";
import { say } from "../output.js";

export function doctorCommand(program: Command): void {
  program
    .command("doctor")
    .argument("<harness>", "claude-code | codex | opencode")
    .description("check that a harness is wired up: hooks, daemon, vault, MCP, and a live probe")
    .action(async (harness: string) => {
      const report = await adapterFor(harness).doctor(os.homedir());
      // Info lines (`info: true` or `severity: "info"`) are notes, not checks: they print after the summary.
      const isInfo = (c: (typeof report.checks)[number]) =>
        c.info === true || c.severity === "info";
      const tests = report.checks.filter((c) => !isInfo(c));
      const width = Math.max(...tests.map((c) => c.name.length));
      for (const c of tests) {
        const label = !c.ok ? "FAIL" : c.severity === "warn" ? "warn" : "ok  ";
        say(`${label}  ${c.name.padEnd(width)}  ${c.detail}`);
        if ((!c.ok || c.severity === "warn") && c.fix) say(`      fix: ${c.fix}`);
        if (c.warning) say(`      WARNING: ${c.warning}`);
      }
      const bad = tests.filter((c) => !c.ok).length;
      say(
        bad === 0 ? `all ${tests.length} checks passed` : `${bad} of ${tests.length} checks failed`,
      );
      for (const c of report.checks.filter(isInfo)) say(`info  ${c.name}: ${c.detail}`);
      if (!report.ok) await exitWith(1);
    });
}
